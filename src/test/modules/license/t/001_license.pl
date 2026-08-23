# Copyright (c) 2022-2023, PostgreSQL Global Development Group

# Startup-time license enforcement tests for the Postgres Enterprise by
# AppsCode build. These exercise the three validity gates, the CA
# self-check boundary, the clock-rollback state, the SQL reporting
# function, and the deliberate non-checks (no cluster binding, no personal
# data).
#
# The tests can only run against a build that embedded a dev CA, because
# they must issue licenses signed by the same CA the binary trusts. Point
# them at that CA with:
#   APPSCODE_LICENSE_DEV_CA      dev CA certificate PEM
#   APPSCODE_LICENSE_DEV_CA_KEY  dev CA private key
# Otherwise the whole suite is skipped.

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename;
use File::Copy qw(copy);
use Digest::SHA qw(sha256 hmac_sha256_hex);
use Math::BigInt;

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $cacert = $ENV{APPSCODE_LICENSE_DEV_CA};
my $cakey  = $ENV{APPSCODE_LICENSE_DEV_CA_KEY};

# The key defaults to the sibling dev-ca.key produced by make-dev-ca.sh, so
# the meson env only needs to pass the certificate path.
if ($cacert && !$cakey)
{
	($cakey = $cacert) =~ s/\.pem$/.key/;
}

if (!$cacert || !$cakey || !-f $cacert || !-f $cakey)
{
	plan skip_all =>
	  'set APPSCODE_LICENSE_DEV_CA (dev CA cert; key assumed alongside as dev-ca.key) to run';
}

my $root = abs_path(dirname(abs_path(__FILE__)) . '/../../../../..');
my $mklic = "$root/scripts/make-license.sh";
my $mkca  = "$root/scripts/make-dev-ca.sh";

# Absolute path: PGLICENSE is read by the backend, whose cwd is not the
# test directory, so a relative tempdir path would not resolve.
my $tmp = abs_path(PostgreSQL::Test::Utils::tempdir());

# Issue a license from the embedded dev CA with the given options.
sub mk_license
{
	my (%o) = @_;
	my $out = "$tmp/" . ($o{name} // 'lic') . ".pem";
	my @args = ('--ca-key', $cakey, '--ca-cert', $cacert, '--out', $out);
	push @args, '--not-before',    $o{not_before}    if defined $o{not_before};
	push @args, '--valid-seconds', $o{valid_seconds} if defined $o{valid_seconds};
	push @args, '--days',          $o{days}          if defined $o{days};
	push @args, '--features',      $o{features}      if defined $o{features};
	push @args, '--plan',          $o{plan}          if defined $o{plan};
	push @args, '--product',       $o{product}       if defined $o{product};
	push @args, '--tier',          $o{tier}          if defined $o{tier};
	push @args, '--eku',           $o{eku}           if defined $o{eku};
	push @args, '--cn',            $o{cn}            if defined $o{cn};
	push @args, '--email',         $o{email}         if defined $o{email};
	push @args, '--no-eku'         if $o{no_eku};
	push @args, '--no-san'         if $o{no_san};
	my $rc = system('sh', $mklic, @args);
	die "make-license.sh failed for $out" if $rc != 0;
	return $out;
}

# Decimal serial of a certificate.
sub cert_serial_dec
{
	my ($path) = @_;
	my $s = `openssl x509 -in "$path" -noout -serial`;
	$s =~ s/serial=//;
	chomp $s;
	return Math::BigInt->from_hex($s)->bstr;
}

# Try to start $node with $licpath as the license; return (ok, logtext).
sub start_with
{
	my ($node, $licpath) = @_;
	local $ENV{PGLICENSE} = $licpath;
	truncate $node->logfile, 0 if -f $node->logfile;
	my $ok = $node->start(fail_ok => 1);
	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile);
	return ($ok, $log);
}

# A known-good license, used to initialize the cluster.
my $valid = mk_license(name => 'valid', days => 30);

# initdb runs a single-user phase that itself requires a license.
$ENV{PGLICENSE} = $valid;
my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf', "log_min_messages = warning\n");

# ---- valid license: starts, and reports the rebranded version ----
{
	my ($ok, $log) = start_with($node, $valid);
	is($ok, 1, 'valid license: server starts');
	my $ver = $node->safe_psql('postgres', 'SELECT version()');
	like($ver, qr/Postgres Enterprise by AppsCode/,
		'valid license: version string is rebranded');
	like($log, qr/license accepted: id \(serial\)/,
		'valid license: acceptance line logged');
	$node->stop;
}

# ---- missing license file ----
{
	my ($ok, $log) = start_with($node, "$tmp/nonexistent.pem");
	is($ok, 0, 'missing license: server refuses to start');
	like($log, qr/could not find a license file/,
		'missing license: diagnostic logged');
}

# ---- expired ----
{
	my $lic = mk_license(name => 'expired', not_before => -5184000, days => 30);
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 0, 'expired license: server refuses to start');
	like($log, qr/license certificate expired on/,
		'expired license: expiry message logged');
}

# ---- not yet valid ----
{
	my $lic = mk_license(name => 'future', not_before => 86400, days => 30);
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 0, 'not-yet-valid license: server refuses to start');
	like($log, qr/is not valid until/, 'not-yet-valid: message logged');
}

# ---- truncated / garbage PEM ----
{
	my $garbage = "$tmp/garbage.pem";
	open my $fh, '>', $garbage or die;
	print $fh "this is not a certificate\n";
	close $fh;
	my ($ok, $log) = start_with($node, $garbage);
	is($ok, 0, 'garbage PEM: server refuses to start');
	like($log, qr/contains no PEM certificate/, 'garbage: message logged');
}

# ---- license signed by a different CA ----
{
	system('sh', $mkca, "$tmp/otherca") == 0 or die 'make-dev-ca failed';
	my $out = "$tmp/othersigned.pem";
	system('sh', $mklic, '--ca-key', "$tmp/otherca/dev-ca.key",
		'--ca-cert', "$tmp/otherca/dev-ca.pem", '--out', $out) == 0
	  or die 'make-license (other CA) failed';
	my ($ok, $log) = start_with($node, $out);
	is($ok, 0, 'different CA: server refuses to start');
	like($log, qr/does not verify against the AppsCode license CA/,
		'different CA: chain failure logged');
}

# ---- rogue root reusing the CA subject DN ----
{
	# A self-signed cert with O=AppsCode Inc., CN=ca but a different key.
	my $rogue_key = "$tmp/rogue-ca.key";
	my $rogue_crt = "$tmp/rogue-ca.pem";
	system("openssl genrsa -out $rogue_key 2048 2>/dev/null") == 0 or die;
	system("openssl req -x509 -new -key $rogue_key -sha256 -days 3650 "
		  . "-subj '/O=AppsCode Inc./CN=ca' "
		  . "-addext 'basicConstraints=critical,CA:TRUE' "
		  . "-addext 'keyUsage=critical,keyCertSign' "
		  . "-out $rogue_crt 2>/dev/null") == 0
	  or die;
	my $out = "$tmp/rogue-leaf.pem";
	system('sh', $mklic, '--ca-key', $rogue_key, '--ca-cert', $rogue_crt,
		'--out', $out) == 0
	  or die;
	my ($ok, $log) = start_with($node, $out);
	is($ok, 0, 'rogue root with same subject DN: server refuses to start');
	like($log, qr/does not verify against the AppsCode license CA/,
		'rogue root: rejected by signature, not name');
}

# ---- serverAuth EKU instead of clientAuth ----
{
	my $lic = mk_license(name => 'server', eku => 'serverAuth');
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 0, 'serverAuth license: server refuses to start');
	like($log, qr/lacks the client authentication/, 'serverAuth: message logged');
}

# ---- no EKU at all ----
{
	my $lic = mk_license(name => 'noeku', no_eku => 1);
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 0, 'no-EKU license: server refuses to start');
}

# ---- O without postgres-enterprise ----
{
	my $lic = mk_license(name => 'nofeat', features => 'kubedb-enterprise');
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 0, 'O lacking postgres-enterprise: server refuses to start');
	like($log, qr/does not include the "postgres-enterprise" feature/,
		'missing feature: message logged');
}

# ---- O with postgres-enterprise plus an unrelated feature: OK ----
{
	my $lic = mk_license(name => 'multi',
		features => 'postgres-enterprise,kubedb-enterprise');
	my ($ok, $log) = start_with($node, $lic);
	is($ok, 1, 'O with postgres-enterprise plus extra: starts');
	$node->stop;
}

# ---- OU not part of the gate (other value, and none) ----
{
	my $lic = mk_license(name => 'ou', plan => 'something-else');
	my ($ok) = start_with($node, $lic);
	is($ok, 1, 'OU other than postgres-enterprise: still starts');
	$node->stop;

	my $lic2 = mk_license(name => 'noou', plan => '');
	my ($ok2) = start_with($node, $lic2);
	is($ok2, 1, 'no OU at all: still starts');
	$node->stop;
}

# ---- C not part of the gate (other value, and none) ----
{
	my $lic = mk_license(name => 'cx', product => 'xx');
	my ($ok) = start_with($node, $lic);
	is($ok, 1, 'C other than postgres: still starts');
	$node->stop;

	my $lic2 = mk_license(name => 'noc', product => '');
	my ($ok2) = start_with($node, $lic2);
	is($ok2, 1, 'no C at all: still starts');
	$node->stop;
}

# ---- DNS SAN present but not checked (no cluster binding) ----
{
	# The default license carries a DNS SAN; starting on this machine, whose
	# identity does not match that SAN, must still succeed.
	my ($ok) = start_with($node, $valid);
	is($ok, 1, 'DNS SAN present: no hostname check, server starts');
	# leave running for the SQL and SAN-privacy checks below
}

# ---- appscode_license_info() and email-SAN privacy ----
{
	my $has_ext = $node->safe_psql('postgres',
		"SELECT count(*) FROM pg_available_extensions WHERE name = 'appscode_license'");
	if ($has_ext eq '1')
	{
		$node->safe_psql('postgres', 'CREATE EXTENSION appscode_license');
		my $serial = $node->safe_psql('postgres',
			'SELECT license_id FROM appscode_license_info()');
		my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile);
		my ($logged) = $log =~ /id \(serial\) (\d+)/;
		is($serial, $logged,
			'appscode_license_info serial matches the startup log');

		my $feat = $node->safe_psql('postgres',
			"SELECT 'postgres-enterprise' = ANY(features) FROM appscode_license_info()");
		is($feat, 't', 'appscode_license_info reports the feature');
	}
	else
	{
		ok(1, 'appscode_license extension not installed; skipping info checks');
	}

	# The default license carries an email SAN (dev\@example.com). It must
	# never appear in the log or in the SQL output.
	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile);
	unlike($log, qr/example\.com/, 'email SAN never appears in the log');
	$node->stop;
}

# ---- clock rollback, via a crafted (validly HMAC'd) state file ----
SKIP:
{
	# Derive the state HMAC key the way license_state.c does:
	# key = SHA256(label || raw CA cert SHA-256 || serial_dec).
	my $fp = `openssl x509 -in "$cacert" -noout -fingerprint -sha256`;
	$fp =~ s/.*=//;
	$fp =~ s/://g;
	chomp $fp;
	$fp = lc $fp;

	my $serial = cert_serial_dec($valid);
	my $label  = 'appscode-pg-license-state-v1';
	my $key    = sha256($label . pack('H*', $fp) . $serial);

	my $statefile = $node->data_dir . '/.pg_license_state';

	my $write_state = sub {
		my ($hwm) = @_;
		my $body =
		    "PGLICSTATE1\n"
		  . "fingerprint=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
		  . "hwm=$hwm\n"
		  . "serial=$serial\n" . "cn=x\n";
		my $mac = hmac_sha256_hex($body, $key);
		open my $fh, '>', $statefile or die "open state: $!";
		print $fh $body . "hmac=$mac\n";
		close $fh;
		chmod 0600, $statefile;
	};

	my $now = time();

	# High-water mark 30 days in the future: starting now looks like a
	# 30-day backward jump, which must fail.
	$write_state->($now + 30 * 86400);
	my ($ok_back, $log_back) = start_with($node, $valid);
	is($ok_back, 0, 'clock 30 days back: server refuses to start');
	like($log_back, qr/clock appears to have moved backward/,
		'clock rollback: message logged');

	# High-water mark 1 hour in the future is within the 24-hour tolerance,
	# so starting now is fine.
	$write_state->($now + 3600);
	my ($ok_ok) = start_with($node, $valid);
	is($ok_ok, 1, 'clock 1 hour within tolerance: server starts');
	$node->stop;
}

# ---- a license/state moved to a second installation is logged, not blocked ----
{
	# A second installation with the same license file. Its state file is
	# seeded from the first installation, whose stored fingerprint will not
	# match the second (different data directory inode). That must log the
	# new-installation message and still start, since there is no cluster
	# binding to enforce.
	$ENV{PGLICENSE} = $valid;
	my $node2 = PostgreSQL::Test::Cluster->new('copy');
	$node2->init;
	$node2->start;			# writes node2's own state
	$node2->stop;

	copy($node->data_dir . '/.pg_license_state',
		$node2->data_dir . '/.pg_license_state')
	  or die "copy state: $!";

	my ($ok, $log) = start_with($node2, $valid);
	is($ok, 1, 'copied license/state: second installation still starts');
	like($log, qr/is now running on a new installation/,
		'copied license/state: new-installation message logged');
	$node2->stop;
}

# ---- single-user mode with an expired license fails ----
{
	my $lic = mk_license(name => 'exp_single', not_before => -5184000, days => 30);
	local $ENV{PGLICENSE} = $lic;
	my $pg = $node->installed_command('postgres');
	my $datadir = $node->data_dir;
	my ($stdout, $stderr);
	my $rc = PostgreSQL::Test::Utils::run_log(
		[ $pg, '--single', '-D', $datadir, 'postgres' ],
		'<', \'SELECT 1;',
		'>', \$stdout,
		'2>', \$stderr);
	isnt($rc, 0, 'single-user with expired license: exits non-zero');
	like($stderr, qr/license certificate expired/,
		'single-user expired: message logged');
}

done_testing();
