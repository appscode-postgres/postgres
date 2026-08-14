# Copyright (c) 2021-2025, PostgreSQL Global Development Group

# The clock rollback state file, and the installation fingerprint.
#
# The clock is never actually moved. Instead the state file is rewritten with a
# high water mark in the future, which is indistinguishable from the server's
# point of view and does not require libfaketime or root. Forging a state file
# is possible here because the HMAC key derives from the embedded CA public key
# digest alone, which is exactly the honest limitation recorded in
# doc/LICENSE_ENFORCEMENT.md section 8.
#
# Requires a development CA build; see t/001_startup.pl for the recipe.

use strict;
use warnings FATAL => 'all';

use Digest::SHA qw(hmac_sha256_hex);
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $devca = $ENV{PG_LICENSE_DEV_CA};

if (!defined $devca || !-f "$devca/ca.crt" || !-f "$devca/ca.key")
{
	plan skip_all =>
	  'PG_LICENSE_DEV_CA is not set to a development CA directory containing ca.crt and ca.key';
}

my $srcdir = $ENV{PG_LICENSE_SRCDIR} || '../../../..';
my $mklicense = "$srcdir/scripts/make-license.sh";

plan skip_all => "cannot find $mklicense" unless -x $mklicense;

my $CLUSTER = '3f2b8c14-9d7e-4a51-b6c3-8e2f1a0d5c47';
my $SECS_PER_DAY = 86400;

local $ENV{PG_CLUSTER_ID} = $CLUSTER;

# The HMAC key is the SHA-256 of the embedded CA SubjectPublicKeyInfo.
my $keyhex = `openssl x509 -in "$devca/ca.crt" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r 2>/dev/null`;
$keyhex =~ s/\s.*$//s;
die "could not compute the dev CA SPKI digest" unless $keyhex =~ /^[0-9a-f]{64}$/;
my $key = pack 'H*', $keyhex;

# Is the server accepting connections? PostgreSQL::Test::Cluster has no
# is_alive in this branch.
sub server_up
{
	my ($n) = @_;
	return $n->psql('postgres', 'SELECT 1') == 0 ? 1 : 0;
}

sub issue_to
{
	my ($out, @args) = @_;
	my @cmd = ($mklicense, '--ca-dir', $devca, '--out', $out, @args);
	my ($o, $e);
	IPC::Run::run \@cmd, '>' => \$o, '2>' => \$e
	  or die "make-license.sh failed: $e";
	chmod 0600, $out;
	return;
}

# The license UUID is the certificate serial, rendered canonically.
sub license_uuid
{
	my ($path) = @_;
	my $serial = `openssl x509 -in "$path" -noout -serial 2>/dev/null`;
	$serial =~ s/^serial=//;
	$serial =~ s/\s//g;
	$serial = lc $serial;
	return join '-', substr($serial, 0, 8), substr($serial, 8, 4),
	  substr($serial, 12, 4), substr($serial, 16, 4), substr($serial, 20, 12);
}

sub system_identifier
{
	my ($node) = @_;
	my $out = `pg_controldata -D "@{[$node->data_dir]}" 2>/dev/null`;
	return $1 if $out =~ /Database system identifier:\s+(\d+)/;
	die 'could not read the system identifier';
}

# Write a state file the server will accept as authentic.
sub write_state
{
	my ($node, $uuid, $installation, $high_water) = @_;
	my $payload = "version=1\n"
	  . "uuid=$uuid\n"
	  . "installation=$installation\n"
	  . "high_water_mark=$high_water";
	my $mac = hmac_sha256_hex($payload, $key);

	my $path = $node->data_dir . '/.pg_license_state';
	open my $fh, '>', $path or die "could not write $path: $!";
	print $fh "# PostgreSQL license state. Do not edit.\n";
	print $fh "$payload\n";
	print $fh "hmac=sha256:$mac\n";
	close $fh;
	chmod 0600, $path;
	return $path;
}

my $node = PostgreSQL::Test::Cluster->new('state');
$node->init;
my $lic = $node->data_dir . '/license.pem';
my $statefile = $node->data_dir . '/.pg_license_state';

issue_to($lic, '--cluster', $CLUSTER);
my $uuid = license_uuid($lic);

#
# A first start creates the state file.
#
$node->start;
ok(server_up($node), 'cluster starts');
$node->stop;

ok(-f $statefile, 'state file is created on first start');

my $mode = (stat $statefile)[2] & 07777;
is(sprintf('%04o', $mode), '0600', 'state file is mode 0600');

my $content = PostgreSQL::Test::Utils::slurp_file($statefile);
like($content, qr/^uuid=\Q$uuid\E$/m, 'state file records the license UUID');
like($content, qr/^hmac=sha256:[0-9a-f]{64}$/m, 'state file carries an HMAC');
unlike($content, qr/cluster_id/,
	'state file does not record the Kubernetes cluster ID');

my $sysid = system_identifier($node);
like($content, qr/^installation=\Q$sysid\E$/m,
	'installation fingerprint is the pg_control system identifier');

#
# An edited state file is refused.
#
{
	my $edited = $content;
	$edited =~ s/^high_water_mark=\d+$/high_water_mark=99999999999/m;
	open my $fh, '>', $statefile or die $!;
	print $fh $edited;
	close $fh;

	my $logstart = -s $node->logfile;
	$node->start(fail_ok => 1);
	ok(!server_up($node), 'edited state file refuses to start');

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	like($log, qr/failed its integrity check/,
		'edited state file reports an integrity failure');
	$node->stop('immediate', fail_ok => 1);
}

#
# A clock that has moved backward beyond the tolerance is refused.
#
# Recorded high water mark 30 days ahead of now is the same thing, from the
# server's point of view, as the clock having been moved back 30 days.
#
{
	write_state($node, $uuid, $sysid, time() + 30 * $SECS_PER_DAY);

	my $logstart = -s $node->logfile;
	$node->start(fail_ok => 1);
	ok(!server_up($node), 'clock moved back 30 days refuses to start');

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	like($log, qr/system clock appears to have moved backward/,
		'clock rollback is reported specifically');
	$node->stop('immediate', fail_ok => 1);
}

#
# A small backward movement is within tolerance and is allowed, so an NTP step
# or a timezone mistake does not take a cluster down.
#
{
	write_state($node, $uuid, $sysid, time() + 3600);

	$node->start;
	ok(server_up($node), 'clock moved back 1 hour still starts');
	$node->stop;
}

#
# Copying a license to a second data directory.
#
# The cluster binding, not the fingerprint, is the enforcement mechanism, so a
# bound license fails outright on the second cluster. An unbound license starts
# and logs the new installation, which is the evidence a license was copied.
#
{
	my $second = PostgreSQL::Test::Cluster->new('second');
	$second->init;

	# Bound to the first cluster, started under a different cluster identity.
	PostgreSQL::Test::Utils::system_or_bail('cp', $lic,
		$second->data_dir . '/license.pem');

	{
		local $ENV{PG_CLUSTER_ID} = '99999999-8888-4777-8666-555555555555';
		my $logstart = -s $second->logfile;
		$second->start(fail_ok => 1);
		ok(!server_up($second),
			'cluster bound license refuses to start on a second cluster');
		my $log =
		  PostgreSQL::Test::Utils::slurp_file($second->logfile, $logstart);
		like($log, qr/is bound to cluster .* but this cluster is/,
			'refusal names both cluster identities');
		$second->stop('immediate', fail_ok => 1);
	}

	# An unbound license does start, and the move is visible in the log.
	issue_to($second->data_dir . '/license.pem', '--cluster', '*',
		'--uuid', $uuid);

	# Seed the state file with the FIRST cluster's fingerprint, which is what
	# copying a whole data directory would leave behind.
	write_state($second, $uuid, $sysid, time());

	my $logstart = -s $second->logfile;
	$second->start;
	ok(server_up($second), 'unbound license starts on the second cluster');

	my $log = PostgreSQL::Test::Utils::slurp_file($second->logfile, $logstart);
	like($log, qr/is now running on a different installation/,
		'a license seen on a new installation is logged');
	$second->stop;
}

done_testing();
