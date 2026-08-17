# Copyright (c) 2021-2025, PostgreSQL Global Development Group

# Startup time license enforcement.
#
# These tests need a server built with a development CA embedded INSTEAD OF the
# production AppsCode CA, because no license we can issue here would ever chain
# to the production root. Build with:
#
#   make -C src/backend/license clean
#   make -C src/backend/license LICENSE_DEV_CA_PEM=/path/to/dev-ca/ca.crt
#   make && make install
#
# then run with PG_LICENSE_DEV_CA=/path/to/dev-ca pointing at the same CA
# directory, which must still hold ca.key so licenses can be issued.
#
# Without that the whole file skips rather than reporting confusing chain
# failures.

use strict;
use warnings FATAL => 'all';

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

if (!-x $mklicense)
{
	plan skip_all => "cannot find $mklicense";
}

my $CLUSTER = '3f2b8c14-9d7e-4a51-b6c3-8e2f1a0d5c47';
my $OTHER = '11111111-2222-4333-8444-555555555555';

my $node = PostgreSQL::Test::Cluster->new('licensed');
$node->init;

my $licpath = $node->data_dir . '/license.pem';

# Issue a license into the node's data directory.
sub issue
{
	my (@args) = @_;
	my @cmd = ($mklicense, '--ca-dir', $devca, '--out', $licpath, @args);
	my ($stdout, $stderr);
	my $ok = IPC::Run::run \@cmd, '>' => \$stdout, '2>' => \$stderr;
	die "make-license.sh failed: $stderr" unless $ok;
	chmod 0600, $licpath;
	return;
}

# Is the server accepting connections?
#
# PostgreSQL::Test::Cluster has no is_alive in this branch, and probing with
# psql is the stronger assertion anyway: it proves the server is serving, not
# merely that a process exists.
sub server_up
{
	my ($n) = @_;
	return $n->psql('postgres', 'SELECT 1') == 0 ? 1 : 0;
}

# Assert the server refuses to start and the log explains why.
sub refuses
{
	my ($desc, $pattern) = @_;
	my $logstart = -s $node->logfile;

	$node->start(fail_ok => 1);
	ok(!server_up($node), "$desc: server is not accepting connections");

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	like($log, $pattern, "$desc: log explains the failure");

	# Leave nothing running for the next case.
	$node->stop('immediate', fail_ok => 1);
	return;
}

# Assert the server starts.
sub accepts
{
	my ($desc, $pattern) = @_;
	my $logstart = -s $node->logfile;

	$node->start;
	ok(server_up($node), "$desc: server is accepting connections");
	is($node->safe_psql('postgres', 'SELECT 1'), '1', "$desc: answers queries");

	if (defined $pattern)
	{
		my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
		like($log, $pattern, "$desc: log records the license");
	}
	$node->stop;
	return;
}

# Every start below resolves the cluster identity from the environment.
local $ENV{PG_CLUSTER_ID} = $CLUSTER;

#
# The happy path, and the log line support relies on.
#
issue('--cluster', $CLUSTER);
accepts('valid license', qr/license [0-9a-f-]{36} verified for "ACME Corporation"/);

#
# Validity window.
#
issue('--cluster', $CLUSTER, '--expired');
refuses('expired license', qr/license has expired/);

issue('--cluster', $CLUSTER, '--not-yet-valid');
refuses('not yet valid license', qr/license is not yet valid/);

#
# Missing and malformed input.
#
unlink $licpath;
refuses('missing license file', qr/does not exist/);

PostgreSQL::Test::Utils::append_to_file($licpath, "not a certificate at all\n");
refuses('garbage license file', qr/not valid PEM/);

issue('--cluster', $CLUSTER);
my $full = PostgreSQL::Test::Utils::slurp_file($licpath);
open my $fh, '>', $licpath or die $!;
print $fh substr($full, 0, 400);
close $fh;
refuses('truncated license file', qr/not valid PEM/);

#
# The trust anchor cannot be substituted.
#
# The rogue CA is generated with the same subject DN as the development CA, so
# this specifically checks that a subject name collision does not stand in for
# signature verification.
#
# A private scratch directory. TESTDIR is set by some harnesses and not by
# others, so it is not relied on here.
my $rogue = PostgreSQL::Test::Utils::tempdir() . '/rogue-ca';
PostgreSQL::Test::Utils::system_or_bail("$srcdir/scripts/make-dev-ca.sh", $rogue);
{
	my @cmd = ($mklicense, '--ca-dir', $rogue, '--out', $licpath,
		'--cluster', $CLUSTER);
	my ($o, $e);
	IPC::Run::run \@cmd, '>' => \$o, '2>' => \$e or die $e;
	chmod 0600, $licpath;
}
refuses('license from a rogue CA with the same subject DN',
	qr/chain verification failed/);

#
# SSL_CERT_FILE and SSL_CERT_DIR must not influence the license trust store.
#
{
	local $ENV{SSL_CERT_FILE} = "$rogue/ca.crt";
	local $ENV{SSL_CERT_DIR} = $rogue;
	refuses('SSL_CERT_FILE and SSL_CERT_DIR do not add a trust anchor',
		qr/chain verification failed/);
}

#
# Certificate content.
#
issue('--cluster', $CLUSTER, '--wrong-product');
refuses('wrong product', qr/does not include product "postgres-enterprise"/);

issue('--cluster', $CLUSTER, '--no-version');
refuses('missing version constraint', qr/does not specify a productVersion/);

issue('--cluster', $CLUSTER, '--version', '>=13,<15');
refuses('version constraint excludes this major version',
	qr/does not satisfy constraint/);

issue('--cluster', $CLUSTER, '--bad-serial');
refuses('serial is not a v4 UUID', qr/not a valid v4 UUID/);

#
# Cluster binding.
#
issue('--cluster', $OTHER);
refuses('license bound to a different cluster',
	qr/is bound to cluster .* but this cluster is/);

issue('--cluster', '*');
accepts('unbound license', qr/cluster any/);

issue('--cluster', $CLUSTER);
{
	local $ENV{PG_CLUSTER_ID} = '';
	refuses('bound license with no resolvable cluster identity',
		qr/no cluster identity could be resolved/);
}

#
# File permissions.
#
# The license carries no secret and no personal data, and in Kubernetes it
# normally arrives as a read only Secret mount that the operator cannot chmod,
# so a permissive mode must not be fatal. A group or world writable file is an
# integrity concern and warns.
#
issue('--cluster', $CLUSTER);
chmod 0666, $licpath;
accepts('world writable license still starts', qr/writable by group or world/);

chmod 0644, $licpath;
{
	my $logstart = -s $node->logfile;
	$node->start;
	ok(server_up($node), 'world readable license starts');
	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	unlike($log, qr/writable by group or world/,
		'world readable license draws no permission warning');
	$node->stop;
}

#
# The reporting extension.
#
# It must agree with the startup log line, since a support engineer is expected
# to be able to use either. It must also not be load bearing: dropping it
# changes nothing about enforcement.
#
issue('--cluster', $CLUSTER);
{
	# Read only the portion this start appends. The log file accumulates
	# across every case in this file, so matching from the beginning would
	# pick up an earlier license.
	my $logstart = -s $node->logfile;
	$node->start;

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	my ($logged) = $log =~ /license ([0-9a-f-]{36}) verified/;

	$node->safe_psql('postgres', 'CREATE EXTENSION appscode_license');

	my $reported = $node->safe_psql('postgres',
		'SELECT uuid FROM appscode_license_info()');
	is($reported, $logged,
		'appscode_license_info() reports the UUID from the startup log');

	my $row = $node->safe_psql('postgres',
		q{SELECT product || '|' || version_constraint || '|' || cluster_id
		  FROM appscode_license_info()});
	is($row, "postgres-enterprise|>=15,<19|$CLUSTER",
		'appscode_license_info() reports the certificate fields');

	is($node->safe_psql('postgres',
			'SELECT length(leaf_fingerprint) FROM appscode_license_info()'),
		'64', 'appscode_license_info() reports a sha256 leaf fingerprint');

	is($node->safe_psql('postgres',
			'SELECT not_after > now() FROM appscode_license_info()'),
		't', 'appscode_license_info() reports a future expiry');

	# Dropping the extension must not affect enforcement.
	$node->safe_psql('postgres', 'DROP EXTENSION appscode_license');
	$node->restart;
	ok(server_up($node),
		'server still starts after the reporting extension is dropped');
	$node->stop;
}

#
# Single user mode is covered too, since it can run arbitrary SQL.
#
issue('--cluster', $CLUSTER, '--expired');
{
	my ($stdout, $stderr);
	my $ret = IPC::Run::run [ 'postgres', '--single', '-D', $node->data_dir,
		'postgres' ],
	  '<' => \"SELECT 1;\n", '>' => \$stdout, '2>' => \$stderr;
	ok(!$ret, 'single user mode refuses an expired license');
	like($stderr, qr/license has expired/,
		'single user mode explains the refusal');
}

done_testing();
