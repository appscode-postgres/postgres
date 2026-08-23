# Copyright (c) 2022-2023, PostgreSQL Global Development Group

# Runtime license enforcement: the background worker shuts the cluster
# down when the license expires while running, and an in-place renewal
# before expiry prevents that. These are slow (the worker re-checks every
# 60 seconds), so they run only when PG_TEST_EXTRA lists appscode_license,
# and only against a dev-CA build (see 001_license.pl for the env vars).

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename;

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $cacert = $ENV{APPSCODE_LICENSE_DEV_CA};
my $cakey  = $ENV{APPSCODE_LICENSE_DEV_CA_KEY};

if ($cacert && !$cakey)
{
	($cakey = $cacert) =~ s/\.pem$/.key/;
}

if (!$cacert || !$cakey || !-f $cacert || !-f $cakey)
{
	plan skip_all =>
	  'set APPSCODE_LICENSE_DEV_CA (dev CA cert; key assumed alongside as dev-ca.key) to run';
}
if (($ENV{PG_TEST_EXTRA} || '') !~ /\bappscode_license\b/)
{
	plan skip_all =>
	  'these tests are slow; enable with PG_TEST_EXTRA=appscode_license';
}

my $root = abs_path(dirname(abs_path(__FILE__)) . '/../../../../..');
my $mklic = "$root/scripts/make-license.sh";
# Absolute path: PGLICENSE is read by the backend, whose cwd is not the
# test directory, so a relative tempdir path would not resolve.
my $tmp = abs_path(PostgreSQL::Test::Utils::tempdir());

sub issue
{
	my ($out, @extra) = @_;
	my $rc = system('sh', $mklic, '--ca-key', $cakey, '--ca-cert', $cacert,
		'--out', $out, @extra);
	die "make-license.sh failed" if $rc != 0;
	return $out;
}

# Wait up to $timeout seconds for the logfile to contain $re.
sub wait_for_log
{
	my ($node, $re, $timeout) = @_;
	for (my $i = 0; $i < $timeout; $i++)
	{
		my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile);
		return 1 if $log =~ $re;
		sleep 1;
	}
	return 0;
}

# ---- runtime expiry: the cluster shuts itself down ----
{
	my $lic = issue("$tmp/short.pem", '--valid-seconds', '75');
	local $ENV{PGLICENSE} = $lic;

	my $node = PostgreSQL::Test::Cluster->new('expiry');
	$node->init;
	$node->start;

	# Worker re-checks every 60s; expiry at ~75s is caught by ~135s.
	my $found = wait_for_log($node,
		qr/requesting fast shutdown/, 160);
	is($found, 1, 'runtime expiry: worker requests shutdown');
	my $down = wait_for_log($node,
		qr/database system is shut down/, 30);
	is($down, 1, 'runtime expiry: cluster shuts down cleanly');

	# The node stopped on its own; clear the tracked PID so the automatic
	# teardown does not try (and fail) to stop an already-dead postmaster.
	$node->_update_pid(-1);
}

# ---- in-place renewal before expiry prevents shutdown ----
{
	my $licpath = "$tmp/renew.pem";
	issue($licpath, '--valid-seconds', '80');
	local $ENV{PGLICENSE} = $licpath;

	my $node = PostgreSQL::Test::Cluster->new('renew');
	$node->init;
	$node->start;

	# Before the original 80s expiry, drop in a long-lived license.
	sleep 35;
	my $fresh = "$tmp/renew.new.pem";
	issue($fresh, '--days', '365');
	rename($fresh, $licpath) or die "rename: $!";

	# Wait past the original expiry; the cluster must stay up.
	my $shutdown = wait_for_log($node, qr/requesting fast shutdown/, 100);
	is($shutdown, 0, 'renewal in place: no shutdown after original expiry');
	is($node->safe_psql('postgres', 'SELECT 1'), '1',
		'renewal in place: cluster still serving queries');
	$node->stop;
}

done_testing();
