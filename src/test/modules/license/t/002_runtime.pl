# Copyright (c) 2021-2025, PostgreSQL Global Development Group

# Runtime license enforcement: expiry shuts the cluster down, and a renewal
# dropped in before expiry does not.
#
# These are wall clock tests and take a couple of minutes, because the re-check
# interval is 60 seconds and cannot be shortened without a GUC, which the
# design deliberately does not provide.
#
# Requires a development CA build; see t/001_startup.pl for the recipe.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use Time::HiRes qw(time sleep);

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

local $ENV{PG_CLUSTER_ID} = $CLUSTER;

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
	my @cmd = ($mklicense, '--ca-dir', $devca, '--out', $out,
		'--cluster', $CLUSTER, @args);
	my ($o, $e);
	IPC::Run::run \@cmd, '>' => \$o, '2>' => \$e
	  or die "make-license.sh failed: $e";
	chmod 0600, $out;
	return;
}

# Poll until the server stops answering, or give up.
sub wait_until_down
{
	my ($node, $limit) = @_;
	my $start = time();

	while (time() - $start < $limit)
	{
		my $rc = $node->psql('postgres', 'SELECT 1');
		return time() - $start if $rc != 0;
		sleep 3;
	}
	return -1;
}

#
# Expiry while running shuts the cluster down.
#
{
	my $node = PostgreSQL::Test::Cluster->new('expiring');
	$node->init;

	my $lic = $node->data_dir . '/license.pem';

	# Short enough that the test finishes, long enough that startup succeeds.
	issue_to($lic, '--expires-in', '90');

	my $logstart = -s $node->logfile;
	$node->start;
	ok(server_up($node), 'cluster starts with a license expiring in 90 seconds');

	my $elapsed = wait_until_down($node, 240);
	ok($elapsed > 0, "cluster shut itself down on expiry after ${elapsed}s");

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	like($log, qr/shutting down: license is no longer valid/,
		'shutdown reason is logged');
	like($log, qr/License UUID [0-9a-f-]{36}: license has expired/,
		'shutdown message carries the license UUID');
	like($log, qr/received fast shutdown request/,
		'fast shutdown was requested, not immediate');

	# Fast shutdown runs a shutdown checkpoint, so the next start must not need
	# crash recovery. That is the whole reason SIGINT is used over SIGQUIT.
	unlike($log, qr/database system was not properly shut down/,
		'shutdown was clean, no crash recovery needed');

	$node->stop('immediate', fail_ok => 1);
}

#
# A renewal dropped in before expiry is picked up without a restart.
#
{
	my $node = PostgreSQL::Test::Cluster->new('renewed');
	$node->init;

	my $lic = $node->data_dir . '/license.pem';
	my $new = $node->data_dir . '/license.new';

	issue_to($lic, '--expires-in', '150');

	my $logstart = -s $node->logfile;
	$node->start;
	ok(server_up($node), 'cluster starts with a license expiring in 150 seconds');

	# Write beside the target and rename, so the worker never sees a partial
	# file. This is the renewal procedure the documentation prescribes.
	sleep 70;
	issue_to($new);
	rename $new, $lic or die "could not rename: $!";

	# Well past the original expiry.
	sleep 140;

	is($node->psql('postgres', 'SELECT 1'), 0,
		'cluster is still up past the original expiry, renewal was absorbed');

	my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
	like($log, qr/license UUID changed from [0-9a-f-]{36} to [0-9a-f-]{36}/,
		'renewal is logged as a UUID change');
	unlike($log, qr/shutting down: license is no longer valid/,
		'no shutdown was triggered');

	$node->stop;
}

done_testing();
