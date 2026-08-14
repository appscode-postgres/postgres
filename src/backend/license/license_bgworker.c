/*-------------------------------------------------------------------------
 *
 * license_bgworker.c
 *	  Background worker that re-checks the license while the server runs.
 *
 * Registered unconditionally by the postmaster, not through
 * shared_preload_libraries, which is user editable. It re-reads the license
 * file from disk on every cycle so an operator can drop in a renewed license
 * without restarting the cluster.
 *
 * On a genuine failure the reason is logged and the whole cluster is shut down
 * immediately, with no grace period. The worker needs no database connection,
 * so it starts at postmaster start and keeps running through recovery.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/backend/license/license_bgworker.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "license/license.h"
#include "license/license_worker.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "utils/timestamp.h"
#include "utils/guc.h"
#include "utils/wait_event.h"

/* How often to re-verify, in milliseconds. */
#define LICENSE_RECHECK_INTERVAL_MS		60000L

/* Pause before retrying a read that may have caught a renewal mid write. */
#define LICENSE_RETRY_DELAY_MS			2000L

/* Start warning this many days before expiry. */
#define LICENSE_EXPIRY_WARN_DAYS		30

#define SECS_PER_DAY					86400

/*
 * Custom wait event, so this worker is distinguishable in pg_stat_activity
 * rather than showing up as a generic sleep. Registered on first use, the same
 * way any other in-core custom wait event is.
 */
static uint32 license_wait_event_main = 0;

/*
 * Is this failure possibly a transient artifact of a renewal in progress?
 *
 * An operator replacing the license file may briefly leave it absent,
 * truncated, or empty if they write it in place rather than renaming it over.
 * Taking the cluster down for that would be a self inflicted outage, so these
 * are retried once before being believed. Everything else, including an
 * expired or wrongly bound license, is definitive on the first observation.
 */
static bool
is_possibly_transient(LicenseStatus status)
{
	switch (status)
	{
		case LICENSE_ERR_NOT_FOUND:
		case LICENSE_ERR_UNREADABLE:
		case LICENSE_ERR_PARSE:
			return true;
		default:
			return false;
	}
}

/*
 * Shut the cluster down because the license is no longer valid.
 *
 * SIGINT is fast shutdown: open transactions are aborted, but a shutdown
 * checkpoint still runs, so the next start does not require crash recovery.
 * SIGQUIT would skip that and force recovery, which costs availability and
 * operator confidence without making enforcement any stronger. See
 * doc/LICENSE_ENFORCEMENT.md section 13.
 */
static void
license_shutdown_cluster(const LicenseInfo *info, const char *reason)
{
	ereport(LOG,
			(errmsg("shutting down: license is no longer valid"),
			 errdetail("License UUID %s: %s",
					   info->uuid[0] != '\0' ? info->uuid : "unknown", reason),
			 errhint("Install a valid license and start the server again.")));

	if (kill(PostmasterPid, SIGINT) != 0)
		ereport(WARNING,
				(errmsg("could not signal the postmaster to shut down: %m")));
}

pg_noreturn void
LicenseWorkerMain(Datum main_arg)
{
	TimestampTz last_warned = 0;

	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
	BackgroundWorkerUnblockSignals();

	ereport(DEBUG1,
			(errmsg("license re-check worker started, interval %ld ms",
					LICENSE_RECHECK_INTERVAL_MS)));

	if (license_wait_event_main == 0)
		license_wait_event_main = WaitEventExtensionNew("LicenseCheckerMain");

	for (;;)
	{
		LicenseInfo info;
		char		errbuf[512];
		LicenseStatus status;

		(void) WaitLatch(MyLatch,
						 WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
						 LICENSE_RECHECK_INTERVAL_MS,
						 license_wait_event_main);
		ResetLatch(MyLatch);

		if (ShutdownRequestPending)
			break;

		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		/*
		 * Re-read from disk every cycle. Nothing is cached, so a renewed
		 * license takes effect within one interval with no restart.
		 */
		status = LicenseVerifyNow(&info, errbuf, sizeof(errbuf));

		if (status != LICENSE_OK && is_possibly_transient(status))
		{
			ereport(DEBUG1,
					(errmsg("license re-check hit a possibly transient error, retrying: %s",
							errbuf)));
			pg_usleep(LICENSE_RETRY_DELAY_MS * 1000L);
			status = LicenseVerifyNow(&info, errbuf, sizeof(errbuf));
		}

		if (status != LICENSE_OK)
		{
			license_shutdown_cluster(&info, errbuf);
			break;
		}

		/*
		 * Advance the clock high water mark, and refuse to keep running if the
		 * clock has been moved backward or the state file has been edited.
		 * Checking this at runtime matters: without it, moving the clock back
		 * while the server is up would make an expired license look valid.
		 */
		if (!LicenseUpdateState(&info, errbuf, sizeof(errbuf)))
		{
			license_shutdown_cluster(&info, errbuf);
			break;
		}

		/*
		 * Warn once per day inside the expiry window, so expiry is never a
		 * surprise. The UUID is included so the warning is actionable from a
		 * log bundle alone.
		 */
		if (info.days_remaining <= LICENSE_EXPIRY_WARN_DAYS)
		{
			TimestampTz now = GetCurrentTimestamp();

			if (last_warned == 0 ||
				TimestampDifferenceExceeds(last_warned, now,
										   SECS_PER_DAY * 1000))
			{
				ereport(WARNING,
						(errmsg("license %s expires in %d days",
								info.uuid, info.days_remaining),
						 errdetail("Licensed to \"%s\", serial %s.",
								   info.licensee, info.serial_hex),
						 errhint("Renew before expiry; the cluster shuts down when the license expires.")));
				last_warned = now;
			}
		}
	}

	proc_exit(0);
}

/*
 * Register the worker.
 *
 * Called from PostmasterMain(), not from a _PG_init() hook, because
 * shared_preload_libraries is user editable and removing an entry there must
 * not disable enforcement.
 *
 * No database connection is requested, so the worker can start at postmaster
 * start and keep checking throughout recovery, when a connection would not yet
 * be possible.
 */
void
LicenseWorkerRegister(void)
{
	BackgroundWorker worker;

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_PostmasterStart;
	worker.bgw_restart_time = 60;
	worker.bgw_notify_pid = 0;
	snprintf(worker.bgw_name, BGW_MAXLEN, "license checker");
	snprintf(worker.bgw_type, BGW_MAXLEN, "license checker");
	snprintf(worker.bgw_library_name, MAXPGPATH, "postgres");
	snprintf(worker.bgw_function_name, BGW_MAXLEN, "LicenseWorkerMain");

	RegisterBackgroundWorker(&worker);
}
