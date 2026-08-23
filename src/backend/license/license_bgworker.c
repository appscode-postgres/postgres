/*-------------------------------------------------------------------------
 *
 * license_bgworker.c
 *	  Background worker that enforces license expiry at run time.
 *
 * Registered directly by the patched postmaster (not via
 * shared_preload_libraries, which is user editable). Every 60 seconds it
 * re-runs full verification, re-reading the license file so an operator can
 * drop in a renewed license without a restart. On a confirmed failure it
 * logs the reason and requests a fast shutdown of the whole cluster by
 * signaling the postmaster. It also emits a daily WARNING starting 30 days
 * before expiry.
 *
 * See doc/LICENSE_ENFORCEMENT.md section 8.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <signal.h>
#include <time.h>

#include "license/license.h"
#include "license/license_check.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/procsignal.h"
#include "utils/guc.h"
#include "utils/wait_event.h"

/* Re-check interval and the transient-read retry delay, in milliseconds. */
#define LICENSE_RECHECK_INTERVAL_MS (60 * 1000)
#define LICENSE_RETRY_DELAY_MS 2000

/* Start warning this many days before expiry. */
#define LICENSE_WARN_DAYS 30

PGDLLEXPORT void AppsCodeLicenseWorkerMain(Datum main_arg);

/*
 * Register the worker. Called once from PostmasterMain, unconditionally.
 */
void
AppsCodeLicenseRegisterWorker(void)
{
	BackgroundWorker worker;

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_PostmasterStart;
	worker.bgw_restart_time = 60;	/* seconds */
	snprintf(worker.bgw_name, BGW_MAXLEN, "AppsCode license enforcement");
	snprintf(worker.bgw_type, BGW_MAXLEN, "appscode license");
	snprintf(worker.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(worker.bgw_function_name, BGW_MAXLEN, "AppsCodeLicenseWorkerMain");
	worker.bgw_main_arg = (Datum) 0;
	worker.bgw_notify_pid = 0;

	RegisterBackgroundWorker(&worker);
}

/* Trigger a fast shutdown of the whole cluster via the postmaster. */
static void
request_fast_shutdown(const char *reason)
{
	ereport(LOG,
			(errmsg("license verification failed during periodic re-check: %s; requesting fast shutdown",
					reason)));

	/*
	 * SIGINT to the postmaster requests a fast shutdown: active transactions
	 * abort, a shutdown checkpoint runs, data durability is preserved. This
	 * is deliberately not SIGQUIT (immediate mode), which would skip the
	 * shutdown checkpoint. There is no grace period beyond the detection
	 * interval.
	 */
	if (PostmasterPid != 0)
		kill(PostmasterPid, SIGINT);
}

/*
 * Emit the daily pre-expiry warning at most once per calendar day.
 */
static void
maybe_warn_expiry(const LicenseInfo *info, time_t *last_warn_day)
{
	time_t		now = time(NULL);
	time_t		today = now / (24 * 60 * 60);

	if (info->days_remaining <= LICENSE_WARN_DAYS &&
		info->days_remaining >= 0 &&
		today != *last_warn_day)
	{
		ereport(WARNING,
				(errmsg("license for Postgres Enterprise by AppsCode expires in %ld days",
						info->days_remaining)));
		*last_warn_day = today;
	}
}

void
AppsCodeLicenseWorkerMain(Datum main_arg)
{
	time_t		last_warn_day = 0;

	pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	BackgroundWorkerUnblockSignals();

	for (;;)
	{
		LicenseInfo info;
		LicenseStatus st;

		(void) WaitLatch(MyLatch,
						 WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
						 LICENSE_RECHECK_INTERVAL_MS,
						 PG_WAIT_EXTENSION);
		ResetLatch(MyLatch);

		if (ShutdownRequestPending)
			break;
		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		CHECK_FOR_INTERRUPTS();

		st = AppsCodeLicenseRecheck(&info);
		if (st != LICENSE_OK)
		{
			/*
			 * Retry once after a short delay before treating this as a
			 * failure, so a partially written license file during an
			 * in-place renewal does not take the cluster down.
			 */
			(void) WaitLatch(MyLatch,
							 WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
							 LICENSE_RETRY_DELAY_MS,
							 PG_WAIT_EXTENSION);
			ResetLatch(MyLatch);

			st = AppsCodeLicenseRecheck(&info);
			if (st != LICENSE_OK)
			{
				request_fast_shutdown(info.reason);
				break;
			}
		}

		maybe_warn_expiry(&info, &last_warn_day);
	}

	proc_exit(0);
}
