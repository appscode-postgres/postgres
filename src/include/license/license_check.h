/*-------------------------------------------------------------------------
 *
 * license_check.h
 *	  Backend entry points for AppsCode license enforcement.
 *
 * These wrap the header-free verification core (license.c) with the backend
 * conventions: ereport(FATAL) on failure, elog(LOG) for the success and
 * advisory lines, and access to pg_control for the installation
 * fingerprint. Included by the small hooks in postmaster.c and postgres.c.
 *
 *-------------------------------------------------------------------------
 */
#ifndef APPSCODE_LICENSE_CHECK_H
#define APPSCODE_LICENSE_CHECK_H

#include "license/license.h"

/*
 * A read-only snapshot of the license the local postmaster verified, copied
 * out of shared memory. This is the only thing the reporting extension
 * consumes; it never re-parses or re-verifies the license file. All string
 * fields are NUL-terminated. "features" is a comma-joined list. The SAN
 * email and any DNS SAN entry are deliberately absent.
 */
typedef struct AppsCodeLicenseReport
{
	bool		populated;		/* false until the first publish */
	bool		verifies;		/* last verification result was LICENSE_OK */
	char		serial_dec[80]; /* license ID (serial), decimal */
	char		cn[APPSCODE_LICENSE_STRBUF];	/* separate UUID-shaped id */
	char		product_line[APPSCODE_LICENSE_STRBUF];	/* C */
	char		tier[APPSCODE_LICENSE_STRBUF];	/* ST */
	char		plan[APPSCODE_LICENSE_STRBUF];	/* OU */
	char		features[APPSCODE_LICENSE_STRBUF];	/* O, comma-joined */
	char		not_before[32];
	char		not_after[32];
	int64		days_remaining;
	char		leaf_sha256[100];
} AppsCodeLicenseReport;

/*
 * Run the full startup license check for the given execution mode
 * ("postmaster", "single-user"). Resolves the license path, verifies the
 * certificate, runs the clock-rollback and installation-fingerprint state
 * update, logs the outcome, and ereport(FATAL)s on any failure. Returns
 * normally only when the license is valid.
 */
extern void AppsCodeLicenseCheckStartup(const char *mode_label);

/*
 * Re-run verification without the state update, for the background worker's
 * periodic re-check. Fills *info and returns its status; never ereports.
 * The caller decides how to react (shutdown, warn, log).
 */
extern LicenseStatus AppsCodeLicenseRecheck(LicenseInfo *info);

/*
 * Copy the most recently accepted license into *info. Returns true if a
 * license has been accepted in this process since startup.
 */
extern bool AppsCodeLicenseGetLast(LicenseInfo *info);

/*
 * Shared-memory snapshot plumbing. AppsCodeLicenseShmemSize/Init are wired
 * into the core shared-memory setup (ipci.c). AppsCodeLicensePublish writes
 * a verified snapshot (called from the postmaster at shmem init and from the
 * background worker after each re-check). AppsCodeLicenseReadShared copies
 * the snapshot out for the reporting extension; it takes no path into the
 * verification routine. Returns false if nothing has been published yet.
 */
extern Size AppsCodeLicenseShmemSize(void);
extern void AppsCodeLicenseShmemInit(void);
extern void AppsCodeLicensePublish(const LicenseInfo *info);
extern bool AppsCodeLicenseReadShared(AppsCodeLicenseReport *out);

/* Log the standard one-line acceptance record at LOG level. */
extern void AppsCodeLicenseLogAccepted(const LicenseInfo *info);

/*
 * Register the runtime-expiry background worker. Called once, unconditionally,
 * from PostmasterMain (not via shared_preload_libraries).
 */
extern void AppsCodeLicenseRegisterWorker(void);

/*
 * Background worker entry point. Referenced by name from the in-core worker
 * table in bgworker.c. Declared here (Datum comes from postgres.h, which
 * every backend includer pulls in first).
 */
extern PGDLLEXPORT void AppsCodeLicenseWorkerMain(Datum main_arg);

#endif							/* APPSCODE_LICENSE_CHECK_H */
