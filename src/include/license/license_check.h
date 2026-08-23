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
 * license has been accepted in this process since startup. Used by the
 * appscode_license_info() SQL function.
 */
extern bool AppsCodeLicenseGetLast(LicenseInfo *info);

/* Log the standard one-line acceptance record at LOG level. */
extern void AppsCodeLicenseLogAccepted(const LicenseInfo *info);

#endif							/* APPSCODE_LICENSE_CHECK_H */
