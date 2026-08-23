/*-------------------------------------------------------------------------
 *
 * license_check.c
 *	  Backend integration for AppsCode license enforcement.
 *
 * Bridges the header-free verification core (license.c) and the
 * clock/fingerprint state module (license_state.c) to the backend: it
 * resolves the license path, verifies, runs the state update, logs, and
 * ereport(FATAL)s on failure. The hooks in postmaster.c and postgres.c call
 * AppsCodeLicenseCheckStartup(); the background worker calls
 * AppsCodeLicenseRecheck().
 *
 * The decision is carried as a struct (LicenseInfo) consumed at several call
 * sites, not a single global bool, so that no one-instruction patch fully
 * disables enforcement.
 *
 * This mechanism is not claimed to be tamper proof; see
 * doc/LICENSE_ENFORCEMENT.md.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <time.h>

#include "access/xlog.h"
#include "miscadmin.h"
#include "storage/shmem.h"
#include "storage/spin.h"
#include "utils/elog.h"

#include "license/license.h"
#include "license/license_check.h"
#include "license/license_state.h"

/* Most recently accepted license in this process. */
static LicenseInfo last_accepted;
static bool have_last_accepted = false;

/*
 * Shared-memory snapshot of the verified license, written by the postmaster
 * (at shmem init) and the background worker (after each re-check), and read
 * by the reporting extension. Guarded by a spinlock; the payload is small
 * and writes are infrequent.
 */
typedef struct AppsCodeLicenseShared
{
	slock_t		mutex;
	AppsCodeLicenseReport report;
} AppsCodeLicenseShared;

static AppsCodeLicenseShared *license_shared = NULL;

/* Join the O feature list into a comma-separated string. */
static void
join_features(const LicenseInfo *info, char *out, size_t outlen)
{
	size_t		p = 0;
	int			i;

	out[0] = '\0';
	for (i = 0; i < info->num_features && p < outlen - 1; i++)
		p += snprintf(out + p, outlen - p, "%s%s",
					  i ? "," : "", info->features[i]);
}

Size
AppsCodeLicenseShmemSize(void)
{
	return sizeof(AppsCodeLicenseShared);
}

void
AppsCodeLicenseShmemInit(void)
{
	bool		found;

	license_shared = (AppsCodeLicenseShared *)
		ShmemInitStruct("AppsCode License Snapshot",
						AppsCodeLicenseShmemSize(), &found);

	if (!found)
	{
		SpinLockInit(&license_shared->mutex);
		memset(&license_shared->report, 0, sizeof(license_shared->report));
		license_shared->report.populated = false;

		/*
		 * The postmaster verified the license before shared memory existed,
		 * so seed the snapshot from that result now. The background worker
		 * keeps it fresh across renewals.
		 */
		if (have_last_accepted)
			AppsCodeLicensePublish(&last_accepted);
	}
}

void
AppsCodeLicensePublish(const LicenseInfo *info)
{
	AppsCodeLicenseReport rep;

	if (license_shared == NULL)
		return;

	memset(&rep, 0, sizeof(rep));
	rep.populated = true;
	rep.verifies = (info->status == LICENSE_OK);
	snprintf(rep.serial_dec, sizeof(rep.serial_dec), "%s", info->serial_dec);
	snprintf(rep.cn, sizeof(rep.cn), "%s", info->cn);
	snprintf(rep.product_line, sizeof(rep.product_line), "%s",
			 info->product_line);
	snprintf(rep.tier, sizeof(rep.tier), "%s", info->tier);
	snprintf(rep.plan, sizeof(rep.plan), "%s", info->plan);
	join_features(info, rep.features, sizeof(rep.features));
	snprintf(rep.not_before, sizeof(rep.not_before), "%s", info->not_before);
	snprintf(rep.not_after, sizeof(rep.not_after), "%s", info->not_after);
	rep.days_remaining = (int64) info->days_remaining;
	snprintf(rep.leaf_sha256, sizeof(rep.leaf_sha256), "%s", info->leaf_sha256);

	SpinLockAcquire(&license_shared->mutex);
	license_shared->report = rep;
	SpinLockRelease(&license_shared->mutex);
}

bool
AppsCodeLicenseReadShared(AppsCodeLicenseReport *out)
{
	if (license_shared == NULL)
	{
		memset(out, 0, sizeof(*out));
		return false;
	}

	SpinLockAcquire(&license_shared->mutex);
	*out = license_shared->report;
	SpinLockRelease(&license_shared->mutex);

	return out->populated;
}

/*
 * Map a verification status to a FATAL ereport. Called only for failures.
 * The specific human-readable text lives in info->reason, matching the
 * error catalog in doc/LICENSE_ENFORCEMENT.md section 11.
 */
static void
license_fatal(const LicenseInfo *info, const char *path, const char *mode_label)
{
	/*
	 * For a missing file, expand the reason to name the whole search order so
	 * an operator knows every place that was checked.
	 */
	if (info->status == LICENSE_ERR_NO_FILE)
		ereport(FATAL,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not find a license file"),
				 errdetail("Checked the PGLICENSE environment variable, \"%s/license.pem\", and the compiled-in default \"%s\".",
						   DataDir ? DataDir : "$PGDATA",
						   APPSCODE_LICENSE_DEFAULT_PATH),
				 errhint("Install a valid Postgres Enterprise by AppsCode license certificate.")));

	ereport(FATAL,
			(errcode(ERRCODE_CONFIG_FILE_ERROR),
			 errmsg("%s", info->reason),
			 errdetail("License path: \"%s\"; mode: %s; failure: %s.",
					   path, mode_label,
					   appscode_license_status_tag(info->status))));
}

void
AppsCodeLicenseLogAccepted(const LicenseInfo *info)
{
	StringInfoData feats;
	int			i;

	initStringInfo(&feats);
	for (i = 0; i < info->num_features; i++)
		appendStringInfo(&feats, "%s%s", i ? "," : "", info->features[i]);

	/*
	 * One LOG line with the identifying and informational fields. The serial
	 * is the license ID; the CN is labeled as a separate identifier. The SAN
	 * email is never logged.
	 */
	ereport(LOG,
			(errmsg("license accepted: id (serial) %s, CN %s, features %s, plan %s, product line %s, tier %s, expires %s (%ld days remaining), certificate SHA-256 %s",
					info->serial_dec[0] ? info->serial_dec : "(none)",
					info->cn[0] ? info->cn : "(none)",
					feats.len ? feats.data : "(none)",
					info->plan[0] ? info->plan : "(none)",
					info->product_line[0] ? info->product_line : "(none)",
					info->tier[0] ? info->tier : "(none)",
					info->not_after,
					info->days_remaining,
					info->leaf_sha256)));
	pfree(feats.data);
}

void
AppsCodeLicenseCheckStartup(const char *mode_label)
{
	char	   *path;
	LicenseInfo info;
	LicenseStateInput sin;
	LicenseStateResult sres;
	bool		new_install = false;
	char		smsg[256];

	path = appscode_license_resolve_path(DataDir);
	if (path == NULL)
		ereport(FATAL,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory resolving license path")));

	if (appscode_license_verify(path, &info) != LICENSE_OK)
	{
		license_fatal(&info, path, mode_label);
		/* not reached */
	}

	/*
	 * Certificate is valid. Now the clock-rollback and installation
	 * fingerprint state, keyed by the embedded CA fingerprint and the license
	 * serial. This is additional hardening; a failure here is still fatal.
	 */
	memset(&sin, 0, sizeof(sin));
	sin.datadir = DataDir;
	sin.system_identifier = GetSystemIdentifier();
	sin.ca_fingerprint_hex = appscode_ca_cert_sha256_pins[0];
	sin.serial_dec = info.serial_dec;
	sin.cn = info.cn;
	sin.clock_tolerance_sec = APPSCODE_LICENSE_CLOCK_TOLERANCE_SEC;
	sin.now = (long) time(NULL);

	sres = appscode_license_state_update(&sin, &new_install, smsg, sizeof(smsg));
	switch (sres)
	{
		case LSTATE_OK:
			break;
		case LSTATE_ERR_CLOCK_BACK:
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("%s", smsg),
					 errdetail("License path: \"%s\"; mode: %s.",
							   path, mode_label)));
			break;
		case LSTATE_ERR_CORRUPT:
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("%s", smsg),
					 errhint("If this is benign corruption, remove the file and restart to regenerate it.")));
			break;
		case LSTATE_ERR_IO:
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("%s", smsg)));
			break;
	}

	if (new_install)
		ereport(LOG,
				(errmsg("license id (serial) %s is now running on a new installation",
						info.serial_dec)));

	AppsCodeLicenseLogAccepted(&info);

	last_accepted = info;
	have_last_accepted = true;

	free(path);
}

LicenseStatus
AppsCodeLicenseRecheck(LicenseInfo *info)
{
	char	   *path = appscode_license_resolve_path(DataDir);
	LicenseStatus st;

	if (path == NULL)
	{
		memset(info, 0, sizeof(*info));
		info->status = LICENSE_ERR_INTERNAL;
		snprintf(info->reason, sizeof(info->reason),
				 "out of memory resolving license path");
		return info->status;
	}
	st = appscode_license_verify(path, info);
	if (st == LICENSE_OK)
	{
		last_accepted = *info;
		have_last_accepted = true;
	}
	free(path);
	return st;
}

bool
AppsCodeLicenseGetLast(LicenseInfo *info)
{
	if (!have_last_accepted)
		return false;
	*info = last_accepted;
	return true;
}
