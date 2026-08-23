/*-------------------------------------------------------------------------
 *
 * license.h
 *	  Offline, certificate-based license verification for the
 *	  Postgres Enterprise by AppsCode build.
 *
 * This interface is intentionally free of PostgreSQL backend types so the
 * verification core (license.c) can be linked into a standalone unit-test
 * harness that runs outside the server. The backend integration in
 * postmaster.c and the background worker translate LicenseInfo into
 * ereport() calls; the core itself never ereports and never longjmps.
 *
 * See doc/LICENSE_ENFORCEMENT.md for the full design.
 *
 *-------------------------------------------------------------------------
 */
#ifndef APPSCODE_LICENSE_H
#define APPSCODE_LICENSE_H

#include <stdbool.h>

/* The one feature this build gates on (membership in the O list). */
#define APPSCODE_LICENSE_REQUIRED_FEATURE "postgres-enterprise"

/* Reject license files larger than this before parsing. */
#define APPSCODE_LICENSE_MAX_BYTES (64 * 1024)

/* Fixed caps so LicenseInfo needs no dynamic cleanup by callers. */
#define APPSCODE_LICENSE_MAX_FEATURES 64
#define APPSCODE_LICENSE_STRBUF 256

/*
 * Compiled-in default license path, used when neither PGLICENSE nor
 * $PGDATA/license.pem resolves. Overridable at build time.
 */
#ifndef APPSCODE_LICENSE_DEFAULT_PATH
#define APPSCODE_LICENSE_DEFAULT_PATH "/etc/appscode/license.pem"
#endif

/*
 * Verification outcome. LICENSE_OK means all three validity gates plus the
 * CA self-check passed. Every other value is a distinct, logged failure so
 * support can diagnose from logs alone. Keep in sync with
 * appscode_license_status_tag() and doc/LICENSE_ENFORCEMENT.md section 11.
 */
typedef enum LicenseStatus
{
	LICENSE_OK = 0,
	LICENSE_ERR_NO_FILE,		/* no license file at any resolved path */
	LICENSE_ERR_READ,			/* path resolved but unreadable */
	LICENSE_ERR_TOO_LARGE,		/* exceeds APPSCODE_LICENSE_MAX_BYTES */
	LICENSE_ERR_NO_PEM,			/* no PEM certificate in the file */
	LICENSE_ERR_MALFORMED,		/* PEM framing ok, DER does not parse */
	LICENSE_ERR_CHAIN,			/* does not chain to the embedded CA */
	LICENSE_ERR_NO_CLIENTAUTH,	/* leaf lacks the clientAuth EKU */
	LICENSE_ERR_NOT_YET_VALID,	/* notBefore in the future */
	LICENSE_ERR_EXPIRED,		/* notAfter in the past */
	LICENSE_ERR_MISSING_FEATURE,	/* O list lacks postgres-enterprise */
	LICENSE_ERR_CA_SELFCHECK,	/* embedded CA failed its pin check */
	LICENSE_ERR_INTERNAL		/* OpenSSL or allocation failure */
} LicenseStatus;

/*
 * Parsed license, plus the outcome. Fields below status are populated on a
 * best-effort basis as parsing proceeds; on an early failure (for example
 * LICENSE_ERR_NO_FILE) they are empty. On LICENSE_OK all are populated.
 *
 * Deliberately absent: anything derived from the SAN email entry. The core
 * never reads it (doc section 6).
 */
typedef struct LicenseInfo
{
	LicenseStatus status;
	char		reason[APPSCODE_LICENSE_STRBUF];	/* specific human reason */

	char		serial_dec[80]; /* serial as decimal, the license ID */
	char		cn[APPSCODE_LICENSE_STRBUF];	/* CN, a separate identifier */
	char		product_line[APPSCODE_LICENSE_STRBUF];	/* C, informational */
	char		tier[APPSCODE_LICENSE_STRBUF];	/* ST, informational */
	char		plan[APPSCODE_LICENSE_STRBUF];	/* OU, informational */
	char		features[APPSCODE_LICENSE_MAX_FEATURES][APPSCODE_LICENSE_STRBUF];
	int			num_features;	/* count in features[] (O list) */
	char		feature_flags[APPSCODE_LICENSE_MAX_FEATURES][APPSCODE_LICENSE_STRBUF];
	int			num_feature_flags;	/* L list, key=value */

	char		not_before[32]; /* "YYYY-MM-DD HH:MM:SSZ" */
	char		not_after[32];
	long		days_remaining; /* whole days from now to notAfter */

	char		leaf_sha256[100];	/* leaf cert SHA-256, hex with colons */
	bool		has_required_feature;
} LicenseInfo;

/*
 * Verify the license certificate at "path" against the embedded trust
 * anchor(s). Fills *info and returns info->status. Never ereports; safe to
 * call in early postmaster startup and from the standalone harness. Uses
 * malloc/free internally.
 */
extern LicenseStatus appscode_license_verify(const char *path,
											 LicenseInfo *info);

/*
 * Resolve the license path: PGLICENSE if set, else datadir/license.pem if
 * datadir is non-NULL and that file exists, else the compiled-in default.
 * Returns a malloc'd string the caller must free, or NULL on OOM.
 */
extern char *appscode_license_resolve_path(const char *datadir);

/* Short, stable tag for a status, for structured logging. */
extern const char *appscode_license_status_tag(LicenseStatus st);

/*
 * Trust-anchor fingerprint pins, defined by license_pins.c in a different
 * translation unit than the embedded DER bytes. Each entry is a lowercase
 * hex SHA-256 with no separators. Index i pins anchor i.
 */
extern const char *const appscode_ca_cert_sha256_pins[];
extern const char *const appscode_ca_spki_sha256_pins[];
extern const int appscode_ca_num_pins;

#endif							/* APPSCODE_LICENSE_H */
