/*-------------------------------------------------------------------------
 *
 * license.h
 *	  Offline certificate based license verification.
 *
 * The verification core in license_core.c is deliberately free of PostgreSQL
 * headers so it can be linked into a standalone test harness that runs outside
 * the server. Server side glue lives in license.c.
 *
 * See doc/LICENSE_ENFORCEMENT.md for the certificate profile, the verification
 * algorithm, and an honest statement of what this does and does not defend
 * against.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/include/license/license.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef LICENSE_H
#define LICENSE_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/*
 * Result codes. Each maps to exactly one operator visible message in
 * doc/LICENSE_ENFORCEMENT.md section 14, so support can diagnose from a log
 * line alone without asking for a reproduction.
 */
typedef enum LicenseStatus
{
	LICENSE_OK = 0,
	LICENSE_ERR_NOT_FOUND,
	LICENSE_ERR_UNREADABLE,
	LICENSE_ERR_TOO_LARGE,
	LICENSE_ERR_PARSE,
	LICENSE_ERR_CA_PIN,
	LICENSE_ERR_CHAIN,
	LICENSE_ERR_EKU,
	LICENSE_ERR_NOT_YET_VALID,
	LICENSE_ERR_EXPIRED,
	LICENSE_ERR_PRODUCT,
	LICENSE_ERR_VERSION_MISSING,
	LICENSE_ERR_VERSION,
	LICENSE_ERR_CLUSTER_MISMATCH,
	LICENSE_ERR_CLUSTER_UNRESOLVED,
	LICENSE_ERR_SERIAL_UUID,
	LICENSE_ERR_INTERNAL
} LicenseStatus;

#define LICENSE_UUID_LEN		37	/* 36 chars plus NUL */
#define LICENSE_SERIAL_HEX_LEN	33	/* 32 chars plus NUL */
#define LICENSE_FP_LEN			65	/* 64 chars plus NUL */
#define LICENSE_NAME_LEN		256
#define LICENSE_CONSTRAINT_LEN	64

/*
 * Everything verification learned about the license.
 *
 * This is returned by value rather than reduced to a single "license is ok"
 * boolean on purpose. Callers consume several distinct fields, so disabling
 * enforcement is not a matter of flipping one branch. See
 * doc/LICENSE_ENFORCEMENT.md section 10.
 */
typedef struct LicenseInfo
{
	LicenseStatus status;

	char		uuid[LICENSE_UUID_LEN];
	char		serial_hex[LICENSE_SERIAL_HEX_LEN];
	char		leaf_fingerprint[LICENSE_FP_LEN];

	char		licensee[LICENSE_NAME_LEN];		/* subject CN */
	char		org[LICENSE_NAME_LEN];			/* first subject O */
	char		product[LICENSE_NAME_LEN];		/* matched product feature */
	char		version_constraint[LICENSE_CONSTRAINT_LEN];
	char		cluster_id[LICENSE_NAME_LEN];	/* bound cluster, or "*" */

	bool		cluster_unbound;

	time_t		not_before;
	time_t		not_after;
	int			days_remaining;
} LicenseInfo;

/*
 * Verify a license bundle.
 *
 * path				license bundle to read
 * runtime_cluster	resolved cluster identity, or NULL if none could be found
 * pg_major			server major version, for the productVersion constraint
 * now				wall clock to evaluate validity against
 * out				populated on success, and partially populated on failure
 *					so error messages can name the license
 * errbuf/errlen	human readable detail, always NUL terminated
 *
 * Returns LICENSE_OK or the first failing check. No memory context is
 * required, so this is safe to call in early postmaster startup before
 * palloc is available.
 */
extern LicenseStatus license_verify_file(const char *path,
										 const char *runtime_cluster,
										 int pg_major,
										 time_t now,
										 LicenseInfo *out,
										 char *errbuf, size_t errlen);

/* Same, but from a buffer already in memory. Used by the test harness. */
extern LicenseStatus license_verify_buffer(const unsigned char *pem,
										   size_t pemlen,
										   const char *runtime_cluster,
										   int pg_major,
										   time_t now,
										   LicenseInfo *out,
										   char *errbuf, size_t errlen);

/* Stable short name for a status, for logs and tests. */
extern const char *license_status_name(LicenseStatus status);

/*
 * The pinned SubjectPublicKeyInfo SHA-256 digests of the embedded anchors.
 *
 * Defined in ca_pin.c, a different translation unit from the generated DER
 * bytes, and hand maintained rather than generated. Replacing the embedded PEM
 * alone therefore produces a mismatch. See doc/LICENSE_ENFORCEMENT.md 2.4.
 */
extern const unsigned char appscode_ca_spki_pins[][32];
extern const int appscode_ca_spki_pin_count;

/*
 * Server side entry points, implemented in license.c.
 *
 * Declared with plain C types so this header stays usable by the standalone
 * test harness, which links license_core.c without any PostgreSQL runtime.
 */
extern void LicenseVerifyAtStartup(LicenseInfo *out, const char *context);
extern void LicenseResolvePath(char *buf, size_t buflen);
extern bool LicenseResolveCluster(char *buf, size_t buflen);

/*
 * Reporting-free verification, used by the re-check worker. A runtime failure
 * must become an orderly cluster shutdown, not a FATAL that would only kill
 * and restart the worker.
 */
extern LicenseStatus LicenseVerifyNow(LicenseInfo *out, char *errbuf,
									  size_t errlen);
extern bool LicenseUpdateState(const LicenseInfo *info, char *errbuf,
							   size_t errlen);

/* Implemented in license_bgworker.c. */
extern void LicenseWorkerRegister(void);

#endif							/* LICENSE_H */
