/*-------------------------------------------------------------------------
 *
 * license_state.h
 *	  Clock-rollback resistance and installation fingerprinting for the
 *	  Postgres Enterprise by AppsCode license enforcement.
 *
 * This is additional hardening layered on top of certificate verification,
 * not one of the three license-validity gates. It maintains
 * $PGDATA/.pg_license_state (mode 0600): an installation fingerprint, a
 * monotonic wall-clock high-water mark, and the last license serial and CN
 * seen, all authenticated by an HMAC keyed from the embedded CA fingerprint
 * and the license serial. See doc/LICENSE_ENFORCEMENT.md sections 9 and 10.
 *
 * Pure C (OpenSSL + libc) so it links into the standalone harness.
 *
 *-------------------------------------------------------------------------
 */
#ifndef APPSCODE_LICENSE_STATE_H
#define APPSCODE_LICENSE_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Default rollback tolerance: 24 hours. */
#define APPSCODE_LICENSE_CLOCK_TOLERANCE_SEC (24 * 60 * 60)

typedef enum LicenseStateResult
{
	LSTATE_OK = 0,				/* state fine, high-water mark advanced */
	LSTATE_ERR_CLOCK_BACK,		/* clock rolled back beyond tolerance */
	LSTATE_ERR_CORRUPT,			/* state file HMAC did not verify */
	LSTATE_ERR_IO				/* could not read or write the state file */
} LicenseStateResult;

typedef struct LicenseStateInput
{
	const char *datadir;		/* $PGDATA; state file lives here */
	uint64_t	system_identifier;	/* from pg_control */
	const char *ca_fingerprint_hex; /* first anchor cert SHA-256, hex */
	const char *serial_dec;		/* license serial, decimal */
	const char *cn;				/* license CN */
	long		clock_tolerance_sec;	/* rollback tolerance */
	long		now;			/* current wall clock (epoch seconds) */
	int			file_mode;		/* permissions for the state file, normally
								 * the cluster's pg_file_create_mode (0600, or
								 * 0640 for a group-access cluster) */
} LicenseStateInput;

/*
 * Update (or create) the state file. On return:
 *   *new_install is set true when a valid state file existed but its stored
 *     fingerprint differs from this installation (advisory; not an error).
 *   msg receives a human-readable detail on any non-OK result.
 * Returns the result code.
 */
extern LicenseStateResult appscode_license_state_update(const LicenseStateInput *in,
														bool *new_install,
														char *msg, size_t msglen);

/*
 * Compute the installation fingerprint (SHA-256 of system_identifier and
 * the data directory inode) into out (hex; needs 65 bytes). Returns false
 * on failure (for example datadir cannot be stat'd).
 */
extern bool appscode_license_fingerprint(const char *datadir,
										 uint64_t system_identifier,
										 char *out, size_t outlen);

#endif							/* APPSCODE_LICENSE_STATE_H */
