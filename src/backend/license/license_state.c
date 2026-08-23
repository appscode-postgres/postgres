/*-------------------------------------------------------------------------
 *
 * license_state.c
 *	  Clock-rollback resistance and installation fingerprinting.
 *
 * See license_state.h and doc/LICENSE_ENFORCEMENT.md sections 9 and 10.
 * Pure C (OpenSSL + libc); never ereports.
 *
 * The state file cannot be defended against a user with write access to the
 * data directory; deleting it resets the high-water mark. That is accepted
 * in the threat model: the goal is to stop casual clock backdating, not a
 * deliberate on-disk edit.
 *
 *-------------------------------------------------------------------------
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "license/license_state.h"

#define STATE_FILENAME ".pg_license_state"
#define STATE_MAGIC "PGLICSTATE1"
#define HMAC_KEY_LABEL "appscode-pg-license-state-v1"

/* Lowercase hex, no separators. out must hold 2*len+1. */
static void
to_hex(const unsigned char *in, size_t len, char *out)
{
	static const char hexdig[] = "0123456789abcdef";
	size_t		i;

	for (i = 0; i < len; i++)
	{
		out[2 * i] = hexdig[(in[i] >> 4) & 0xf];
		out[2 * i + 1] = hexdig[in[i] & 0xf];
	}
	out[2 * len] = '\0';
}

/* Decode up to maxlen bytes of hex from in; returns bytes written or -1. */
static int
from_hex(const char *in, unsigned char *out, size_t maxlen)
{
	size_t		n = strlen(in);
	size_t		i;

	if (n % 2 != 0 || n / 2 > maxlen)
		return -1;
	for (i = 0; i < n / 2; i++)
	{
		unsigned int b;

		if (sscanf(in + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (unsigned char) b;
	}
	return (int) (n / 2);
}

bool
appscode_license_fingerprint(const char *datadir, uint64_t system_identifier,
							 char *out, size_t outlen)
{
	struct stat st;
	unsigned char buf[16];
	unsigned char md[SHA256_DIGEST_LENGTH];
	uint64_t	ino;
	int			i;

	if (outlen < 2 * SHA256_DIGEST_LENGTH + 1)
		return false;
	if (datadir == NULL || stat(datadir, &st) != 0)
		return false;

	ino = (uint64_t) st.st_ino;
	for (i = 0; i < 8; i++)
		buf[i] = (unsigned char) ((system_identifier >> (8 * i)) & 0xff);
	for (i = 0; i < 8; i++)
		buf[8 + i] = (unsigned char) ((ino >> (8 * i)) & 0xff);

	SHA256(buf, sizeof(buf), md);
	to_hex(md, sizeof(md), out);
	return true;
}

/*
 * Derive the HMAC key: SHA-256(label || ca_fp_bytes || serial_dec).
 * Returns key length (SHA256_DIGEST_LENGTH) or 0 on failure.
 */
static unsigned int
derive_key(const char *ca_fp_hex, const char *serial_dec, unsigned char *key)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	unsigned char ca_bytes[SHA256_DIGEST_LENGTH];
	unsigned int keylen = 0;

	if (mdctx == NULL)
		return 0;
	if (from_hex(ca_fp_hex, ca_bytes, sizeof(ca_bytes)) < 0)
	{
		EVP_MD_CTX_free(mdctx);
		return 0;
	}
	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) &&
		EVP_DigestUpdate(mdctx, HMAC_KEY_LABEL, strlen(HMAC_KEY_LABEL)) &&
		EVP_DigestUpdate(mdctx, ca_bytes, sizeof(ca_bytes)) &&
		EVP_DigestUpdate(mdctx, serial_dec, strlen(serial_dec)) &&
		EVP_DigestFinal_ex(mdctx, key, &keylen))
	{
		/* success */
	}
	else
		keylen = 0;
	EVP_MD_CTX_free(mdctx);
	return keylen;
}

/* Build the HMAC-authenticated body (the five lines) into buf. */
static int
format_body(char *buf, size_t buflen, const char *fingerprint,
			long hwm, const char *serial, const char *cn)
{
	return snprintf(buf, buflen,
					STATE_MAGIC "\n"
					"fingerprint=%s\n"
					"hwm=%ld\n"
					"serial=%s\n"
					"cn=%s\n",
					fingerprint, hwm, serial, cn);
}

/* Compute HMAC-SHA256 over body into out (hex). Returns false on failure. */
static bool
compute_hmac(const unsigned char *key, unsigned int keylen,
			 const char *body, size_t bodylen, char *out_hex)
{
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;

	if (HMAC(EVP_sha256(), key, (int) keylen,
			 (const unsigned char *) body, bodylen, mac, &maclen) == NULL)
		return false;
	to_hex(mac, maclen, out_hex);
	return true;
}

/*
 * Read and parse an existing state file. On success fills fingerprint (>=65),
 * *hwm and verifies the HMAC. Returns:
 *   1  parsed and HMAC valid
 *   0  file does not exist
 *  -1  present but corrupt (HMAC mismatch or malformed)
 *  -2  I/O error
 */
static int
read_state(const char *path, const char *ca_fp_hex,
		   char *fingerprint, size_t fplen, long *hwm,
		   char *serial_out, size_t serlen)
{
	FILE	   *f = fopen(path, "rb");
	char		line[512];
	char		got_fp[128] = "";
	char		got_serial[128] = "";
	char		got_cn[256] = "";
	char		got_hmac[2 * EVP_MAX_MD_SIZE + 1] = "";
	long		got_hwm = 0;
	bool		have_magic = false;
	char		body[1024];
	char		calc_hmac[2 * EVP_MAX_MD_SIZE + 1];
	unsigned char key[EVP_MAX_MD_SIZE];
	unsigned int keylen;
	int			blen;

	if (f == NULL)
	{
		if (errno == ENOENT)
			return 0;
		return -2;
	}

	while (fgets(line, sizeof(line), f) != NULL)
	{
		size_t		n = strlen(line);

		if (n > 0 && line[n - 1] == '\n')
			line[n - 1] = '\0';
		if (strcmp(line, STATE_MAGIC) == 0)
			have_magic = true;
		else if (strncmp(line, "fingerprint=", 12) == 0)
			snprintf(got_fp, sizeof(got_fp), "%s", line + 12);
		else if (strncmp(line, "hwm=", 4) == 0)
			got_hwm = strtol(line + 4, NULL, 10);
		else if (strncmp(line, "serial=", 7) == 0)
			snprintf(got_serial, sizeof(got_serial), "%s", line + 7);
		else if (strncmp(line, "cn=", 3) == 0)
			snprintf(got_cn, sizeof(got_cn), "%s", line + 3);
		else if (strncmp(line, "hmac=", 5) == 0)
			snprintf(got_hmac, sizeof(got_hmac), "%s", line + 5);
	}
	if (ferror(f))
	{
		fclose(f);
		return -2;
	}
	fclose(f);

	if (!have_magic || got_fp[0] == '\0' || got_hmac[0] == '\0')
		return -1;

	/*
	 * Derive the key from the serial stored in the file, so the file is
	 * self-verifying regardless of which license is now in effect. A
	 * legitimate license replacement carries a new serial; the old state
	 * file still verifies here (proving it was written by this build), and
	 * the caller then regenerates it for the new serial. Only a real
	 * integrity failure (edited bytes) makes the HMAC mismatch.
	 */
	keylen = derive_key(ca_fp_hex, got_serial, key);
	if (keylen == 0)
		return -1;

	blen = format_body(body, sizeof(body), got_fp, got_hwm, got_serial, got_cn);
	if (blen < 0 || (size_t) blen >= sizeof(body))
		return -1;
	if (!compute_hmac(key, keylen, body, (size_t) blen, calc_hmac))
		return -1;
	if (strcmp(calc_hmac, got_hmac) != 0)
		return -1;

	snprintf(fingerprint, fplen, "%s", got_fp);
	*hwm = got_hwm;
	if (serial_out != NULL)
		snprintf(serial_out, serlen, "%s", got_serial);
	return 1;
}

/* Atomically write the state file with mode 0600. Returns false on error. */
static bool
write_state(const char *path, const unsigned char *key, unsigned int keylen,
			const char *fingerprint, long hwm,
			const char *serial, const char *cn)
{
	char		body[1024];
	char		hmac_hex[2 * EVP_MAX_MD_SIZE + 1];
	int			blen;
	char		tmp[PATH_MAX];
	int			fd;
	FILE	   *f;

	blen = format_body(body, sizeof(body), fingerprint, hwm, serial, cn);
	if (blen < 0 || (size_t) blen >= sizeof(body))
		return false;
	if (!compute_hmac(key, keylen, body, (size_t) blen, hmac_hex))
		return false;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return false;
	f = fdopen(fd, "wb");
	if (f == NULL)
	{
		close(fd);
		unlink(tmp);
		return false;
	}
	if (fwrite(body, 1, (size_t) blen, f) != (size_t) blen ||
		fprintf(f, "hmac=%s\n", hmac_hex) < 0 ||
		fflush(f) != 0)
	{
		fclose(f);
		unlink(tmp);
		return false;
	}
	if (fclose(f) != 0)
	{
		unlink(tmp);
		return false;
	}
	if (rename(tmp, path) != 0)
	{
		unlink(tmp);
		return false;
	}
	return true;
}

LicenseStateResult
appscode_license_state_update(const LicenseStateInput *in, bool *new_install,
							  char *msg, size_t msglen)
{
	char		path[PATH_MAX];
	unsigned char key[EVP_MAX_MD_SIZE];
	unsigned int keylen;
	char		cur_fp[128];
	char		old_fp[128];
	char		old_serial[128] = "";
	long		old_hwm = 0;
	long		hwm;
	int			rc;

	*new_install = false;
	if (msg != NULL && msglen > 0)
		msg[0] = '\0';

	if (!appscode_license_fingerprint(in->datadir, in->system_identifier,
									  cur_fp, sizeof(cur_fp)))
	{
		snprintf(msg, msglen, "could not compute installation fingerprint");
		return LSTATE_ERR_IO;
	}

	/* Key for writing is derived from the current license serial. */
	keylen = derive_key(in->ca_fingerprint_hex, in->serial_dec, key);
	if (keylen == 0)
	{
		snprintf(msg, msglen, "could not derive license state key");
		return LSTATE_ERR_IO;
	}

	snprintf(path, sizeof(path), "%s/%s", in->datadir, STATE_FILENAME);

	/* Verification key is derived internally from the file's own serial. */
	rc = read_state(path, in->ca_fingerprint_hex, old_fp, sizeof(old_fp),
					&old_hwm, old_serial, sizeof(old_serial));
	if (rc == -2)
	{
		snprintf(msg, msglen, "could not read license state file \"%s\"", path);
		return LSTATE_ERR_IO;
	}
	if (rc == -1)
	{
		snprintf(msg, msglen,
				 "license state file \"%s\" is corrupt or has been tampered with",
				 path);
		return LSTATE_ERR_CORRUPT;
	}

	if (rc == 1)
	{
		/* Clock rollback check. */
		if (in->now < old_hwm - in->clock_tolerance_sec)
		{
			snprintf(msg, msglen,
					 "system clock appears to have moved backward: current time is more than %ld hours before the last recorded time",
					 in->clock_tolerance_sec / 3600);
			return LSTATE_ERR_CLOCK_BACK;
		}
		/*
		 * New-installation detection (advisory). A changed installation
		 * fingerprint means the license or data directory moved; a changed
		 * serial means the license was replaced. Either way the file is
		 * authentic (HMAC verified above), so this is not tampering; the
		 * high-water mark is carried forward below and the file rewritten.
		 */
		if (strcmp(old_fp, cur_fp) != 0)
			*new_install = true;
	}

	/* Advance the high-water mark; never let it move backward. */
	hwm = (rc == 1 && old_hwm > in->now) ? old_hwm : in->now;

	if (!write_state(path, key, keylen, cur_fp, hwm, in->serial_dec, in->cn))
	{
		snprintf(msg, msglen,
				 "could not write license state file \"%s\"", path);
		return LSTATE_ERR_IO;
	}

	return LSTATE_OK;
}
