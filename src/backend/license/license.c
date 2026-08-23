/*-------------------------------------------------------------------------
 *
 * license.c
 *	  Offline, certificate-based license verification core for the
 *	  Postgres Enterprise by AppsCode build.
 *
 * This translation unit includes the embedded trust-anchor bytes (from the
 * generated appscode_root_ca_der.h) and implements the three validity
 * gates plus the CA self-check described in doc/LICENSE_ENFORCEMENT.md
 * section 4. It depends only on OpenSSL and libc so it can be linked into a
 * standalone unit-test harness; it never ereports and never longjmps.
 *
 * This mechanism is not claimed to be tamper proof. Its goal is to make
 * bypass require deliberate binary patching rather than a config edit.
 *
 *-------------------------------------------------------------------------
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE				/* for memmem() on glibc */
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "license.h"

/* Embedded trust-anchor DER bytes; generated, in this TU only. */
#include "appscode_root_ca_der.h"

/*
 * Set info->reason from a printf-style format, once, safely truncating.
 */
static void
set_reason(LicenseInfo *info, const char *fmt,...)
{
	va_list		ap;

	va_start(ap, fmt);
	vsnprintf(info->reason, sizeof(info->reason), fmt, ap);
	va_end(ap);
}

/* Lowercase hex, no separators, into out (must hold 2*len+1). */
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

/* Uppercase hex with colon separators, into out (must hold 3*len). */
static void
to_hex_colon(const unsigned char *in, size_t len, char *out)
{
	static const char hexdig[] = "0123456789ABCDEF";
	size_t		i;
	size_t		p = 0;

	for (i = 0; i < len; i++)
	{
		if (i > 0)
			out[p++] = ':';
		out[p++] = hexdig[(in[i] >> 4) & 0xf];
		out[p++] = hexdig[in[i] & 0xf];
	}
	out[p] = '\0';
}

/*
 * Load the embedded trust anchors into a fresh STACK_OF(X509). Returns NULL
 * on failure. Caller frees with sk_X509_pop_free(sk, X509_free).
 */
static STACK_OF(X509) *
load_embedded_anchors(void)
{
	STACK_OF(X509) *sk = sk_X509_new_null();
	int			i;

	if (sk == NULL)
		return NULL;

	for (i = 0; i < APPSCODE_CA_COUNT; i++)
	{
		const unsigned char *p = appscode_ca_ders[i].der;
		X509	   *x = d2i_X509(NULL, &p, (long) appscode_ca_ders[i].len);

		if (x == NULL || !sk_X509_push(sk, x))
		{
			X509_free(x);
			sk_X509_pop_free(sk, X509_free);
			return NULL;
		}
	}
	return sk;
}

/*
 * Verify every loaded anchor against the compiled-in pins (a different TU).
 * Requires an exact count match and, per index, both the certificate and
 * the SubjectPublicKeyInfo SHA-256 to match. Returns true on success.
 */
static bool
ca_self_check(STACK_OF(X509) * anchors, char *why, size_t whylen)
{
	int			i;

	if (sk_X509_num(anchors) != appscode_ca_num_pins)
	{
		snprintf(why, whylen,
				 "embedded anchor count %d does not match pin count %d",
				 sk_X509_num(anchors), appscode_ca_num_pins);
		return false;
	}

	for (i = 0; i < appscode_ca_num_pins; i++)
	{
		X509	   *x = sk_X509_value(anchors, i);
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int mdlen = 0;
		char		hex[2 * EVP_MAX_MD_SIZE + 1];
		unsigned char *spki = NULL;
		int			spki_len;

		/* Certificate fingerprint. */
		if (!X509_digest(x, EVP_sha256(), md, &mdlen))
		{
			snprintf(why, whylen, "could not hash anchor %d", i);
			return false;
		}
		to_hex(md, mdlen, hex);
		if (strcmp(hex, appscode_ca_cert_sha256_pins[i]) != 0)
		{
			snprintf(why, whylen,
					 "anchor %d certificate fingerprint mismatch", i);
			return false;
		}

		/* SubjectPublicKeyInfo fingerprint. */
		spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &spki);
		if (spki_len <= 0 || spki == NULL)
		{
			OPENSSL_free(spki);
			snprintf(why, whylen, "could not encode anchor %d public key", i);
			return false;
		}
		SHA256(spki, (size_t) spki_len, md);
		OPENSSL_free(spki);
		to_hex(md, SHA256_DIGEST_LENGTH, hex);
		if (strcmp(hex, appscode_ca_spki_sha256_pins[i]) != 0)
		{
			snprintf(why, whylen,
					 "anchor %d public key fingerprint mismatch", i);
			return false;
		}
	}
	return true;
}

/* Copy the first value of the given NID from name into buf (truncating). */
static void
name_get_first(X509_NAME *name, int nid, char *buf, size_t buflen)
{
	int			idx = X509_NAME_get_index_by_NID(name, nid, -1);

	buf[0] = '\0';
	if (idx >= 0)
	{
		X509_NAME_ENTRY *e = X509_NAME_get_entry(name, idx);
		ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
		unsigned char *utf8 = NULL;
		int			len = ASN1_STRING_to_UTF8(&utf8, s);

		if (len >= 0 && utf8 != NULL)
		{
			size_t		n = (size_t) len < buflen - 1 ? (size_t) len : buflen - 1;

			memcpy(buf, utf8, n);
			buf[n] = '\0';
		}
		OPENSSL_free(utf8);
	}
}

/*
 * Collect every value of the given NID from name into the fixed 2D array
 * out[max][APPSCODE_LICENSE_STRBUF]; returns the count written.
 */
static int
name_get_all(X509_NAME *name, int nid,
			 char out[][APPSCODE_LICENSE_STRBUF], int max)
{
	int			count = 0;
	int			idx = -1;

	for (;;)
	{
		X509_NAME_ENTRY *e;
		ASN1_STRING *s;
		unsigned char *utf8 = NULL;
		int			len;

		idx = X509_NAME_get_index_by_NID(name, nid, idx);
		if (idx < 0 || count >= max)
			break;
		e = X509_NAME_get_entry(name, idx);
		s = X509_NAME_ENTRY_get_data(e);
		len = ASN1_STRING_to_UTF8(&utf8, s);
		if (len >= 0 && utf8 != NULL)
		{
			size_t		n = (size_t) len < APPSCODE_LICENSE_STRBUF - 1 ?
				(size_t) len : APPSCODE_LICENSE_STRBUF - 1;

			memcpy(out[count], utf8, n);
			out[count][n] = '\0';
			count++;
		}
		OPENSSL_free(utf8);
	}
	return count;
}

/* Format an ASN1_TIME as "YYYY-MM-DD HH:MM:SSZ" into buf (>= 32). */
static void
fmt_time(const ASN1_TIME *t, char *buf, size_t buflen)
{
	struct tm	tm;

	buf[0] = '\0';
	if (t != NULL && ASN1_TIME_to_tm(t, &tm))
		snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02dZ",
				 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				 tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/*
 * Read a file, refusing anything over APPSCODE_LICENSE_MAX_BYTES. On
 * success returns a malloc'd buffer and sets *outlen; caller frees. On
 * failure returns NULL and sets *status/reason.
 */
static unsigned char *
read_capped(const char *path, size_t *outlen,
			LicenseInfo *info, const char *datadir_note)
{
	FILE	   *f;
	unsigned char *buf;
	size_t		cap = APPSCODE_LICENSE_MAX_BYTES;
	size_t		total = 0;
	size_t		n;

	(void) datadir_note;
	f = fopen(path, "rb");
	if (f == NULL)
	{
		if (errno == ENOENT)
		{
			info->status = LICENSE_ERR_NO_FILE;
			set_reason(info, "could not find a license file at \"%s\"", path);
		}
		else
		{
			info->status = LICENSE_ERR_READ;
			set_reason(info, "could not read license file \"%s\": %s",
					   path, strerror(errno));
		}
		return NULL;
	}

	/* Read up to cap+1 so we can detect oversize without trusting stat(). */
	buf = malloc(cap + 1);
	if (buf == NULL)
	{
		fclose(f);
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "out of memory reading license file");
		return NULL;
	}

	while (total <= cap && (n = fread(buf + total, 1, cap + 1 - total, f)) > 0)
		total += n;

	if (ferror(f))
	{
		free(buf);
		fclose(f);
		info->status = LICENSE_ERR_READ;
		set_reason(info, "could not read license file \"%s\": %s",
				   path, strerror(errno));
		return NULL;
	}
	fclose(f);

	if (total > cap)
	{
		free(buf);
		info->status = LICENSE_ERR_TOO_LARGE;
		set_reason(info,
				   "license file \"%s\" exceeds the maximum size of 64 kB",
				   path);
		return NULL;
	}

	*outlen = total;
	return buf;
}

/*
 * The core verifier. See the ordered steps in doc section 4.
 */
LicenseStatus
appscode_license_verify(const char *path, LicenseInfo *info)
{
	unsigned char *filebuf = NULL;
	size_t		filelen = 0;
	BIO		   *bio = NULL;
	X509	   *leaf = NULL;
	STACK_OF(X509) *chain = NULL;	/* untrusted intermediates from bundle */
	STACK_OF(X509) *anchors = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
	X509_NAME  *subject;
	uint32_t	xku;
	int			cmp_nb,
				cmp_na;
	int			pday,
				psec;
	char		selfcheck_why[128];

	memset(info, 0, sizeof(*info));
	info->status = LICENSE_ERR_INTERNAL;

	if (path == NULL)
	{
		info->status = LICENSE_ERR_NO_FILE;
		set_reason(info, "no license path was resolved");
		return info->status;
	}

	/* Step 1/2: read and PEM-parse (size-capped). */
	filebuf = read_capped(path, &filelen, info, NULL);
	if (filebuf == NULL)
		goto done;				/* status/reason already set */

	bio = BIO_new_mem_buf(filebuf, (int) filelen);
	if (bio == NULL)
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "out of memory parsing license file");
		goto done;
	}

	leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (leaf == NULL)
	{
		/*
		 * Distinguish "no PEM certificate at all" from "PEM present but the
		 * DER inside is malformed" by checking for the header marker.
		 */
		if (memmem(filebuf, filelen, "-----BEGIN CERTIFICATE-----",
				   strlen("-----BEGIN CERTIFICATE-----")) == NULL)
		{
			info->status = LICENSE_ERR_NO_PEM;
			set_reason(info,
					   "license file \"%s\" contains no PEM certificate",
					   path);
		}
		else
		{
			info->status = LICENSE_ERR_MALFORMED;
			set_reason(info,
					   "license file \"%s\" contains malformed certificate data",
					   path);
		}
		goto done;
	}

	/* Any further certificates in the bundle are untrusted intermediates. */
	chain = sk_X509_new_null();
	if (chain == NULL)
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "out of memory building chain");
		goto done;
	}
	for (;;)
	{
		X509	   *extra = PEM_read_bio_X509(bio, NULL, NULL, NULL);

		if (extra == NULL)
		{
			/* Clear the expected end-of-data error. */
			ERR_clear_error();
			break;
		}
		if (!sk_X509_push(chain, extra))
		{
			X509_free(extra);
			info->status = LICENSE_ERR_INTERNAL;
			set_reason(info, "out of memory building chain");
			goto done;
		}
	}

	/* Step 3a: load embedded anchors and run the CA self-check. */
	anchors = load_embedded_anchors();
	if (anchors == NULL)
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "could not load embedded license CA");
		goto done;
	}
	if (!ca_self_check(anchors, selfcheck_why, sizeof(selfcheck_why)))
	{
		info->status = LICENSE_ERR_CA_SELFCHECK;
		set_reason(info,
				   "embedded license CA failed its integrity self-check: %s",
				   selfcheck_why);
		goto done;
	}

	/*
	 * Parse the informational and identifying fields now, so callers can log
	 * them even for some failures. None of these gate validity except the
	 * feature list, checked below.
	 */
	subject = X509_get_subject_name(leaf);
	name_get_first(subject, NID_commonName, info->cn, sizeof(info->cn));
	name_get_first(subject, NID_countryName,
				   info->product_line, sizeof(info->product_line));
	name_get_first(subject, NID_stateOrProvinceName,
				   info->tier, sizeof(info->tier));
	name_get_first(subject, NID_organizationalUnitName,
				   info->plan, sizeof(info->plan));
	info->num_features = name_get_all(subject, NID_organizationName,
									  info->features,
									  APPSCODE_LICENSE_MAX_FEATURES);
	info->num_feature_flags = name_get_all(subject, NID_localityName,
										   info->feature_flags,
										   APPSCODE_LICENSE_MAX_FEATURES);

	/* Serial as decimal (the license ID). */
	{
		ASN1_INTEGER *aserial = X509_get_serialNumber(leaf);
		BIGNUM	   *bn = ASN1_INTEGER_to_BN(aserial, NULL);
		char	   *dec = bn ? BN_bn2dec(bn) : NULL;

		if (dec != NULL)
		{
			snprintf(info->serial_dec, sizeof(info->serial_dec), "%s", dec);
			OPENSSL_free(dec);
		}
		BN_free(bn);
	}

	/* Leaf certificate SHA-256 fingerprint. */
	{
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int mdlen = 0;

		if (X509_digest(leaf, EVP_sha256(), md, &mdlen))
			to_hex_colon(md, mdlen, info->leaf_sha256);
	}

	fmt_time(X509_get0_notBefore(leaf),
			 info->not_before, sizeof(info->not_before));
	fmt_time(X509_get0_notAfter(leaf),
			 info->not_after, sizeof(info->not_after));

	/* Step 3b: chain verification (signature + strict), time isolated. */
	store = X509_STORE_new();
	ctx = X509_STORE_CTX_new();
	if (store == NULL || ctx == NULL)
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "out of memory verifying license");
		goto done;
	}
	{
		int			i;

		for (i = 0; i < sk_X509_num(anchors); i++)
			X509_STORE_add_cert(store, sk_X509_value(anchors, i));
	}
	if (!X509_STORE_CTX_init(ctx, store, leaf, chain))
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "could not initialize verification context");
		goto done;
	}
	{
		X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);

		/*
		 * Strict RFC 5280 checking. Time is checked separately below so we
		 * can report expiry distinctly from a signature failure, so disable
		 * the built-in time check here. Purpose/EKU is likewise checked
		 * explicitly below to yield a dedicated message, so it is not set on
		 * the context.
		 */
		X509_VERIFY_PARAM_set_flags(param,
									X509_V_FLAG_X509_STRICT |
									X509_V_FLAG_NO_CHECK_TIME);
	}
	if (X509_verify_cert(ctx) != 1)
	{
		int			err = X509_STORE_CTX_get_error(ctx);

		info->status = LICENSE_ERR_CHAIN;
		set_reason(info,
				   "license certificate chain does not verify against the AppsCode license CA: %s",
				   X509_verify_cert_error_string(err));
		goto done;
	}

	/*
	 * Step 3c: leaf must carry the clientAuth EKU (part of gate 1). Note
	 * that X509_get_extended_key_usage() returns all-ones when the EKU
	 * extension is absent, so an explicit presence check via
	 * EXFLAG_XKUSAGE is required; otherwise a license with no EKU at all
	 * would pass.
	 */
	xku = X509_get_extended_key_usage(leaf);
	if ((X509_get_extension_flags(leaf) & EXFLAG_XKUSAGE) == 0 ||
		(xku & XKU_SSL_CLIENT) == 0)
	{
		info->status = LICENSE_ERR_NO_CLIENTAUTH;
		set_reason(info,
				   "license certificate lacks the client authentication extended key usage");
		goto done;
	}

	/* Step 4: validity window (gate 2), via OpenSSL time comparison. */
	cmp_nb = X509_cmp_current_time(X509_get0_notBefore(leaf));
	cmp_na = X509_cmp_current_time(X509_get0_notAfter(leaf));
	if (cmp_nb == 0 || cmp_na == 0)
	{
		info->status = LICENSE_ERR_INTERNAL;
		set_reason(info, "could not compare license certificate validity time");
		goto done;
	}
	if (cmp_nb > 0)				/* notBefore is in the future */
	{
		info->status = LICENSE_ERR_NOT_YET_VALID;
		set_reason(info, "license certificate is not valid until %s",
				   info->not_before);
		goto done;
	}
	if (cmp_na < 0)				/* notAfter is in the past */
	{
		info->status = LICENSE_ERR_EXPIRED;
		set_reason(info, "license certificate expired on %s",
				   info->not_after);
		goto done;
	}

	/* Days remaining from now to notAfter. */
	if (ASN1_TIME_diff(&pday, &psec, NULL, X509_get0_notAfter(leaf)))
		info->days_remaining = (long) pday;

	/* Step 5: feature membership (gate 3). */
	{
		int			i;

		for (i = 0; i < info->num_features; i++)
		{
			if (strcmp(info->features[i], APPSCODE_LICENSE_REQUIRED_FEATURE) == 0)
			{
				info->has_required_feature = true;
				break;
			}
		}
	}
	if (!info->has_required_feature)
	{
		char		joined[APPSCODE_LICENSE_STRBUF];
		size_t		p = 0;
		int			i;

		joined[0] = '\0';
		for (i = 0; i < info->num_features && p < sizeof(joined) - 1; i++)
			p += snprintf(joined + p, sizeof(joined) - p, "%s%s",
						  i ? "," : "", info->features[i]);
		info->status = LICENSE_ERR_MISSING_FEATURE;
		set_reason(info,
				   "license does not include the \"%s\" feature (features present: %s)",
				   APPSCODE_LICENSE_REQUIRED_FEATURE,
				   joined[0] ? joined : "(none)");
		goto done;
	}

	info->status = LICENSE_OK;
	set_reason(info, "license accepted");

done:
	if (ctx != NULL)
		X509_STORE_CTX_free(ctx);
	if (store != NULL)
		X509_STORE_free(store);
	if (chain != NULL)
		sk_X509_pop_free(chain, X509_free);
	if (anchors != NULL)
		sk_X509_pop_free(anchors, X509_free);
	if (leaf != NULL)
		X509_free(leaf);
	if (bio != NULL)
		BIO_free(bio);
	if (filebuf != NULL)
		free(filebuf);
	ERR_clear_error();
	return info->status;
}

char *
appscode_license_resolve_path(const char *datadir)
{
	const char *env = getenv("PGLICENSE");

	if (env != NULL && env[0] != '\0')
		return strdup(env);

	if (datadir != NULL && datadir[0] != '\0')
	{
		size_t		len = strlen(datadir) + strlen("/license.pem") + 1;
		char	   *p = malloc(len);

		if (p == NULL)
			return NULL;
		snprintf(p, len, "%s/license.pem", datadir);
		if (access(p, F_OK) == 0)
			return p;
		free(p);
		/* fall through to the compiled-in default */
	}

	return strdup(APPSCODE_LICENSE_DEFAULT_PATH);
}

const char *
appscode_license_status_tag(LicenseStatus st)
{
	switch (st)
	{
		case LICENSE_OK:
			return "ok";
		case LICENSE_ERR_NO_FILE:
			return "no-file";
		case LICENSE_ERR_READ:
			return "read-error";
		case LICENSE_ERR_TOO_LARGE:
			return "too-large";
		case LICENSE_ERR_NO_PEM:
			return "no-pem";
		case LICENSE_ERR_MALFORMED:
			return "malformed";
		case LICENSE_ERR_CHAIN:
			return "chain-invalid";
		case LICENSE_ERR_NO_CLIENTAUTH:
			return "no-clientauth";
		case LICENSE_ERR_NOT_YET_VALID:
			return "not-yet-valid";
		case LICENSE_ERR_EXPIRED:
			return "expired";
		case LICENSE_ERR_MISSING_FEATURE:
			return "missing-feature";
		case LICENSE_ERR_CA_SELFCHECK:
			return "ca-selfcheck";
		case LICENSE_ERR_INTERNAL:
			return "internal-error";
	}
	return "unknown";
}
