/*-------------------------------------------------------------------------
 *
 * license_core.c
 *	  Offline certificate based license verification, free of PostgreSQL
 *	  headers so it can also be linked into a standalone test harness.
 *
 * This file deliberately uses malloc/free rather than palloc/pfree. The
 * primary caller runs early in PostmasterMain(), before a memory context is
 * necessarily available, and the same object is linked into a test binary that
 * has no PostgreSQL runtime at all.
 *
 * Every error path frees the OpenSSL objects it created. The test harness is
 * intended to be run under valgrind or ASan.
 *
 * The certificate profile carries all license fields in standard X.509
 * attributes rather than private extensions, because AppsCode has no IANA
 * Private Enterprise Number and squatting on an arbitrary OID arc would be
 * wrong. See doc/LICENSE_ENFORCEMENT.md section 3.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/backend/license/license_core.c
 *
 *-------------------------------------------------------------------------
 */
#if defined(__linux__) || defined(__GLIBC__)
#define HAVE_DLADDR 1
#include <dlfcn.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>			/* strncasecmp */

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "license/license.h"
#include "appscode_root_ca.h"

/*
 * Size cap on the license bundle. A license is a few kilobytes; anything
 * larger is not a license and should not be read into memory.
 */
#define LICENSE_MAX_BYTES		(64 * 1024)

/* The product feature string that gates this build. */
#define LICENSE_PRODUCT_FEATURE	"postgres-enterprise"

/* Feature flag key carrying the major version constraint. */
#define LICENSE_VERSION_KEY		"productVersion"

#define SECS_PER_DAY			86400

/*
 * The format attribute is spelled out rather than using PostgreSQL's
 * pg_attribute_printf, because this file is deliberately free of PostgreSQL
 * headers so it can be linked into the standalone test harness.
 */
#if defined(__GNUC__)
__attribute__((format(printf, 3, 4)))
#endif
static void
set_err(char *errbuf, size_t errlen, const char *fmt,...)
{
	va_list		ap;

	if (errbuf == NULL || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(errbuf, errlen, fmt, ap);
	va_end(ap);
}

/*
 * Verify that the OpenSSL we are calling is the one we were built against.
 *
 * This is the weaker half of the anti-bypass measures. It catches a libcrypto
 * that has been swapped for a different version underneath us, which is the
 * accidental or lazy case. It does NOT stop LD_PRELOAD interposition, and no
 * check written in this process can, because the interposed library is
 * answering the very questions we would ask. That is stated in section 1 of
 * the design document as out of scope rather than papered over here.
 *
 * Only the major and minor version are compared. Patch level differences are
 * routine and expected on a distribution that updates OpenSSL in place.
 *
 * Refusing based on the resolved library PATH was considered and deliberately
 * not implemented: there is no portable notion of an expected location, and a
 * check that fires on Debian but not on Alpine would cost more in false
 * refusals than it buys. The path is recorded in the caller's diagnostics
 * instead, so a support bundle shows where the symbols actually came from.
 */
bool
license_openssl_is_expected(char *errbuf, size_t errlen)
{
	unsigned long built = OPENSSL_VERSION_NUMBER;
	unsigned long running = OpenSSL_version_num();

	/* Bits 28..20 are major, bits 19..12 are minor. */
	if ((built >> 20) != (running >> 20))
	{
		set_err(errbuf, errlen,
				"built against OpenSSL 0x%08lx but running against 0x%08lx",
				built, running);
		return false;
	}
	return true;
}

/*
 * Where did the OpenSSL symbols actually resolve from?
 *
 * Diagnostic only, never a refusal. Returns false if the platform cannot
 * answer, which is not an error.
 */
bool
license_openssl_origin(char *buf, size_t buflen)
{
#ifdef HAVE_DLADDR
	Dl_info		info;

	if (dladdr((const void *) EVP_sha256, &info) != 0 && info.dli_fname != NULL)
	{
		snprintf(buf, buflen, "%s", info.dli_fname);
		return true;
	}
#endif
	snprintf(buf, buflen, "unknown");
	return false;
}

const char *
license_status_name(LicenseStatus status)
{
	switch (status)
	{
		case LICENSE_OK:					return "ok";
		case LICENSE_ERR_NOT_FOUND:			return "not_found";
		case LICENSE_ERR_UNREADABLE:		return "unreadable";
		case LICENSE_ERR_TOO_LARGE:			return "too_large";
		case LICENSE_ERR_PARSE:				return "parse";
		case LICENSE_ERR_CA_PIN:			return "ca_pin";
		case LICENSE_ERR_CHAIN:				return "chain";
		case LICENSE_ERR_EKU:				return "eku";
		case LICENSE_ERR_NOT_YET_VALID:		return "not_yet_valid";
		case LICENSE_ERR_EXPIRED:			return "expired";
		case LICENSE_ERR_PRODUCT:			return "product";
		case LICENSE_ERR_VERSION_MISSING:	return "version_missing";
		case LICENSE_ERR_VERSION:			return "version";
		case LICENSE_ERR_CLUSTER_MISMATCH:	return "cluster_mismatch";
		case LICENSE_ERR_CLUSTER_UNRESOLVED: return "cluster_unresolved";
		case LICENSE_ERR_SERIAL_UUID:		return "serial_uuid";
		case LICENSE_ERR_INTERNAL:			return "internal";
	}
	return "unknown";
}

/*
 * Constant time comparison of two NUL terminated strings, case insensitive.
 *
 * Length is not secret here, so an early length check is acceptable; what is
 * avoided is an early exit on the first differing byte.
 */
static bool
ci_equal_ct(const char *a, const char *b)
{
	size_t		la = strlen(a);
	size_t		lb = strlen(b);
	unsigned char diff = 0;
	size_t		i;

	if (la != lb)
		return false;
	for (i = 0; i < la; i++)
		diff |= (unsigned char) (tolower((unsigned char) a[i]) ^
								 tolower((unsigned char) b[i]));
	return diff == 0;
}

/* Trim ASCII whitespace from both ends, in place. */
static void
trim(char *s)
{
	char	   *p = s;
	size_t		n;

	while (*p && isspace((unsigned char) *p))
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);

	n = strlen(s);
	while (n > 0 && isspace((unsigned char) s[n - 1]))
		s[--n] = '\0';
}

/*
 * Copy one occurrence of an X.509 name attribute into a caller buffer.
 *
 * "index" selects among repeated attributes of the same NID, which matters for
 * O and L: the profile stores the feature list in repeated O attributes and
 * feature flags in repeated L attributes.
 *
 * Returns false if there is no such occurrence.
 */
static bool
get_name_entry(X509_NAME *name, int nid, int index, char *buf, size_t buflen)
{
	int			loc = -1;
	int			seen = 0;

	for (;;)
	{
		X509_NAME_ENTRY *e;
		ASN1_STRING *val;
		unsigned char *utf8 = NULL;
		int			len;

		loc = X509_NAME_get_index_by_NID(name, nid, loc);
		if (loc < 0)
			return false;
		if (seen++ != index)
			continue;

		e = X509_NAME_get_entry(name, loc);
		if (e == NULL)
			return false;
		val = X509_NAME_ENTRY_get_data(e);
		if (val == NULL)
			return false;

		/*
		 * Convert through UTF-8 rather than reading the raw ASN.1 bytes, so a
		 * value encoded as BMPString or PrintableString is handled the same
		 * way a UTF8String would be.
		 */
		len = ASN1_STRING_to_UTF8(&utf8, val);
		if (len < 0)
			return false;
		if ((size_t) len >= buflen)
		{
			OPENSSL_free(utf8);
			return false;
		}
		memcpy(buf, utf8, (size_t) len);
		buf[len] = '\0';
		OPENSSL_free(utf8);
		return true;
	}
}

/*
 * Does the subject carry the required product feature in O?
 *
 * The existing AppsCode scheme treats O as a multi valued feature list and
 * accepts a license if any requested feature is present, so this walks every O
 * attribute rather than only the first.
 */
static bool
has_product_feature(X509_NAME *subj, const char *want, char *matched,
					size_t matchedlen)
{
	int			i;

	for (i = 0;; i++)
	{
		char		buf[LICENSE_NAME_LEN];

		if (!get_name_entry(subj, NID_organizationName, i, buf, sizeof(buf)))
			break;
		trim(buf);
		if (ci_equal_ct(buf, want))
		{
			snprintf(matched, matchedlen, "%s", buf);
			return true;
		}
	}
	return false;
}

/*
 * Find a "key=value" feature flag among the repeated L attributes.
 */
static bool
get_feature_flag(X509_NAME *subj, const char *key, char *val, size_t vallen)
{
	size_t		keylen = strlen(key);
	int			i;

	for (i = 0;; i++)
	{
		char		buf[LICENSE_NAME_LEN];
		char	   *eq;

		if (!get_name_entry(subj, NID_localityName, i, buf, sizeof(buf)))
			break;
		trim(buf);
		eq = strchr(buf, '=');
		if (eq == NULL)
			continue;
		if ((size_t) (eq - buf) != keylen)
			continue;
		if (strncasecmp(buf, key, keylen) != 0)
			continue;

		snprintf(val, vallen, "%s", eq + 1);
		trim(val);
		return true;
	}
	return false;
}

/*
 * Evaluate a version constraint such as ">=15,<19" against a major version.
 *
 * Every clause must hold. Whitespace is not accepted, and any parse failure is
 * reported as a failure rather than silently passing, so a malformed
 * constraint can never widen entitlement.
 */
static bool
version_satisfies(const char *constraint, int major, bool *malformed)
{
	const char *p = constraint;

	*malformed = false;

	if (*p == '\0')
	{
		*malformed = true;
		return false;
	}

	while (*p)
	{
		int			op_ge = 0,
					op_gt = 0,
					op_le = 0,
					op_lt = 0,
					op_eq = 0;
		long		want;
		char	   *end;

		if (p[0] == '>' && p[1] == '=') { op_ge = 1; p += 2; }
		else if (p[0] == '<' && p[1] == '=') { op_le = 1; p += 2; }
		else if (p[0] == '>') { op_gt = 1; p += 1; }
		else if (p[0] == '<') { op_lt = 1; p += 1; }
		else if (p[0] == '=') { op_eq = 1; p += 1; }
		else
		{
			*malformed = true;
			return false;
		}

		if (!isdigit((unsigned char) *p))
		{
			*malformed = true;
			return false;
		}

		errno = 0;
		want = strtol(p, &end, 10);
		if (end == p || errno != 0 || want < 0 || want > 1000000)
		{
			*malformed = true;
			return false;
		}
		p = end;

		if (op_ge && !(major >= want)) return false;
		if (op_gt && !(major > want)) return false;
		if (op_le && !(major <= want)) return false;
		if (op_lt && !(major < want)) return false;
		if (op_eq && !(major == want)) return false;

		if (*p == ',')
		{
			p++;
			if (*p == '\0')
			{
				*malformed = true;
				return false;
			}
			continue;
		}
		if (*p != '\0')
		{
			*malformed = true;
			return false;
		}
	}
	return true;
}

/*
 * Render the certificate serial as a canonical lowercase v4 UUID.
 *
 * The serial IS the license UUID: the same 128 bits, so that
 * "openssl x509 -noout -serial" reveals the license primary key without
 * needing our tooling.
 *
 * DER prepends a zero byte when the high bit of the first content byte is set,
 * so this works from the integer magnitude rather than the raw encoding.
 * Otherwise a UUID whose first byte is >= 0x80 would look 17 bytes long.
 */
static bool
serial_to_uuid(const ASN1_INTEGER *serial, char *uuid, char *hex)
{
	BIGNUM	   *bn;
	unsigned char raw[16];
	int			nbytes;
	int			i;

	if (serial == NULL)
		return false;

	/* A negative or zero serial is not a valid identifier. */
	if (ASN1_STRING_length(serial) == 0)
		return false;

	bn = ASN1_INTEGER_to_BN(serial, NULL);
	if (bn == NULL)
		return false;
	if (BN_is_negative(bn) || BN_is_zero(bn))
	{
		BN_free(bn);
		return false;
	}

	nbytes = BN_num_bytes(bn);
	if (nbytes > 16)
	{
		BN_free(bn);
		return false;
	}

	/* Left pad to exactly 16 bytes. */
	memset(raw, 0, sizeof(raw));
	if (BN_bn2bin(bn, raw + (16 - nbytes)) != nbytes)
	{
		BN_free(bn);
		return false;
	}
	BN_free(bn);

	/*
	 * Require a well formed v4 UUID: version nibble 4, RFC 4122 variant.
	 * A serial that is merely 16 bytes of something else is rejected, since
	 * the UUID is the support system's primary key.
	 */
	if (((raw[6] & 0xf0) >> 4) != 4)
		return false;
	if ((raw[8] & 0xc0) != 0x80)
		return false;

	for (i = 0; i < 16; i++)
		sprintf(hex + i * 2, "%02x", raw[i]);
	hex[32] = '\0';

	snprintf(uuid, LICENSE_UUID_LEN,
			 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
			 raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14],
			 raw[15]);
	return true;
}

/* Hex SHA-256 of a certificate's DER encoding. */
static bool
cert_fingerprint(X509 *cert, char *out)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	unsigned int i;

	if (!X509_digest(cert, EVP_sha256(), md, &mdlen) || mdlen != 32)
		return false;
	for (i = 0; i < mdlen; i++)
		sprintf(out + i * 2, "%02x", md[i]);
	out[64] = '\0';
	return true;
}

/* SHA-256 over a certificate's SubjectPublicKeyInfo. */
static bool
spki_digest(X509 *cert, unsigned char out[32])
{
	unsigned char *der = NULL;
	int			len;

	len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
	if (len <= 0 || der == NULL)
		return false;
	SHA256(der, (size_t) len, out);
	OPENSSL_free(der);
	return true;
}

/*
 * Build the trust store from the embedded anchors, and verify each against its
 * pinned SPKI digest.
 *
 * The store is created empty and only embedded anchors are added, so
 * SSL_CERT_FILE, SSL_CERT_DIR, and the OpenSSL default paths cannot influence
 * license verification.
 */
static X509_STORE *
build_trust_store(char *errbuf, size_t errlen, LicenseStatus *status)
{
	X509_STORE *store;
	int			i;

	store = X509_STORE_new();
	if (store == NULL)
	{
		*status = LICENSE_ERR_INTERNAL;
		set_err(errbuf, errlen, "could not allocate certificate store");
		return NULL;
	}

	if (APPSCODE_TRUST_ANCHOR_COUNT != appscode_ca_spki_pin_count)
	{
		X509_STORE_free(store);
		*status = LICENSE_ERR_CA_PIN;
		set_err(errbuf, errlen,
				"embedded trust anchor count %d does not match pinned digest count %d",
				APPSCODE_TRUST_ANCHOR_COUNT, appscode_ca_spki_pin_count);
		return NULL;
	}

	for (i = 0; i < APPSCODE_TRUST_ANCHOR_COUNT; i++)
	{
		const unsigned char *p = appscode_trust_anchors[i].der;
		X509	   *ca;
		unsigned char digest[32];

		ca = d2i_X509(NULL, &p, (long) appscode_trust_anchors[i].len);
		if (ca == NULL)
		{
			X509_STORE_free(store);
			*status = LICENSE_ERR_INTERNAL;
			set_err(errbuf, errlen, "embedded trust anchor %d is malformed", i);
			return NULL;
		}

		/*
		 * Compare the anchor's public key against the digest hard coded in
		 * ca_pin.c, a different translation unit. Replacing the embedded PEM
		 * alone produces a mismatch here.
		 */
		if (!spki_digest(ca, digest) ||
			memcmp(digest, appscode_ca_spki_pins[i], 32) != 0)
		{
			X509_free(ca);
			X509_STORE_free(store);
			*status = LICENSE_ERR_CA_PIN;
			set_err(errbuf, errlen,
					"embedded trust anchor %d does not match its pinned public key digest",
					i);
			return NULL;
		}

		if (X509_STORE_add_cert(store, ca) != 1)
		{
			X509_free(ca);
			X509_STORE_free(store);
			*status = LICENSE_ERR_INTERNAL;
			set_err(errbuf, errlen, "could not add trust anchor %d to store", i);
			return NULL;
		}
		X509_free(ca);
	}

	return store;
}

/* Does the leaf carry the clientAuth extended key usage? */
static bool
has_client_auth_eku(X509 *leaf)
{
	EXTENDED_KEY_USAGE *eku;
	bool		found = false;
	int			i;

	eku = X509_get_ext_d2i(leaf, NID_ext_key_usage, NULL, NULL);
	if (eku == NULL)
		return false;

	for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
	{
		if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == NID_client_auth)
		{
			found = true;
			break;
		}
	}
	EXTENDED_KEY_USAGE_free(eku);
	return found;
}

/*
 * Compare the dNSName SAN entries against the runtime cluster identity.
 *
 * DNS wildcard semantics are deliberately not applied. A cluster identifier is
 * an opaque value, not a hostname, and partial wildcard matching on it would
 * weaken the binding. Only two forms mean unbound: a literal "*", and the
 * "*.<something>" form the existing Go verifier produces for wildcard
 * licenses.
 */
static LicenseStatus
check_cluster_binding(X509 *leaf, const char *runtime_cluster,
					  LicenseInfo *out, char *errbuf, size_t errlen)
{
	GENERAL_NAMES *sans;
	int			i;
	bool		any_dns = false;
	bool		matched = false;

	sans = X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
	if (sans == NULL)
	{
		set_err(errbuf, errlen,
				"license carries no subjectAltName, so it names no cluster");
		return LICENSE_ERR_CLUSTER_MISMATCH;
	}

	for (i = 0; i < sk_GENERAL_NAME_num(sans) && !matched; i++)
	{
		const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
		const unsigned char *data;
		int			len;
		char		value[LICENSE_NAME_LEN];

		if (gn == NULL || GENERAL_NAME_get0_value((GENERAL_NAME *) gn, NULL) == NULL)
			continue;
		/*
		 * rfc822Name entries are ignored rather than rejected. Postgres
		 * licenses carry no contact SAN, but the signing service is shared
		 * with other products, so one that still emits a contact must remain
		 * valid.
		 */
		if (gn->type != GEN_DNS)
			continue;

		data = ASN1_STRING_get0_data(gn->d.dNSName);
		len = ASN1_STRING_length(gn->d.dNSName);
		if (data == NULL || len <= 0 || (size_t) len >= sizeof(value))
			continue;
		memcpy(value, data, (size_t) len);
		value[len] = '\0';
		trim(value);

		any_dns = true;

		/* Unbound forms. */
		if (strcmp(value, "*") == 0 || strncmp(value, "*.", 2) == 0)
		{
			out->cluster_unbound = true;
			snprintf(out->cluster_id, sizeof(out->cluster_id), "%s", value);
			matched = true;
			break;
		}

		if (out->cluster_id[0] == '\0')
			snprintf(out->cluster_id, sizeof(out->cluster_id), "%s", value);

		if (runtime_cluster != NULL && ci_equal_ct(value, runtime_cluster))
		{
			snprintf(out->cluster_id, sizeof(out->cluster_id), "%s", value);
			matched = true;
			break;
		}
	}

	GENERAL_NAMES_free(sans);

	if (matched)
		return LICENSE_OK;

	if (!any_dns)
	{
		set_err(errbuf, errlen,
				"license carries no dNSName entry, so it names no cluster");
		return LICENSE_ERR_CLUSTER_MISMATCH;
	}

	/*
	 * The license names a specific cluster. If no runtime identity could be
	 * resolved we fail closed rather than treating an absent identity as a
	 * match.
	 */
	if (runtime_cluster == NULL || runtime_cluster[0] == '\0')
	{
		set_err(errbuf, errlen,
				"license is bound to cluster \"%s\" but no cluster identity could be resolved",
				out->cluster_id);
		return LICENSE_ERR_CLUSTER_UNRESOLVED;
	}

	set_err(errbuf, errlen,
			"license is bound to cluster \"%s\" but this cluster is \"%s\"",
			out->cluster_id, runtime_cluster);
	return LICENSE_ERR_CLUSTER_MISMATCH;
}

LicenseStatus
license_verify_buffer(const unsigned char *pem, size_t pemlen,
					  const char *runtime_cluster, int pg_major, time_t now,
					  LicenseInfo *out, char *errbuf, size_t errlen)
{
	BIO		   *bio = NULL;
	X509	   *leaf = NULL;
	STACK_OF(X509) *chain = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
	X509_NAME  *subj;
	LicenseStatus status = LICENSE_ERR_INTERNAL;
	bool		malformed = false;
	bool		serial_ok;
	char		constraint[LICENSE_CONSTRAINT_LEN];

	memset(out, 0, sizeof(*out));
	out->status = LICENSE_ERR_INTERNAL;
	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';

	if (pemlen == 0)
	{
		set_err(errbuf, errlen, "license bundle is empty");
		status = LICENSE_ERR_PARSE;
		goto done;
	}
	if (pemlen > LICENSE_MAX_BYTES)
	{
		set_err(errbuf, errlen, "license bundle exceeds %d bytes",
				LICENSE_MAX_BYTES);
		status = LICENSE_ERR_TOO_LARGE;
		goto done;
	}

	bio = BIO_new_mem_buf(pem, (int) pemlen);
	if (bio == NULL)
	{
		set_err(errbuf, errlen, "could not allocate memory BIO");
		goto done;
	}

	/* First certificate is the leaf; anything after it is an intermediate. */
	leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (leaf == NULL)
	{
		set_err(errbuf, errlen, "license bundle is not valid PEM");
		status = LICENSE_ERR_PARSE;
		goto done;
	}

	chain = sk_X509_new_null();
	if (chain == NULL)
	{
		set_err(errbuf, errlen, "could not allocate chain stack");
		goto done;
	}
	for (;;)
	{
		X509	   *extra = PEM_read_bio_X509(bio, NULL, NULL, NULL);

		if (extra == NULL)
		{
			/* Clear the expected end of file condition. */
			ERR_clear_error();
			break;
		}
		if (sk_X509_push(chain, extra) == 0)
		{
			X509_free(extra);
			set_err(errbuf, errlen, "could not extend chain stack");
			goto done;
		}
	}

	/*
	 * Extract identity before verifying the chain, so that a failure message
	 * can name the license. Note this is only used to populate diagnostics;
	 * the decision to reject a malformed serial is deferred until after chain
	 * verification below, so that a forged certificate reports the chain
	 * failure rather than a subsidiary complaint about its serial.
	 */
	(void) cert_fingerprint(leaf, out->leaf_fingerprint);
	serial_ok = serial_to_uuid(X509_get0_serialNumber(leaf), out->uuid,
							   out->serial_hex);

	subj = X509_get_subject_name(leaf);
	if (subj == NULL)
	{
		set_err(errbuf, errlen, "license certificate has no subject");
		status = LICENSE_ERR_PARSE;
		goto done;
	}
	(void) get_name_entry(subj, NID_commonName, 0, out->licensee,
						  sizeof(out->licensee));
	(void) get_name_entry(subj, NID_organizationName, 0, out->org,
						  sizeof(out->org));

	/* Step 3: chain verification against the embedded anchors only. */
	store = build_trust_store(errbuf, errlen, &status);
	if (store == NULL)
		goto done;

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL)
	{
		set_err(errbuf, errlen, "could not allocate verification context");
		status = LICENSE_ERR_INTERNAL;
		goto done;
	}
	if (X509_STORE_CTX_init(ctx, store, leaf, chain) != 1)
	{
		set_err(errbuf, errlen, "could not initialize verification context");
		status = LICENSE_ERR_INTERNAL;
		goto done;
	}

	/*
	 * Strict mode enforces RFC 5280 rules that OpenSSL otherwise relaxes.
	 * Validity dates are checked separately below so that an expired license
	 * reports "expired" rather than a generic chain failure, which matters for
	 * operator diagnosis.
	 */
	X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_X509_STRICT |
							 X509_V_FLAG_NO_CHECK_TIME);

	if (X509_verify_cert(ctx) != 1)
	{
		int			err = X509_STORE_CTX_get_error(ctx);

		set_err(errbuf, errlen,
				"license chain verification failed: %s (depth %d)",
				X509_verify_cert_error_string(err),
				X509_STORE_CTX_get_error_depth(ctx));
		status = LICENSE_ERR_CHAIN;
		goto done;
	}

	/*
	 * The chain is trusted from here on, so a malformed serial is now a
	 * property of a genuinely issued certificate rather than of an attacker
	 * supplied one. The UUID is the support system's primary key, so a
	 * certificate without a usable one is rejected.
	 */
	if (!serial_ok)
	{
		set_err(errbuf, errlen,
				"license serial is not a valid v4 UUID, so the license has no usable identity");
		status = LICENSE_ERR_SERIAL_UUID;
		goto done;
	}

	/* Step 4: purpose. */
	if (!has_client_auth_eku(leaf))
	{
		set_err(errbuf, errlen,
				"license certificate lacks the clientAuth extended key usage");
		status = LICENSE_ERR_EKU;
		goto done;
	}

	/* Step 5: validity window, using OpenSSL time comparison. */
	if (X509_cmp_time(X509_get0_notBefore(leaf), &now) > 0)
	{
		set_err(errbuf, errlen, "license is not yet valid");
		status = LICENSE_ERR_NOT_YET_VALID;
		goto done;
	}
	if (X509_cmp_time(X509_get0_notAfter(leaf), &now) < 0)
	{
		set_err(errbuf, errlen, "license has expired");
		status = LICENSE_ERR_EXPIRED;
		goto done;
	}

	/* Step 6: product gate. */
	if (!has_product_feature(subj, LICENSE_PRODUCT_FEATURE, out->product,
							 sizeof(out->product)))
	{
		set_err(errbuf, errlen,
				"license does not include product \"%s\"",
				LICENSE_PRODUCT_FEATURE);
		status = LICENSE_ERR_PRODUCT;
		goto done;
	}

	/* Step 7: version constraint. A missing constraint is not "all versions". */
	if (!get_feature_flag(subj, LICENSE_VERSION_KEY, constraint,
						  sizeof(constraint)))
	{
		set_err(errbuf, errlen,
				"license does not specify a %s constraint", LICENSE_VERSION_KEY);
		status = LICENSE_ERR_VERSION_MISSING;
		goto done;
	}
	snprintf(out->version_constraint, sizeof(out->version_constraint), "%s",
			 constraint);

	if (!version_satisfies(constraint, pg_major, &malformed))
	{
		if (malformed)
			set_err(errbuf, errlen,
					"license %s constraint \"%s\" is malformed",
					LICENSE_VERSION_KEY, constraint);
		else
			set_err(errbuf, errlen,
					"server major version %d does not satisfy constraint \"%s\"",
					pg_major, constraint);
		status = LICENSE_ERR_VERSION;
		goto done;
	}

	/* Step 8: cluster binding. */
	status = check_cluster_binding(leaf, runtime_cluster, out, errbuf, errlen);
	if (status != LICENSE_OK)
		goto done;

	/* Report the window in the caller's terms. */
	{
		struct tm	tm;
		ASN1_TIME  *epoch = ASN1_TIME_set(NULL, 0);
		int			days = 0,
					secs = 0;

		memset(&tm, 0, sizeof(tm));
		if (epoch != NULL)
		{
			if (ASN1_TIME_diff(&days, &secs, epoch, X509_get0_notAfter(leaf)))
				out->not_after = (time_t) days * SECS_PER_DAY + secs;
			if (ASN1_TIME_diff(&days, &secs, epoch, X509_get0_notBefore(leaf)))
				out->not_before = (time_t) days * SECS_PER_DAY + secs;
			ASN1_TIME_free(epoch);
		}
		if (ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(leaf)))
			out->days_remaining = days;
	}

	status = LICENSE_OK;

done:
	out->status = status;
	if (ctx != NULL)
		X509_STORE_CTX_free(ctx);
	if (store != NULL)
		X509_STORE_free(store);
	if (chain != NULL)
		sk_X509_pop_free(chain, X509_free);
	if (leaf != NULL)
		X509_free(leaf);
	if (bio != NULL)
		BIO_free(bio);
	ERR_clear_error();
	return status;
}

LicenseStatus
license_verify_file(const char *path, const char *runtime_cluster,
					int pg_major, time_t now, LicenseInfo *out,
					char *errbuf, size_t errlen)
{
	FILE	   *fp;
	unsigned char *buf;
	size_t		nread;
	long		size;
	LicenseStatus status;

	memset(out, 0, sizeof(*out));
	out->status = LICENSE_ERR_INTERNAL;

	fp = fopen(path, "rb");
	if (fp == NULL)
	{
		if (errno == ENOENT)
		{
			set_err(errbuf, errlen, "license file \"%s\" does not exist", path);
			out->status = LICENSE_ERR_NOT_FOUND;
			return LICENSE_ERR_NOT_FOUND;
		}
		set_err(errbuf, errlen, "could not read license file \"%s\": %s",
				path, strerror(errno));
		out->status = LICENSE_ERR_UNREADABLE;
		return LICENSE_ERR_UNREADABLE;
	}

	if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
		fseek(fp, 0, SEEK_SET) != 0)
	{
		fclose(fp);
		set_err(errbuf, errlen, "could not determine size of \"%s\"", path);
		out->status = LICENSE_ERR_UNREADABLE;
		return LICENSE_ERR_UNREADABLE;
	}

	/* Cap before allocating, not after. */
	if (size > LICENSE_MAX_BYTES)
	{
		fclose(fp);
		set_err(errbuf, errlen,
				"license file \"%s\" is %ld bytes, exceeding the %d byte maximum",
				path, size, LICENSE_MAX_BYTES);
		out->status = LICENSE_ERR_TOO_LARGE;
		return LICENSE_ERR_TOO_LARGE;
	}

	buf = malloc((size_t) size + 1);
	if (buf == NULL)
	{
		fclose(fp);
		set_err(errbuf, errlen, "out of memory reading license file");
		out->status = LICENSE_ERR_INTERNAL;
		return LICENSE_ERR_INTERNAL;
	}

	nread = fread(buf, 1, (size_t) size, fp);
	fclose(fp);
	buf[nread] = '\0';

	status = license_verify_buffer(buf, nread, runtime_cluster, pg_major, now,
								   out, errbuf, errlen);
	free(buf);
	return status;
}
