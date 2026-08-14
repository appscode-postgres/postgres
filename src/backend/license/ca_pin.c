/*-------------------------------------------------------------------------
 *
 * ca_pin.c
 *	  Pinned SubjectPublicKeyInfo digests for the embedded license trust
 *	  anchors.
 *
 * This lives in a different translation unit from the generated DER bytes in
 * appscode_root_ca.h, and unlike that header it is hand maintained rather than
 * generated. Replacing the committed PEM alone therefore produces a mismatch
 * at startup, because this file still carries the old digest.
 *
 * The digest is over the SubjectPublicKeyInfo, not over the certificate, so it
 * survives a re-issue of the same key with different validity dates. That is
 * what makes a routine CA renewal a one line change here rather than a
 * scramble.
 *
 * To update after a genuine CA rotation:
 *
 *	  openssl x509 -in appscode_root_ca.pem -noout -pubkey \
 *		| openssl pkey -pubin -outform DER \
 *		| openssl dgst -sha256 -r
 *
 * The order of entries must match the order of the PEM files passed to
 * generate_ca_header.pl, since the two arrays are indexed together.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/backend/license/ca_pin.c
 *
 *-------------------------------------------------------------------------
 */
#include "license/license.h"

#ifdef LICENSE_DEV_CA

/*
 * Test builds embed the development CA INSTEAD OF the production CA, never in
 * addition to it. The digest cannot be hand maintained here because every
 * developer generates their own dev CA, so it is generated alongside the DER
 * bytes. A release build must never define LICENSE_DEV_CA; CI inspects the
 * shipped binary for the dev CA fingerprint and fails if it appears.
 */
#include "dev_ca_pin.h"

/*
 * A grep-able marker so CI can tell a development build from a release build
 * by inspecting the shipped binary, rather than by trusting the build recipe.
 *
 * Comparing fingerprints alone would not be enough: a dev CA is generated
 * fresh by whoever runs the tests, so CI has no fixed value to search for.
 * This string is fixed, and it only exists when LICENSE_DEV_CA is defined.
 *
 * Deliberately not static, and referenced through a volatile pointer below, so
 * the compiler cannot discard it as unused.
 */
const char appscode_license_dev_ca_marker[] =
	"APPSCODE-LICENSE-DEV-CA-BUILD-DO-NOT-SHIP";

const char *volatile appscode_license_dev_ca_marker_ref =
	appscode_license_dev_ca_marker;

#else

/*
 * Production: AppsCode license root CA.
 *
 * Retrieved 2026-08-14 from https://licenses.appscode.com/certificates/ca.crt
 *	  subject		O = AppsCode Inc., CN = ca
 *	  notAfter		2036-05-26
 *	  SPKI SHA-256	04d6a4452265b903e9e0d7444855e785a7a67f3aa3d7be41ee07cd9166edd700
 */
const unsigned char appscode_ca_spki_pins[][32] = {
	{
		0x04, 0xd6, 0xa4, 0x45, 0x22, 0x65, 0xb9, 0x03,
		0xe9, 0xe0, 0xd7, 0x44, 0x48, 0x55, 0xe7, 0x85,
		0xa7, 0xa6, 0x7f, 0x3a, 0xa3, 0xd7, 0xbe, 0x41,
		0xee, 0x07, 0xcd, 0x91, 0x66, 0xed, 0xd7, 0x00
	}
};

const int	appscode_ca_spki_pin_count =
	(int) (sizeof(appscode_ca_spki_pins) / sizeof(appscode_ca_spki_pins[0]));

#endif							/* LICENSE_DEV_CA */
