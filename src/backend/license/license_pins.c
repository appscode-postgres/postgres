/*-------------------------------------------------------------------------
 *
 * license_pins.c
 *	  Trust-anchor fingerprint pins for license verification.
 *
 * This file deliberately lives in a different translation unit than the
 * embedded CA bytes (which license.c includes from the generated
 * appscode_root_ca_der.h). The verifier hashes the loaded trust anchor at
 * startup and compares it against these pins, so replacing the embedded
 * PEM alone, without also editing these literals in this separate object
 * file, produces a mismatch and a refusal to start.
 *
 * Release builds use the hand-written production pins below. Dev/test
 * builds define APPSCODE_LICENSE_DEV_BUILD and pull generated pins for the
 * randomly generated dev CA instead; those fingerprints cannot be
 * hand-written. The CI dev-CA-fingerprint gate ensures a dev CA never
 * ships in a release binary.
 *
 * See doc/LICENSE_ENFORCEMENT.md sections 2 and 14.
 *
 *-------------------------------------------------------------------------
 */
#include "license/license.h"

#ifdef APPSCODE_LICENSE_DEV_BUILD

#include "appscode_root_ca_pins.h"

const char *const appscode_ca_cert_sha256_pins[] = APPSCODE_CA_CERT_SHA256_PINS;
const char *const appscode_ca_spki_sha256_pins[] = APPSCODE_CA_SPKI_SHA256_PINS;
const int	appscode_ca_num_pins = APPSCODE_CA_PIN_COUNT;

#else

/*
 * Production AppsCode license root CA fingerprints.
 *
 * Certificate SHA-256:
 *	 EE:B8:16:2F:75:6B:B4:05:DF:27:02:EF:29:85:9D:6F:
 *	 F7:CE:DD:C3:9F:FD:15:F7:DF:3D:6D:BE:BF:66:13:97
 * SubjectPublicKeyInfo SHA-256:
 *	 04d6a4452265b903e9e0d7444855e785a7a67f3aa3d7be41ee07cd9166edd700
 */
const char *const appscode_ca_cert_sha256_pins[] = {
	"eeb8162f756bb405df2702ef29859d6ff7ceddc39ffd15f7df3d6dbebf661397",
};
const char *const appscode_ca_spki_sha256_pins[] = {
	"04d6a4452265b903e9e0d7444855e785a7a67f3aa3d7be41ee07cd9166edd700",
};
const int	appscode_ca_num_pins = 1;

#endif							/* APPSCODE_LICENSE_DEV_BUILD */
