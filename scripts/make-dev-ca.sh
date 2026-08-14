#!/usr/bin/env bash
#
# Create a development license CA for local testing and CI.
#
# The dev CA reproduces the production AppsCode root profile exactly, so a
# license issued by it is byte comparable in shape to a production license.
# A test that passes against the dev CA therefore exercises the same code
# paths a production license would.
#
# Production root profile being reproduced (retrieved 2026-08-14 from
# https://licenses.appscode.com/certificates/ca.crt):
#
#   Subject/Issuer   O = AppsCode Inc., CN = ca   (self signed)
#   Serial           0
#   Key              RSA 2048, sha256WithRSAEncryption
#   Basic Constraints critical, CA:TRUE, no pathlen
#   Key Usage        critical: digitalSignature, keyEncipherment, keyCertSign
#   SKI              present
#   AKI, EKU, AIA, CRL DP, Name Constraints   absent
#
# The subject DN deliberately matches production. That is what makes this CA
# usable as the fixture for the "rogue root sharing the AppsCode subject DN is
# rejected" test: identical DN, different key.
#
# This CA is for testing only. The production CA private key never lives in
# this repository; it stays with the licenses.appscode.com signing service.
#
# Usage:
#   scripts/make-dev-ca.sh [OUTPUT_DIR]
#
# Default OUTPUT_DIR is ./dev-ca

set -euo pipefail

OUT="${1:-dev-ca}"

if [ -e "$OUT/ca.crt" ]; then
	echo "make-dev-ca.sh: $OUT/ca.crt already exists, refusing to overwrite" >&2
	echo "remove the directory first if you really want a new CA" >&2
	exit 1
fi

mkdir -p "$OUT"

cat > "$OUT/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no

[dn]
O  = AppsCode Inc.
CN = ca

[v3_ca]
keyUsage             = critical, digitalSignature, keyEncipherment, keyCertSign
basicConstraints     = critical, CA:TRUE
subjectKeyIdentifier = hash
EOF

openssl genrsa -out "$OUT/ca.key" 2048 2>/dev/null
chmod 600 "$OUT/ca.key"

# -set_serial 0 reproduces the production root, which also carries serial 0.
# That is not RFC 5280 conforming for a leaf, but OpenSSL exempts trust
# anchors from the positive serial check, so it verifies under
# X509_V_FLAG_X509_STRICT. See doc/LICENSE_ENFORCEMENT.md section 2.2.
openssl req -x509 -new \
	-key "$OUT/ca.key" \
	-config "$OUT/ca.cnf" \
	-set_serial 0 \
	-days 3650 \
	-sha256 \
	-out "$OUT/ca.crt" 2>/dev/null

# State needed by "openssl ca" when issuing leaves.
mkdir -p "$OUT/newcerts"
: > "$OUT/index.txt"
echo 01 > "$OUT/crlnumber"

echo "dev CA created in $OUT"
echo
openssl x509 -in "$OUT/ca.crt" -noout -subject -issuer -serial -dates
echo -n "SPKI SHA-256: "
openssl x509 -in "$OUT/ca.crt" -noout -pubkey \
	| openssl pkey -pubin -outform DER 2>/dev/null \
	| openssl dgst -sha256 -r | cut -d' ' -f1
echo
echo "This fingerprint must never appear in a release binary."
echo "The CI gate in doc/LICENSE_ENFORCEMENT.md section 16 checks for it."
