#!/usr/bin/env bash
#
# Standalone unit tests for the license verification core.
#
# Builds license_core.c against a freshly generated development CA, with no
# PostgreSQL runtime involved, and exercises every branch of the verification
# algorithm. This runs long before a server is available and is the first thing
# to run after changing license_core.c.
#
# ASan and UBSan are enabled by default because every error path in
# license_core.c frees OpenSSL objects and that is easy to get wrong. Set
# LICENSE_TEST_NO_SANITIZE=1 to build without them.
#
# Usage:
#   src/backend/license/test/run_tests.sh [WORKDIR]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LICDIR="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$LICDIR/../../.." && pwd)"
WORK="${1:-$(mktemp -d)}"

mkdir -p "$WORK"
cd "$WORK" || exit 2

SAN="-fsanitize=address,undefined"
[ "${LICENSE_TEST_NO_SANITIZE:-0}" = "1" ] && SAN=""

pass=0
fail=0

ok()   { printf '  ok    %-46s -> %s\n' "$1" "$2"; pass=$((pass + 1)); }
bad()  { printf '  FAIL  %-46s\n%s\n' "$1" "$(echo "$2" | sed 's/^/          /')"; fail=$((fail + 1)); }

# run <description> <expected-status> [env VAR=val ...] -- <args to license_test>
run()
{
	local desc="$1" exp="$2"
	shift 2
	local out
	if out=$(env "$@" 2>&1); then ok "$desc" "$exp"; else bad "$desc" "$out"; fi
}

echo "=== building development CA ==="
bash "$ROOT/scripts/make-dev-ca.sh" dev-ca > /dev/null || exit 2
bash "$ROOT/scripts/make-dev-ca.sh" rogue-ca > /dev/null || exit 2

echo "=== generating trust anchor header ==="
perl "$LICDIR/generate_ca_header.pl" \
	--output appscode_root_ca.h --pin-output dev_ca_pin.h \
	dev-ca/ca.crt || exit 2

echo "=== compiling harness ==="
# shellcheck disable=SC2086
gcc -std=c99 -Wall -Wextra -Wno-unused-parameter -g -O1 -D_GNU_SOURCE \
	-DLICENSE_DEV_CA $SAN \
	-I. -I"$LICDIR" -I"$ROOT/src/include" \
	-o license_test \
	"$HERE/license_test.c" "$LICDIR/license_core.c" "$LICDIR/ca_pin.c" \
	-lcrypto || exit 2

CL=3f2b8c14-9d7e-4a51-b6c3-8e2f1a0d5c47
OTHER=11111111-2222-4333-8444-555555555555
MK="$ROOT/scripts/make-license.sh"

echo "=== generating fixtures ==="
gen() { local out="$1"; shift; bash "$MK" --ca-dir dev-ca --out "$out" "$@" > /dev/null 2>&1 || echo "could not generate $out" >&2; }
gen valid.pem      --cluster "$CL"
gen expired.pem    --cluster "$CL" --expired
gen future.pem     --cluster "$CL" --not-yet-valid
gen wrongprod.pem  --cluster "$CL" --wrong-product
gen nover.pem      --cluster "$CL" --no-version
gen badserial.pem  --cluster "$CL" --bad-serial
gen unbound.pem    --cluster '*'
gen otherclus.pem  --cluster "$OTHER"
gen oldver.pem     --cluster "$CL" --version '>=13,<15'
gen rogue.pem      --cluster "$CL" --ca-dir rogue-ca

head -c 400 valid.pem > truncated.pem
echo "not a certificate at all" > garbage.pem
: > empty.pem

echo
echo "=== field and lifecycle checks ==="
run "valid license"                  ok                 ./license_test ok                 valid.pem     "$CL" 18
run "expired"                        expired            ./license_test expired            expired.pem   "$CL" 18
run "not yet valid"                  not_yet_valid      ./license_test not_yet_valid      future.pem    "$CL" 18
run "missing file"                   not_found          ./license_test not_found          nosuch.pem    "$CL" 18
run "empty file"                     parse              ./license_test parse              empty.pem     "$CL" 18
run "truncated PEM"                  parse              ./license_test parse              truncated.pem "$CL" 18
run "garbage file"                   parse              ./license_test parse              garbage.pem   "$CL" 18
run "wrong product"                  product            ./license_test product            wrongprod.pem "$CL" 18
run "missing version constraint"     version_missing    ./license_test version_missing    nover.pem     "$CL" 18
run "version excludes this major"    version            ./license_test version            oldver.pem    "$CL" 18
run "version constraint allows 16"   ok                 ./license_test ok                 valid.pem     "$CL" 16
run "serial is not a v4 UUID"        serial_uuid        ./license_test serial_uuid        badserial.pem "$CL" 18
run "wrong cluster"                  cluster_mismatch   ./license_test cluster_mismatch   otherclus.pem "$CL" 18
run "unbound cluster"                ok                 ./license_test ok                 unbound.pem   "$CL" 18
run "bound license, no runtime id"   cluster_unresolved ./license_test cluster_unresolved valid.pem     -     18

echo
echo "=== trust anchor cannot be substituted ==="
run "rogue CA with identical subject DN" chain ./license_test chain rogue.pem "$CL" 18
run "SSL_CERT_FILE has no effect" chain \
	SSL_CERT_FILE="$PWD/rogue-ca/ca.crt" ./license_test chain rogue.pem "$CL" 18
run "SSL_CERT_DIR has no effect" chain \
	SSL_CERT_DIR="$PWD/rogue-ca" ./license_test chain rogue.pem "$CL" 18
run "neither breaks a valid license" ok \
	SSL_CERT_FILE="$PWD/rogue-ca/ca.crt" SSL_CERT_DIR="$PWD/rogue-ca" \
	./license_test ok valid.pem "$CL" 18

echo
echo "=== a TLS server certificate from our own CA is not a license ==="
cat > srv.cnf <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
O = postgres-enterprise
OU = postgres-enterprise
L = productVersion=>=15,<19
CN = ACME Corporation
[v3_srv]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$CL
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl genrsa -out srv.key 2048 2>/dev/null
openssl req -new -key srv.key -config srv.cnf -out srv.csr 2>/dev/null
openssl x509 -req -in srv.csr -CA dev-ca/ca.crt -CAkey dev-ca/ca.key \
	-set_serial 0x7a1c9e4f2b8d4c61a3f5e07b91d2c4a8 -days 365 -sha256 \
	-extfile srv.cnf -extensions v3_srv -out tlsserver.pem 2>/dev/null
run "serverAuth certificate is rejected" eku ./license_test eku tlsserver.pem "$CL" 18

echo
echo "=== swapping the embedded PEM without updating ca_pin.c ==="
mkdir -p tamper && (
	cd tamper || exit 2
	perl "$LICDIR/generate_ca_header.pl" --output appscode_root_ca.h \
		../rogue-ca/ca.crt 2>/dev/null
	# Built WITHOUT -DLICENSE_DEV_CA, so ca_pin.c supplies the hand maintained
	# production digest while the header supplies rogue DER bytes.
	# shellcheck disable=SC2086
	gcc -std=c99 -Wall -g -O1 -D_GNU_SOURCE -I. -I"$LICDIR" -I"$ROOT/src/include" \
		-o license_test_tamper \
		"$HERE/license_test.c" "$LICDIR/license_core.c" "$LICDIR/ca_pin.c" \
		-lcrypto 2>/dev/null
) || true
if [ -x tamper/license_test_tamper ]; then
	run "pin mismatch is detected" ca_pin \
		./tamper/license_test_tamper ca_pin rogue.pem "$CL" 18
else
	bad "pin mismatch is detected" "could not build the tampered harness"
fi

echo
echo "passed=$pass failed=$fail"
echo "workdir: $WORK"
[ "$fail" -eq 0 ]
