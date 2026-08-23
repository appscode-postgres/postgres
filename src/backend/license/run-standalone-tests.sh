#!/bin/sh
#
# run-standalone-tests.sh - build and run the license core outside the server.
#
# Generates a throwaway dev CA, issues license certificates of every shape
# the verifier must classify, builds license_test against the dev CA, and
# asserts the expected status for each. This exercises the verification core
# (license.c) with no PostgreSQL backend involved, complementing the TAP
# suite under src/test/modules/license that exercises the full server.
#
# Requires: a C compiler, OpenSSL headers/libs, python3 + cryptography (for
# issuance only). Set CC to override the compiler.
#
# Usage: run-standalone-tests.sh [workdir]
#   workdir defaults to a fresh mktemp directory.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
root=$(CDPATH= cd "$here/../../.." && pwd)
CC=${CC:-cc}

work=${1:-$(mktemp -d)}
mkdir -p "$work/gen"
echo "workdir: $work" >&2

# Dev CA and generated headers.
"$root/scripts/make-dev-ca.sh" "$work" >/dev/null 2>&1
python3 "$here/generate-ca-header.py" \
	--pem "$work/dev-ca.pem" \
	--der-out "$work/gen/appscode_root_ca_der.h" \
	--pins-out "$work/gen/appscode_root_ca_pins.h"

# Build the harness against the dev CA.
$CC -Wall -Wextra -Wno-unused-parameter -std=c99 \
	-DAPPSCODE_LICENSE_DEV_BUILD \
	-I"$here" -I"$work/gen" \
	"$here/license.c" "$here/license_pins.c" "$here/license_test.c" \
	-lcrypto -o "$work/license_test"

mk() {
	"$root/scripts/make-license.sh" \
		--ca-key "$work/dev-ca.key" --ca-cert "$work/dev-ca.pem" "$@" \
		>/dev/null 2>&1
}

# One license of each shape.
mk --out "$work/valid.pem"
mk --out "$work/expired.pem" --not-before -5184000
mk --out "$work/future.pem" --not-before 86400
mk --out "$work/server.pem" --eku serverAuth
mk --out "$work/noeku.pem" --no-eku
mk --out "$work/nofeat.pem" --features kubedb-enterprise
mk --out "$work/multi.pem" --features postgres-enterprise,kubedb-enterprise
mk --out "$work/noou.pem" --plan ""
mk --out "$work/noc.pem" --product ""
mk --out "$work/nosan.pem" --no-san
printf 'this is not a certificate' >"$work/garbage.pem"
head -c 160 "$work/valid.pem" >"$work/trunc.pem"

# A license from a different CA (chain must fail).
mkdir -p "$work/otherca"
"$root/scripts/make-dev-ca.sh" "$work/otherca" >/dev/null 2>&1
"$root/scripts/make-license.sh" \
	--ca-key "$work/otherca/dev-ca.key" --ca-cert "$work/otherca/dev-ca.pem" \
	--out "$work/othersigned.pem" >/dev/null 2>&1

fail=0
check() {
	if "$work/license_test" "$1" "$2" >/dev/null 2>&1; then
		echo "PASS $1"
	else
		echo "FAIL $1 ($2)"
		fail=1
	fi
}

check ok "$work/valid.pem"
check ok "$work/multi.pem"
check ok "$work/noou.pem"
check ok "$work/noc.pem"
check ok "$work/nosan.pem"
check expired "$work/expired.pem"
check not-yet-valid "$work/future.pem"
check no-clientauth "$work/server.pem"
check no-clientauth "$work/noeku.pem"
check missing-feature "$work/nofeat.pem"
check no-pem "$work/garbage.pem"
check malformed "$work/trunc.pem"
check chain-invalid "$work/othersigned.pem"
check no-file "$work/does-not-exist.pem"

if [ "$fail" -eq 0 ]; then
	echo "all standalone license tests passed"
else
	echo "some standalone license tests FAILED" >&2
	exit 1
fi
