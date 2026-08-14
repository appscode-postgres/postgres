#!/usr/bin/env bash
#
# CI gate: a release binary must embed the production AppsCode CA and must not
# be a development CA build.
#
# Inspecting the shipped artifact rather than trusting the build recipe is the
# point. A build that was configured wrongly, or a stale object file left in a
# reused build tree, produces exactly the artifact this catches.
#
# Usage:
#   scripts/ci-check-release-binary.sh /path/to/postgres
#
# Exits non-zero, loudly, on any problem.

set -euo pipefail

BIN="${1:-}"

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
	echo "usage: $0 /path/to/postgres" >&2
	exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA="$here/src/backend/license/appscode_root_ca.pem"

if [ ! -f "$CA" ]; then
	echo "FAIL: cannot find the committed CA at $CA" >&2
	exit 2
fi

fail=0

# 1. The development CA marker must be absent.
#
# The marker exists only when LICENSE_DEV_CA is defined. Searching for a dev CA
# fingerprint would not work, because each developer generates their own.
#
# Note the deliberate use of "grep -c" rather than "grep -q" here. With
# "set -o pipefail", a "grep -q" that matches exits early, strings dies with
# SIGPIPE, and the pipeline reports failure, which inverts the result and makes
# this check silently pass on exactly the artifact it exists to reject. Counting
# consumes all input, so no signal is raised.
marker_hits="$(strings -a "$BIN" | grep -c 'APPSCODE-LICENSE-DEV-CA-BUILD-DO-NOT-SHIP' || true)"

if [ "${marker_hits:-0}" -gt 0 ]; then
	echo "FAIL: $BIN is a development CA build and must not be shipped" >&2
	fail=1
else
	echo "ok   no development CA marker"
fi

# 2. The production CA DER bytes must be present.
#
# This is the positive half: it is not enough that the dev marker is absent, the
# real anchor has to actually be in there.
der="$(mktemp)"
trap 'rm -f "$der"' EXIT
openssl x509 -in "$CA" -outform DER -out "$der"

# An exact byte search. grep is not used: the DER contains NUL bytes and is not
# line oriented, so grep's behaviour varies with locale and implementation.
if python3 -c '
import sys
binary = open(sys.argv[1], "rb").read()
needle = open(sys.argv[2], "rb").read()
sys.exit(0 if needle in binary else 1)
' "$BIN" "$der"; then
	echo "ok   production CA is embedded"
else
	echo "FAIL: the production CA DER bytes are not present in $BIN" >&2
	fail=1
fi

# 3. The pinned public key digest must match the committed CA.
#
# Catches a PEM that was replaced without updating the hand maintained pin in
# ca_pin.c, which would otherwise only surface at server startup.
spki="$(openssl x509 -in "$CA" -noout -pubkey \
	| openssl pkey -pubin -outform DER 2>/dev/null \
	| openssl dgst -sha256 -r | cut -d' ' -f1)"

if python3 -c '
import re, sys
src = open(sys.argv[1]).read()
want = sys.argv[2]
# The pin is a C byte array, so extract the bytes and compare those.
body = re.search(r"appscode_ca_spki_pins\[\]\[32\]\s*=\s*\{(.*?)\n\};", src, re.S)
if not body:
    sys.exit(1)
got = "".join(re.findall(r"0x([0-9a-fA-F]{2})", body.group(1))).lower()
sys.exit(0 if want in got else 1)
' "$here/src/backend/license/ca_pin.c" "$spki"; then
	echo "ok   pinned public key digest matches the committed CA"
else
	echo "FAIL: ca_pin.c does not carry the digest of $CA" >&2
	echo "      expected $spki" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo
	echo "This artifact must not be released." >&2
	exit 1
fi

echo
echo "PASS: $BIN is a release build embedding the production AppsCode CA"
