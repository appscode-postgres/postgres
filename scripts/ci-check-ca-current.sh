#!/usr/bin/env bash
#
# CI job: alert when the published AppsCode CA differs from the committed copy.
#
# This job REPORTS. It deliberately does not feed the build. The committed PEM
# at src/backend/license/appscode_root_ca.pem stays the source of truth, because
# a build that fetches its own trust anchor can be redirected by anyone who
# controls DNS, a proxy, or the build container.
#
# The point is to notice a CA rotation before customers hit it, since a build
# embedding only the old root will reject every license signed by the new one.
#
# Usage:
#   scripts/ci-check-ca-current.sh
#
# Exit codes:
#   0  published CA matches the committed copy
#   1  they differ, a rotation has probably happened, act on it
#   2  could not check, for example the network is unavailable
#
# Exit 2 is deliberately distinct from exit 1 so a CI outage is not mistaken
# for a CA rotation.

set -uo pipefail

URL="${APPSCODE_CA_URL:-https://licenses.appscode.com/certificates/ca.crt}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMITTED="$here/src/backend/license/appscode_root_ca.pem"

if [ ! -f "$COMMITTED" ]; then
	echo "could not find the committed CA at $COMMITTED" >&2
	exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if ! curl -sS --fail --max-time 60 -o "$tmp" "$URL"; then
	echo "could not fetch $URL, skipping the comparison" >&2
	exit 2
fi

if [ ! -s "$tmp" ]; then
	echo "fetched an empty document from $URL" >&2
	exit 2
fi

# Compare the DER bytes rather than the PEM text, so a difference in line
# wrapping or trailing whitespace is not reported as a rotation.
committed_der="$(openssl x509 -in "$COMMITTED" -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1)"
published_der="$(openssl x509 -in "$tmp" -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1)"

if [ -z "$published_der" ]; then
	echo "the document at $URL is not a certificate" >&2
	exit 2
fi

if [ "$committed_der" = "$published_der" ]; then
	echo "ok   published CA matches the committed copy"
	echo "     sha256 $committed_der"
	exit 0
fi

echo "ALERT: the published AppsCode CA differs from the committed copy" >&2
echo >&2
echo "  committed $committed_der" >&2
echo "  published $published_der" >&2
echo >&2
echo "committed:" >&2
openssl x509 -in "$COMMITTED" -noout -subject -issuer -dates -fingerprint -sha256 >&2
echo >&2
echo "published:" >&2
openssl x509 -in "$tmp" -noout -subject -issuer -dates -fingerprint -sha256 >&2
echo >&2
cat >&2 <<'NOTE'
If this is a genuine rotation, do NOT simply replace the committed PEM. A build
embedding only the new root rejects every license signed by the old one, and a
build embedding only the old root rejects every license signed by the new one.

Follow the rotation plan in doc/LICENSE_ENFORCEMENT.md section 2.3: ship a build
embedding BOTH roots for at least one full license term, then drop the outgoing
one. Remember that the pinned public key digest in
src/backend/license/ca_pin.c is hand maintained and must be updated in the same
commit, or the new anchor is rejected at startup.
NOTE

exit 1
