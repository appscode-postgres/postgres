#!/usr/bin/env bash
#
# CI smoke test: run the image and assert that every version surface reports
# the custom product name AND that the numeric version is still exactly 18.6.
#
# Usage: docker/smoke-test.sh [IMAGE]

set -euo pipefail

IMAGE="${1:-ghcr.io/kubedb/postgres:18.6}"

PRODUCT='Postgres Enterprise by AppsCode'
VERSION='18.6'
VERSION_NUM='180006'

cid=""
cleanup() { [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

# --- checks that need no running server -------------------------------------

got="$(docker run --rm --entrypoint postgres "$IMAGE" --version)"
[ "$got" = "postgres ($PRODUCT) $VERSION" ] \
	|| fail "postgres --version: got '$got'"
pass "postgres --version"

got="$(docker run --rm --entrypoint pg_config "$IMAGE" --version)"
[ "$got" = "$PRODUCT $VERSION" ] || fail "pg_config --version: got '$got'"
pass "pg_config --version"

got="$(docker run --rm --entrypoint psql "$IMAGE" --version)"
[ "$got" = "psql ($PRODUCT) $VERSION" ] || fail "psql --version: got '$got'"
pass "psql --version"

# No binary should still be reporting stock branding.
if docker run --rm --entrypoint sh "$IMAGE" -c \
	'for f in /usr/local/bin/*; do [ -x "$f" ] && "$f" --version 2>/dev/null; done' \
	| grep -F '(PostgreSQL)'; then
	fail "some binaries still report the stock product name"
fi
pass "no binary reports stock branding"

# --- checks that need a running server ---------------------------------------

cid="$(docker run -d -e POSTGRES_PASSWORD=smoketest "$IMAGE")"

for _ in $(seq 60); do
	if docker exec "$cid" pg_isready -q -U postgres 2>/dev/null; then break; fi
	sleep 1
done
docker exec "$cid" pg_isready -U postgres >/dev/null || fail "server never became ready"

q() { docker exec "$cid" psql -U postgres -d postgres -tAc "$1"; }

got="$(q 'SELECT version();')"
case "$got" in
	"$PRODUCT $VERSION on "*) pass "SELECT version()" ;;
	*) fail "SELECT version(): got '$got'" ;;
esac

# The numeric version must be untouched, so anything parsing \d+\.\d+ out of
# version() keeps working.
got="$(q "SELECT substring(version() from '[0-9]+\.[0-9]+');")"
[ "$got" = "$VERSION" ] || fail "numeric version parsed from version(): got '$got'"
pass "numeric version parses out of version()"

got="$(q 'SHOW server_version;')"
[ "$got" = "$VERSION" ] || fail "server_version: got '$got'"
pass "server_version = $VERSION"

got="$(q 'SHOW server_version_num;')"
[ "$got" = "$VERSION_NUM" ] || fail "server_version_num: got '$got'"
pass "server_version_num = $VERSION_NUM"

if ! docker logs "$cid" 2>&1 | grep -qF "starting $PRODUCT $VERSION on "; then
	fail "startup log line does not carry the custom product name"
fi
pass "startup log line"

echo
echo "PASS: $IMAGE reports '$PRODUCT $VERSION' on every surface"
