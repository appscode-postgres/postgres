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

# Must satisfy the shipped credential policy: >=11 chars, upper+lower+digit+special.
# initdb sets the superuser password through credcheck, so a weak value here
# would make the container fail to start -- which is itself asserted below.
PGPW='SmokeTest1!aq'

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

cid="$(docker run -d -e POSTGRES_PASSWORD="$PGPW" "$IMAGE")"

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

# --- credential policy (credcheck) --------------------------------------------

[ "$(q "SHOW shared_preload_libraries;")" = "credcheck" ] \
	|| fail "credcheck is not preloaded"
pass "credcheck preloaded"

[ "$(q "SELECT extversion FROM pg_extension WHERE extname='credcheck';")" = "5.0.0" ] \
	|| fail "credcheck extension not installed at 5.0.0"
pass "credcheck extension 5.0.0"

# template1 too, so databases created later inherit it.
[ "$(docker exec "$cid" psql -U postgres -d template1 -tAc \
	"SELECT extversion FROM pg_extension WHERE extname='credcheck';")" = "5.0.0" ] \
	|| fail "credcheck missing from template1"
pass "credcheck present in template1"

# The policy must be live, not merely present on disk.
for kv in \
	"credcheck.password_min_length=11" \
	"credcheck.password_min_upper=1" \
	"credcheck.password_min_lower=1" \
	"credcheck.password_min_digit=1" \
	"credcheck.password_min_special=1" \
	"credcheck.password_valid_until=90" \
	"credcheck.password_valid_max=90" \
	"credcheck.password_change_first_login=on" \
	"credcheck.max_auth_failure=5" \
	"credcheck.password_contain_username=on" \
	"credcheck.password_ignore_case=off" \
	"credcheck.password_reuse_history=5" \
	"credcheck.password_reuse_interval=365" \
	"credcheck.superuser_nocheck=off" \
	"credcheck.reset_superuser=off" \
	"password_encryption=scram-sha-256" \
; do
	name="${kv%%=*}"; want="${kv#*=}"
	got="$(q "SELECT setting FROM pg_settings WHERE name='$name';")"
	[ "$got" = "$want" ] || fail "$name: want '$want', got '$got'"
done
pass "all policy GUCs live with expected values"

# Each rule actually rejects. Without this the GUCs could be set but inert.
try_role() { docker exec "$cid" psql -U postgres -d postgres -tA \
	-c "DROP ROLE IF EXISTS smoke1;" >/dev/null 2>&1
	docker exec "$cid" psql -U postgres -d postgres -tA \
		-c "CREATE ROLE smoke1 PASSWORD '$1';" 2>&1; }

expect_reject() {
	# psql exits non-zero on rejection, which is the expected path here, so the
	# assignment must not trip `set -e`.
	out="$(try_role "$1")" || true
	case "$out" in
		CREATE*) fail "password '$1' was ACCEPTED; expected rejection ($2)" ;;
		*) pass "rejected '$1' ($2)" ;;
	esac
}

expect_reject 'Short1!'           'below min length'
expect_reject 'noupperclass1!'    'no uppercase'
expect_reject 'NOLOWERCLASS1!'    'no lowercase'
expect_reject 'NoDigitClass!x'    'no digit'
expect_reject 'NoSpecialClass1x'  'no special'
expect_reject 'Containssmoke1!x'  'contains role name'

out="$(try_role 'GoodPass1!xyz')" || true
case "$out" in CREATE*) pass "accepted a compliant password" ;;
	*) fail "compliant password rejected: $out" ;; esac

# Expiry must have been auto-applied even though no VALID UNTIL was given.
[ "$(q "SELECT rolvaliduntil IS NOT NULL FROM pg_roles WHERE rolname='smoke1';")" = "t" ] \
	|| fail "expiry was not auto-applied"
pass "expiry auto-applied with no VALID UNTIL"

docker exec "$cid" psql -U postgres -d postgres -tA \
	-c "DROP ROLE IF EXISTS smoke1;" >/dev/null 2>&1

# A POSTGRES_PASSWORD that violates the policy must fail loudly at initdb
# rather than silently starting an unprotected cluster.
weak_cid="$(docker run -d -e POSTGRES_PASSWORD=weak "$IMAGE")"
sleep 12
if docker exec "$weak_cid" pg_isready -q -U postgres 2>/dev/null; then
	docker rm -f "$weak_cid" >/dev/null 2>&1
	fail "a weak POSTGRES_PASSWORD started successfully; policy not applied at initdb"
fi
if ! docker logs "$weak_cid" 2>&1 | grep -qF 'credcheck.password_min_length'; then
	docker rm -f "$weak_cid" >/dev/null 2>&1
	fail "weak POSTGRES_PASSWORD failed, but not with a credcheck message"
fi
docker rm -f "$weak_cid" >/dev/null 2>&1
pass "weak POSTGRES_PASSWORD rejected at initdb with a credcheck error"

echo
echo "PASS: $IMAGE reports '$PRODUCT $VERSION' on every surface"
echo "PASS: credcheck $(q "SELECT extversion FROM pg_extension WHERE extname='credcheck';") policy live and enforcing"
