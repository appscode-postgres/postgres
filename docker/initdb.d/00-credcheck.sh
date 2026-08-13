#!/usr/bin/env bash
#
# Create the credcheck extension so its views and functions
# (pg_banned_role, pg_banned_role_reset(), pg_password_history) are reachable.
#
# The password RULES do not need this -- they are enforced by the preloaded
# shared library regardless. Only the introspection/administration surface
# needs the SQL objects, which is why a failure here must not be silent.
#
# Runs first (00-) so that anything a downstream image drops into
# /docker-entrypoint-initdb.d can already rely on credcheck being present.
#
# Only executes on first initialisation of an empty data directory, which is
# the same contract as every other script in this directory.

set -euo pipefail

# template1 as well as the application database, so databases created later
# inherit the extension.
for db in template1 postgres "${POSTGRES_DB:-}"; do
	[ -n "$db" ] || continue
	# postgres and POSTGRES_DB are frequently the same; CREATE EXTENSION IF NOT
	# EXISTS makes the repeat harmless.
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" \
		-c 'CREATE EXTENSION IF NOT EXISTS credcheck;'
	echo "credcheck: extension present in database '$db'"
done
