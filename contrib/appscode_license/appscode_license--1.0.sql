/* contrib/appscode_license/appscode_license--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION appscode_license" to load this file. \quit

-- Read-only reporting of the license the local postmaster already verified.
-- The values come from a shared-memory snapshot; this function never reads
-- or re-verifies the license file, and cannot affect enforcement.
CREATE FUNCTION appscode_license_info(
	OUT license_id text,		-- serial number, the license ID
	OUT cn text,				-- UUID-shaped id from issuance; not the serial
	OUT product_line text,		-- C; informational
	OUT tier text,				-- ST; informational
	OUT plan text,				-- OU; informational
	OUT features text[],		-- O; includes postgres-enterprise
	OUT not_before text,
	OUT not_after text,
	OUT days_remaining bigint,
	OUT verifies boolean,		-- last verification result (true on a
								-- running server)
	OUT leaf_sha256 text		-- SHA-256 of the leaf certificate
)
RETURNS record
AS 'MODULE_PATHNAME', 'appscode_license_info'
LANGUAGE C VOLATILE;

-- The values are not secret (they match the startup log line), but restrict
-- execution to roles that can already inspect server state.
REVOKE ALL ON FUNCTION appscode_license_info() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appscode_license_info() TO pg_monitor;
