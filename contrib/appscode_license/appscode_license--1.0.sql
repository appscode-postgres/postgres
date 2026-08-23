/* contrib/appscode_license/appscode_license--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION appscode_license" to load this file. \quit

CREATE FUNCTION appscode_license_info(
	OUT license_id text,		-- serial, the license ID
	OUT cn text,				-- CN, a separate human-facing identifier
	OUT features text[],		-- O list
	OUT plan text,				-- OU
	OUT product_line text,		-- C
	OUT tier text,				-- ST
	OUT not_before text,
	OUT not_after text,
	OUT days_remaining bigint,
	OUT leaf_sha256 text,
	OUT status text				-- verification status tag as of this call
)
RETURNS record
AS 'MODULE_PATHNAME', 'appscode_license_info'
LANGUAGE C VOLATILE;

-- License details are not secret (they match the startup log line), but the
-- function re-reads the license file on each call, so restrict it to roles
-- that can already inspect server state.
REVOKE ALL ON FUNCTION appscode_license_info() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appscode_license_info() TO pg_monitor;
