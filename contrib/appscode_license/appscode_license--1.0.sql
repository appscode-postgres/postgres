/* contrib/appscode_license/appscode_license--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION appscode_license" to load this file. \quit

CREATE FUNCTION appscode_license_info(
    OUT uuid                text,
    OUT licensee            text,
    OUT org                 text,
    OUT product             text,
    OUT version_constraint  text,
    OUT cluster_id          text,
    OUT cluster_unbound     boolean,
    OUT not_before          timestamptz,
    OUT not_after           timestamptz,
    OUT days_remaining      integer,
    OUT leaf_fingerprint    text
)
RETURNS record
AS 'MODULE_PATHNAME', 'appscode_license_info'
LANGUAGE C VOLATILE PARALLEL RESTRICTED;

COMMENT ON FUNCTION appscode_license_info() IS
'report the license this server is running under';

-- Readable by anyone. The license contains no secret and no personal data, and
-- being able to read it changes nothing about enforcement.
REVOKE ALL ON FUNCTION appscode_license_info() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appscode_license_info() TO PUBLIC;
