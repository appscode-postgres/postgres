/*-------------------------------------------------------------------------
 *
 * appscode_license.c
 *	  Read only reporting of the license this server is running under.
 *
 * This extension exists so a support engineer can ask for one query instead of
 * a file. It is strictly a reporting shim: it cannot influence whether the
 * server starts, and removing it does not disable enforcement, which lives in
 * the postmaster. See doc/LICENSE_ENFORCEMENT.md section 12.
 *
 * The license is re-verified on each call rather than read from a cached copy.
 * That keeps the extension free of shared memory, so enforcement needs no
 * additional hooks in the core startup path, and it means the reported values
 * reflect the license file as it is now rather than as it was at startup,
 * which is the more useful answer after a renewal.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * contrib/appscode_license/appscode_license.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <time.h>

#include "fmgr.h"
#include "funcapi.h"
#include "license/license.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(appscode_license_info);

/* Column order must match appscode_license--1.0.sql. */
#define ALI_UUID				0
#define ALI_LICENSEE			1
#define ALI_ORG					2
#define ALI_PRODUCT				3
#define ALI_VERSION_CONSTRAINT	4
#define ALI_CLUSTER_ID			5
#define ALI_CLUSTER_UNBOUND		6
#define ALI_NOT_BEFORE			7
#define ALI_NOT_AFTER			8
#define ALI_DAYS_REMAINING		9
#define ALI_LEAF_FINGERPRINT	10
#define ALI_NCOLS				11

Datum
appscode_license_info(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[ALI_NCOLS];
	bool		nulls[ALI_NCOLS];
	LicenseInfo info;
	char		errbuf[512];
	LicenseStatus status;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	status = LicenseVerifyNow(&info, errbuf, sizeof(errbuf));

	/*
	 * Report a currently invalid license as an error rather than as a row of
	 * nulls. If this fails, the background worker is about to shut the cluster
	 * down anyway, and the reason is the useful part.
	 */
	if (status != LICENSE_OK)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("license is not currently valid: %s", errbuf),
				 errdetail("Check \"%s\".", license_status_name(status))));

	memset(nulls, 0, sizeof(nulls));

	values[ALI_UUID] = CStringGetTextDatum(info.uuid);
	values[ALI_LICENSEE] = CStringGetTextDatum(info.licensee);
	values[ALI_ORG] = CStringGetTextDatum(info.org);
	values[ALI_PRODUCT] = CStringGetTextDatum(info.product);
	values[ALI_VERSION_CONSTRAINT] =
		CStringGetTextDatum(info.version_constraint);
	values[ALI_CLUSTER_ID] = CStringGetTextDatum(info.cluster_id);
	values[ALI_CLUSTER_UNBOUND] = BoolGetDatum(info.cluster_unbound);
	values[ALI_NOT_BEFORE] =
		TimestampTzGetDatum(time_t_to_timestamptz(info.not_before));
	values[ALI_NOT_AFTER] =
		TimestampTzGetDatum(time_t_to_timestamptz(info.not_after));
	values[ALI_DAYS_REMAINING] = Int32GetDatum(info.days_remaining);
	values[ALI_LEAF_FINGERPRINT] = CStringGetTextDatum(info.leaf_fingerprint);

	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}
