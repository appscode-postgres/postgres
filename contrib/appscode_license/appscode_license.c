/*-------------------------------------------------------------------------
 *
 * appscode_license.c
 *	  SQL-callable reporting for AppsCode license enforcement.
 *
 * Exposes appscode_license_info(), a read-only function returning the
 * current license as the running server sees it, so support can query a
 * cluster instead of asking for the license file. The fields mirror the
 * startup log line exactly. The SAN email is never exposed, matching the
 * verifier core.
 *
 * Enforcement itself lives in the server binary (src/backend/license/); this
 * extension is only a reporting convenience and does not gate anything.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_type.h"
#include "funcapi.h"
#include "license/license.h"
#include "license/license_check.h"
#include "utils/array.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(appscode_license_info);

#define LICENSE_INFO_NCOLS 11

Datum
appscode_license_info(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[LICENSE_INFO_NCOLS];
	bool		nulls[LICENSE_INFO_NCOLS];
	HeapTuple	tuple;
	LicenseInfo info;
	LicenseStatus st;
	ArrayType  *feat_arr;
	Datum	   *feat_elems;
	int			i;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context that cannot accept type record")));
	tupdesc = BlessTupleDesc(tupdesc);

	/* Re-verify so the report reflects the live license file. */
	st = AppsCodeLicenseRecheck(&info);

	memset(nulls, 0, sizeof(nulls));

	values[0] = CStringGetTextDatum(info.serial_dec);
	values[1] = CStringGetTextDatum(info.cn);

	feat_elems = (Datum *) palloc(sizeof(Datum) * Max(info.num_features, 1));
	for (i = 0; i < info.num_features; i++)
		feat_elems[i] = CStringGetTextDatum(info.features[i]);
	feat_arr = construct_array(feat_elems, info.num_features,
							   TEXTOID, -1, false, TYPALIGN_INT);
	values[2] = PointerGetDatum(feat_arr);

	values[3] = CStringGetTextDatum(info.plan);
	values[4] = CStringGetTextDatum(info.product_line);
	values[5] = CStringGetTextDatum(info.tier);
	values[6] = CStringGetTextDatum(info.not_before);
	values[7] = CStringGetTextDatum(info.not_after);
	values[8] = Int64GetDatum((int64) info.days_remaining);
	values[9] = CStringGetTextDatum(info.leaf_sha256);
	values[10] = CStringGetTextDatum(appscode_license_status_tag(st));

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}
