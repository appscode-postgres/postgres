/*-------------------------------------------------------------------------
 *
 * appscode_license.c
 *	  SQL-callable reporting for AppsCode license enforcement.
 *
 * Exposes appscode_license_info(), a read-only function returning the
 * license the local postmaster already verified, read from a shared-memory
 * snapshot. This extension is pure reporting: it never re-parses or
 * re-verifies the license file, has no path into the enforcement routine in
 * src/backend/license/, and cannot affect whether the server starts or
 * stays up. Its presence or absence changes nothing about enforcement,
 * which runs unconditionally in the postmaster.
 *
 * The snapshot deliberately carries no SAN email and no DNS/cluster value;
 * licenses in this system are not cluster-bound.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_type.h"
#include "funcapi.h"
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
	AppsCodeLicenseReport rep;
	bool		have;
	ArrayType  *feat_arr;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context that cannot accept type record")));
	tupdesc = BlessTupleDesc(tupdesc);

	/* Read the cached snapshot only. No re-parse, no re-verify. */
	have = AppsCodeLicenseReadShared(&rep);

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));

	if (!have)
	{
		/*
		 * Nothing has been published yet (should not happen on a running
		 * server). Report verifies = false and leave the rest NULL.
		 */
		int			i;

		for (i = 0; i < LICENSE_INFO_NCOLS; i++)
			nulls[i] = true;
		values[9] = BoolGetDatum(false);
		nulls[9] = false;

		tuple = heap_form_tuple(tupdesc, values, nulls);
		PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
	}

	/* Split the comma-joined feature list into a text[]. */
	{
		int			nfeat = 0;
		Datum		elems[APPSCODE_LICENSE_MAX_FEATURES];
		char	   *buf = pstrdup(rep.features);
		char	   *tok;
		char	   *save = NULL;

		for (tok = strtok_r(buf, ",", &save);
			 tok != NULL && nfeat < APPSCODE_LICENSE_MAX_FEATURES;
			 tok = strtok_r(NULL, ",", &save))
			elems[nfeat++] = CStringGetTextDatum(tok);

		feat_arr = construct_array(elems, nfeat, TEXTOID, -1, false,
								   TYPALIGN_INT);
	}

	values[0] = CStringGetTextDatum(rep.serial_dec); /* license ID (serial) */
	values[1] = CStringGetTextDatum(rep.cn);		 /* CN, distinct id */
	values[2] = CStringGetTextDatum(rep.product_line);	/* C */
	values[3] = CStringGetTextDatum(rep.tier);		 /* ST */
	values[4] = CStringGetTextDatum(rep.plan);		 /* OU */
	values[5] = PointerGetDatum(feat_arr);			 /* O */
	values[6] = CStringGetTextDatum(rep.not_before);
	values[7] = CStringGetTextDatum(rep.not_after);
	values[8] = Int64GetDatum(rep.days_remaining);
	values[9] = BoolGetDatum(rep.verifies);
	values[10] = CStringGetTextDatum(rep.leaf_sha256);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}
