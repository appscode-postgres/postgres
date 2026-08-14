/*-------------------------------------------------------------------------
 *
 * license_worker.h
 *	  Entry point for the license re-check background worker.
 *
 * Kept separate from license.h because the worker entry point takes a Datum,
 * and license.h is deliberately free of PostgreSQL types so it can be included
 * by the standalone verification test harness.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/include/license/license_worker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef LICENSE_WORKER_H
#define LICENSE_WORKER_H

/*
 * Named in the InternalBGWorkers table in bgworker.c, so the postmaster can
 * resolve it by name across a fork or exec.
 */
pg_noreturn extern PGDLLEXPORT void LicenseWorkerMain(Datum main_arg);

#endif							/* LICENSE_WORKER_H */
