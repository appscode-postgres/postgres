/*-------------------------------------------------------------------------
 *
 * license_test.c
 *	  Standalone unit test harness for the license verification core.
 *
 * This links license_core.c and the generated trust anchor header directly,
 * with no PostgreSQL runtime, so the verification algorithm can be exercised
 * and run under valgrind or ASan long before a server is involved.
 *
 * Usage:
 *	  license_test <expected-status> <license.pem> [cluster-id] [major] [now]
 *
 *	  expected-status  a name from license_status_name(), or "any"
 *	  cluster-id       runtime cluster identity, or "-" for none
 *	  major            server major version, default 18
 *	  now              unix timestamp to evaluate against, default current time
 *
 * Exits 0 if the observed status matches the expectation.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/backend/license/test/license_test.c
 *
 *-------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "license.h"

int
main(int argc, char **argv)
{
	LicenseInfo info;
	char		errbuf[512];
	const char *expected;
	const char *path;
	const char *cluster = NULL;
	int			major = 18;
	time_t		now = time(NULL);
	LicenseStatus status;

	if (argc < 3)
	{
		fprintf(stderr,
				"usage: %s <expected-status> <license.pem> [cluster-id] [major] [now]\n",
				argv[0]);
		return 2;
	}

	expected = argv[1];
	path = argv[2];

	if (argc > 3 && strcmp(argv[3], "-") != 0)
		cluster = argv[3];
	if (argc > 4)
		major = atoi(argv[4]);
	if (argc > 5)
		now = (time_t) strtoll(argv[5], NULL, 10);

	status = license_verify_file(path, cluster, major, now, &info,
								 errbuf, sizeof(errbuf));

	printf("status      : %s\n", license_status_name(status));
	if (errbuf[0] != '\0')
		printf("detail      : %s\n", errbuf);
	if (info.uuid[0] != '\0')
		printf("uuid        : %s\n", info.uuid);
	if (info.serial_hex[0] != '\0')
		printf("serial      : %s\n", info.serial_hex);
	if (info.licensee[0] != '\0')
		printf("licensee    : %s\n", info.licensee);
	if (info.product[0] != '\0')
		printf("product     : %s\n", info.product);
	if (info.version_constraint[0] != '\0')
		printf("constraint  : %s\n", info.version_constraint);
	if (info.cluster_id[0] != '\0')
		printf("cluster     : %s%s\n", info.cluster_id,
			   info.cluster_unbound ? " (unbound)" : "");
	if (status == LICENSE_OK)
		printf("days left   : %d\n", info.days_remaining);
	if (info.leaf_fingerprint[0] != '\0')
		printf("leaf sha256 : %s\n", info.leaf_fingerprint);

	if (strcmp(expected, "any") == 0)
		return 0;

	if (strcmp(expected, license_status_name(status)) != 0)
	{
		fprintf(stderr, "FAIL: expected status '%s', got '%s'\n",
				expected, license_status_name(status));
		return 1;
	}
	return 0;
}
