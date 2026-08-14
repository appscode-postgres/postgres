/*-------------------------------------------------------------------------
 *
 * license.c
 *	  Server side glue for offline license verification.
 *
 * The verification algorithm itself lives in license_core.c, which is free of
 * PostgreSQL headers so it can be unit tested outside the server. This file
 * supplies the parts that need the server: resolving the license path and the
 * cluster identity, maintaining the clock rollback state file, and reporting
 * through ereport().
 *
 * The entry point runs early in PostmasterMain(), after GUC processing and
 * after the data directory is known, but before any listen socket is created,
 * before any child is forked, and before process_shared_preload_libraries(),
 * so a preloaded library cannot interfere with the outcome.
 *
 * See doc/LICENSE_ENFORCEMENT.md for the certificate profile, the verification
 * algorithm, and an honest statement of what this does and does not defend
 * against.
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/backend/license/license.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/hmac.h>

#include "access/xlog.h"
#include "license/license.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/guc.h"

/* Default when neither PGLICENSE nor a data directory relative file is used. */
#define LICENSE_DEFAULT_BASENAME	"license.pem"
#define LICENSE_STATE_BASENAME		".pg_license_state"

/*
 * Tolerance for a backward clock movement before it is treated as a rollback.
 * Small corrections, NTP steps, and timezone confusion should not take a
 * cluster down; a deliberate jump backward should.
 */
#define LICENSE_CLOCK_TOLERANCE_SECS	(24 * 60 * 60)

/* Warn daily once inside this window before expiry. */
#define LICENSE_EXPIRY_WARN_DAYS		30

/*
 * Resolve the license file path.
 *
 * The path is configurable. Whether verification runs is not: there is no
 * setting, environment variable, or build flag that disables it.
 */
void
LicenseResolvePath(char *buf, size_t buflen)
{
	const char *env = getenv("PGLICENSE");

	if (env != NULL && env[0] != '\0')
	{
		snprintf(buf, buflen, "%s", env);
		return;
	}

	if (DataDir != NULL && DataDir[0] != '\0')
	{
		snprintf(buf, buflen, "%s/%s", DataDir, LICENSE_DEFAULT_BASENAME);
		return;
	}

	snprintf(buf, buflen, "%s", LICENSE_DEFAULT_BASENAME);
}

/*
 * Resolve this cluster's identity, used for the license cluster binding.
 *
 * Order: PG_CLUSTER_ID, then a cluster_id file in the data directory, then a
 * Kubernetes namespace UID if one has been injected into the environment.
 *
 * Returns false if no identity could be resolved. A license that names a
 * specific cluster then fails closed, rather than an absent identity being
 * treated as a match.
 */
bool
LicenseResolveCluster(char *buf, size_t buflen)
{
	const char *env;
	char		path[MAXPGPATH];
	FILE	   *fp;

	env = getenv("PG_CLUSTER_ID");
	if (env != NULL && env[0] != '\0')
	{
		snprintf(buf, buflen, "%s", env);
		return true;
	}

	if (DataDir != NULL && DataDir[0] != '\0')
	{
		snprintf(path, sizeof(path), "%s/cluster_id", DataDir);
		fp = AllocateFile(path, "r");
		if (fp != NULL)
		{
			char	   *nl;

			if (fgets(buf, (int) buflen, fp) != NULL)
			{
				FreeFile(fp);
				nl = strchr(buf, '\n');
				if (nl != NULL)
					*nl = '\0';
				if (buf[0] != '\0')
					return true;
				return false;
			}
			FreeFile(fp);
		}
	}

	env = getenv("POD_NAMESPACE_UID");
	if (env != NULL && env[0] != '\0')
	{
		snprintf(buf, buflen, "%s", env);
		return true;
	}

	buf[0] = '\0';
	return false;
}

/*
 * HMAC over the canonical state file serialization.
 *
 * The key derives from the embedded CA public key digest alone. It
 * deliberately does NOT include the license serial: a renewal issues a new
 * serial, and since an HMAC mismatch is fail closed, mixing the serial in
 * would refuse to start the cluster after every legitimate renewal.
 *
 * Honest limitation, also stated in the design document: the key derives from
 * values present in the binary, so anyone holding the binary can recompute
 * this. It stops casual editing of the recorded timestamp. It does not stop an
 * attacker who is already out of scope.
 */
static void
state_hmac(const char *payload, char *hex, size_t hexlen)
{
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;
	unsigned int i;

	HMAC(EVP_sha256(),
		 appscode_ca_spki_pins[0], 32,
		 (const unsigned char *) payload, strlen(payload),
		 mac, &maclen);

	for (i = 0; i < maclen && (i * 2 + 2) < hexlen; i++)
		sprintf(hex + i * 2, "%02x", mac[i]);
	hex[maclen * 2] = '\0';
}

/*
 * Build the canonical serialization the HMAC covers: every field except the
 * HMAC itself, in a fixed order. Fixing the order here rather than sorting at
 * read time keeps writer and reader trivially in agreement.
 */
static void
state_payload(char *buf, size_t buflen, const char *uuid,
			  uint64 installation, int64 high_water)
{
	snprintf(buf, buflen,
			 "version=1\n"
			 "uuid=%s\n"
			 "installation=" UINT64_FORMAT "\n"
			 "high_water_mark=" INT64_FORMAT,
			 uuid, installation, high_water);
}

typedef struct LicenseState
{
	char		uuid[LICENSE_UUID_LEN];
	uint64		installation;
	int64		high_water;
	bool		present;
} LicenseState;

/* Read and authenticate the state file. Returns false if it is absent. */
static bool
read_state(const char *path, LicenseState *st, bool *corrupt)
{
	FILE	   *fp;
	char		line[512];
	char		payload[1024];
	char		want[EVP_MAX_MD_SIZE * 2 + 1];
	char		got[EVP_MAX_MD_SIZE * 2 + 1];

	*corrupt = false;
	memset(st, 0, sizeof(*st));
	got[0] = '\0';

	fp = AllocateFile(path, "r");
	if (fp == NULL)
		return false;

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char	   *nl = strchr(line, '\n');

		if (nl != NULL)
			*nl = '\0';
		if (line[0] == '#' || line[0] == '\0')
			continue;

		if (strncmp(line, "uuid=", 5) == 0)
			snprintf(st->uuid, sizeof(st->uuid), "%s", line + 5);
		else if (strncmp(line, "installation=", 13) == 0)
			(void) sscanf(line + 13, UINT64_FORMAT, &st->installation);
		else if (strncmp(line, "high_water_mark=", 16) == 0)
			(void) sscanf(line + 16, INT64_FORMAT, &st->high_water);
		else if (strncmp(line, "hmac=sha256:", 12) == 0)
			snprintf(got, sizeof(got), "%s", line + 12);
	}
	FreeFile(fp);

	state_payload(payload, sizeof(payload), st->uuid, st->installation,
				  st->high_water);
	state_hmac(payload, want, sizeof(want));

	if (got[0] == '\0' || strcmp(got, want) != 0)
	{
		*corrupt = true;
		return true;
	}

	st->present = true;
	return true;
}

/*
 * Write the state file atomically: temporary file in the same directory,
 * fsync, rename, fsync the directory. A crash mid write therefore cannot leave
 * a torn file that would fail the integrity check and refuse to start.
 */
static void
write_state(const char *path, const char *uuid, uint64 installation,
			int64 high_water)
{
	char		tmp[MAXPGPATH];
	char		payload[1024];
	char		mac[EVP_MAX_MD_SIZE * 2 + 1];
	FILE	   *fp;
	int			fd;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	state_payload(payload, sizeof(payload), uuid, installation, high_water);
	state_hmac(payload, mac, sizeof(mac));

	fp = AllocateFile(tmp, "w");
	if (fp == NULL)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not write license state file \"%s\": %m", tmp)));
		return;
	}

	fprintf(fp, "# PostgreSQL license state. Do not edit.\n");
	fprintf(fp, "%s\n", payload);
	fprintf(fp, "hmac=sha256:%s\n", mac);

	if (fflush(fp) != 0 || FreeFile(fp) != 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not flush license state file \"%s\": %m", tmp)));
		return;
	}

	if (chmod(tmp, S_IRUSR | S_IWUSR) != 0)
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not set permissions on \"%s\": %m", tmp)));

	fd = BasicOpenFile(tmp, O_RDWR | PG_BINARY);
	if (fd >= 0)
	{
		(void) pg_fsync(fd);
		close(fd);
	}

	if (rename(tmp, path) != 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not rename \"%s\" to \"%s\": %m", tmp, path)));
		(void) unlink(tmp);
		return;
	}

	fsync_fname(DataDir, true);
}

/*
 * Permission policy for the license file itself.
 *
 * The license carries no secret and no personal data, and in Kubernetes it
 * normally arrives as a read only Secret mount at 0444 or 0644 that the
 * operator cannot chmod. Restrictive read modes are therefore not required.
 * A group or world writable file is an integrity concern worth a warning,
 * since another local user could swap it, though only for another genuinely
 * signed license.
 */
static void
warn_on_license_permissions(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return;
	if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		ereport(WARNING,
				(errmsg("license file \"%s\" is writable by group or world",
						path),
				 errdetail("Another local user could replace the license file."),
				 errhint("Restrict it with \"chmod go-w %s\".", path)));
}

/*
 * Map a verification status onto the documented operator message.
 *
 * Every string is distinct so support can diagnose from a log line alone. The
 * license UUID is included whenever one could be parsed, so it is present in
 * any log bundle a customer sends.
 */
static void
license_report_failure(const LicenseInfo *info, const char *path,
					   const char *detail)
{
	int			elevel = FATAL;

	ereport(elevel,
			(errcode(ERRCODE_CONFIG_FILE_ERROR),
			 errmsg("license verification failed: %s", detail),
			 info->uuid[0] != '\0'
			 ? errdetail("License UUID %s, file \"%s\", check \"%s\".",
						 info->uuid, path, license_status_name(info->status))
			 : errdetail("License file \"%s\", check \"%s\".",
						 path, license_status_name(info->status)),
			 errhint("See doc/LICENSE_ENFORCEMENT.md for this error and its remedy.")));
}

/*
 * Verify the license, or terminate the process.
 *
 * The populated struct is returned to the caller rather than reduced to a
 * boolean, and callers consume several of its fields, so disabling enforcement
 * is not a matter of flipping one branch.
 */
void
LicenseVerifyAtStartup(LicenseInfo *out, const char *context)
{
	char		path[MAXPGPATH];
	char		statepath[MAXPGPATH];
	char		cluster[LICENSE_NAME_LEN];
	char		errbuf[512];
	bool		have_cluster;
	time_t		now = time(NULL);
	LicenseState st;
	bool		corrupt = false;
	uint64		installation;
	LicenseStatus status;

	LicenseResolvePath(path, sizeof(path));
	have_cluster = LicenseResolveCluster(cluster, sizeof(cluster));

	warn_on_license_permissions(path);

	status = license_verify_file(path,
								 have_cluster ? cluster : NULL,
								 PG_VERSION_NUM / 10000,
								 now,
								 out,
								 errbuf, sizeof(errbuf));

	if (status != LICENSE_OK)
		license_report_failure(out, path, errbuf);

	/*
	 * Clock rollback check. The installation fingerprint is the pg_control
	 * system identifier alone; see doc/LICENSE_ENFORCEMENT.md section 9 for
	 * why neither the cluster ID nor the data directory inode belongs here.
	 */
	installation = GetSystemIdentifier();
	snprintf(statepath, sizeof(statepath), "%s/%s", DataDir,
			 LICENSE_STATE_BASENAME);

	if (read_state(statepath, &st, &corrupt))
	{
		if (corrupt)
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("license state file failed its integrity check"),
					 errdetail("License UUID %s, file \"%s\".",
							   out->uuid, statepath),
					 errhint("Contact support before removing this file.")));

		if ((int64) now < st.high_water - LICENSE_CLOCK_TOLERANCE_SECS)
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("system clock appears to have moved backward"),
					 errdetail("License UUID %s. The clock is %ld seconds behind the highest value previously recorded.",
							   out->uuid,
							   (long) (st.high_water - (int64) now)),
					 errhint("Correct the system clock before starting the server.")));

		if (st.uuid[0] != '\0' && strcmp(st.uuid, out->uuid) != 0)
			ereport(LOG,
					(errmsg("license UUID changed from %s to %s",
							st.uuid, out->uuid),
					 errdetail("This is expected after a renewal.")));

		if (st.installation != 0 && st.installation != installation)
			ereport(LOG,
					(errmsg("license %s is now running on a different installation",
							out->uuid),
					 errdetail("Recorded installation " UINT64_FORMAT ", this installation " UINT64_FORMAT ".",
							   st.installation, installation)));
	}

	if (st.high_water > (int64) now)
		write_state(statepath, out->uuid, installation, st.high_water);
	else
		write_state(statepath, out->uuid, installation, (int64) now);

	/* Success: one line, carrying everything support needs. */
	ereport(LOG,
			(errmsg("license %s verified for \"%s\"",
					out->uuid, out->licensee),
			 errdetail("Product %s, versions %s, cluster %s, expires %s (%d days remaining), serial %s.",
					   out->product,
					   out->version_constraint,
					   out->cluster_unbound ? "any" : out->cluster_id,
					   "see not_after",
					   out->days_remaining,
					   out->serial_hex)));

	if (out->days_remaining <= LICENSE_EXPIRY_WARN_DAYS)
		ereport(WARNING,
				(errmsg("license %s expires in %d days",
						out->uuid, out->days_remaining),
				 errhint("Renew before expiry; the server shuts down when the license expires.")));

	elog(DEBUG1, "license check passed during %s", context);
}
