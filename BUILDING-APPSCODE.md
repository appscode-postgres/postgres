# Building "Postgres Enterprise by AppsCode"

This fork is upstream PostgreSQL plus **one commit** that replaces the product
name in the version string. Everything else is byte-identical to upstream.

- Branch: `appscode/18`
- Base: upstream tag `REL_18_6`
- Rebrand commit: `Rebrand product name to "Postgres Enterprise by AppsCode"`

## What the rebrand does and does not change

Changed — the product-name portion only:

| Surface | Reports |
| --- | --- |
| `SELECT version()` | `Postgres Enterprise by AppsCode 18.6 on x86_64-pc-linux-gnu, compiled by ...` |
| server startup log | `LOG:  starting Postgres Enterprise by AppsCode 18.6 on ...` |
| `pg_config --version` | `Postgres Enterprise by AppsCode 18.6` |
| `<binary> --version` | `psql (Postgres Enterprise by AppsCode) 18.6` |

Unchanged — deliberately, byte-for-byte identical to upstream:

- `PG_VERSION`, `PACKAGE_VERSION`, `PG_VERSION_NUM` (`180006`)
- `SHOW server_version` (`18.6`) and `SHOW server_version_num` (`180006`)
- the `PG_VERSION` file in the data directory (`18`)
- `PACKAGE_TARNAME` (`postgresql`), so install dirs, `pkg-config` names and
  tarball naming are untouched
- the wire protocol, catalog version, and on-disk format

Because the numeric version is untouched, anything parsing `\d+\.\d+` out of
`version()` or `pg_config --version` keeps working. Only code matching the
literal word "PostgreSQL" is affected.

Help text, `--help` output, documentation and translated message catalogs are
**not** rebranded. That is a separate, much larger change (Tier 2) and has not
been done.

### Why not `--with-extra-version`

`./configure --with-extra-version=STRING` (and Meson's `-Dextra_version`)
appends to `PG_VERSION` itself, turning `18.6` into `18.6-something`. That is
the opposite of the requirement here, so the rebrand is a source edit. Do not
add that flag to any build of this fork.

## Build prerequisites (Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y \
  build-essential git pkg-config bison flex \
  libreadline-dev zlib1g-dev libssl-dev libicu-dev \
  libxml2-dev libxslt1-dev libldap2-dev libpam0g-dev \
  uuid-dev liblz4-dev libzstd-dev gettext \
  tcl-dev python3-dev libperl-dev automake libtool m4 \
  docbook-xsl docbook-xml xsltproc \
  meson ninja-build \
  libipc-run-perl libtest-simple-perl   # for the TAP suite
```

`configure.ac` hard-requires **Autoconf 2.69**, but Ubuntu 24.04 ships 2.71.
Install 2.69 into its own prefix and leave the system autoconf alone:

```bash
cd /tmp
curl -O https://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
tar xzf autoconf-2.69.tar.gz && cd autoconf-2.69
./configure --prefix=/opt/autoconf269
make -j"$(nproc)" && sudo make install
/opt/autoconf269/bin/autoconf --version   # must report 2.69
```

Never `apt install`/upgrade the system autoconf to "fix" the version check;
other tools on the machine depend on the distro version.

## Build

`configure` is committed in regenerated form, so a plain build does not need
autoconf at all. Only rerun `autoreconf` if you edit `configure.ac`:

```bash
/opt/autoconf269/bin/autoreconf -f -i
rm -rf autom4te.cache src/include/pg_config.h.in~   # do not commit these
```

Autoconf/make (out-of-tree build recommended):

```bash
mkdir -p ../build && cd ../build
/path/to/postgres/configure --prefix=/usr/local/pgsql \
  --with-openssl --with-libxml --with-libxslt --with-icu \
  --with-lz4 --with-zstd --with-readline --with-ldap --with-pam \
  --with-uuid=e2fs --with-perl --with-python --with-tcl --enable-nls
make -j"$(nproc)" world-bin
make check
sudo make install-world-bin
```

Meson:

```bash
meson setup build --prefix=/usr/local/pgsql -Dtap_tests=enabled
meson compile -C build
meson test -C build
meson install -C build
```

Both paths carry the rebrand; neither uses `--with-extra-version`.

## Verify

```bash
B=/usr/local/pgsql/bin
$B/postgres --version                     # postgres (Postgres Enterprise by AppsCode) 18.6
$B/pg_config --version                    # Postgres Enterprise by AppsCode 18.6
$B/initdb -D /tmp/pgdata -U postgres
$B/pg_ctl -D /tmp/pgdata -l /tmp/pg.log -k /tmp -o "-k /tmp" -w start
$B/psql -h /tmp -U postgres -d postgres -c "SELECT version();"
$B/psql -h /tmp -U postgres -d postgres -c "SHOW server_version_num;"   # 180006
grep starting /tmp/pg.log
```

Note the socket directory: the default socket path plus a long build directory
can exceed the 107-byte `sun_path` limit, which shows up as
`Unix-domain socket path ... is too long`. Use a short `-k` directory.

## Docker image

`docker/` builds an Alpine image that mirrors the layout of the official
`docker-library/postgres` 18 Alpine image (uid/gid 70, `/usr/local` prefix,
`PGDATA`, `VOLUME`, `docker-entrypoint.sh`, `STOPSIGNAL SIGINT`), so a
downstream image such as `kubedb/postgres-docker` only needs its `FROM` line
changed:

```dockerfile
-FROM postgres:15.3-alpine
+FROM ghcr.io/kubedb/postgres:18.6
```

Its `apk`-based extension layer, including `$DOCKER_PG_LLVM_DEPS`, keeps
working unmodified.

```bash
docker/build.sh appscode/18 ghcr.io/kubedb/postgres:18.6
docker/smoke-test.sh ghcr.io/kubedb/postgres:18.6
```

`build.sh` feeds the image a `git archive` of the given ref, so image content
is pinned to a git commit rather than to the working tree. The Dockerfile
itself asserts at build time that `postgres --version` and `pg_config
--version` carry the custom product name and the unchanged `18.6`, so a
silently un-rebranded build fails the build rather than shipping.

The image tag is separate from the in-binary version string and may carry
extra qualifiers; the binary always reports exactly `18.6`.

### Credential policy (credcheck)

The image bundles [credcheck](https://github.com/HexaCluster/credcheck) **v5.0**
(pinned to commit `9a101e8`) and ships a default policy for Bangladesh Bank
ICT Security 8.2 / 5.9 and Cybersecurity Framework 4.1.2.

- Policy file: `/etc/postgresql/conf.d/10-bb-ict-security.conf`
- Wired in by `include_dir = '/etc/postgresql/conf.d'`, appended to
  `postgresql.conf.sample`, so every cluster `initdb`'d from this image gets it
- `CREATE EXTENSION credcheck` runs on first init in `template1` and `postgres`
  (`/docker-entrypoint-initdb.d/00-credcheck.sh`) for the admin views
- Override by mounting a later-sorting file (e.g. `20-local-overrides.conf`)
  into `/etc/postgresql/conf.d`; last value wins. Do not edit the shipped file.

`docker/smoke-test.sh` asserts every GUC is live and that each rule actually
rejects, so an inert policy fails CI rather than shipping.

#### Four things to know before deploying

**1. `POSTGRES_PASSWORD` must satisfy the policy.** `initdb` sets the superuser
password with an internal `ALTER USER ... PASSWORD`, and credcheck is already
loaded at that point. A weak value aborts startup:

```
FATAL:  password length should match the configured credcheck.password_min_length (11)
```

This is deliberate — the superuser password must meet policy too — but it is a
breaking change for deployments whose `POSTGRES_PASSWORD` worked on a stock
`postgres` image.

**2. The lockout does not apply to loopback connections.** `initdb` writes
`trust` rules for `127.0.0.1/32` and `::1/128`, and the entrypoint *appends*
`host all all all scram-sha-256` after them. `pg_hba` is first-match-wins, so
loopback authenticates with no password and can neither trigger nor be blocked
by `max_auth_failure`. Verified: five bad passwords over loopback record zero
failures; over a real network path the fifth is `rejecting connection, user
'app1' has been banned`. Anything reachable on the pod network is covered;
sidecars and `docker exec`/`kubectl exec` sessions on loopback are not. Set
`POSTGRES_HOST_AUTH_METHOD` or supply your own `pg_hba.conf` if loopback must
be authenticated too.

**3. Existing data directories do not pick the policy up.** `initdb` copies the
sample into a *new* PGDATA only. A volume carried over from an older image
keeps its own `postgresql.conf` with no `include_dir` line — add it by hand
when upgrading such a volume in place, or the cluster runs unprotected.

**4. `reset_superuser = off` means the superuser can be locked out.** An
operator or health check retrying a stale password will brick admin access
until someone runs `SELECT pg_banned_role_reset('<role>')` from an unbanned
session. Loopback being `trust` (point 2) is the practical escape hatch today;
do not rely on that if you change the `pg_hba` rules.

#### Deviations from a naive reading of the BB controls

| Control | What was configured, and why |
| --- | --- |
| 8.2.7 classes | credcheck has no "N of M" rule; all four classes are required, a compliant superset of "at least 3 of 4" |
| 8.2.7 superuser floor | **Not achievable.** credcheck v5.0's README documents `password_min_length_su`, but the v5.0 source implements no `_su` GUC at all — Postgres logs `invalid configuration parameter name ... removing it` and drops it. `superuser_nocheck = off` at least holds superusers to the same floor |
| 8.2.8 expiry | `password_valid_until` is a **minimum** (and the auto-applied value), not just a default. Both bounds at 90 means an explicit `VALID UNTIL` must be ~exactly 90 days: a stricter 30-day expiry is *rejected*. Auto-applied expiry lands at 91 calendar days after rounding up to midnight |
| 5.9.1 username-in-password | **`password_ignore_case` is off, not on.** v5.0 skips the upper/lower class checks entirely when it is set (`if (!password_ignore_case && ...)`), which would cut 8.2.7 from four classes to two and fail "at least 3 of 4". Residual gap: matching is case-**sensitive**, so role `t1` rejects `Containst1!xyz` but accepts `ContainsT1!xyz` |

#### Residual risks

- credcheck only validates **plaintext** submissions. Restoring a dump or
  migrating already-hashed passwords bypasses every rule above.
- `encrypted_password_allowed` is off by design, so `CREATE/ALTER ROLE ...
  PASSWORD` sends plaintext over the wire. Any connection that sets a password
  must use `sslmode=require` or stronger.
- `$PGDATA/pg_password_history` must be in backups (`pg_basebackup` covers it)
  or reuse history is lost on restore.
- credcheck implements **no** MFA or credential-custody control. BB clauses
  8.2.2, 8.2.10, 4.1.2.12, 4.5.2.7 and 5.9.5 are **not** satisfied by this
  extension and need a separate identity provider / secrets manager.

**Migration note:** upstream changed `PGDATA` in 18 to
`/var/lib/postgresql/18/docker` and moved the `VOLUME` from
`/var/lib/postgresql/data` to `/var/lib/postgresql`. That is an upstream 18
change, not part of the rebrand, but KubeDB manifests pinned to the 15.x
layout need updating.

## Moving to a new upstream point release

The whole rebrand is one commit, so this is mechanical:

```bash
git fetch upstream --tags
git checkout -b appscode/18 REL_18_7          # new branch off the new tag
git cherry-pick <rebrand-commit>
/opt/autoconf269/bin/autoreconf -f -i         # regenerate configure
rm -rf autom4te.cache src/include/pg_config.h.in~
git add configure && git commit --amend --no-edit -s
```

Then rerun the build, `make check` / `meson test`, and the Docker smoke test.

Expect conflicts only where upstream touched the same lines. The most likely
one is the version number inside `configure.ac`'s `AC_INIT` and `meson.build`'s
`project(version:)`, since every point release stamps those — take upstream's
number and keep our product name.

### Guarding against drift

Upstream adds new binaries from time to time, and a new one will print the
stock `(PostgreSQL)` marker. After a cherry-pick, this must come back empty:

```bash
grep -rn '(PostgreSQL)' . \
  --include=*.c --include=*.h --include=*.pl --include=*.pm \
  --include=*.y --include=*.l --include=*.in --include=*.build --include=*.ac \
  | grep -v '/po/'
```

(`/po/` holds translated message catalogs, which are intentionally untouched.
`PostgreSQL-Backup-Manifest-Version` in `pg_verifybackup` is a wire-format key,
not branding — never rename it.)

Worth wiring into CI, along with a job that opens a PR when a new 18.x tag is
published upstream.

## Things that parse the version string back out

Two places in the tree parse a version string and needed adjusting because the
product name now contains spaces. If you add more, follow the same pattern —
never assume a fixed field count:

- `src/bin/pg_upgrade/exec.c`, `get_bin_version()` — scans back from the last
  space instead of skipping two whitespace fields, so it still works against a
  **stock PostgreSQL** old cluster during a major-version upgrade.
- `src/test/perl/PostgreSQL/Version.pm` — accepts either product name, so the
  TAP suite can still compare against stock PostgreSQL binaries.

## Before shipping

- Smoke-test the client stacks KubeDB ships: any bundled JDBC driver,
  monitoring agents (`postgres_exporter`), and Helm/Terraform health checks
  that might string-match on "PostgreSQL".
- Verify `pg_upgrade` and replication against a **stock** PostgreSQL cluster,
  not just against another copy of this build.
- Test extensions whose Makefiles grep `pg_config --version`.
- Building from source means AppsCode owns the security-patch cadence: track
  upstream point releases and rebase promptly.
