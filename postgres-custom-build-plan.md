# Plan: Build a Custom PostgreSQL 18 Distribution ("Postgres Enterprise by AppsCode")

## Objective

Build PostgreSQL 18 from source with a custom product/version string, so that `SELECT version();`, `psql --version`, `pg_config --version`, and the server startup log show "Postgres Enterprise by AppsCode" instead of (or alongside) the stock "PostgreSQL" branding, the same way EDB Postgres Advanced Server or Percona Distribution for PostgreSQL brand their builds. Package the result as a Docker image KubeDB can ship.

Current upstream baseline: PostgreSQL 18.4 (tag `REL_18_4`), source at `https://github.com/postgres/postgres`. This is the latest point release as of this plan (18.5/18.6 have not shipped yet); step 8 covers moving to whichever point release is current when the build actually runs, by cherry-picking the same rebrand commit onto the new tag.

## Scope: two tiers

Rebranding every string in PostgreSQL touches thousands of files (DocBook docs, translated error messages, regression test output). Splitting the work into tiers keeps it tractable.

- **Tier 1 (required):** the handful of places that make up "the version string" as users and tools actually see it: `SELECT version()`, `--version` output of every binary, `pg_config --version`, and the server startup log line. This is what EDB/Percona actually change; it is a small, well-defined patch.
- **Tier 2 (optional, do only if requested later):** broader rebrand of docs, banners, and help text. Do not attempt this in the first pass; note it as a follow-up.

This plan covers Tier 1 in full and lists Tier 2 as a stretch goal at the end.

## Step-by-step plan for Claude Code

Target build machine: Ubuntu 24.04 LTS (Noble Numbat), local, not a container. All commands below assume `sudo` access on that machine.

### 1. Install build dependencies (Ubuntu 24.04)

Ubuntu 24.04's package versions matter here for one specific reason: PostgreSQL's `configure.ac` hard-requires **Autoconf 2.69** exactly, but Ubuntu 24.04 ships Autoconf 2.71 in its repos. Since step 4 requires regenerating `configure` with `autoreconf` after editing `configure.ac`, install Autoconf 2.69 from source in an isolated location rather than relying on `apt`'s Autoconf, so the system-wide `autoconf` used by other tools is left alone.

```bash
sudo apt update

# Core build toolchain + PostgreSQL's standard build/runtime deps
sudo apt install -y \
  build-essential git pkg-config \
  bison flex \
  libreadline-dev zlib1g-dev libssl-dev libicu-dev \
  libxml2-dev libxslt1-dev \
  libldap2-dev libpam0g-dev \
  uuid-dev liblz4-dev libzstd-dev \
  gettext \
  tcl-dev python3-dev libperl-dev \
  automake libtool m4 \
  docbook-xsl docbook-xml xsltproc

# Meson build path (optional, only if KubeDB's existing image build uses Meson instead of autoconf/make)
sudo apt install -y meson ninja-build

# Autoconf 2.69, built from source and kept out of PATH by default,
# since Ubuntu 24.04's packaged autoconf (2.71) fails PostgreSQL's strict version check
cd /tmp
curl -O https://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
tar xzf autoconf-2.69.tar.gz
cd autoconf-2.69
./configure --prefix=/opt/autoconf269
make -j"$(nproc)"
sudo make install
# Use it explicitly as /opt/autoconf269/bin/autoreconf in step 4, not the system autoreconf
```

Verify before moving on:

```bash
gcc --version
bison --version
flex --version
/opt/autoconf269/bin/autoconf --version   # must report 2.69
```

If Docker packaging (step 7) will also happen on this machine, install Docker separately (`docker.io` or Docker CE per Docker's official Ubuntu instructions); that is not covered here since it depends on which Docker edition KubeDB standardizes on.

### 2. Set up the source tree as a maintainable fork

- Clone `https://github.com/postgres/postgres` (or mirror it into AppsCode's own GitHub org, e.g. `appscode/postgres`).
- Checkout tag `REL_18_4` on a new branch, e.g. `appscode/18`.
- Make exactly **one commit** on top of that tag that does the rebrand (step 3 below produces this commit). Do not spread the change across multiple commits and do not mix it with any other change. One commit per upstream tag keeps `git cherry-pick`/`git rebase` onto `REL_18_5`, `REL_18_6`, etc. mechanical.
- Target string, decided: **`Postgres Enterprise by AppsCode 18.4`**, i.e. the product name "PostgreSQL" is replaced by "Postgres Enterprise by AppsCode" and the numeric version stays exactly `18.4`, byte-for-byte the same as upstream. Nothing appends to or mutates the `18.4` part. So `SELECT version();` should read: `Postgres Enterprise by AppsCode 18.4 on x86_64-pc-linux-gnu, compiled by gcc ..., 64-bit`.

### 3. Locate every place the version string is produced

Run these searches against the checked-out source and record every hit before editing anything:

```bash
# Where PG_VERSION_STR itself is assembled (this is the core string)
grep -rn "PG_VERSION_STR" src/ src/Makefile.global.in

# Where the configure/meson build derives PACKAGE_NAME / PACKAGE_STRING / PACKAGE_VERSION
grep -n "AC_INIT" configure.ac
grep -n "PACKAGE_" configure.ac | head -30
grep -n "version" meson.build | head -30
cat meson_options.txt | grep -A3 -i extra_version

# The SQL-callable version() function backing `SELECT version();`
grep -rn "pg_version" src/backend/utils/adt/version.c

# Server startup log line ("LOG:  starting PostgreSQL ...")
grep -rn "PG_VERSION_STR\|starting %s\|starting PostgreSQL" src/backend/postmaster/*.c src/backend/tcop/*.c

# --version output shared by psql, pg_dump, pg_ctl, initdb, createdb, vacuumdb, etc.
grep -rln "PG_VERSION\b" src/bin src/fe_utils | sort

# psql interactive banner ("psql (PostgreSQL) 18.4")
grep -n "PG_VERSION" src/bin/psql/startup.c src/bin/psql/help.c

# pg_config --version
grep -rn "PG_VERSION" src/bin/pg_config/pg_config.c
```

Compile the actual list of matching files/lines from this repo checkout; do not assume the list above is exhaustive or that line numbers/refactors match exactly, since these get reshuffled between major versions.

### 4. Decide the patch mechanism

Do **not** use `./configure --with-extra-version=STRING` or Meson's `-Dextra_version=STRING`. That mechanism appends a suffix to `PACKAGE_VERSION`/`PG_VERSION` itself (e.g. turns `18.4` into `18.4-appscode`), which changes the numeric version field. The requirement here is the opposite: `18.4` stays byte-for-byte identical, and only the product-name portion ("PostgreSQL") is replaced. So this has to be a source edit, not a configure flag.

The cleanest lever is `configure.ac`'s `AC_INIT` call near the top of the file:

```
AC_INIT([PostgreSQL], [18.4], [pgsql-bugs@lists.postgresql.org], [], [https://www.postgresql.org/])
```

`AC_INIT`'s signature is `AC_INIT(PACKAGE, VERSION, [BUG-REPORT-ADDRESS], [TARNAME], [URL])`. Changing only the first argument to `Postgres Enterprise by AppsCode` and leaving the second argument (`18.4`) untouched gives `PACKAGE_NAME = "Postgres Enterprise by AppsCode"` and `PACKAGE_VERSION = "18.4"` unchanged, and `PACKAGE_STRING` (their concatenation) becomes exactly `Postgres Enterprise by AppsCode 18.4`. Explicitly pin the 4th argument (`TARNAME`) to `postgresql` so install directories, `pkg-config` names, and tarball naming stay standard and nothing else in the build breaks from the rename.

Then, from the file/line list gathered in step 2, check each hit and change it only if it hardcodes the literal word "PostgreSQL" as a *product name* (not if it just uses `PG_VERSION`/`PACKAGE_VERSION`, which must stay untouched):

- `src/Makefile.global.in` (or wherever `PG_VERSION_STR` is assembled): if "PostgreSQL" is hardcoded there rather than derived from `PACKAGE_NAME`/`PACKAGE_STRING`, replace the literal.
- `src/backend/utils/adt/version.c`: only if the format string itself (not just `PG_VERSION_STR`) hardcodes "PostgreSQL".
- The shared `--version` handling in `src/fe_utils` (exact function name found via the step 2 grep) so all client binaries print the custom string consistently.
- The startup log line source found in step 2, so `postgres -D ...` logs the custom string.
- `meson.build`'s equivalent version-string construction, if KubeDB's build uses Meson.

After `configure.ac` is edited, regenerate `configure` using the pinned Autoconf 2.69 from step 1 (not the system `autoreconf`), and commit the regenerated file alongside the source edit:

```bash
/opt/autoconf269/bin/autoreconf -f -i
```

Squash all of the above into a **single commit** (e.g. `git commit -m "Rebrand version string to 'Postgres Enterprise by AppsCode 18.4', keep numeric version unchanged"`), and export it as one patch file, e.g. `0001-rebrand-to-postgres-enterprise-by-appscode.patch`. That one commit is the entire AppsCode-specific diff on top of the `REL_18_4` tag; everything else in the branch stays byte-identical to upstream.

### 5. Update regression tests that assert on the version string

```bash
grep -rln "PostgreSQL" src/test/regress/expected/*.out src/test/regress/sql/*.sql | xargs grep -l "version"
```

Some regression tests (notably around `pg_config`/`version()`) match against a `PostgreSQL \d+\.\d+` pattern or literal expected output. Update the expected output files or the matching regex so `make check` / `meson test` still passes after the rename. Flag any test whose intent is genuinely "assert this is a real Postgres server" (don't weaken those; just update the literal string they expect).

### 6. Build and verify

Autoconf/make path:

```bash
/opt/autoconf269/bin/autoreconf -f -i    # required, since configure.ac was edited
./configure --prefix=/usr/local/pgsql [other options KubeDB needs]
make -j$(nproc)
make check
sudo make install
```

Meson path (PostgreSQL 18 supports both; pick whichever matches how KubeDB currently builds Postgres images):

```bash
meson setup build --prefix=/usr/local/pgsql
meson compile -C build
meson test -C build
meson install -C build
```

Neither path uses `--with-extra-version` / `-Dextra_version`; the rebrand comes entirely from the single commit in step 3.

Verify the result end to end:

```bash
/usr/local/pgsql/bin/postgres --version
/usr/local/pgsql/bin/pg_config --version
/usr/local/pgsql/bin/initdb -D /tmp/pgdata
/usr/local/pgsql/bin/pg_ctl -D /tmp/pgdata -l /tmp/pg.log start
/usr/local/pgsql/bin/psql -d postgres -c "SELECT version();"
grep "starting" /tmp/pg.log
```

Confirm the string appears correctly and identically in all four surfaces (SQL `version()`, `pg_config --version`, `--version` flags, startup log), and specifically confirm `18.4` is unchanged and no suffix was added anywhere.

### 7. Package as a Docker image for KubeDB

- Base the Dockerfile on whatever KubeDB's existing Postgres image build uses (check for an existing `kubedb/postgres` or `appscode/postgres` Dockerfile/build repo first, since the base image, entrypoint scripts, and extension set should stay consistent with KubeDB's current Postgres images).
- Build stage: compile from the patched source as in step 5.
- Runtime stage: copy only the built binaries/libraries into a slim base image, matching KubeDB's existing image layout so the KubeDB Postgres operator does not need changes.
- Tag the Docker image itself however KubeDB's tagging scheme requires (e.g. `appscode/postgres:18.4`); this is a container tag, separate from the in-binary version string, so it can carry extra qualifiers even though the binary's own version string stays exactly `18.4`.
- Add a smoke test to CI that runs the container and checks `SELECT version();` output matches the expected custom string.

### 8. Make it repeatable for future point releases

- Because the whole rebrand is one commit on top of the tag, updating to `REL_18_5` later is a single `git cherry-pick` (or `git rebase`) of that commit onto the new tag, resolving conflicts if the upstream files it touches moved.
- Document (in a short `BUILDING-APPSCODE.md` in the fork) the exact steps: fetch new upstream tag, cherry-pick the rebrand commit onto it, rerun steps 4 to 6.
- Consider a CI job that automatically opens a PR when a new PostgreSQL 18.x tag is published upstream, cherry-picks the commit, and rebuilds.

### 9. Tier 2 (optional follow-up, not in first pass)

If a full rebrand (docs, help text, banners) is wanted later:

- `doc/src/sgml` uses the DocBook entity `<productname>PostgreSQL</productname>` throughout; a global rename here is a large, mechanical, easy-to-verify change (regex over SGML files) but produces a huge diff and needs its own review pass.
- Translated message catalogs (`src/backend/po/*.po`, etc.) also contain "PostgreSQL" in many strings; only touch these if multi-language rebranding is actually required.
- Treat this as a separate, later project with its own review, not bundled into the Tier 1 build.

## Risks and things to double-check before shipping

- The word "PostgreSQL" is being fully replaced (only "Postgres" survives as a substring, in "Postgres Enterprise by AppsCode"). EDB does the same thing (`EDB Postgres Advanced Server` also drops "PostgreSQL"), and mainstream drivers/tools (pgJDBC, psycopg, pgAdmin, most ORMs) rely on the wire protocol version negotiation, not on parsing `SELECT version()`, so this is generally safe. Still, smoke-test the specific client stacks KubeDB ships against (JDBC driver version if bundled, any monitoring agent that string-matches on "PostgreSQL", Terraform/Helm health checks) before shipping.
- Because `PACKAGE_VERSION`/`PG_VERSION` stay exactly `18.4`, anything that parses the numeric version out of `version()` or `pg_config --version` (e.g. `\d+\.\d+` regexes) keeps working; only code that specifically looks for the literal word "PostgreSQL" is at risk.
- `pg_upgrade` and replication tooling sometimes compare version strings between old/new clusters; verify these still work against the rebranded string before relying on them in KubeDB's upgrade paths.
- Extensions built against `pg_config --version` for compatibility checks (some `Makefile`s in extensions grep this) should be tested against the new string.
- Rebuilding from source means AppsCode owns security patching cadence: track upstream PostgreSQL security releases and rebase promptly (this is the same tradeoff EDB/Percona accept for their distributions).
- Ubuntu 24.04's default `autoconf` (2.71) will fail PostgreSQL's strict `configure.ac` version check. Use the pinned `/opt/autoconf269` build from step 1 for `autoreconf`, and never `apt install --reinstall` or update the system autoconf to "fix" this, since other tools on the machine may depend on the distro's version.
