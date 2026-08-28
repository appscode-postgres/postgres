# Building Postgres Enterprise by AppsCode

This branch (`AC_16_15`) is upstream PostgreSQL 16.15 (`REL_16_15`) plus a
single rebrand commit that changes the product-name portion of the version
string to **"Postgres Enterprise by AppsCode"**. The numeric version stays
byte-for-byte identical to upstream (`server_version` = `16.15`,
`server_version_num` = `160015`, `PG_VERSION` data-directory file = `16`),
so tooling that parses `\d+\.\d+` out of any version surface keeps working.

Docker packaging is **not** done in this repository. Images (Alpine and
Debian bases, following the layout of the official `docker-library/postgres`
repo) are built in a separate repository. <!-- TODO: link the Docker repo
once it exists. -->

## Branch model

- Upstream tag: `REL_<MAJOR>_<MINOR>` (this branch: `REL_16_15`)
- AppsCode branch: `AC_<MAJOR>_<MINOR>` (this branch: `AC_16_15`)
- The rebrand is exactly **one commit** on top of the upstream tag
  ("Rebrand product name to \"Postgres Enterprise by AppsCode\""), also
  exported as `0001-rebrand-to-postgres-enterprise-by-appscode.patch`.
  Keep it that way: no other changes mixed in, so each new point release
  is a mechanical cherry-pick.

## New point release (e.g. 16.16)

```sh
git fetch --tags origin
git checkout -b AC_16_16 REL_16_16
git cherry-pick <rebrand commit from AC_16_15>
```

Then rerun the regenerate/build/verify steps below. The cherry-pick will
conflict in `configure` (it is a generated file); resolve by simply
regenerating it instead of hand-merging.

## Prerequisites (Ubuntu 24.04)

Normal PostgreSQL build deps (`gcc`, `make`, `bison`, `flex`,
`libreadline-dev`, `zlib1g-dev`, `libicu-dev`, `pkg-config`, plus `meson`
and `ninja-build` for the meson path), and one special case:

- **Autoconf 2.69, exactly.** `configure.ac` hard-requires 2.69; Ubuntu
  24.04 ships 2.71. A pinned build lives in `/opt/autoconf269`. If it is
  missing, rebuild it from the GNU release tarball into that prefix; never
  replace the system autoconf.

## Regenerate configure

Only needed when `configure.ac` changed (e.g. after a cherry-pick whose
`configure` hunk conflicted):

```sh
PATH=/opt/autoconf269/bin:$PATH autoreconf -f -i
```

Commit the regenerated `configure` inside the rebrand commit
(`git commit --amend`) so the branch stays one-commit-on-tag, and re-export
the patch file:

```sh
git format-patch -1 HEAD
```

## Build and test — autoconf/make path

```sh
mkdir build-make && cd build-make
/path/to/source/configure --prefix=/desired/prefix \
    --with-icu --with-readline --with-zlib
make -j"$(nproc)" world-bin
make check          # expect: All 217 tests passed
make install-world-bin
```

## Build and test — meson path

```sh
meson setup build-meson /path/to/source --prefix=/desired/prefix \
    -Dicu=enabled -Dreadline=enabled -Dzlib=enabled
ninja -C build-meson
meson test -C build-meson --suite setup --suite regress
```

## Verify the rebrand end to end

All of these must print exactly `Postgres Enterprise by AppsCode 16.15`
as the product+version (no suffix on the number):

```sh
bin/postgres --version      # postgres (Postgres Enterprise by AppsCode) 16.15
bin/pg_config --version     # Postgres Enterprise by AppsCode 16.15
bin/initdb -D data -U postgres
bin/pg_ctl -D data -l server.log -w start
grep starting server.log    # LOG:  starting Postgres Enterprise by AppsCode 16.15 on ...
bin/psql -U postgres -Atc 'SELECT version();'
                            # Postgres Enterprise by AppsCode 16.15 on ..., compiled by ...
bin/psql -U postgres -Atc 'SHOW server_version;'      # 16.15  (unchanged)
bin/psql -U postgres -Atc 'SHOW server_version_num;'  # 160015 (unchanged)
```

## What the rebrand commit covers (and deliberately does not)

Covered (Tier 1 — the version string as users and tooling see it):
`AC_INIT` package name in `configure.ac` (TARNAME pinned to `postgresql`
so install paths and pkg-config names are unchanged), the equivalent
`PACKAGE_NAME`/`PACKAGE_STRING`/`PG_VERSION_STR` settings in `meson.build`,
`PG_BACKEND_VERSIONSTR` in `src/include/port.h`, `pg_config --version`
(`src/common/config_info.c`), the psql banner, and every client binary's
`--version` marker `(PostgreSQL)` across `src/bin`, `src/fe_utils`,
`src/interfaces`, `src/test` and `contrib`. Two version-string *parsers*
were adapted for a product name containing spaces: pg_upgrade's
`get_bin_version()` and `PostgreSQL::Test::Version` (the latter still
accepts stock "PostgreSQL" so TAP tests can compare against unbranded
binaries, and pg_upgrade still works against a stock old cluster).

Not covered (Tier 2, optional later follow-up): documentation, help/usage
text, and translated message catalogs.

## Risks to keep in mind before shipping

- Client stacks (drivers, monitoring agents, health checks) that
  string-match on the literal word "PostgreSQL" — confirm the ones this
  project actually uses parse only the numeric version. `server_version`
  and `server_version_num` are unchanged, which is what libpq and most
  drivers read.
- pg_upgrade and replication tooling compare version strings between
  clusters; pg_upgrade's parser was adjusted (see above) and should be
  re-verified whenever it changes upstream.
- Building from source means we own the security-patching cadence: track
  upstream PostgreSQL minor releases and cherry-pick/rebase promptly.
