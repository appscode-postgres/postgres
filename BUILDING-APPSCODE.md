# Building Postgres Enterprise by AppsCode

This branch (`AC_18_6`) is upstream PostgreSQL 18.6 (`REL_18_6`) plus a
single rebrand commit that appends **" - Postgres Enterprise by AppsCode"**
to the version string, using PostgreSQL's own `--with-extra-version` hook.
The product name stays `PostgreSQL`, so every version surface still begins
with `PostgreSQL <numeric version>`:

```
PostgreSQL 18.6 - Postgres Enterprise by AppsCode on x86_64-pc-linux-gnu, ...
```

This is the same shape Percona (`16.15 - Percona Distribution`) and the
Debian packages (`16.15 (Debian 16.15-1.pgdg13+2)`) use, and it is what
third-party version parsers are written against. `PG_VERSION_NUM` /
`server_version_num` (`180006`) and the `PG_VERSION` data-directory file
(`18`) are byte-for-byte identical to upstream.

Docker packaging is **not** done in this repository. Images (Alpine and
Debian bases, following the layout of the official `docker-library/postgres`
repo) are built in a separate repository. <!-- TODO: link the Docker repo
once it exists. -->

## Branch model

- Upstream tag: `REL_<MAJOR>_<MINOR>` (this branch: `REL_18_6`)
- AppsCode branch: `AC_<MAJOR>_<MINOR>` (this branch: `AC_18_6`)
- The rebrand is carried on top of the upstream tag by the commit
  "Rebrand product name to \"Postgres Enterprise by AppsCode\"" plus the
  follow-up "Brand via --with-extra-version, not the product name", which
  together reduce to three touched files: `configure.ac`,
  `meson_options.txt`, and the regenerated `configure`. The `configure`
  delta against upstream is a single line, so cherry-picking onto a new
  point release is essentially conflict-free. Keep it that way: no other
  changes mixed into those commits.

## New point release (e.g. 18.7)

```sh
git fetch --tags origin
git checkout -b AC_18_7 REL_18_7
git cherry-pick <rebrand commit from AC_18_6>
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

Every surface must begin with `PostgreSQL 18.6` and carry the brand as a
suffix:

```sh
bin/postgres --version      # postgres (PostgreSQL) 18.6 - Postgres Enterprise by AppsCode
bin/pg_config --version     # PostgreSQL 18.6 - Postgres Enterprise by AppsCode
bin/initdb -D data -U postgres
bin/pg_ctl -D data -l server.log -w start
grep starting server.log    # LOG:  starting PostgreSQL 18.6 - Postgres Enterprise by AppsCode on ...
bin/psql -U postgres -Atc 'SELECT version();'
                            # PostgreSQL 18.6 - Postgres Enterprise by AppsCode on ..., compiled by ...
bin/psql -U postgres -Atc 'SHOW server_version;'      # 18.6 - Postgres Enterprise by AppsCode
bin/psql -U postgres -Atc 'SHOW server_version_num;'  # 180006 (unchanged)
```

Note the `(PostgreSQL)` marker in `<binary> --version` is deliberate and
matches Percona and Debian; the brand rides on the version number, not the
product name.

## What the rebrand commit covers (and deliberately does not)

Covered: the default value of PostgreSQL's own extra-version hook, in both
build systems — the `PGAC_ARG_REQ(with, extra-version, ...)` default in
`configure.ac` and the `extra_version` option default in
`meson_options.txt`. Because upstream already threads that value into
`PG_VERSION`, everything downstream follows for free: `version()`,
`PG_VERSION_STR` and the startup log, `pg_config --version`, the psql
banner, every client binary's `--version`, and the `server_version` GUC.
An explicit `--with-extra-version=` / `-Dextra_version=` still overrides
the default, so a build can opt out or use a different suffix.

Not covered (optional later follow-up): documentation, help/usage text,
and translated message catalogs.

### Why not change the product name

An earlier revision of this fork replaced `AC_INIT`'s package name (and the
`(PostgreSQL)` marker in ~30 client binaries) so that `version()` read
`Postgres Enterprise by AppsCode 18.6 on ...`. That broke third-party
version parsers, which expect the product name to be a single token
followed by digits — postgres_exporter matches
`^\w+ ((\d+)(\.\d+)?(\.\d+)?)` against `version()`, so `\w+` consumed
`Postgres` and then hit `Enterprise` instead of a digit; pgpool's probe
fails the same way. It also forced two source hacks (pg_upgrade's
`get_bin_version()` and `PostgreSQL::Test::Version`) to cope with spaces in
the product name, and a 35-file patch to carry onto every point release.
Do not reintroduce it.

## Risks to keep in mind before shipping

- `server_version` now carries the brand suffix (`18.6 - Postgres
  Enterprise by AppsCode`), exactly as it does on Percona and Debian
  builds. Anything that must have a bare number should read
  `server_version_num` (`180006`), which is unchanged; that is what libpq
  and most drivers already use.
- pg_upgrade and replication tooling compare version strings between
  clusters. Both parsers are now stock upstream code again, and
  `src/bin/pg_upgrade` TAP passes.
- Building from source means we own the security-patching cadence: track
  upstream PostgreSQL minor releases and cherry-pick/rebase promptly.
