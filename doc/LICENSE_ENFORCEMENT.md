# License Enforcement in Postgres Enterprise by AppsCode

This document describes the offline, certificate-based license enforcement
built into the `postgres` server binary of Postgres Enterprise by AppsCode.
The server refuses to start without a valid, unexpired license certificate
signed by AppsCode's license CA, and shuts itself down if the license
expires while running. There is no configuration option, GUC, environment
variable, or build flag that disables verification.

Status: design document, written before the implementation. It is the
authority for the certificate profile, the verification algorithm, the
on-disk state file format, and the operator-facing error catalog. Code
that disagrees with this document is wrong.

## 1. Threat model

In scope (the enforcement must stop these):

- Editing `postgresql.conf`, `postgresql.auto.conf`, or any GUC.
- Removing an extension or editing `shared_preload_libraries`. The check
  does not live in an extension.
- Pointing `SSL_CERT_FILE`, `SSL_CERT_DIR`, or any OpenSSL default trust
  path at an attacker-controlled CA bundle. The license trust store is
  built empty and contains only the compiled-in anchors.
- Swapping in a self-generated CA, including one that copies the AppsCode
  CA's subject DN (`O = AppsCode Inc., CN = ca`). Chain verification is by
  signature, never by name.
- Forging or hand-editing a license file. Any bit flip breaks the
  signature.
- Backdating the system clock. Bounded by the clock high-water mark
  described in section 9; rollback beyond 24 hours is refused.
- Copying a license file between machines. This is detected and logged
  (section 10) but deliberately never blocked, because the license
  profile carries no machine or cluster binding.

Out of scope (the enforcement cannot stop these, and no code comment,
log message, or document may claim otherwise):

- An attacker with the binary, a disassembler, and time. Native binaries
  cannot be made tamper-proof. The goal is that every bypass requires
  deliberate binary patching, which is a clear license violation, not an
  accident.
- `LD_PRELOAD` interposition on libcrypto symbols. Section 13 describes
  the partial mitigation that is implemented and why it stops there.
- Running a stock community PostgreSQL binary against the same data
  directory. That is a supported migration path, not a bypass of this
  product.

## 2. The trust anchor: AppsCode license root CA

The production root CA is vendored byte-for-byte at
`src/backend/license/appscode_root_ca.pem` and compiled into the binary.
Confirmed profile, verified with OpenSSL 3.0.13 against the committed
file:

| Field | Value |
|---|---|
| Subject / Issuer | `O = AppsCode Inc., CN = ca` (self-signed root) |
| Serial | 0 |
| Key | RSA 2048 |
| Validity | 2026-05-29 16:00:24 GMT to 2036-05-26 16:00:24 GMT |
| Key Usage | critical: Digital Signature, Key Encipherment, Certificate Sign |
| Basic Constraints | critical: CA:TRUE, no path length |
| Certificate SHA-256 | `EE:B8:16:2F:75:6B:B4:05:DF:27:02:EF:29:85:9D:6F:F7:CE:DD:C3:9F:FD:15:F7:DF:3D:6D:BE:BF:66:13:97` |
| SubjectPublicKeyInfo SHA-256 | `04d6a4452265b903e9e0d7444855e785a7a67f3aa3d7be41ee07cd9166edd700` |

Notes recorded during verification:

- The root's serial number is 0, which violates the RFC 5280 requirement
  that serials be positive. OpenSSL 3.0.13 accepts the chain even with
  `X509_V_FLAG_X509_STRICT` (verified empirically). A future OpenSSL
  release could tighten this. If a strict-mode failure ever appears after
  an OpenSSL upgrade, the fix is a CA rotation on the issuance side, not
  a relaxation of strict mode here.
- The CA is valid for roughly ten more years, so no rotation is urgent,
  but the embedding supports multiple trust anchors (section 3) so a
  transition build can accept licenses from both an old and a new CA.

### Embedding

- `appscode_root_ca.pem` may contain one or more concatenated PEM
  certificates. Every certificate in the file becomes a trust anchor.
- A build-time generator converts each certificate to DER and emits
  `appscode_root_ca.h` containing `static const unsigned char` arrays.
  Both the make and meson builds run the generator; the header is never
  committed.
- The X509_STORE used for verification is created empty and populated
  only from the embedded DER. `SSL_CERT_FILE`, `SSL_CERT_DIR`, and
  OpenSSL's compiled-in default paths are never consulted
  (`X509_STORE_set_default_paths` is never called on this store).
- A separate translation unit (`license_pins.c`, distinct from the file
  that includes the generated header) hard-codes the expected SHA-256
  fingerprint of each anchor certificate and of its
  SubjectPublicKeyInfo. At startup, before first use, the loaded anchors
  are hashed and compared against these pins. A mismatch is fatal. This
  means swapping the embedded PEM alone, without also patching the pin
  table in a different object file, produces a refusal to start.
- The build never fetches the CA over the network. A CI job periodically
  re-downloads `https://licenses.appscode.com/certificates/ca.crt` and
  fails if it differs from the committed copy, so a rotation is noticed;
  the committed file remains the source of truth for the build.

## 3. The license certificate profile

A license is a single X.509 leaf certificate signed directly by the root
above (no intermediate today; an optional intermediate included in the
license bundle is supported). Confirmed against a real issued sample,
serial `0x62E7079B5A9E234F` (decimal `7126673299158737743`):

| X.509 field | License meaning | Checked? |
|---|---|---|
| Signature chain to embedded root | Authenticity | Yes, gate 1 |
| `notBefore` / `notAfter` | Validity window | Yes, gate 2 |
| Extended Key Usage `clientAuth` | Marks a license-shaped cert; a `serverAuth` TLS cert from the same CA must not pass | Yes, part of gate 1 |
| `O` (Organization, repeatable) | Feature list. Must contain `postgres-enterprise`; may contain others (bundled purchases) | Yes, gate 3, membership not equality |
| `C` (Country) | Product line (`postgres` in the sample). Nonstandard 8-character value; OpenSSL parses and verifies it without complaint (verified) | No, informational |
| `ST` (Province) | Tier name (`enterprise` vs `community`) | No, informational |
| `OU` (Organizational Unit) | Plan name | No, informational |
| `CN` (Common Name) | AppsCode's human-facing license identifier, UUID-shaped in current issuance. Not the license ID | No, logged only |
| `L` (Locality, repeatable `key=value`) | Feature flags, optional extension point, empty in current issuance | No, parsed and reported only |
| Serial number | The primary machine-readable license ID. Plain unique X.509 serial, no imposed format, not a UUID, may be shorter than 128 bits | No format check; logged and stored |
| SAN `DNS` entries | Kubernetes cluster binding in other AppsCode products. Never used here (section 5) | Never |
| SAN `email` entry | Requester identity from issuance tooling defaults. Never read (section 6) | Never |
| Basic Constraints | Absent on current leaves, which is normal. If present it must say CA:FALSE, which strict chain verification enforces | Only via chain verify |

The serial and the CN are unrelated numbers and are never treated as
interchangeable. The serial is what the reference Go parser returns as
`ID` and what all logs, SQL output, and the issuance database key on.
The CN is a secondary, human-facing identifier used by support. Every
log line and SQL column that carries one labels it explicitly
(`license ID (serial)` vs `license CN`).

The reference semantics are `ParseLicense` in AppsCode's
`license-verifier` Go library. The C implementation matches it with two
deliberate divergences, both subtractive: no cluster binding (section 5)
and no personal data handling (section 6). The Go parser's wildcard
special case (a CN starting with `*.` rewrites the DNS name to match
against the CA's organization) exists only to serve cluster binding, so
it has no counterpart in the C port.

## 4. The verification algorithm

A license is valid if and only if all three of these hold:

1. It chains to an embedded AppsCode root by signature, and the leaf
   carries the `clientAuth` extended key usage. Implemented as one
   OpenSSL `X509_STORE_CTX` verification with the embedded-only store,
   `X509_V_FLAG_X509_STRICT`, and the SSL-client purpose check, matching
   the reference parser's single `cert.Verify(crtopts)` call.
2. It is unexpired: `notBefore <= now <= notAfter`, evaluated with
   OpenSSL's own time comparison (`X509_cmp_current_time`), never by
   string parsing.
3. Its `O` list contains `postgres-enterprise`. Membership check;
   other feature strings alongside it are fine.

Nothing else gates validity. `C`, `ST`, `OU`, `CN`, `L`, and both SAN
entry types are informational or ignored. No check may be added against
them.

Operationally the startup sequence is:

1. Resolve the license path, in order: `PGLICENSE` environment variable
   if set (no fallback if set but unreadable; that is a configuration
   error to surface, not to paper over), else `$PGDATA/license.pem` if
   present, else the compiled-in default `/etc/appscode/license.pem`
   (overridable at build time, `APPSCODE_LICENSE_PATH` make/meson
   variable). The path is configurable; whether verification runs is
   not.
2. Read the file with a 64 KiB size cap and parse the PEM bundle: first
   certificate is the leaf, any further certificates are untrusted
   intermediates for chain building. File permissions and ownership are
   not checked: a license certificate is public data, and read-only
   root-owned mounts (the common Kubernetes secret layout) must work.
   The signature check makes the content tamper-evident regardless of
   mode bits.
3. Run gate 1 (chain + strict + clientAuth purpose).
4. Run gate 2 (validity window), reported separately from gate 1 so an
   expired license produces an expiry message, not a generic chain
   failure.
5. Run gate 3 (feature membership).
6. Run the clock-rollback check (section 9). Hardening, not one of the
   three validity gates, but still required to pass.
7. On success, emit exactly one LOG line carrying: license ID (serial,
   decimal), CN (labeled as a separate identifier), features (O), plan
   (OU), product line (C), tier (ST), expiry date, days remaining, and
   the leaf certificate SHA-256 fingerprint. Never the file contents,
   never the SAN email.
8. On any failure, `ereport(FATAL)` with
   `errcode(ERRCODE_CONFIG_FILE_ERROR)`, a message from the catalog in
   section 11, and the license path. The process exits with status 1.

## 5. No cluster binding

The upstream Go library can bind a license to a Kubernetes cluster UID
by passing the UID as `DNSName` in `VerifyOptions`, which makes Go's
verifier require a matching DNS SAN entry. This build does not implement
that, and must not:

- The C verifier performs no hostname or SAN matching of any kind,
  regardless of what DNS SAN entries a license carries. Current issuance
  populates a DNS SAN by default (mirroring the CN); it is ignored.
- A validly chain-verified, unexpired, correctly-featured license
  authorizes any machine or cluster it is placed on.
- The term "cluster ID" means a Kubernetes cluster UID and nothing else
  anywhere in this codebase, and that value is not used in license logic
  at all.

The compensating control is passive fingerprinting (section 10): copying
a license is noticed and logged, never blocked.

## 6. No personal data

Current issuance tooling populates an email SAN entry by default (the
confirmed sample carries the requester's address). The C parser silently
ignores it: it is never read into any structure, never logged, never
stored in the state file, and never exposed through SQL. Its presence is
not validated and not rejected. There is no customer name or
organization slug anywhere in the certificate profile; the `O` field is
a feature list, not a customer identifier. Customer identity lives only
in AppsCode's issuance database, joined by the certificate serial and,
secondarily, the CN.

## 7. Where the check runs

- Primary hook: early in `PostmasterMain()`
  (`src/backend/postmaster/postmaster.c`), after GUC processing and
  after the data directory is locked, before the postmaster creates any
  listen socket or forks any child.
- Single-user mode (`postgres --single`): fully checked, same gates, in
  `PostgresMain` startup for the standalone case. An expired license
  fails single-user mode too.
- Bootstrap mode (`postgres --boot`): exempt. Rationale, in full:
  bootstrap mode is reachable only through the `--boot` dispatch in
  `main.c`, runs a single process that reads BKI input, accepts no
  client connections, opens no sockets, and exits when initdb's driver
  input ends. It also runs before `pg_control` exists, so the
  installation-fingerprint and clock-state machinery (sections 9 and 10)
  has nothing to attach to. A normal server start cannot reach this
  mode: without `--boot` on the command line, `main.c` dispatches to
  `PostmasterMain` or (with `--single`) to standalone `PostgresMain`,
  both of which run the full check.
- Consequence for initdb: initdb's post-bootstrap phase runs
  `postgres --single`, which is checked. Therefore initdb itself
  requires a valid license. initdb is patched minimally to resolve the
  license (same order: `PGLICENSE`, then the compiled-in default; there
  is no `$PGDATA/license.pem` yet since `$PGDATA` must start empty) and
  copy it to `$PGDATA/license.pem` after bootstrap succeeds, so the
  single-user phase and every later server start find it in place. If no
  license can be found, initdb fails with a clear message before doing
  any work. This is deliberate: there is no unlicensed window at all,
  and no runtime flag exists whose forgery would skip the single-user
  check.
- The check does not live in an extension's `_PG_init()`;
  `shared_preload_libraries` is user-editable.
- Implementation lives in `src/backend/license/` with its own Makefile
  and meson.build.

## 8. Runtime expiry: the license background worker

- A background worker (`license_bgworker.c`, `bgw_flags =
  BGWORKER_SHMEM_ACCESS`, restart time 60 s, started at postmaster
  startup) is registered directly by the patched postmaster, never via
  `shared_preload_libraries`.
- Every 60 seconds it re-runs the full verification, re-reading the
  license file from disk, so an operator can drop in a renewed license
  without a restart.
- On a failed re-check it retries a transient read failure once (a
  partially written file during renewal must not take the cluster down),
  then on confirmed failure it logs the reason at LOG level and signals
  the postmaster with SIGINT, PostgreSQL's fast-shutdown request: active
  transactions abort, a shutdown checkpoint runs, data durability is
  preserved. SIGQUIT (immediate mode, no shutdown checkpoint, crash
  recovery on next start) is deliberately not used. There is no grace
  period beyond the up-to-60-second detection window.
- Starting 30 days before `notAfter` it emits one WARNING per day:
  `license for Postgres Enterprise by AppsCode expires in N days`.
- The worker updates the clock high-water mark (section 9) on every
  cycle.

## 9. Clock-rollback resistance and the state file

State lives in `$PGDATA/.pg_license_state`, mode 0600, owned by the
data directory owner. Text format, version 1:

```
PGLICSTATE1
fingerprint=<64 hex chars, installation fingerprint, section 10>
hwm=<decimal Unix epoch seconds, highest wall clock ever observed>
serial=<decimal serial of the license last seen here>
cn=<CN of the license last seen here>
hmac=<64 hex chars>
```

- `hmac` is HMAC-SHA256 over the exact bytes of the five preceding
  lines. The key is `SHA256("appscode-pg-license-state-v1" ||
  DER-SHA256 of the first embedded CA certificate || serial as a decimal
  string)`. On write the serial is the current license's; on read the key
  is re-derived from the serial stored in the file, so the file is
  self-verifying regardless of which license is now in effect. This is an
  integrity check against accidental corruption and casual edits, not a
  secret-based MAC (the CA fingerprint is public), which is consistent
  with the threat model: deleting or deliberately rewriting the file is
  out of the "casual" scope, and resetting the high-water mark still
  requires a validly signed replacement license that only AppsCode can
  issue.
- A license replacement carries a new serial. The old state file still
  verifies (its key comes from its own stored serial), the serial change
  is treated like an installation-fingerprint change (advisory, not
  tampering), and the file is rewritten for the new serial. Only bytes
  that were actually edited fail the integrity check. The high-water mark
  is carried forward across replacement (`max(stored, now)`), so a
  renewal never weakens clock-rollback protection.
- At startup and on every worker cycle: if current wall clock is more
  than 24 hours behind `hwm`, fail with the clock-rollback error. The
  24-hour tolerance absorbs DST confusion, small NTP steps, and
  timezone mistakes; a 30-day rollback fails, a 1-hour rollback passes.
- If the file is missing, it is created fresh. If present but the HMAC
  does not verify, fail closed with the corrupt-state error. Never
  silently rebuild a file that fails its HMAC.
- `hwm` is monotonically non-decreasing and updated at startup and every
  periodic re-check.

Known limit, stated honestly: deleting the state file resets the
high-water mark. Filesystem contents cannot be defended from root; the
threat model (section 1) covers casual clock backdating, and deleting a
hidden, HMAC-protected file inside `$PGDATA` is a deliberate act. The
same applies to the fingerprint-regeneration path below.

## 10. Installation fingerprint and abuse tracking (advisory only)

- The installation fingerprint is
  `SHA256(pg_control system_identifier, as 8 little-endian bytes ||
  st_ino of $PGDATA, as 8 little-endian bytes)`, hex-encoded. It derives
  only from the data directory itself; no MAC address, hostname, or
  machine ID is included.
- On startup, if the state file's HMAC verifies but its stored
  fingerprint differs from the recomputed one, the server logs a
  distinct LOG line ("license ID (serial) N is now running on a new
  installation") and regenerates the state file fresh, including a fresh
  high-water mark. This never blocks startup: with no cluster binding in
  the profile, there is nothing to enforce against; the log line is the
  product.
- Streaming replicas: `pg_basebackup` copies `.pg_license_state` along
  with the rest of the data directory, but the copy self-invalidates,
  because the replica's `$PGDATA` has a different inode, so the
  recomputed fingerprint differs and the state regenerates fresh on
  first start. Each replica is its own installation and must carry its
  own (copy of a) valid license file; a replica whose license file is
  missing or invalid does not start.
- The same license serial appearing with multiple fingerprints across a
  fleet is the signal support uses to notice a license running in more
  places than expected.

## 11. Error catalog

All fatal license errors use `errcode(ERRCODE_CONFIG_FILE_ERROR)` and
exit status 1. Messages are distinct by design so support can diagnose
from logs alone. `%s`/`%d` placeholders shown abbreviated.

| Message | Cause | Operator remedy |
|---|---|---|
| `could not find a license file (checked PGLICENSE, "<datadir>/license.pem", "/etc/appscode/license.pem")` | No license present at any resolved path | Obtain a license from AppsCode and place it at one of the paths, or set `PGLICENSE` |
| `could not read license file "%s": %m` | Path resolved but unreadable (permissions, dangling symlink, I/O error) | Fix permissions or replace the file |
| `license file "%s" exceeds the maximum size of 64 kB` | Wrong file at the license path, or garbage appended | Install the actual PEM license file |
| `license file "%s" contains no PEM certificate` | Empty, truncated, or non-PEM content | Re-download or re-copy the license; check for transfer corruption |
| `license file "%s" contains malformed certificate data` | PEM framing present but DER inside does not parse | Same as above; the file was corrupted or hand-edited |
| `license certificate chain does not verify against the AppsCode license CA: %s` | Signed by a different or self-generated CA (including a rogue CA reusing AppsCode's subject DN), broken signature, or strict-mode X.509 violation; OpenSSL's reason string is appended | Obtain a genuine license issued by licenses.appscode.com |
| `license certificate lacks the client authentication extended key usage` | A non-license certificate from the CA, for example a TLS server certificate, was installed as the license | Install the license certificate, not a TLS certificate |
| `license certificate is not valid until %s` | `notBefore` in the future, usually a clock set wrong or a license issued for a future term | Check system clock; if the clock is right, contact AppsCode support |
| `license certificate expired on %s` | `notAfter` in the past | Renew the license and drop the new file in place (section 12) |
| `license does not include the "postgres-enterprise" feature (features present: %s)` | License issued for a different AppsCode product | Request a license that includes the `postgres-enterprise` feature |
| `license state file "%s" is corrupt or has been tampered with` | HMAC verification failed on `.pg_license_state` | Investigate; if benign corruption is confirmed (for example fsck aftermath), remove the file and restart, which regenerates it |
| `system clock appears to have moved backward: current time is more than 24 hours before the last recorded time %s` | Wall clock rolled back beyond tolerance | Fix the system clock (NTP); if the rollback was a legitimate correction of a clock that had run far ahead, contact support |
| `embedded license CA failed its integrity self-check` | The compiled-in CA does not match the pinned fingerprints; the binary was modified or corrupted | Reinstall the distributed binaries; if they were not modified locally, treat as a supply-chain incident and contact AppsCode |
| `could not write license state file "%s": %m` | `$PGDATA` not writable at startup | Fix data directory permissions |

Non-fatal messages:

| Level | Message | Meaning |
|---|---|---|
| LOG | `license accepted: id (serial) %s, CN %s, features %s, plan %s, product line %s, tier %s, expires %s (%d days remaining), certificate SHA-256 %s` | The one success line, startup only |
| LOG | `license id (serial) %s is now running on a new installation (fingerprint %s, previously %s)` | License file moved or was copied; advisory only |
| WARNING | `license for Postgres Enterprise by AppsCode expires in %d days` | Daily from 30 days out |
| LOG | `license verification failed during periodic re-check: %s; requesting fast shutdown` | Background worker detected expiry or an invalid replacement file; SIGINT follows |

## 12. Renewal procedure

1. Obtain the renewed license certificate (a new serial; the old license
   remains valid until its own `notAfter`).
2. Write it to a temporary file on the same filesystem as the license
   path, then atomically `mv` it over the existing path. Atomic rename
   is why the worker's single retry exists; a non-atomic copy risks one
   failed read, never a shutdown, but atomic replacement is still the
   documented method.
3. Within 60 seconds the background worker re-reads and logs acceptance
   of the new license. No restart is required.
4. Verify with `SELECT * FROM appscode_license_info();` that the new
   serial and `not_after` are live.

## 13. Anti-bypass hardening, and its honest limits

- The verification routine returns a struct (validity, gates passed,
  serial, expiry, fingerprint), consumed independently at several call
  sites (postmaster gate, background worker, SQL reporting function).
  There is no single `bool license_ok` global whose one-instruction
  patch disables enforcement.
- libcrypto linking follows the normal server build (dynamic). At
  startup the license module verifies that the running OpenSSL major
  version matches the build-time version and, where `dladdr` is
  available, that `X509_verify_cert` resolves from the same shared
  object as the rest of libcrypto. This raises the bar from "set an env
  var" to "ship an interposing library", which is a deliberate act.
  `LD_PRELOAD` interposition remains possible and is out of scope
  (section 1).
- License symbols are file-static wherever possible; nothing is stripped
  that would hinder debugging real crashes.
- All error strings are distinct (section 11).
- No claim of cryptographic unbreakability is made anywhere, including
  here.

## 14. Build, test, and CI

- Trust anchor selection is a build-time choice:
  `appscode_root_ca.pem` (production, the default) or the dev CA
  generated by `scripts/make-dev-ca.sh` (test builds). A build embeds
  exactly one CA set, never both.
- `scripts/make-license.sh` issues licenses from the dev CA matching the
  confirmed production profile exactly: `C=postgres`, `ST=<tier>`,
  one or more `O=<feature>` entries, `OU=<plan>`, `CN=<uuid>`,
  `clientAuth` EKU, DNS and email SAN entries mirroring production
  issuance defaults (so "SAN present but ignored" is exercised), no
  imposed serial format. Flags allow overriding `O` (for the
  missing-feature negative test), validity window (for expiry tests),
  and EKU (for the serverAuth negative test).
- The dev tooling is implemented with `python3` and the `cryptography`
  package, not the `openssl` command-line tool, for one specific reason:
  the production `C` value is `postgres`, 8 characters, which exceeds the
  PKIX countryName `SIZE(2)` upper bound. The production issuer is a Go
  program whose `crypto/x509` does not apply that bound, so the real
  license carries an 8-character country. The `openssl` CLI enforces the
  bound and refuses to emit such a value (verified against OpenSSL
  3.0.13, which fails CSR creation with "string too long, maxsize=2"),
  and so does python-cryptography's default validation; the dev tooling
  passes `_validate=False` on the country attribute only, to mirror the
  Go issuer. This is a property of the issuance side; the Postgres
  verifier does not read `C` at all (section 4), so nothing in the server
  depends on it. `python3` and `cryptography` are therefore build/test
  dependencies of the AppsCode test suite, not runtime dependencies of
  the server, which still needs only OpenSSL.
- The dev CA (`scripts/make-dev-ca.sh`) uses a normal random serial. The
  production root's serial is 0, an RFC 5280 violation that neither Go
  nor python-cryptography will emit; since the dev CA is a distinct trust
  anchor, its serial is irrelevant to verification.
- CI gates:
  - Release-binary inspection fails the build if the dev CA fingerprint
    appears anywhere in the shipped binary.
  - A scheduled job fetches
    `https://licenses.appscode.com/certificates/ca.crt` and diffs it
    against the committed copy, alerting on drift.
- The production CA private key never enters this repository; issuance
  stays with the licenses.appscode.com service.
- Because enforcement is unconditional, every test that starts a server
  (TAP, pg_regress) runs against a dev-CA build with `PGLICENSE`
  pointing at a freshly generated dev license; the TAP suite under
  `src/test/modules/license/` generates its own certificates per test.
- Revocation: none (no CRL, no OCSP; checking must work fully offline).
  The compensating policy is short-lived licenses, 90 days to 1 year
  recommended, with automated renewal.
- Memory discipline: all OpenSSL error paths free their objects; the
  test suite runs under AddressSanitizer in CI.

## 15. Support runbook: tracing a license

Given a report (or a log line) containing a license ID:

1. Confirm which identifier you hold. `id (serial) 7126673299158737743`
   is the serial; `CN 01a02d93-cecb-7be2-b742-261ac3fa12fe` is the
   human-facing UUID. The issuance database is keyed by serial; the CN
   is an alternate lookup key.
2. Look up the issuance record (schema in section 16): customer join,
   features, plan, validity window, renewal lineage via `replaces`.
3. Ask the customer to run `SELECT * FROM appscode_license_info();` on
   the running cluster instead of mailing the license file. It returns
   license ID (serial), CN, features, plan, product line, tier,
   not_before, not_after, days remaining, and the leaf fingerprint,
   matching the startup log line field for field.
4. Collect "new installation" log lines for that serial across the
   customer's fleet. Multiple fingerprints for one serial means the file
   was copied; that is expected for replicas (each replica logs it once
   on first start) and for restored backups. A count far exceeding the
   contracted deployment size is a commercial conversation, not a
   technical enforcement action.
5. Decide: reissue (renewal or replacement, recording `replaces`),
   or escalate commercially. Nothing in the server blocks a copied
   license, by design; the evidence trail is the product.

## 16. Issuance database schema sketch (lives with the issuance service, not in this repo)

```sql
CREATE TABLE license (
    serial        numeric      PRIMARY KEY,  -- X.509 serial, arbitrary precision, no format assumed
    cn            text         NOT NULL,     -- human-facing ID, UUID-shaped in current tooling
    product_line  text         NOT NULL,     -- from C
    tier          text         NOT NULL,     -- from ST
    features      text[]       NOT NULL,     -- from O, must include 'postgres-enterprise'
    plan          text,                      -- from OU
    not_before    timestamptz  NOT NULL,
    not_after     timestamptz  NOT NULL,
    issuer        text         NOT NULL,     -- issuing CA identity
    reason        text         NOT NULL CHECK (reason IN ('new', 'renewal', 'replacement', 'demo')),
    replaces      numeric      REFERENCES license(serial)  -- renewal lineage
);
```

No customer name, email, or organization slug column. Customer identity
lives in AppsCode's separate customer records, joined by license serial.

## 17. What this defends against, in one paragraph

This system makes it so that running Postgres Enterprise by AppsCode
without a valid license, or past expiry, or with a rolled-back clock,
requires deliberately patching a distributed binary or interposing on
its crypto library, both unambiguous license violations, rather than
editing a config file or copying a certificate. It does not, and cannot,
stop a determined attacker with binary-modification tools, and it
deliberately does not stop a valid license from being copied to more
installations than were paid for; it makes that visible in logs and
support tooling instead.
