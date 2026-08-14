# License Enforcement

Status: design approved 2026-08-14. Implementation in progress; the
verification core and its standalone test harness exist, the postmaster hook
and the background worker do not yet. All design questions are closed, see
section 20.

This document describes offline, certificate-based license enforcement built
into the `postgres` binary of the AppsCode distribution. The server refuses to
start without a valid, unexpired license, and shuts down if the license expires
while running.

## 1. What this defends against, and what it does not

State this plainly, because overstating it would be dishonest and would give
operators a false sense of the guarantee.

### In scope

The mechanism stops casual bypass. Each of the following is detected and
results in a fatal startup error:

- editing `postgresql.conf`, since there is no GUC that disables verification
- removing or disabling an extension, since the check does not live in one
- pointing the server at a self-generated CA, since the trust anchor is
  compiled in and pinned by public key hash
- setting the system clock backward, within the limits in section 8
- copying a license file between clusters, when the license is cluster bound
- editing a license file, or forging one, since the chain must verify against
  the embedded root

### Out of scope

An attacker with the binary, a disassembler, and time will win. Native binaries
cannot be made tamper proof. A single instruction patch in the right place
disables any check written in C, and no amount of obfuscation changes that; it
only changes how long the work takes.

The goal is narrower and achievable: make bypass require deliberate binary
patching. That is an unambiguous license violation rather than an accident or a
misconfiguration, and the customer cannot claim they "just changed a setting."

Specifically not defended against:

- binary patching of the verification routines
- `LD_PRELOAD` interposition of OpenSSL symbols (section 10)
- a debugger attached to a running postmaster
- an attacker holding the AppsCode CA private key
- rebuilding the distribution from source with the checks removed

No claim of cryptographic unbreakability is made anywhere in this system. The
cryptography establishes that a license was issued by AppsCode. It does not and
cannot establish that the code checking it was allowed to run.

### Difference from the Kubernetes-side verifier

The Go implementation at `appscode-cloud/license-verifier` exposes an
`EnforceLicense` build variable and a `SkipLicenseVerification()` helper that
disable verification outright. This implementation has no equivalent. There is
no GUC, environment variable, build flag, or compile-time constant that turns
verification off. The only build-time variation is which trust anchor is
embedded (section 16).

## 2. The trust anchor

### 2.1 The published CA, as retrieved 2026-08-14

Retrieved once from `https://licenses.appscode.com/certificates/ca.crt`
(1111 bytes, a single PEM certificate, no intermediate).

| Field | Value |
| --- | --- |
| Subject | `O = AppsCode Inc., CN = ca` |
| Issuer | `O = AppsCode Inc., CN = ca` (self signed root) |
| Serial | `0` |
| Signature algorithm | `sha256WithRSAEncryption` |
| Public key | RSA 2048, exponent 65537 |
| notBefore | 2026-05-29 16:00:24 UTC |
| notAfter | 2036-05-26 16:00:24 UTC |
| Basic Constraints | critical, `CA:TRUE`, no pathlen |
| Key Usage | critical: Digital Signature, Key Encipherment, Certificate Sign |
| Subject Key Identifier | `35:0D:5E:BF:6C:5E:09:E9:2C:5A:A0:82:3E:3F:81:43:3D:27:84:E0` |
| Authority Key Identifier | absent (permitted for a self signed root) |
| Extended Key Usage | absent, so it does not constrain leaf EKUs |
| AIA, CRL DP, Name Constraints | absent, which suits fully offline use |

Fingerprints:

```
certificate SHA-256  EE:B8:16:2F:75:6B:B4:05:DF:27:02:EF:29:85:9D:6F:F7:CE:DD:C3:9F:FD:15:F7:DF:3D:6D:BE:BF:66:13:97
SPKI SHA-256         04d6a4452265b903e9e0d7444855e785a7a67f3aa3d7be41ee07cd9166edd700
PEM file SHA-256     dca444524cf8c0d09cc7d1bf4e584ddf5a65e05145b4e2210f2d52d1711a8a3b
DER length           779 bytes
```

The SPKI SHA-256 value is the constant pinned in a separate translation unit
per section 2.4. It is the public key hash, not the certificate hash, so it
survives a re-issue of the same key with different validity dates.

### 2.2 Findings from testing the anchor

Three properties were verified empirically rather than assumed.

**`X509_V_FLAG_X509_STRICT` is compatible with this profile.** Serial number 0
violates RFC 5280, which requires a positive serial. OpenSSL exempts trust
anchors from that check, so strict mode does not reject the root. A replica CA
built to the same profile, issuing a leaf, verifies under `-x509_strict` both
with and without `-partial_chain`. Tested on OpenSSL 3.0.13. Strict mode checks
have tightened between OpenSSL releases, so this must be re-verified against
the OpenSSL version each release actually links.

**A subject DN collision does not substitute for signature verification.** The
CA subject is `O = AppsCode Inc., CN = ca`, which is trivially guessable. A
rogue CA was built with a byte identical subject DN. A leaf issued under it
fails against the real anchor with `error 20: unable to get local issuer
certificate`. The SPKI pin is an independent second barrier.

**CA lifetime does not constrain the 18.x line.** notAfter 2036-05-26 outlives
PostgreSQL 18 end of life (approximately 2030-11) by about 5.5 years. No cross
signed successor root is needed for this release series.

### 2.3 CA rotation

Confirmed: there was no previous root CA, so the first release embeds exactly
one anchor. The retrieved CA has notBefore 2026-05-29, which is the original
issuance rather than a rotation.

The trust store is still built as an array of anchors, so adding a second is a
one line change to a table rather than a change to verification logic.

Rotation plan, in order of preference:

1. Ship a build embedding both outgoing and incoming roots for at least one
   full license term (section 15), then drop the outgoing root.
2. If that window cannot be met, cross sign the successor root with the
   outgoing root and embed the cross certificate.
3. Gate release lifetime on CA lifetime only as a last resort, since it couples
   two schedules that should stay independent.

### 2.4 Embedding rules

- The CA is vendored at `src/backend/license/appscode_root_ca.pem`. That
  committed file is the source of truth for the build.
- The build never fetches the CA over the network. A build that downloads its
  own trust anchor can be redirected by anyone controlling DNS, a proxy, or the
  build container.
- A CI job re-downloads the published CA and fails if it differs from the
  committed copy, so a rotation is noticed before customers hit it. That job
  reports; it does not feed the build.
- `appscode_root_ca.h` is generated at build time from the PEM, containing DER
  bytes as a `static const unsigned char[]`, wired into make and meson.
- The `X509_STORE` is created empty. Only embedded anchors are added.
  `SSL_CERT_FILE`, `SSL_CERT_DIR`, and OpenSSL default paths are never
  consulted for this store. No code path reads the anchor from disk, an
  environment variable, or a GUC.
- The SPKI SHA-256 constant lives in a different translation unit from the PEM
  bytes and is asserted against the loaded anchor before first use, so
  replacing the embedded PEM alone produces a mismatch.

## 3. Certificate profile

### 3.1 What AppsCode issues today

Derived from `appscode-cloud/license-verifier` (`lib.go`, `info/lib.go`). The
existing profile uses **no custom extensions and no private OIDs**, which is
consistent with AppsCode having no IANA Private Enterprise Number. Everything
is carried in standard DN attributes and SANs.

| Concept | Encoding | Verifier behavior |
| --- | --- | --- |
| License ID | `serialNumber`, rendered as a decimal string | reported only |
| Cluster binding | SAN `dNSName` entries | matched against the cluster UID using DNS hostname semantics |
| Features (product gate) | Subject `O`, multi valued | valid if **any** requested feature is present |
| Plan name | Subject `OU[0]` | reported |
| Product line | Subject `C[0]` | reported |
| Tier name | Subject `ST[0]` | reported |
| Feature flags | Subject `L` entries, parsed as `key=value` | reported |
| User name and email | SAN `rfc822Name`, format `Name <email>` | reported |
| Purpose | EKU `clientAuth` (`1.3.6.1.5.5.7.3.2`) | required by chain verification |
| Validity | `notBefore` / `notAfter` | enforced |

There is a wildcard path: if the leaf CN begins with `*.`, the Go verifier
matches against `*.<CA organization>` instead of the cluster UID.

### 3.2 Agreed Postgres profile

Decision: reuse the existing DN and SAN encoding. No new OIDs are introduced,
since AppsCode has no PEN and squatting on an arbitrary arc would be wrong. A
certificate issued for Postgres is therefore shape identical to every other
AppsCode license, and a dev CA can produce byte-comparable certificates.

| Requirement | Encoding | New? |
| --- | --- | --- |
| product | `O` contains the Postgres product feature string | no, existing gate |
| productVersion | `L` entry `productVersion=>=15,<19` | **yes**, new flag key |
| clusterID | SAN `dNSName` | no, existing mechanism |
| license UUID | `serialNumber` carrying a v4 UUID's 128 bits | **yes**, constrains issuance |
| licensee | `CN` | no |
| org slug | `O` | no |
| validity window | `notBefore` / `notAfter` | no |
| purpose | EKU `clientAuth` | no |
| contact name and email | **not issued**, see 3.4 | **yes**, omission |

Three changes are required in the issuing service, and only three:

1. Postgres licenses must use a v4 UUID as the certificate serial (section 5).
2. Postgres licenses must carry a `productVersion` entry in `L`.
3. Postgres licenses must omit the `rfc822Name` contact SAN (section 3.4).

The product feature string is `postgres-enterprise`, confirmed 2026-08-14. It
is the single value the build gates on, defined as `LICENSE_PRODUCT_FEATURE` in
`src/backend/license/license_core.c`.

### 3.3 Purpose separation, and its accepted limit

Decision: the verifier requires EKU `clientAuth` only, matching the existing Go
verifier, rather than demanding an additional license-specific marker.

Recorded honestly: `clientAuth` alone does not distinguish a license from an
ordinary TLS client certificate issued by the same CA. What actually separates
them is verification step 6, the product check: a TLS client certificate will
not carry the Postgres product feature in `O`, so it is rejected there.

The residual exposure is therefore narrow but real. A certificate the CA issues
for a non-license purpose that also carries the Postgres product feature in `O`
would validate as a license. Closing that in the verifier requires either a
dedicated EKU OID, which requires a PEN, or an extra marker attribute. Neither
was adopted. Controlling it is an issuance discipline matter: the signing
service must not put the Postgres product feature into `O` for anything except
a Postgres license.

### 3.4 Personal data

Decision: a Postgres license contains **no personal data**. The `rfc822Name`
SAN that other AppsCode products use to carry a `Name <email>` contact is not
issued for Postgres.

The reason is distribution. A license file is copied into container images,
backups, log bundles, and support tickets, so anything inside it travels to
every one of those places. Contact details belong in the issuance database
(section 11), where access is controlled and a correction takes effect
immediately, rather than in a signed artifact that cannot be edited without
re-issuing and that may sit in an image registry for years.

What remains in the certificate is organizational, not personal:

- `CN`, the customer or organization display name
- `O`, the organization and feature slugs

The UUID is the join key. Given a UUID from a log line, support resolves the
contact through `license_issuance` (section 19).

The verifier **ignores** an `rfc822Name` SAN if one is present rather than
rejecting it. The signing service is shared with other products, so a Postgres
certificate that still carries a contact SAN must remain valid rather than
locking a customer out. Absence is the issuance policy; tolerance is the
verifier policy.

### 3.5 Version constraint syntax

A comma separated list of clauses, all of which must hold. Each clause is an
operator from `>=`, `>`, `<=`, `<`, `=` followed by a major version integer.

```
productVersion=>=15,<19
```

Compared against `PG_VERSION_NUM / 10000`, the major version only. Whitespace
is not permitted. Any parse failure is fatal, never a silent pass. A license
with no `productVersion` entry is rejected, since a missing constraint must not
mean "all versions."

### 3.6 Cluster ID matching

The Go verifier applies DNS hostname semantics through
`x509.VerifyOptions.DNSName`. This implementation enumerates `dNSName` SAN
entries directly and compares them itself, because DNS wildcard matching is not
the semantics wanted for a cluster identifier.

Rules:

- Comparison is case insensitive, trimmed of surrounding whitespace, and uses a
  constant time comparison.
- A SAN entry of exactly `*` means unbound, and matches any cluster.
- The Go `*.<CA organization>` wildcard form is also accepted as unbound, so
  existing wildcard licenses keep working.
- No other wildcard form is honored. A cluster UID is an opaque identifier, not
  a hostname, and partial wildcard matching on it would be a binding weakness.

Confirmed 2026-08-14: both forms mean any cluster.

## 4. License file format

A PEM bundle containing:

1. the leaf license certificate (required, must be first)
2. optionally, an issuing intermediate CA certificate

Certificates in the bundle are never treated as trust anchors, regardless of
their basic constraints. The bundle must chain to an embedded anchor.

No intermediate exists today. The verification code accepts one anyway, so an
issuing intermediate can be introduced later with no client side change.

## 5. License UUID scheme

Decision: Postgres licenses carry a v4 UUID as the certificate serial number.

The existing scheme reports `serialNumber` as a decimal string and imposes no
structure. Postgres licenses tighten this so the serial is exactly a v4 UUID's
128 bits. There is no separate UUID extension, since adding one would require
an OID arc that does not exist. The serial is the UUID, which also means
`openssl x509 -noout -serial` reveals it with no tooling.

### 5.1 Encoding and validation

- Parse the serial as an `ASN1_INTEGER`. Reject negative values and zero.
- Convert to a big endian byte buffer, left padded with zeros to exactly 16
  bytes. Reject anything longer than 16 bytes.
- Render canonically as lowercase `8-4-4-4-12` for logging and reporting.
- Validate the version and variant nibbles: version must be 4, variant must be
  RFC 4122. A serial that is not a well formed v4 UUID is fatal.

DER encodes a leading zero byte when the high bit of the first content byte is
set. Working from the magnitude rather than raw DER avoids a spurious length
mismatch for UUIDs whose first byte is `>= 0x80`.

Because the UUID is the serial, there is no serial-versus-extension mismatch
case to check; the two cannot disagree.

## 6. Verification algorithm

All steps must pass, in this order. Any failure is fatal.

1. **Resolve the license path.** `PGLICENSE` if set, otherwise
   `$PGDATA/license.pem`, otherwise a compiled in default. The path is
   configurable; whether verification runs is not.
2. **Read and parse.** Enforce a 64 KiB size cap before reading. PEM parse the
   bundle. Fail closed on truncation, garbage, or an empty bundle.
3. **Build and verify the chain.** `X509_STORE_CTX` with trust anchors set to
   the embedded roots only, `X509_V_FLAG_X509_STRICT`, basic constraints and
   path length enforced.
4. **Check purpose.** The leaf must carry EKU `clientAuth`. See 3.3 for what
   this does and does not establish.
5. **Check validity dates.** `notBefore <= now <= notAfter` using
   `X509_cmp_time`, never string parsing.
6. **Check product.** `O` must contain the Postgres product feature string.
   This is the check that actually separates a license from another
   certificate type.
7. **Check version.** Parse the `productVersion` entry from `L` and confirm
   `PG_VERSION_NUM / 10000` satisfies every clause. A missing entry is fatal.
8. **Check cluster binding.** Compare `dNSName` SAN entries against the runtime
   cluster identity per 3.6, unless an entry marks the license unbound.
9. **Check the clock.** See section 8.
10. **On success**, emit one `LOG` line: license UUID, licensee, expiry date,
    days remaining, cluster ID, and serial. License file contents are never
    logged.
11. **On any failure**, `ereport(FATAL, ...)` with
    `errcode(ERRCODE_CONFIG_FILE_ERROR)`, a specific reason, the license path,
    and a documented exit code. The process exits non-zero.

Unknown critical extensions are rejected. Malformed values are rejected. There
is no "warn and continue" path.

## 7. Cluster identity binding

Resolution order:

1. `PG_CLUSTER_ID` environment variable
2. `cluster_id` file in `$PGDATA`
3. Kubernetes namespace UID, where injected

If the license names a specific cluster and no runtime identity resolves,
verification fails closed.

## 8. Clock rollback resistance

State file `$PGDATA/.pg_license_state`, mode `0600`, owned by the postgres
user. Format approved 2026-08-14.

Contents:

- a monotonically non decreasing "highest wall clock seen" timestamp
- the license UUID currently in force
- the installation fingerprint (section 9)
- an HMAC over all of the above

The cluster ID is deliberately **not** stored here. It is a Kubernetes cluster
UID, identical across every Postgres instance in that Kubernetes cluster, so it
discriminates nothing at the installation level. It is resolved fresh at each
startup and used only for the binding check in section 7.

Text format, one `key=value` per line, rather than a packed struct: support can
have a customer paste the file into a ticket, there are no endianness or
padding concerns across architectures, and new keys can be added without
breaking existing readers.

```
# PostgreSQL license state. Do not edit.
version=1
uuid=faf67999-8c16-4903-a6f6-cdd6a65e5023
installation=7431299057265837291
high_water_mark=2026-08-14T06:07:02Z
hmac=sha256:1c2d3e4f...
```

The HMAC covers a canonical serialization: every line except `hmac=`, sorted by
key, joined with a newline. Sorting makes ordering and whitespace differences
harmless rather than a spurious integrity failure.

The HMAC key is derived from the embedded CA SPKI fingerprint alone. It
deliberately does **not** include the license serial; see section 20.1 for why
including it would break every renewal.

Writes go to a temporary file in the same directory, then `fsync`, `rename`,
and `fsync` of the directory. A crash mid write therefore cannot leave a torn
file that would fail the integrity check and refuse to start the cluster.

Behavior:

- Missing file: create it, record the current time, continue.
- Present and HMAC verifies: continue.
- Present and HMAC does not verify: fail closed.
- Wall clock more than 24 hours behind the recorded high water mark: fail with
  a clock rollback error.
- The high water mark is updated at startup and on every periodic re-check.

**Replicas regenerate on first start.** `.pg_license_state` lives inside
`$PGDATA`, so `pg_basebackup` copies the primary's file to every replica. A
replica discards the inherited file and writes a fresh one on first start
rather than adopting the primary's high water mark. Inheriting it would import
the primary's clock history onto a machine whose clock may legitimately differ,
which could refuse to start a healthy replica. The installation fingerprint is
`system_identifier`, which a replica shares with its primary by design, so
regenerating does not produce a spurious "new installation" signal.

**Honest limitation.** The HMAC key derives from values present in the binary
and the license file. Anyone holding both can recompute the HMAC and rewrite
the state file. This stops casual editing of the timestamp. It does not stop an
attacker already placed out of scope in section 1.

## 9. Installation fingerprint and reuse detection

The installation fingerprint is the `system_identifier` from `pg_control`,
stored in the state file. Nothing else feeds into it.

**Why not the cluster ID.** The cluster ID is a Kubernetes cluster UID, so it
is identical for every Postgres instance running in that Kubernetes cluster.
Mixing it into the fingerprint would make two separate installations sharing
one license inside the same Kubernetes cluster look like a single installation,
which is precisely the case this signal exists to catch. It is also already the
enforcement binding in section 7, and reusing it here would conflate the
binding with the detection signal.

**Why not the data directory inode.** It changes on `pg_upgrade`, on any
restore, and on moving the data directory, so the copy signal would fire during
routine maintenance. An alert that fires on maintenance stops being evidence.

**What `system_identifier` gives.** It is assigned at `initdb`, is stable
across restarts, upgrades, and directory moves, and is unique per initialized
cluster. Two Postgres installations in the same Kubernetes cluster have
different values, so sharing one license across them is visible. It is cloned
onto streaming replicas, so a replica correctly does not register as a separate
installation.

**Honest limitation.** A byte copy of an entire data directory carries
`system_identifier` with it, so cloning `$PGDATA` is indistinguishable from
moving it. Detection covers the realistic sharing case, where each deployment
runs its own `initdb`, and not a deliberate data directory clone. The cluster
binding in section 7, not this signal, is the enforcement mechanism.

Because it is not a secret and support benefits from cross checking it, the
value is stored directly rather than hashed; an operator can compare it against
`pg_controldata` output. If further inputs are added later, hash the tuple then.

- When a UUID is first seen with a new installation fingerprint, a distinct
  `LOG` line records it. That line is the evidence a license moved or was
  copied.
- A changed UUID with the same fingerprint is a normal renewal, logged at `LOG`
  level, never fatal.
- The cluster binding, not the fingerprint, is the enforcement mechanism.
  Unbound licenses should be issued sparingly and flagged in the issuance
  database, since those are the ones that get shared.
- If a telemetry channel exists elsewhere in the product, it may report UUID,
  fingerprint, and a coarse timestamp. Multiple concurrent fingerprints for one
  UUID is the abuse signal. The server never depends on that channel to start.

## 10. Anti-bypass measures and their limits

- Prefer static linking of libcrypto for the license path. Failing that, verify
  the OpenSSL version and refuse to run if resolved symbols come from an
  unexpected location.
- `LD_PRELOAD` interposition remains possible and is out of scope.
- The verification routine returns a populated struct consumed at several call
  sites rather than setting a single `bool license_ok`, so a one instruction
  patch does not fully disable enforcement.
- License symbols are not exported unnecessarily. Nothing is stripped that
  would impair debugging of genuine crashes.
- Every license error string is distinct, so support can diagnose from logs
  alone.

## 11. Issuance database schema sketch

```sql
CREATE TABLE license_issuance (
    uuid                uuid PRIMARY KEY,        -- also the certificate serial
    org_slug            text        NOT NULL,
    display_name        text        NOT NULL,    -- certificate CN
    cluster_id          text        NOT NULL,    -- '*' means unbound
    product             text        NOT NULL,    -- feature string placed in O
    version_constraint  text        NOT NULL,    -- productVersion flag in L
    not_before          timestamptz NOT NULL,
    not_after           timestamptz NOT NULL,
    issued_by           text        NOT NULL,    -- operator identity
    reason              text        NOT NULL
        CHECK (reason IN ('new', 'renewal', 'replacement', 'demo')),
    replaces            uuid REFERENCES license_issuance (uuid),
    unbound_justification text,                  -- required when unbound
    revoked_at          timestamptz,
    revoked_reason      text,
    created_at          timestamptz NOT NULL DEFAULT now(),

    CHECK (not_after > not_before),
    CHECK (cluster_id <> '*' OR unbound_justification IS NOT NULL)
);

CREATE INDEX ON license_issuance (org_slug);
CREATE INDEX ON license_issuance (cluster_id) WHERE cluster_id <> '*';
CREATE INDEX ON license_issuance (not_after);
```

A renewal inserts a new row with a fresh UUID and `replaces` pointing at the
previous one, so lineage is walkable in both directions.

Sightings arrive from telemetry rather than issuance, so they live separately:

```sql
CREATE TABLE license_sighting (
    uuid                     uuid NOT NULL REFERENCES license_issuance (uuid),
    installation_fingerprint text NOT NULL,
    first_seen               timestamptz NOT NULL DEFAULT now(),
    last_seen                timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (uuid, installation_fingerprint)
);
```

More than one live fingerprint for a single UUID is the signal worth
investigating.

Contact details live here and **only** here. They are deliberately absent from
the certificate (section 3.4), so this database is the sole authoritative copy
and the UUID is the only way to get from a log line back to a customer.

## 12. Reading license state from a running cluster

`CREATE EXTENSION appscode_license` provides `appscode_license_info()`,
returning UUID, licensee, org, cluster ID, product, version constraint,
`not_before`, `not_after`, days remaining, and the leaf fingerprint.

This extension is a read only reporting shim over state the postmaster already
verified. It cannot influence whether the server starts, and removing it does
not disable enforcement.

## 13. Runtime expiry

A background worker is started unconditionally by the patched postmaster, not
through `shared_preload_libraries`. `bgw_flags = BGWORKER_SHMEM_ACCESS`,
restart time 60 seconds.

- Every 60 seconds it re-runs the full verification, re-reading the license file
  so a renewed license can be dropped in without a restart.
- A transient read error is retried once before being treated as a failure, so
  a partially written file during renewal does not take the cluster down.
- On the first genuine failure it logs the reason, then signals the postmaster
  with `SIGINT` for a fast shutdown. No grace period.
- `SIGINT` (fast shutdown) is chosen over `SIGQUIT` (immediate) deliberately.
  Fast shutdown aborts open transactions but still performs a clean shutdown
  checkpoint, so the cluster does not require crash recovery on next start.
  `SIGQUIT` would skip that and force recovery, risking a longer outage and
  more operator confusion for no enforcement benefit.
- Starting 30 days before `notAfter`, a `WARNING` is emitted once per day.

## 14. Error catalog

Every message includes the license UUID where one could be parsed, and the
resolved license path.

| Exit | Message | Cause | Operator remedy |
| --- | --- | --- | --- |
| 1 | `license file not found` | no file at the resolved path | place the license, or set `PGLICENSE` |
| 1 | `license file exceeds maximum size` | larger than 64 KiB | not a license bundle; re-download |
| 1 | `license file is not valid PEM` | truncated or garbage input | re-download the license |
| 1 | `license chain verification failed` | not issued by the AppsCode CA | obtain a genuine license |
| 1 | `license certificate lacks the clientAuth extended key usage` | wrong certificate type | request a license certificate |
| 1 | `license has expired` | now > notAfter | renew |
| 1 | `license is not yet valid` | now < notBefore | check the clock, or wait |
| 1 | `license does not include product "%s"` | product feature absent from `O` | request a Postgres license |
| 1 | `license does not specify a productVersion constraint` | missing `L` entry | re-issue with the constraint |
| 1 | `server major version %d does not satisfy constraint "%s"` | version out of range | request a license covering this version |
| 1 | `license is bound to cluster "%s" but this cluster is "%s"` | copied license | request a license for this cluster |
| 1 | `license is cluster bound but no cluster identity could be resolved` | missing `PG_CLUSTER_ID` and `cluster_id` | set the cluster identity |
| 1 | `license serial is not a valid v4 UUID` | misissued certificate | re-issue |
| 1 | `system clock appears to have moved backward` | rollback beyond tolerance | correct the clock |
| 1 | `license state file failed integrity check` | edited state file | escalate; do not delete without support |

Exit codes are provisional. If a distinct code per failure class is wanted for
orchestrator use, say so and it will be assigned before implementation.

## 15. Renewal procedure

1. Request a renewal. The service issues a new certificate with a fresh UUID
   and a `replaces` pointer to the current one.
2. Write the new bundle to a temporary file in the same directory and rename it
   into place, so the worker never observes a partial file.
3. Within 60 seconds the worker picks it up. No restart is required.
4. The re-check log line reports the new UUID. The state file records the UUID
   change at `LOG` level; this is expected and not an error.

Revocation is deliberately not implemented through CRL or OCSP, because
verification must work fully offline. Short lived licenses, 90 days to one
year, with automated renewal are the intended control. If revocation becomes a
requirement, a signed revocation list embedded in the bundle refresh is the
path, not a network lookup.

## 16. Build modes

- A release build embeds only the AppsCode production CA.
- A `--dev-ca` build embeds the dev CA **instead of**, never in addition to,
  the production CA.
- A CI gate inspects the shipped binary and fails if the dev CA fingerprint
  appears in it.
- The production CA private key never lives in the repository. It stays with
  the existing `licenses.appscode.com` signing service.

## 17. File permission policy

Approved 2026-08-14. The policy is deliberately asymmetric between the two
files, because we control the mode of one and not the other.

### 17.1 `license.pem`, supplied by the operator

Under section 3.4 this file contains no personal data and no secret. It is a
signed certificate whose entire contents are already known to AppsCode. Reading
it grants nothing: a cluster bound license is useless on another cluster, and
the signature cannot be forged from the public material.

The decisive practical constraint is that in Kubernetes this file will normally
arrive as a mounted Secret or ConfigMap. Those mount at `0444` or `0644` on a
read only volume, and the operator cannot `chmod` a read only mount. Applying
PostgreSQL's TLS private key rule, where any group or world access is fatal,
would make the most likely deployment shape for KubeDB impossible to run.

| Condition | Action |
| --- | --- |
| unreadable | FATAL, indistinguishable from missing |
| group or world writable | `WARNING`, not fatal |
| group or world readable | no diagnostic |
| owned by another user | no diagnostic |

A world writable license file is an integrity concern, since another local user
could swap it, but they could only substitute another genuinely signed license,
not forge one. A local user who can write into `$PGDATA` already has more
direct means of interfering, so this warns rather than fails.

### 17.2 `.pg_license_state`, written by us

This file is created by the server, never mounted, and carries the clock high
water mark that section 8 depends on. There is no deployment constraint on its
mode, so it is held to a strict standard.

| Condition | Action |
| --- | --- |
| created by us | mode `0600` |
| group or world writable | FATAL |
| readable modes | no diagnostic, it holds no secret |

The asymmetry is the point: we cannot dictate the mode of a file the operator
mounts, but we can and should be strict about the one we write ourselves.

## 18. Where the check runs

- Primary: early in `PostmasterMain()`, after GUC processing and after the data
  directory is known, before any listen socket is created and before any child
  is forked.
- Single user mode (`postgres --single`) is covered. It can execute arbitrary
  SQL against an existing cluster, so exempting it would be a bypass.
- Bootstrap mode (`postgres --boot`) is **exempt**, deliberately.

Rationale for the bootstrap exemption: `initdb` runs bootstrap mode to create
the data directory, which necessarily happens before any license can be placed
in `$PGDATA`. Enforcing there would make it impossible to initialize a cluster.
Bootstrap mode cannot serve clients, opens no sockets, runs only the bootstrap
parser rather than the normal SQL grammar, and exits when initialization
completes. The exemption is keyed on the bootstrap mode flag, reachable only by
passing `--boot` explicitly; the postmaster never sets it on a normal server
start, so the exemption cannot be reached by starting a server. A cluster
created without a license still cannot be started without one.

## 19. Support runbook: tracing a UUID

Given a UUID from a customer log bundle, from `openssl x509 -noout -serial`, or
from `SELECT * FROM appscode_license_info()`:

1. `SELECT * FROM license_issuance WHERE uuid = ?` gives org, bound cluster ID,
   product, version constraint, validity window, issuing operator, and reason.
2. Walk lineage: follow `replaces` backward, or query `replaces = ?` forward.
3. Compare the customer's reported cluster ID against `cluster_id`. A mismatch
   on a bound license means the server would not have started, so ask for the
   startup log.
4. `SELECT * FROM license_sighting WHERE uuid = ? ORDER BY first_seen`. More
   than one live fingerprint means the license is in use in more than one
   installation.
5. Decide: reissue with a tighter binding (replace unbound with a specific
   cluster ID), or escalate commercially if the pattern indicates sharing.
6. For a clock rollback or state file integrity report, ask for
   `$PGDATA/.pg_license_state` and the startup log before advising deletion.
   Deleting the state file resets the high water mark and is a supported
   recovery step, but it should be recorded on the ticket.

## 20. Decisions taken, and open items

Decisions recorded, including two that reverse the original brief:

| Decision | Outcome |
| --- | --- |
| Field encoding | Reuse existing DN and SAN fields. No new OIDs, since AppsCode has no PEN. |
| Purpose separation | EKU `clientAuth` only. Reverses the brief's dedicated license EKU. Limit documented in 3.3. |
| License identity | Certificate serial must be a v4 UUID. Requires an issuing service change. |
| Personal data | No contact name or email in the certificate. The verifier tolerates one if the shared signing service emits it. Section 3.4. |
| Cluster wildcard | `*` and the Go `*.<CA organization>` form both mean any cluster. Section 3.6. |
| Product feature string | `postgres-enterprise`, confirmed. |
| Trust anchors | One anchor, since no previous CA exists. Array structure retained for rotation. |
| Bootstrap mode | Exempt, with the reasoning in section 18. |

All design questions are closed. Approved 2026-08-14:

| Item | Outcome |
| --- | --- |
| State file format (section 8) | Approved, text `key=value` with a canonical HMAC |
| HMAC key derivation | CA SPKI fingerprint only, not the license serial |
| Installation fingerprint | `system_identifier` only |
| Replica behavior | Regenerates the state file on first start |
| File permission policy (section 17) | Approved as written |

### 20.1 Three corrections made to the state file design

All three were found while specifying section 8. Each would have caused an
outage or a useless alert as the original brief was written.

**The HMAC key must not include the license serial.** The brief keys the HMAC
on the CA fingerprint and the license serial. The serial changes on every
renewal, since section 5 mandates a fresh UUID per issuance, so after any
renewal the recorded HMAC no longer verifies. Section 8 treats an HMAC mismatch
as fail closed, which means every renewal would refuse to start the cluster.

Recommended: derive the key from the CA SPKI fingerprint alone. This costs
nothing against the threat model in section 1, since the key is already
recomputable by anyone holding the binary and the license, and it removes a
guaranteed outage.

**The installation fingerprint is `system_identifier` alone.** The brief
derives it from cluster ID, `system_identifier`, and the data directory inode.
Both of the other two inputs are wrong, for different reasons.

The cluster ID is a Kubernetes cluster UID, shared by every Postgres instance
in that Kubernetes cluster, so including it would hide the very case the signal
is for: two installations inside one Kubernetes cluster sharing a license.

The data directory inode changes on `pg_upgrade`, on any restore, and on moving
the data directory, so the copy signal would fire during routine maintenance.

Section 9 has the full reasoning and states the residual limitation honestly: a
byte copy of `$PGDATA` carries `system_identifier` with it, so a deliberate
data directory clone is not distinguished from a move.

Related and worth an explicit decision: `.pg_license_state` lives inside
`$PGDATA`, so `pg_basebackup` copies it to every replica. Decide whether a
replica inherits the primary's state file or regenerates it on first start.
