#!/bin/sh
#
# make-license.sh - issue a license certificate from a dev CA for testing.
#
# The issued leaf matches the confirmed AppsCode production license profile
# exactly:
#
#   Subject: C=<product line>, ST=<tier>, O=<feature>[,O=<feature>...],
#            OU=<plan>, CN=<uuid>
#   Extended Key Usage: clientAuth (only, not critical)
#   Key Usage: critical, digitalSignature, keyEncipherment
#   Subject Alternative Name: DNS:<cn>, email:<email>
#   Serial: random, no imposed format (not a UUID, not fixed length)
#   No Basic Constraints extension (a non-CA leaf)
#
# The DNS and email SAN entries mirror production issuance defaults so that
# tests exercise "SAN present but ignored" the same way real licenses do.
# The Postgres verifier never reads either SAN entry.
#
# A license issued here validates against a build embedding the matching dev
# CA and is rejected by a build embedding only the production CA, so a test
# that passes against the dev CA proves the same license shape works in
# production.
#
# Implemented with python3 + the "cryptography" package rather than the
# openssl CLI, for one reason: the production profile's C (countryName) is
# "postgres", 8 characters, which violates the PKIX countryName SIZE(2)
# upper bound. The production issuer is a Go program whose crypto/x509 does
# not apply that bound; python-cryptography does not either. The openssl
# CLI does apply it and refuses to emit such a value, so it cannot
# reproduce the real license shape. See doc/LICENSE_ENFORCEMENT.md.
#
# This script does not run any production signing. The production CA private
# key is not in this repository.

set -eu

usage() {
	cat >&2 <<'EOF'
usage: make-license.sh --ca-key FILE --ca-cert FILE --out FILE [options]

required:
  --ca-key FILE       dev CA private key (from make-dev-ca.sh)
  --ca-cert FILE      dev CA certificate (from make-dev-ca.sh)
  --out FILE          output license certificate path (PEM)

optional:
  --features LIST     comma-separated O values
                      (default: postgres-enterprise)
                      use this to build negative cases, e.g.
                      --features kubedb-enterprise  (no postgres-enterprise)
                      --features ""                 (no O at all)
  --plan NAME         OU value (default: postgres-enterprise; "" omits OU)
  --tier NAME         ST value (default: enterprise; "" omits ST)
  --product NAME      C value  (default: postgres; "" omits C)
  --cn UUID           CN value (default: a generated UUID)
  --email ADDR        email SAN entry (default: dev@example.com)
  --days N            validity window in days (default: 30)
  --valid-seconds N   validity window in seconds; overrides --days
                      (use for the runtime-expiry test, e.g. 90)
  --not-before N      notBefore offset from now in seconds, may be
                      negative (default: 0). e.g. -5184000 for 60 days ago
                      (expired case), 86400 for tomorrow (not-yet-valid)
  --eku NAME          leaf extended key usage: clientAuth or serverAuth
                      (default: clientAuth; serverAuth is for the
                      "wrong EKU is rejected" negative test)
  --no-eku            omit the extended key usage extension entirely
                      (for the "no EKU is rejected" negative test)
  --locality LIST     comma-separated L values (key=value feature flags),
                      empty by default
  --no-san            omit the subjectAltName extension entirely
EOF
	exit 2
}

ca_key=
ca_cert=
out=
features=postgres-enterprise
plan=postgres-enterprise
tier=enterprise
product=postgres
cn=
email=dev@example.com
days=30
valid_seconds=
not_before=0
eku=clientAuth
want_eku=1
locality=
want_san=1

while [ $# -gt 0 ]; do
	case "$1" in
		--ca-key)        ca_key=$2; shift 2 ;;
		--ca-cert)       ca_cert=$2; shift 2 ;;
		--out)           out=$2; shift 2 ;;
		--features)      features=$2; shift 2 ;;
		--plan)          plan=$2; shift 2 ;;
		--tier)          tier=$2; shift 2 ;;
		--product)       product=$2; shift 2 ;;
		--cn)            cn=$2; shift 2 ;;
		--email)         email=$2; shift 2 ;;
		--days)          days=$2; shift 2 ;;
		--valid-seconds) valid_seconds=$2; shift 2 ;;
		--not-before)    not_before=$2; shift 2 ;;
		--eku)           eku=$2; shift 2 ;;
		--no-eku)        want_eku=0; shift ;;
		--locality)      locality=$2; shift 2 ;;
		--no-san)        want_san=0; shift ;;
		-h|--help)       usage ;;
		*) echo "unknown option: $1" >&2; usage ;;
	esac
done

[ -n "$ca_key" ] && [ -n "$ca_cert" ] && [ -n "$out" ] || usage

case "$eku" in
	clientAuth|serverAuth) ;;
	*) echo "--eku must be clientAuth or serverAuth" >&2; exit 2 ;;
esac

[ -n "$valid_seconds" ] || valid_seconds=$(( days * 86400 ))

# Generate a UUID for the CN if not supplied.
if [ -z "$cn" ]; then
	if command -v uuidgen >/dev/null 2>&1; then
		cn=$(uuidgen | tr 'A-Z' 'a-z')
	else
		cn=$(python3 -c 'import uuid; print(uuid.uuid4())')
	fi
fi

export LIC_CA_KEY="$ca_key" LIC_CA_CERT="$ca_cert" LIC_OUT="$out"
export LIC_FEATURES="$features" LIC_PLAN="$plan" LIC_TIER="$tier"
export LIC_PRODUCT="$product" LIC_CN="$cn" LIC_EMAIL="$email"
export LIC_VALID_SECONDS="$valid_seconds" LIC_NOT_BEFORE="$not_before"
export LIC_EKU="$eku" LIC_LOCALITY="$locality" LIC_WANT_SAN="$want_san"
export LIC_WANT_EKU="$want_eku"

python3 - <<'PY'
import datetime
import os
import secrets
import sys
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def env(name):
    return os.environ[name]


with open(env("LIC_CA_KEY"), "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
with open(env("LIC_CA_CERT"), "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Build the subject DN. O is repeatable: one attribute per feature. Empty
# product/tier/plan/features omit the corresponding RDN, for negative
# tests. python-cryptography does not apply PKIX string upper bounds, so an
# 8-character countryName such as the production "postgres" is accepted,
# matching the Go issuer.
attrs = []
if env("LIC_PRODUCT"):
    # The production C value ("postgres") is longer than the PKIX
    # countryName SIZE(2) bound; _validate=False mirrors the Go issuer,
    # which does not enforce that bound. The warning is expected.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        attrs.append(
            x509.NameAttribute(
                NameOID.COUNTRY_NAME, env("LIC_PRODUCT"), _validate=False
            )
        )
if env("LIC_TIER"):
    attrs.append(
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, env("LIC_TIER"))
    )
for feat in env("LIC_FEATURES").split(","):
    feat = feat.strip()
    if feat:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, feat))
for loc in env("LIC_LOCALITY").split(","):
    loc = loc.strip()
    if loc:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, loc))
if env("LIC_PLAN"):
    attrs.append(
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, env("LIC_PLAN"))
    )
attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, env("LIC_CN")))
subject = x509.Name(attrs)

now = datetime.datetime.now(datetime.timezone.utc)
nb = now + datetime.timedelta(seconds=int(env("LIC_NOT_BEFORE")))
na = nb + datetime.timedelta(seconds=int(env("LIC_VALID_SECONDS")))

leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

if env("LIC_EKU") == "serverAuth":
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
else:
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

# Random serial with no imposed structure (production serials are plain
# unique X.509 serials, not UUIDs, and may be shorter than 128 bits).
serial = int.from_bytes(secrets.token_bytes(8), "big") or 1

builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(leaf_key.public_key())
    .serial_number(serial)
    .not_valid_before(nb)
    .not_valid_after(na)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
)

if env("LIC_WANT_EKU") == "1":
    builder = builder.add_extension(eku, critical=False)

if env("LIC_WANT_SAN") == "1":
    sans = [x509.DNSName(env("LIC_CN"))]
    if env("LIC_EMAIL"):
        sans.append(x509.RFC822Name(env("LIC_EMAIL")))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sans), critical=False
    )

cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

out = env("LIC_OUT")
with open(out, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

key_out = out[:-4] + ".key" if out.endswith(".pem") else out + ".key"
with open(key_out, "wb") as f:
    f.write(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

print("license written to %s" % out, file=sys.stderr)
print("serial=%d (0x%X)" % (serial, serial), file=sys.stderr)
print(
    "notBefore=%s notAfter=%s"
    % (nb.strftime("%Y-%m-%d %H:%M:%SZ"), na.strftime("%Y-%m-%d %H:%M:%SZ")),
    file=sys.stderr,
)
PY
