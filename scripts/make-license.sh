#!/usr/bin/env bash
#
# Issue a license certificate matching the AppsCode license profile.
#
# The profile is documented in doc/LICENSE_ENFORCEMENT.md section 3. Summary of
# where each field lives, all in standard X.509 attributes since AppsCode has
# no IANA Private Enterprise Number and therefore no private OID arc:
#
#   serial          v4 UUID, 128 bits, the license primary key
#   CN              customer or organization display name
#   O               feature strings, the product gate (repeatable)
#   OU              plan name, for example postgres-enterprise
#   L               feature flags as key=value (repeatable)
#                   including productVersion=<constraint>
#   SAN dNSName     cluster ID binding, or a wildcard meaning any cluster
#   EKU             clientAuth
#
# Deliberately NOT set: SAN rfc822Name. Other AppsCode products carry a
# "Name <email>" contact there, but a Postgres license must contain no personal
# data. The license file is copied into container images, backups, and support
# bundles, so anything in it travels with those. The license UUID is the join
# key; contact details live only in the issuance database. The verifier ignores
# an rfc822Name SAN if one is present, so a certificate issued by the shared
# signing service that still carries one remains valid.
#
# Deliberately NOT set: C (country) and ST (province). The Go verifier reads
# product line from C[0] and tier from ST[0], but X.509 constrains countryName
# to exactly two characters, so "postgres" cannot be encoded there in a
# conforming certificate. The verifier's documented fallback splits the plan
# name in OU on "-" instead, giving product line "postgres" and tier
# "enterprise" from OU=postgres-enterprise. That path is conforming and is what
# this script relies on.
#
# Usage:
#   scripts/make-license.sh --ca-dir dev-ca --out license.pem [options]
#
# Options:
#   --ca-dir DIR         CA directory from make-dev-ca.sh   (default dev-ca)
#   --out FILE           output PEM bundle                  (default license.pem)
#   --cn NAME            subject CN            (default "ACME Corporation")
#   --feature STR        add a feature to O    (default postgres-enterprise)
#   --plan STR           subject OU            (default postgres-enterprise)
#   --cluster ID         SAN dNSName cluster binding, or '*' for unbound
#                                              (default a random UUID)
#   --version CONSTRAINT productVersion flag   (default ">=15,<19")
#   --flag k=v           extra L feature flag, repeatable
#   --uuid UUID          use this UUID as serial (default: generate v4)
#   --not-before-offset SECONDS   relative to now (default 0, may be negative)
#   --not-after-offset  SECONDS   relative to now (default 31536000, one year)
#
# QA scenario shortcuts, which just set the offsets or fields above:
#   --expired            notAfter one hour in the past
#   --not-yet-valid      notBefore one day in the future
#   --expires-in SECONDS notAfter this many seconds from now
#   --wrong-product      feature becomes "kubedb-enterprise"
#   --no-version         omit the productVersion flag entirely
#   --bad-serial         use a non-UUID serial, to test serial validation
#
# Every option is independent, so invalid combinations are possible on purpose;
# QA needs to be able to build malformed certificates.

set -euo pipefail

CA_DIR=dev-ca
OUT=license.pem
CN="ACME Corporation"
PLAN=postgres-enterprise
CLUSTER=""
VERSION=">=15,<19"
UUID=""
NB_OFF=0
NA_OFF=31536000
BAD_SERIAL=0
OMIT_VERSION=0
FEATURES=()
FLAGS=()

die() { echo "make-license.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
		--ca-dir)  CA_DIR="$2"; shift 2 ;;
		--out)     OUT="$2"; shift 2 ;;
		--cn)      CN="$2"; shift 2 ;;
		--feature) FEATURES+=("$2"); shift 2 ;;
		--plan)    PLAN="$2"; shift 2 ;;
		--cluster) CLUSTER="$2"; shift 2 ;;
		--version) VERSION="$2"; shift 2 ;;
		--flag)    FLAGS+=("$2"); shift 2 ;;
		--uuid)    UUID="$2"; shift 2 ;;
		--not-before-offset) NB_OFF="$2"; shift 2 ;;
		--not-after-offset)  NA_OFF="$2"; shift 2 ;;
		--expired)       NA_OFF=-3600; shift ;;
		--not-yet-valid) NB_OFF=86400; NA_OFF=172800; shift ;;
		--expires-in)    NA_OFF="$2"; shift 2 ;;
		--wrong-product) FEATURES=("kubedb-enterprise"); PLAN=kubedb-enterprise; shift ;;
		--no-version)    OMIT_VERSION=1; shift ;;
		--bad-serial)    BAD_SERIAL=1; shift ;;
		-h|--help)  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown option: $1" ;;
	esac
done

[ ${#FEATURES[@]} -gt 0 ] || FEATURES=(postgres-enterprise)

[ -f "$CA_DIR/ca.crt" ] || die "no CA at $CA_DIR/ca.crt, run scripts/make-dev-ca.sh first"
[ -f "$CA_DIR/ca.key" ] || die "no CA key at $CA_DIR/ca.key"

# A v4 UUID: 122 random bits with the version nibble set to 4 and the variant
# bits set to 10xx, per RFC 4122.
gen_uuid() {
	if [ -r /proc/sys/kernel/random/uuid ]; then
		cat /proc/sys/kernel/random/uuid
		return
	fi
	python3 -c 'import uuid; print(uuid.uuid4())'
}

[ -n "$UUID" ] || UUID="$(gen_uuid)"
[ -n "$CLUSTER" ] || CLUSTER="$(gen_uuid)"

# The serial IS the UUID: same 128 bits, so "openssl x509 -noout -serial"
# reveals the license primary key with no tooling.
if [ "$BAD_SERIAL" = 1 ]; then
	SERIAL_HEX=DEADBEEF
else
	SERIAL_HEX="$(printf '%s' "$UUID" | tr -d '-' | tr 'a-z' 'A-Z')"
	[ ${#SERIAL_HEX} -eq 32 ] || die "UUID '$UUID' is not 32 hex digits"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/newcerts"
: > "$WORK/index.txt"

# Build the subject. O is repeatable, and OpenSSL needs unique config keys for
# repeated attributes, so they are numbered with the "N.attr" form.
{
	echo "[req]"
	echo "distinguished_name = dn"
	echo "prompt = no"
	echo
	echo "[dn]"
	i=0
	for f in "${FEATURES[@]}"; do
		printf '%d.O = %s\n' "$i" "$f"
		i=$((i + 1))
	done
	printf 'OU = %s\n' "$PLAN"
	# Feature flags live in L as key=value, one L per flag.
	i=0
	if [ "$OMIT_VERSION" = 0 ]; then
		printf '%d.L = productVersion=%s\n' "$i" "$VERSION"
		i=$((i + 1))
	fi
	for kv in ${FLAGS[@]+"${FLAGS[@]}"}; do
		printf '%d.L = %s\n' "$i" "$kv"
		i=$((i + 1))
	done
	printf 'CN = %s\n' "$CN"
} > "$WORK/req.cnf"

# Extensions applied at signing time.
{
	echo "[v3_license]"
	echo "basicConstraints = critical, CA:FALSE"
	echo "keyUsage = critical, digitalSignature, keyEncipherment"
	echo "extendedKeyUsage = clientAuth"
	echo "subjectKeyIdentifier = hash"
	echo "authorityKeyIdentifier = keyid"
	echo "subjectAltName = @alt"
	echo
	echo "[alt]"
	printf 'DNS.0 = %s\n' "$CLUSTER"
	# No rfc822Name entry: a Postgres license carries no personal data.
} > "$WORK/ext.cnf"

# "openssl ca" is used rather than "openssl x509 -req" because it accepts
# -startdate and -enddate with second precision. The runtime expiry test needs
# a license that expires roughly 90 seconds after issuance, which -days cannot
# express. OpenSSL 3.0 has no -not_before/-not_after on the x509 subcommand.
NB="$(date -u -d "@$(( $(date -u +%s) + NB_OFF ))" +%Y%m%d%H%M%SZ)"
NA="$(date -u -d "@$(( $(date -u +%s) + NA_OFF ))" +%Y%m%d%H%M%SZ)"

cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = CA_default

[CA_default]
dir              = $CA_DIR
# The CA database is deliberately a throwaway in the per invocation temp dir
# rather than persistent state under \$CA_DIR. openssl ca enforces serial
# uniqueness through index.txt, so a persistent database would make re-issuing
# the same --uuid fail the second time. QA needs to regenerate a fixture with a
# fixed UUID repeatably, and a dev CA has no need to retain issuance history.
database         = $WORK/index.txt
new_certs_dir    = $WORK/newcerts
certificate      = \$dir/ca.crt
private_key      = \$dir/ca.key
serial           = \$dir/serial
default_md       = sha256
policy           = policy_anything
email_in_dn      = no
unique_subject   = no
copy_extensions  = none
# Note: do NOT add "rand_serial" here, not even set to "no". OpenSSL's ca app
# tests only for the presence of that key and ignores its value, so
# "rand_serial = no" switches random serials ON and the serial file is never
# read. Omitting the key entirely is what makes ca take the serial from the
# serial file, which is how the certificate serial is pinned to the UUID.

[policy_anything]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = optional
emailAddress           = optional
EOF

# openssl ca takes the next serial from this file, as hex. Writing the UUID
# there is how the serial and the license UUID are kept identical.
printf '%s\n' "$SERIAL_HEX" > "$CA_DIR/serial"

openssl genrsa -out "$WORK/leaf.key" 2048 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -config "$WORK/req.cnf" -out "$WORK/leaf.csr" 2>/dev/null

openssl ca -batch -notext \
	-config "$WORK/ca.cnf" \
	-extfile "$WORK/ext.cnf" -extensions v3_license \
	-startdate "$NB" -enddate "$NA" \
	-in "$WORK/leaf.csr" -out "$WORK/leaf.crt" 2>"$WORK/ca.err" \
	|| { cat "$WORK/ca.err" >&2; die "openssl ca failed"; }

# The bundle is the leaf, optionally followed by an issuing intermediate. The
# dev CA is a root with no intermediate, so the bundle is the leaf alone. The
# trust anchor is never shipped in the bundle: it is compiled into the binary,
# and certificates found in the bundle are never treated as anchors.
cp "$WORK/leaf.crt" "$OUT"
cp "$WORK/leaf.key" "${OUT%.pem}.key" 2>/dev/null || true

echo "issued $OUT"
echo "  uuid/serial : $UUID"
echo "  cluster     : $CLUSTER"
echo "  features    : ${FEATURES[*]}"
echo "  plan        : $PLAN"
echo "  validity    : $NB .. $NA"
