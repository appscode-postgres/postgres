#!/bin/sh
#
# make-dev-ca.sh - generate a development license CA for testing.
#
# This produces a self-signed root CA whose profile mirrors the AppsCode
# production license CA (O = AppsCode Inc., CN = ca; CA:TRUE; keyCertSign)
# so that a license issued by scripts/make-license.sh against this dev CA
# has exactly the same shape as a production license. A test build embeds
# this dev CA INSTEAD OF the production CA (never in addition to it); a
# release build must never contain it.
#
# The dev CA private key produced here is a test artifact with no security
# value. The production CA private key never lives in this repository; it
# stays with the licenses.appscode.com signing service.
#
# Implemented with python3 + the "cryptography" package rather than the
# openssl CLI. This matches the production issuer, which is a Go program:
# both Go's crypto/x509 and python-cryptography issue certificates without
# applying the PKIX string upper bounds (for example the countryName
# SIZE(2) limit), while the openssl CLI enforces them and would reject the
# production profile's 8-character C=postgres value. See make-license.sh
# and doc/LICENSE_ENFORCEMENT.md section 14.
#
# Usage: make-dev-ca.sh <output-directory>
#   writes <dir>/dev-ca.key and <dir>/dev-ca.pem

set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 <output-directory>" >&2
	exit 2
fi

outdir=$1
mkdir -p "$outdir"

DEV_CA_DIR="$outdir" python3 - "$@" <<'PY'
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

outdir = os.environ["DEV_CA_DIR"]
key_path = os.path.join(outdir, "dev-ca.key")
crt_path = os.path.join(outdir, "dev-ca.pem")

# RSA 2048, matching the production CA key type and size.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Subject DN and extensions match the production CA profile exactly.
name = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AppsCode Inc."),
    x509.NameAttribute(NameOID.COMMON_NAME, "ca"),
])

now = datetime.datetime.now(datetime.timezone.utc)
builder = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    # The production root uses serial 0, an RFC 5280 violation that
    # python-cryptography (like Go) refuses to emit. The dev CA is a
    # distinct trust anchor and its serial is irrelevant to verification,
    # so use a normal random serial here.
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 years
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=True,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )
)

cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

with open(key_path, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
os.chmod(key_path, 0o600)

with open(crt_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

fp = cert.fingerprint(hashes.SHA256()).hex().upper()
fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
import sys
print("dev CA written to %s" % crt_path, file=sys.stderr)
print("subject=O = AppsCode Inc., CN = ca", file=sys.stderr)
print("sha256 Fingerprint=%s" % fp, file=sys.stderr)
PY
