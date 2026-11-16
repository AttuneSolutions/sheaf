"""Files in `trust/` (section 4): the witness's public keys and the certificates the mandate pins
for each time-stamp authority. The gateway stores them, before the mandate naming them applies,
only if they pass these checks; the verifier repeats them."""

import hashlib
import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_core.problems import Problem

MAX_BYTES = 64 * 1024
_WITNESS_KEY = re.compile(r"trust/witness-keys/([A-Za-z0-9-]{1,127}/[A-Za-z0-9]{1,64})\.pem")
_CERTIFICATE = re.compile(r"trust/tsa/([a-z0-9]+(?:-[a-z0-9]+)*)/([0-9a-f]{64})\.der")


def check_trust_file(path: str, data: bytes) -> list[Problem]:
    """Whether `data` may be stored at `path` in `trust/`: an EC P-256 public key in PEM at
    `trust/witness-keys/{key_id}.pem`, or a CA certificate in DER at
    `trust/tsa/{authority}/{sha256}.der` whose SHA-256 is its name."""
    if len(data) > MAX_BYTES:
        return [Problem("too_large", "bytes", f"a trust file is at most {MAX_BYTES} bytes")]
    if _WITNESS_KEY.fullmatch(path):
        try:
            key = serialization.load_pem_public_key(data)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            key = None
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            return [Problem("trust_invalid", "$", "a witness key is an EC P-256 public key, PEM")]
        return []
    match = _CERTIFICATE.fullmatch(path)
    if match:
        if hashlib.sha256(data).hexdigest() != match.group(2):
            return [Problem("trust_sha256_mismatch", "$", "the certificate has another SHA-256")]
        try:
            certificate = x509.load_der_x509_certificate(data)
            ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except (ValueError, x509.ExtensionNotFound):
            ca = False
        if not ca:
            return [Problem("trust_invalid", "$", "a pinned certificate is a CA certificate, DER")]
        return []
    detail = "trust/witness-keys/{key_id}.pem or trust/tsa/{authority}/{sha256}.der"
    return [Problem("trust_path", "path", detail)]
