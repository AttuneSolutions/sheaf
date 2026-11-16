"""The witness key (7.5). In production an Azure Key Vault EC P-256 key the witness identity may
only sign with, created without a release policy so it cannot be exported. `LocalSigner` holds a
key in memory, for tests and development only."""

import base64
import hashlib
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_core.witness import sign_es256


class Signer(Protocol):
    key_id: str

    def public_key_pem(self) -> bytes:
        """The public key, as stored in `trust/witness-keys/{key_id}.pem`."""

    def sign(self, data: bytes) -> str:
        """An ES256 signature over `data`, base64url without padding (5.2)."""


class LocalSigner:
    def __init__(self, key_id: str, key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self.key_id = key_id
        self._key = key or ec.generate_private_key(ec.SECP256R1())

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data: bytes) -> str:
        return sign_es256(self._key, data)


class KeyVaultSigner:
    """An Azure Key Vault EC P-256 key: Key Vault signs the SHA-256 digest (ES256) and returns r and
    s as 64 raw bytes. The key never leaves the vault."""

    def __init__(
        self,
        key_id: str,
        *,
        public_jwk: Mapping[str, Any],
        sign_digest: Callable[[bytes], bytes],
    ) -> None:
        curve = public_jwk.get("crv")
        if getattr(curve, "value", curve) != "P-256":  # the SDK gives an enum, not a string
            raise ValueError(f"{key_id}: the witness key is EC P-256")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(public_jwk["x"], "big"),
            int.from_bytes(public_jwk["y"], "big"),
            ec.SECP256R1(),
        )
        self.key_id = key_id
        self._pem = numbers.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._sign_digest = sign_digest

    def public_key_pem(self) -> bytes:
        return self._pem

    def sign(self, data: bytes) -> str:
        raw = self._sign_digest(hashlib.sha256(data).digest())
        if len(raw) != 64:
            raise ValueError(f"{self.key_id}: an ES256 signature is 64 bytes, got {len(raw)}")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def key_vault_signer(key_id: str, vault_url: str, credential: Any) -> KeyVaultSigner:
    """The signer for `key_id` (Key Vault key name / version) in the vault at `vault_url`."""
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

    name, version = key_id.split("/", 1)
    key = KeyClient(vault_url, credential).get_key(name, version)
    crypto = CryptographyClient(key, credential)
    jwk = {"crv": key.key.crv, "x": key.key.x, "y": key.key.y}
    return KeyVaultSigner(
        key_id,
        public_jwk=jwk,
        sign_digest=lambda digest: crypto.sign(SignatureAlgorithm.es256, digest).signature,
    )
