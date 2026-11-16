import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sheaf_core import testing as t
from sheaf_core.witness import signing_input, verify_signature
from sheaf_witness.build import daily
from sheaf_witness.signer import KeyVaultSigner


def test_a_key_vault_signer_signs_the_digest_and_reports_its_public_key():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {"crv": "P-256", "x": numbers.x.to_bytes(32, "big"), "y": numbers.y.to_bytes(32, "big")}
    asked = []

    def sign_digest(digest):
        # Key Vault's ES256 sign: the SHA-256 digest in, r and s as 64 raw bytes out.
        asked.append(digest)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        r, s = decode_dss_signature(key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    signer = KeyVaultSigner(t.KEY_ID, public_jwk=jwk, sign_digest=sign_digest)
    witness = daily(
        t.CHAIN, __import__("datetime").date(2026, 11, 26), 7, "sha256:" + "a" * 64, signer
    )

    assert verify_signature(witness, signer.public_key_pem()) == []
    assert len(asked) == 1 and len(asked[0]) == 32
    assert "=" not in witness["signature"]
    assert base64.urlsafe_b64decode(witness["signature"] + "==")[:1] is not None
    assert signing_input(witness)
