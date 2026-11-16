import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.trust import check_trust_file


def codes(problems):
    return [p.code for p in problems]


def test_the_witness_key_and_an_authority_root_are_trust_files():
    for path, data in t.trust_files().items():
        assert check_trust_file(path, data) == [], path


def test_the_witness_key_is_an_ec_p256_public_key_in_pem():
    p384 = (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    path = paths.witness_key(t.KEY_ID)

    assert codes(check_trust_file(path, p384)) == ["trust_invalid"]
    assert codes(check_trust_file(path, b"not a key")) == ["trust_invalid"]


def test_an_authority_certificate_is_filed_under_its_own_sha256():
    root = t.authority("tsa-a").root

    assert codes(check_trust_file(paths.tsa_certificate("tsa-a", "0" * 64), root)) == [
        "trust_sha256_mismatch"
    ]
    junk = b"not a certificate"
    junk_path = paths.tsa_certificate("tsa-a", hashlib.sha256(junk).hexdigest())
    assert codes(check_trust_file(junk_path, junk)) == ["trust_invalid"]


@pytest.mark.parametrize(
    "path",
    [
        "trust/other/file",
        "trust/tsa/Not A Slug/" + "0" * 64 + ".der",
        "trust/tsa/tsa-a/" + "0" * 63 + ".der",
        "trust/witness-keys/no-version.pem",
        "artefacts/sha256/00/00/x",
    ],
)
def test_only_the_two_kinds_of_trust_file_are_accepted(path):
    assert codes(check_trust_file(path, b"x")) == ["trust_path"]
