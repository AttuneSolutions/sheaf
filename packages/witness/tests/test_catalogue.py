import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.mandate import check_mandate
from sheaf_witness.catalogue import catalogue, default, default_authorities

# Each root's public key, pinned when the authorities were checked on 16 November 2026.
PINS = {
    "freetsa": "52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5",
    "sectigo": "a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795",
    "digicert": "59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c",
}


def spki(der):
    key = x509.load_der_x509_certificate(der).public_key()
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def test_the_free_default_is_freetsa_sectigo_and_digicert():
    assert [a.authority for a in default()] == ["freetsa", "sectigo", "digicert"]


def test_each_root_holds_the_key_pinned_when_the_authorities_were_checked():
    for name, pin in PINS.items():
        (root,) = catalogue()[name].roots
        assert spki(root) == pin, name


def test_the_default_is_three_operators_in_three_jurisdictions():
    authorities = default()

    assert len({a.jurisdiction for a in authorities}) == 3
    assert len({a.operator for a in authorities}) == 3


def test_the_default_authorities_make_a_valid_mandate_part():
    doc = t.mandate_document()
    doc["authorities"] = default_authorities(
        by=t.APPROVER, date="2026-11-20", statement="Free tier: see the catalogue's limits."
    )

    assert check_mandate(doc) == []
    assert [a["authority"] for a in doc["authorities"]["list"]] == [
        "freetsa",
        "sectigo",
        "digicert",
    ]


def test_a_root_is_named_by_the_sha256_of_its_der_and_filed_under_it():
    freetsa = catalogue()["freetsa"]
    (root,) = freetsa.roots
    sha256 = hashlib.sha256(root).hexdigest()

    assert freetsa.mandate_entry()["roots"] == [sha256]
    assert freetsa.trust_files() == {paths.tsa_certificate("freetsa", sha256): root}
