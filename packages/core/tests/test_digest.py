import hashlib

import pytest

from sheaf_core.digest import (
    artefact_sha256,
    canonical_digest,
    entry_hash,
    is_artefact_digest,
    is_entry_digest,
)


def test_artefact_digest_is_bare_lowercase_hex_of_the_exact_bytes():
    assert artefact_sha256(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert is_artefact_digest(artefact_sha256(b"abc"))


def test_entry_hash_is_sha256_of_the_canonical_entry_without_hash():
    entry = {"b": 1, "a": "x", "hash": "sha256:" + "0" * 64}
    expected = "sha256:" + hashlib.sha256(b'{"a":"x","b":1}').hexdigest()

    assert entry_hash(entry) == expected


def test_entry_hash_ignores_key_order_and_an_existing_hash():
    assert entry_hash({"a": 1, "b": 2}) == entry_hash({"b": 2, "a": 1, "hash": "sha256:stale"})


def test_entry_hash_changes_when_any_field_changes():
    assert entry_hash({"a": 1}) != entry_hash({"a": 2})


def test_entry_hash_does_not_mutate_its_argument():
    entry = {"a": 1, "hash": "sha256:" + "0" * 64}
    entry_hash(entry)
    assert "hash" in entry


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("sha256:" + "a" * 64, True),
        ("sha256:" + "A" * 64, False),
        ("a" * 64, False),
        ("sha256:" + "a" * 63, False),
        (None, False),
    ],
)
def test_entry_digest_format(value, ok):
    assert is_entry_digest(value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [("a" * 64, True), ("sha256:" + "a" * 64, False), ("g" * 64, False), (b"a" * 64, False)],
)
def test_artefact_digest_format(value, ok):
    assert is_artefact_digest(value) is ok


def test_canonical_digest_is_prefixed_sha256_of_rfc8785_bytes():
    expected = "sha256:" + hashlib.sha256(b'{"a":[1,2],"b":"x"}').hexdigest()

    assert canonical_digest({"b": "x", "a": [1, 2]}) == expected


def test_entry_hash_is_the_canonical_digest_without_hash():
    entry = {"a": 1, "hash": "sha256:" + "0" * 64}

    assert entry_hash(entry) == canonical_digest({"a": 1})
