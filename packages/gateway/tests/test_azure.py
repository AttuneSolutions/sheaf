from datetime import UTC, date, datetime

import pytest

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.artefact import check_artefact
from sheaf_gateway.azure import BlobStore
from sheaf_gateway.store import BlobConflict

from .fake_azure import FakeContainerClient


@pytest.fixture
def container():
    return FakeContainerClient()


@pytest.fixture
def store(container):
    return BlobStore(container, immutability="Locked")


def receipt(data=t.INSTRUCTIONS, kind="text.markdown", media_type="text/markdown"):
    info, problems = check_artefact(
        data, sha256=t.artefact_sha256(data), kind=kind, media_type=media_type, sensitivity="none"
    )
    assert problems == []
    return info


def test_an_artefact_is_stored_once_with_its_type_metadata_and_tags(store, container):
    info = receipt()

    assert store.put_artefact(info, t.INSTRUCTIONS) is True
    assert store.put_artefact(info, t.INSTRUCTIONS) is False
    blob = container.blobs[paths.artefact(info.sha256)]
    assert blob.content_type == "text/markdown"
    assert blob.tags == {"kind": "text.markdown", "sensitivity": "none"}
    assert store.info(info.sha256) == info
    assert store.info("0" * 64) is None


def test_a_json_artefact_keeps_its_declared_schema(store):
    doc = t.mandate_document()
    info = receipt(t.mandate_bytes(doc), "data.json", "application/json")
    store.put_artefact(info, t.mandate_bytes(doc))

    assert store.info(info.sha256).declared_schema == "sheaf.mandate/1"
    assert store.json(info.sha256) == doc


def test_an_entry_is_a_write_once_block_blob_kept_by_its_own_retention(store, container):
    path = "dossiers/case-review/2026/11/cr-1/0000000000000003.json"

    assert store.put_blob(path, b'{"seq":3}\n', "application/json") is True
    store.retain(path, date(2033, 11, 26))

    assert container.blobs[path].kind == "BlockBlob"
    assert container.blobs[path].policy.expiry_time == datetime(2033, 11, 27, tzinfo=UTC)
    assert store.read(path) == b'{"seq":3}\n'


def test_retention_is_set_locked_through_the_whole_day_and_only_ever_extended(store, container):
    path = paths.artefact(receipt().sha256)
    store.put_artefact(receipt(), t.INSTRUCTIONS)

    store.retain(path, date(2033, 11, 26))
    store.retain(path, date(2030, 1, 1))

    policy = container.blobs[path].policy
    assert policy.expiry_time == datetime(2033, 11, 27, tzinfo=UTC)
    assert str(policy.policy_mode) == "Locked"


def test_a_witness_or_trust_file_is_written_once(store):
    path = "trust/witness-keys/acme-witness/3f1c0d2e9a7b.pem"

    assert store.put_blob(path, b"key", "application/x-pem-file") is True
    assert store.put_blob(path, b"key", "application/x-pem-file") is False
    with pytest.raises(BlobConflict):
        store.put_blob(path, b"other", "application/x-pem-file")
    assert store.trust(path) == b"key"
    assert store.trust("trust/missing.pem") is None


def test_listing_is_one_level(store):
    store.put_blob("chain/case-review/2026/11/26/0000000000000001.json", b"x\n", "application/json")
    store.put_blob("chain/case-review/2026/11/27/0000000000000002.json", b"y\n", "application/json")

    assert store.list("chain/case-review/") == ["chain/case-review/2026/"]
    assert store.list("chain/case-review/2026/11/") == [
        "chain/case-review/2026/11/26/",
        "chain/case-review/2026/11/27/",
    ]


def test_the_immutability_mode_is_chosen_not_defaulted(container):
    with pytest.raises(ValueError):
        BlobStore(container, immutability="Sometimes")


def test_idempotency_receipts_are_kept_in_gateway_state_by_workflow(container):
    from sheaf_gateway.azure import AzureState

    state = AzureState(container, t.WORKFLOW)
    name = "a" * 64

    assert state.read_receipt(name) is None
    state.write_receipt(name, b'{"request":"r1"}')
    state.write_receipt(name, b'{"request":"r1"}')  # finishing from the journal writes it again

    assert state.read_receipt(name) == b'{"request":"r1"}'
    assert f"receipts/{t.WORKFLOW}/{name}.json" in container.blobs
