import time
from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.artefact import check_artefact
from sheaf_gateway.azure import AzureState, BlobReader, BlobReadFailed, BlobStore
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


# The gateway's role may create blobs but not write over one (deployment guide, section 6). Azure
# then answers an upload to an existing blob with 403 UnauthorizedBlobOverwrite, not 409.


@pytest.fixture
def create_only():
    container = FakeContainerClient(may_overwrite=False)
    return container, BlobStore(container, immutability="Locked")


def test_an_artefact_already_stored_is_left_as_stored_without_overwrite_rights(create_only):
    container, store = create_only
    info = receipt()
    assert store.put_artefact(info, t.INSTRUCTIONS) is True
    assert store.put_artefact(info, t.INSTRUCTIONS) is False
    assert store.read(paths.artefact(info.sha256)) == t.INSTRUCTIONS


def test_the_same_bytes_again_are_a_no_op_without_overwrite_rights(create_only):
    # Finishing an entry from the journal writes each of its blobs again.
    container, store = create_only
    path = paths.entry(paths.chain_segment(t.WORKFLOW, datetime(2026, 11, 26, tzinfo=UTC)), 1)
    assert store.put_blob(path, b'{"seq":1}\n', "application/json") is True
    assert store.put_blob(path, b'{"seq":1}\n', "application/json") is False


def test_other_bytes_are_a_conflict_without_overwrite_rights(create_only):
    container, store = create_only
    path = paths.witness_key(t.KEY_ID)
    store.put_blob(path, b"first", "application/x-pem-file")
    with pytest.raises(BlobConflict):
        store.put_blob(path, b"second", "application/x-pem-file")
    assert store.read(path) == b"first"


def test_any_other_refusal_is_not_taken_for_an_existing_blob(create_only, monkeypatch):
    from azure.core.exceptions import HttpResponseError

    from .fake_azure import FakeBlobClient, _error

    container, store = create_only

    def refused(self, data, **kw):
        raise _error("AuthorizationPermissionMismatch")

    monkeypatch.setattr(FakeBlobClient, "upload_blob", refused)
    with pytest.raises(HttpResponseError):
        store.put_blob(paths.witness_key(t.KEY_ID), b"first", "application/x-pem-file")


def test_a_lease_already_lost_is_given_up_without_an_error(container):
    class Lost:
        def release(self):
            raise HttpResponseError(message="LeaseIdMismatchWithLeaseOperation")

    state = AzureState(container, t.WORKFLOW)
    state._lease = Lost()

    state.release()

    assert not state.held()


def test_proposals_are_kept_per_chain_by_the_mandates_digest(container):
    state = AzureState(container, t.WORKFLOW)
    other = AzureState(container, "claims-triage")

    state.write_proposal("a" * 64, b'{"status":"pending"}')
    state.write_proposal("a" * 64, b'{"status":"withdrawn"}')
    state.write_proposal("b" * 64, b'{"status":"pending"}')

    assert state.read_proposal("a" * 64) == b'{"status":"withdrawn"}'
    assert state.read_proposal("c" * 64) is None
    assert state.list_proposals() == [b'{"status":"withdrawn"}', b'{"status":"pending"}']
    assert other.list_proposals() == []
    assert f"proposals/{t.WORKFLOW}/{'a' * 64}.json" in container.blobs


# -- reading a blob with one plain GET -----------------------------------------------------------

URL = "https://acme.blob.core.windows.net/evidence"


class FakeHttp:
    """Answers each request in turn with (status, body, headers), and records it."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def request(self, method, url, headers=None, **kw):
        self.requests.append((method, url, dict(headers or {})))
        status, body, headers = self.answers.pop(0)
        return SimpleNamespace(status=status, data=body, headers=headers)


class FakeCredential:
    def __init__(self, clock=time.time, lifetime=3600):
        self.clock, self.lifetime, self.issued = clock, lifetime, 0

    def get_token(self, *scopes):
        assert scopes == ("https://storage.azure.com/.default",)
        self.issued += 1
        return AccessToken(f"token-{self.issued}", int(self.clock()) + self.lifetime)


def test_a_blob_is_read_with_one_authorised_get():
    http = FakeHttp((200, b"the bytes", {}))
    reader = BlobReader(URL, FakeCredential(), http=http)

    assert reader.read("chain/case-review/2026/11/26/0000000000000001.json") == b"the bytes"

    [(method, url, headers)] = http.requests
    assert method == "GET"
    assert url == f"{URL}/chain/case-review/2026/11/26/0000000000000001.json"
    assert headers["Authorization"] == "Bearer token-1"
    assert headers["x-ms-version"] and headers["x-ms-date"]


def test_a_blob_name_is_quoted_in_its_url():
    http = FakeHttp((200, b"", {}))

    BlobReader(URL, FakeCredential(), http=http).read("dossiers/case-review/2026/11/a b%.json")

    assert http.requests[0][1] == f"{URL}/dossiers/case-review/2026/11/a%20b%25.json"


def test_only_a_missing_blob_reads_as_nothing():
    http = FakeHttp(
        (404, b"", {"x-ms-error-code": "BlobNotFound"}),
        (404, b"", {"x-ms-error-code": "ContainerNotFound"}),
        (403, b"", {"x-ms-error-code": "AuthorizationPermissionMismatch"}),
        (500, b"", {}),
    )
    reader = BlobReader(URL, FakeCredential(), http=http)

    assert reader.read("chain/x") is None
    for code in ("ContainerNotFound", "AuthorizationPermissionMismatch", "500"):
        with pytest.raises(BlobReadFailed, match=code):
            reader.read("chain/x")


def test_the_token_is_kept_until_five_minutes_before_it_expires():
    now = [1_000_000.0]
    credential = FakeCredential(clock=lambda: now[0])
    http = FakeHttp(*[(200, b"", {})] * 3)
    reader = BlobReader(URL, credential, http=http, clock=lambda: now[0])

    reader.read("a")
    now[0] += 3600 - 301
    reader.read("a")
    assert credential.issued == 1

    now[0] += 2
    reader.read("a")
    assert credential.issued == 2
    assert http.requests[-1][2]["Authorization"] == "Bearer token-2"


def test_the_store_reads_through_the_reader_it_is_given(container):
    store = BlobStore(container, immutability="Locked", reader=lambda path: f"read {path}".encode())

    assert store.read("chain/x") == b"read chain/x"
    assert store.trust("trust/x") == b"read trust/x"


def test_a_token_is_sent_only_over_https():
    with pytest.raises(ValueError, match="HTTPS"):
        BlobReader("http://acme.blob.core.windows.net/evidence", FakeCredential(), http=FakeHttp())
