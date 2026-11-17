import base64
import json
import threading
import time

import pytest

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_gateway.gateway import Gateway, Rejected, Settings
from sheaf_gateway.recovery import ChainCorrupt, replay
from sheaf_gateway.state import LeaseHeld, MemoryState
from sheaf_gateway.store import MemoryStore

from .test_api import Clock, FailingStore


def gateway(store, state, clock=None):
    g = Gateway(
        Settings(chain=t.CHAIN, bootstrap_caller=t.APPROVER["id"]),
        store,
        state=state,
        clock=clock or Clock(),
    )
    g.recover()
    return g


def run(g, caller, entry):
    return g.commit(caller, t.mandate_bytes(entry))[0]


def genesis(g):
    doc, approver = t.mandate_document(), t.APPROVER["id"]
    for data, kind, media_type in (
        (t.mandate_bytes(doc), "data.json", "application/json"),
        (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
        (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
    ):
        g.upload(
            approver,
            data,
            sha256=t.artefact_sha256(data),
            kind=kind,
            media_type=media_type,
            sensitivity="none",
            idempotency_key=t.artefact_sha256(data),
        )
    for path, data in t.trust_files(doc).items():
        g.put_trust(approver, path, data)
    config = run(g, approver, t.config_changed(doc))
    witness, tokens = t.attested("interim", 1, config["hash"])
    body = {
        "entry": t.witness_draft(witness),
        "tokens": {n: base64.b64encode(d).decode() for n, d in tokens.items()},
    }
    g.commit_witness(t.WITNESS["id"], json.dumps(body).encode())
    for data in (t.REQUEST, t.RESPONSE):
        g.upload(
            t.AGENT["id"],
            data,
            sha256=t.artefact_sha256(data),
            kind="ai.exchange.raw",
            media_type="application/json",
            sensitivity="none",
            idempotency_key=t.artefact_sha256(data),
        )
    return config


def test_a_restarted_gateway_carries_on_from_the_stored_chain():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    config = genesis(first)
    run(first, t.AGENT["id"], t.opened(config["hash"]))
    run(first, t.AGENT["id"], t.ai_exchange())
    head = first.state.head
    state.release()

    second = gateway(store, state)

    assert second.state.head == head
    assert second.state.in_force.config == config["hash"]
    assert run(second, t.AGENT["id"], t.sealed(3, 2))["seq"] == head[0] + 1


def test_a_half_written_entry_is_finished_from_the_journal_on_restart():
    store, state = FailingStore(), MemoryState()
    first = gateway(store, state)
    config = genesis(first)
    store.ready = True
    with pytest.raises(Rejected):
        run(first, t.AGENT["id"], t.opened(config["hash"]))
    state.release()

    second = gateway(store, state)

    assert second.state.head[0] == 3
    assert state.read_journal() is None
    assert run(second, t.AGENT["id"], t.ai_exchange())["seq"] == 4


class FailsOnWitnessFiles(MemoryStore):
    """Fails once, on the first witness file, after the entry and segment record are written."""

    failed = False

    def put_blob(self, path, data, content_type):
        if path.startswith("witness/") and not self.failed:
            self.failed = True
            raise OSError("blob write failed")
        return super().put_blob(path, data, content_type)


def test_an_entry_already_in_the_chain_still_gets_its_witness_files_from_the_journal():
    store, state = FailsOnWitnessFiles(), MemoryState()
    first = gateway(store, state)
    with pytest.raises(Rejected):
        genesis(first)  # the interim witness: entry and segment record written, files not
    state.release()

    second = gateway(store, state)

    assert second.state.head[0] == 2
    assert state.read_journal() is None
    written = [paths.witness_interim(t.WORKFLOW, 1)] + [
        paths.interim_token(t.WORKFLOW, 1, name) for name, _ in t.AUTHORITIES
    ]
    assert all(path in store._files and path in store.retention for path in written)


def test_a_store_that_does_not_add_up_refuses_to_start():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    genesis(first)
    state.release()
    genesis_blob = paths.entry(paths.chain_dossier(t.WORKFLOW, first.clock()), 1)
    store._files[genesis_blob] = store._files[genesis_blob].replace(b'"version"', b'"versioN"', 1)

    with pytest.raises(ChainCorrupt):
        gateway(store, state)


class Slow(MemoryStore):
    """Each read takes a while, as a Blob read does; counts the most reads in flight at once."""

    def __init__(self):
        super().__init__()
        self._counting = threading.Lock()
        self.reading = self.most = 0

    def read(self, path):
        with self._counting:
            self.reading += 1
            self.most = max(self.most, self.reading)
        try:
            time.sleep(0.002)
            return super().read(path)
        finally:
            with self._counting:
                self.reading -= 1


def a_longer_chain(store, state, entries=20):
    g = gateway(store, state)
    config = genesis(g)
    run(g, t.AGENT["id"], t.opened(config["hash"]))
    for _ in range(entries):
        run(g, t.AGENT["id"], t.ai_exchange())
    state.release()
    return g


def test_a_restart_reads_several_blobs_at_a_time_and_rebuilds_the_same_chain():
    store, state = Slow(), MemoryState()
    head = a_longer_chain(store, state).state.head
    store.most = 0

    second = gateway(store, state)

    assert second.state.head == head
    assert store.most > 1
    assert list(replay(store, t.WORKFLOW, readers=8)) == list(replay(store, t.WORKFLOW, readers=1))


def test_reading_ahead_still_reports_the_first_fault_in_the_chain():
    store, state = MemoryStore(), MemoryState()
    first = a_longer_chain(store, state)
    head = first.state.head
    genesis_blob = paths.entry(paths.chain_dossier(t.WORKFLOW, first.clock()), 1)
    store._files[genesis_blob] = store._files[genesis_blob].replace(b'"version"', b'"versioN"', 1)
    last_record = paths.entry(paths.chain_segment(t.WORKFLOW, first.clock()), head[0])
    store._files[last_record] = b"not a segment record"

    with pytest.raises(ChainCorrupt) as error:
        gateway(store, state)

    assert str(error.value).startswith("seq 1:")


def test_a_second_gateway_cannot_take_the_lease():
    state = MemoryState()
    gateway(MemoryStore(), state)

    with pytest.raises(LeaseHeld):
        gateway(MemoryStore(), state)


def test_without_the_lease_the_gateway_commits_nothing():
    store, state = MemoryStore(), MemoryState()
    g = gateway(store, state)
    genesis(g)
    state.lose()

    with pytest.raises(Rejected) as refused:
        run(g, t.ADMIN["id"], t.notice(dossier=None, actor=t.ADMIN))

    assert "lease" in str(refused.value)


# -- idempotency receipts survive a restart (7.2 step 2) -------------------------------------


def notice_bytes():
    entry = t.notice(dossier=None, actor=t.ADMIN)
    return t.mandate_bytes(entry)


def test_a_retry_after_a_restart_gets_the_first_receipt():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    genesis(first)
    receipt, created = first.commit(t.ADMIN["id"], notice_bytes(), "retry-1")
    state.release()

    second = gateway(store, state)

    assert created is True
    assert second.commit(t.ADMIN["id"], notice_bytes(), "retry-1") == (receipt, False)
    assert second.state.head[0] == receipt["seq"]


def test_a_key_used_before_a_restart_is_not_used_for_another_entry():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    genesis(first)
    first.commit(t.ADMIN["id"], notice_bytes(), "retry-1")
    state.release()
    other = t.notice(dossier=None, actor=t.ADMIN)
    other["body"]["detail"] = "something else"

    with pytest.raises(Rejected) as refused:
        gateway(store, state).commit(t.ADMIN["id"], t.mandate_bytes(other), "retry-1")

    assert refused.value.status == 409


class LosesReceiptsOnce(MemoryState):
    """The entry is written, then keeping its receipt fails: the process dies there."""

    failed = False

    def write_receipt(self, name, data):
        if not self.failed:
            self.failed = True
            raise OSError("gateway-state write failed")
        super().write_receipt(name, data)


def test_a_receipt_lost_in_a_crash_is_kept_from_the_journal_on_restart():
    store, state = MemoryStore(), LosesReceiptsOnce()
    first = gateway(store, state)
    state.failed = True
    genesis(first)
    state.failed = False
    with pytest.raises(Rejected) as halted:
        first.commit(t.ADMIN["id"], notice_bytes(), "retry-1")
    assert halted.value.status == 503
    committed = first.state.head
    state.release()

    second = gateway(store, state)
    receipt, created = second.commit(t.ADMIN["id"], notice_bytes(), "retry-1")

    assert created is False
    assert (receipt["seq"], receipt["hash"]) == committed
    assert second.state.head == committed


class CannotReadReceipts(MemoryState):
    def read_receipt(self, name):
        raise OSError("gateway-state unreachable")


def test_a_keyed_commit_waits_while_the_receipts_cannot_be_read():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    genesis(first)
    head = first.state.head
    state.release()
    blind = CannotReadReceipts()
    blind._journal = state._journal
    second = gateway(store, blind)

    with pytest.raises(Rejected) as refused:
        second.commit(t.ADMIN["id"], notice_bytes(), "retry-1")

    assert refused.value.status == 503
    assert second.state.head == head
    assert run(second, t.ADMIN["id"], t.notice(dossier=None, actor=t.ADMIN))["seq"] == head[0] + 1


def test_an_upload_key_used_before_a_restart_names_the_same_artefact():
    store, state = MemoryStore(), MemoryState()
    first = gateway(store, state)
    approver = t.APPROVER["id"]
    declared = {"kind": "text.markdown", "media_type": "text/markdown", "sensitivity": "none"}
    first.upload(
        approver,
        t.INSTRUCTIONS,
        sha256=t.artefact_sha256(t.INSTRUCTIONS),
        idempotency_key="u1",
        **declared,
    )
    state.release()
    other = b"# Other\n"

    with pytest.raises(Rejected) as refused:
        gateway(store, state).upload(
            approver, other, sha256=t.artefact_sha256(other), idempotency_key="u1", **declared
        )

    assert refused.value.status == 409


def test_an_upload_whose_receipt_is_not_kept_asks_for_a_retry_and_the_retry_succeeds():
    store, state = MemoryStore(), LosesReceiptsOnce()
    g = gateway(store, state)
    upload = {
        "sha256": t.artefact_sha256(t.INSTRUCTIONS),
        "kind": "text.markdown",
        "media_type": "text/markdown",
        "sensitivity": "none",
        "idempotency_key": "u1",
    }

    with pytest.raises(Rejected) as refused:
        g.upload(t.APPROVER["id"], t.INSTRUCTIONS, **upload)
    assert refused.value.status == 503

    assert g.upload(t.APPROVER["id"], t.INSTRUCTIONS, **upload)[1] is False
