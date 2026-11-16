import base64
import json

import pytest

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_gateway.gateway import Gateway, Rejected, Settings
from sheaf_gateway.recovery import ChainCorrupt
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
