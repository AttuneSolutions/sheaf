"""`GET /v1/status` (7.7): how each chain stands, for operators and readers, with no client data."""

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from sheaf_core import testing as t
from sheaf_core.digest import artefact_sha256
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Gateways, Settings
from sheaf_gateway.recovery import ChainCorrupt
from sheaf_gateway.state import MemoryState
from sheaf_gateway.store import MemoryStore

from .test_api import (
    BOOTSTRAP,
    Clock,
    commit,
    genesis,
    header_caller,
    upload,
    upload_examples,
)

OTHER = "acme/claims-triage"


class World:
    def __init__(self):
        self.clock, self.store = Clock(), MemoryStore()
        self.gateways = Gateways(
            Gateway(
                Settings(chain=chain, bootstrap_caller=BOOTSTRAP),
                self.store,
                clock=self.clock,
                state=MemoryState(),
            )
            for chain in (t.CHAIN, OTHER)
        )
        self.gateways.recover()
        self.client = TestClient(create_app(self.gateways, authenticate=header_caller))

    def status(self, caller="acme-operator", roles=("status",)):
        headers = {"X-Test-Caller": caller}
        if roles:
            headers["X-Test-Roles"] = ",".join(roles)
        return self.client.get("/v1/status", headers=headers)

    def chain(self, report, name=t.CHAIN):
        return next(c for c in report["chains"] if c["chain"] == name)


@pytest.fixture
def world():
    return World()


def test_status_is_read_under_the_status_role(world):
    assert world.status(roles=()).status_code == 403
    assert world.status().status_code == 200
    assert world.status(roles=("proposer",)).status_code == 200
    assert world.status(caller=BOOTSTRAP, roles=()).status_code == 200
    assert world.client.get("/v1/status").status_code == 401


def test_status_says_how_each_chain_stands(world):
    config = genesis(world.client)

    report = world.status().json()

    chain = world.chain(report)
    assert chain["state"] == "running" and chain["halted"] is None
    assert chain["lease_held"] is True
    assert chain["head"]["seq"] == 2
    mandate = chain["mandate"]["in_force"]
    assert mandate == {
        "version": t.mandate_document()["version"],
        "fingerprint": artefact_sha256(t.mandate_bytes(t.mandate_document())),
        "config": config["hash"],
        "seq": 1,
        "committed_at": config["committed_at"],
        "approved_by": t.APPROVER["id"],
    }
    assert chain["mandate"]["pending"] is None
    assert chain["mandate"]["proposals_pending"] == 0
    interim = chain["witness"]["interim"]
    assert (interim["seq"], interim["last_seq"]) == (2, 1)
    assert interim["attested"] == ["tsa-a", "tsa-b"]
    assert chain["witness"]["daily"] is None
    assert chain["witness"]["daily_overdue"] is False
    assert chain["started"]["seconds"] >= 0
    assert world.chain(report, OTHER)["mandate"]["in_force"] is None
    assert report["storage"] == {"immutability": None}


def test_a_daily_witness_is_overdue_eight_hours_after_its_day(world):
    genesis(world.client)
    world.clock.now = datetime(2026, 11, 27, 7, 59, tzinfo=UTC)
    assert world.chain(world.status().json())["witness"]["daily_overdue"] is False

    world.clock.now = datetime(2026, 11, 27, 8, 1, tzinfo=UTC)
    report = world.chain(world.status().json())

    assert report["witness"]["daily_overdue"] is True
    assert report["witness"]["daily_due_by"] == "2026-11-27T08:00:00.000Z"


def test_refusals_in_the_last_day_are_counted_by_code(world):
    genesis(world.client)
    for _ in range(2):
        commit(
            world.client,
            "acme-stranger",
            t.notice(dossier=None, actor={**t.ADMIN, "id": "acme-stranger"}),
        )
    world.client.get("/v1/me")

    refusals = world.status().json()["refusals"]

    assert refusals["last_24h"] == {"caller_unknown": 2, "unauthenticated": 1}


def test_status_holds_no_client_data(world):
    config = genesis(world.client)
    upload_examples(world.client)
    for data in (t.SOURCE,):
        upload(world.client, t.AGENT["id"], data, "record.snapshot", "application/json")
    commit(world.client, t.AGENT["id"], t.opened(config["hash"]))
    commit(world.client, t.AGENT["id"], t.ai_exchange())

    text = json.dumps(world.status().json())

    for secret in (
        t.DOSSIER,
        t.SUBJECT["id"],
        t.SUBJECT["system"],
        artefact_sha256(t.REQUEST),
        "Review the case",
        t.AGENT["id"],
        t.RETENTION["min_until"],
    ):
        assert secret not in text


def test_a_halted_chain_says_why_by_code_alone(world):
    gateway = world.gateways.chain(OTHER)
    from sheaf_gateway.gateway import _halt

    _halt(OTHER, gateway, ChainCorrupt(f"dossier {t.DOSSIER} was never opened"))

    report = world.chain(world.status().json(), OTHER)

    assert report["state"] == "halted"
    assert report["halted"] == {"code": "chain_corrupt"}
    assert t.DOSSIER not in json.dumps(world.status().json())


def test_status_is_read_while_every_chain_is_halted(world):
    for chain in (t.CHAIN, OTHER):
        world.gateways.chain(chain)._halt("chain_corrupt", "the stored chain does not add up")

    assert world.status(caller=t.PROPOSER["id"], roles=("proposer",)).status_code == 200
    assert world.status().status_code == 200


def test_a_flood_of_one_refusal_does_not_push_out_the_others():
    from sheaf_gateway.app import Refusals

    now = [1_000_000.0]
    refusals = Refusals(clock=lambda: now[0])
    refusals.record("four_eyes")
    for _ in range(100_010):
        refusals.record("unauthenticated")

    counted = refusals.counts()["last_24h"]

    assert counted == {"four_eyes": 1, "unauthenticated": 100_010}
    now[0] += 25 * 3600
    assert refusals.counts()["last_24h"] == {}
