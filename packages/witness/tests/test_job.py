"""The witness job end to end: the real gateway, in memory, as the container and the API."""

from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.store import MemoryStore
from sheaf_witness.job import ChainBroken, GatewayClient, SubmissionRefused, run_once
from sheaf_witness.signer import LocalSigner
from sheaf_witness.stamp import Stamper


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


class Container:
    """The witness's read-only view of the container, over the gateway's memory store."""

    def __init__(self, store):
        self.store = store

    def read(self, path):
        try:
            return self.store.blob(path)
        except KeyError:
            return None

    def list(self, prefix):
        # One level, as a Blob listing with "/" as the delimiter.
        names = set(self.store._files)
        found = set()
        for name in names:
            if name.startswith(prefix):
                rest = name[len(prefix) :]
                found.add(prefix + rest.split("/")[0] + "/" if "/" in rest else name)
        return sorted(found)


class World:
    def __init__(self):
        self.store, self.clock = MemoryStore(), Clock()
        self.gateway = Gateway(
            Settings(chain=t.CHAIN, bootstrap_caller=t.APPROVER["id"]), self.store, clock=self.clock
        )
        self.gateway.recover()
        app = create_app(self.gateway, authenticate=lambda r: _caller(r))
        self.client = GatewayClient(
            TestClient(app), "http://gateway", headers=lambda: {"X-Test-Caller": t.WITNESS["id"]}
        )
        self.container = Container(self.store)
        self.down = set()
        self.signer = _test_signer()

        def tsa(request):
            name = request.url.host.split(".")[0]
            if name in self.down:
                return httpx.Response(503)
            at = self.clock.now
            return httpx.Response(200, content=t.authority(name).respond(request.content, at=at))

        self.stamper = Stamper(
            httpx.Client(transport=httpx.MockTransport(tsa)), retry_for=0, sleep=lambda s: None
        )

    def genesis(self):
        doc = t.mandate_document()
        approver = t.APPROVER["id"]
        for data, kind, media_type in (
            (t.mandate_bytes(doc), "data.json", "application/json"),
            (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
            (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
        ):
            self.gateway.upload(
                approver,
                data,
                sha256=t.artefact_sha256(data),
                kind=kind,
                media_type=media_type,
                sensitivity="none",
                idempotency_key=t.artefact_sha256(data),
            )
        for path, data in t.trust_files(doc).items():
            self.gateway.put_trust(approver, path, data)
        return self.commit(approver, t.config_changed(doc))

    def commit(self, caller, entry):
        return self.gateway.commit(caller, t.mandate_bytes(entry))[0]

    def run(self, at):
        self.clock.now = at
        return run_once(
            self.container,
            self.client,
            signer_for=lambda key_id: self.signer,
            stamper=self.stamper,
            chain=t.CHAIN,
            actor=t.WITNESS,
            now=at,
        )


def _caller(request):
    identity = request.headers.get("X-Test-Caller")
    return Caller(identity) if identity else None


def _test_signer():
    # The fixture mandate pins sheaf_core.testing's witness key.
    return LocalSigner(t.KEY_ID, t._witness_key())


@pytest.fixture
def world():
    return World()


def test_the_genesis_mandate_gets_its_interim_witness(world):
    config = world.genesis()

    receipts = world.run(datetime(2026, 11, 26, 9, 5, tzinfo=UTC))

    assert [r["seq"] for r in receipts] == [2]
    assert world.gateway.state.in_force.config == config["hash"]
    for name, _ in t.AUTHORITIES:
        assert world.container.read(paths.interim_token(t.WORKFLOW, 1, name)) is not None


def test_each_ended_day_is_witnessed_once_in_order(world):
    world.genesis()
    world.run(datetime(2026, 11, 26, 9, 5, tzinfo=UTC))
    world.commit(t.ADMIN["id"], t.notice(dossier=None, actor=t.ADMIN))

    first = world.run(datetime(2026, 11, 27, 0, 5, tzinfo=UTC))
    again = world.run(datetime(2026, 11, 27, 0, 10, tzinfo=UTC))
    later = world.run(datetime(2026, 11, 29, 0, 10, tzinfo=UTC))

    assert len(first) == 1 and again == [] and len(later) == 2
    day = world.container.read(paths.witness_daily(t.WORKFLOW, date(2026, 11, 26)))
    assert b'"last_seq":3' in day
    assert world.container.read(paths.witness_daily(t.WORKFLOW, date(2026, 11, 28))) is not None


def test_a_day_is_witnessed_even_when_an_authority_is_down(world):
    world.genesis()
    world.run(datetime(2026, 11, 26, 9, 5, tzinfo=UTC))
    world.down.add("tsa-b")

    (receipt,) = world.run(datetime(2026, 11, 27, 0, 5, tzinfo=UTC))

    assert receipt["seq"] == 3
    day = world.container.read(paths.witness_daily(t.WORKFLOW, date(2026, 11, 26)))
    assert b'"attested_count":1' in day


def test_the_job_never_signs_a_chain_it_has_not_followed(world):
    world.genesis()
    world.run(datetime(2026, 11, 26, 9, 5, tzinfo=UTC))
    day = paths.chain_segment(t.WORKFLOW, datetime(2026, 11, 26, tzinfo=UTC))
    del world.store._files[paths.entry(day, 1)]  # seq 1 is gone

    with pytest.raises(ChainBroken):
        world.run(datetime(2026, 11, 27, 0, 5, tzinfo=UTC))


# -- a gateway that is starting -----------------------------------------------------------------


def starting(retry_after):
    problems = [{"code": "gateway_starting", "path": "$", "detail": "starting"}]
    return httpx.Response(503, json={"problems": problems}, headers={"Retry-After": retry_after})


def answering(*responses, wait_for_start=60):
    queue, slept = list(responses), []
    client = GatewayClient(
        httpx.Client(transport=httpx.MockTransport(lambda request: queue.pop(0))),
        "http://gateway",
        headers=dict,
        wait_for_start=wait_for_start,
        sleep=slept.append,
    )
    return client, slept


def test_a_starting_gateway_is_asked_again_after_the_wait_it_names():
    receipt = {"seq": 3, "hash": "sha256:" + "0" * 64, "committed_at": "2026-11-26T00:10:00Z"}
    client, slept = answering(starting("2"), starting("1"), httpx.Response(201, json=receipt))

    assert client.submit({"type": "witness.daily"}, {}) == receipt
    assert slept == [2, 1]


def test_a_gateway_that_does_not_finish_starting_is_reported():
    client, slept = answering(*[starting("5")] * 5, wait_for_start=12)

    with pytest.raises(SubmissionRefused) as refused:
        client.submit({"type": "witness.daily"}, {})

    assert refused.value.status == 503
    assert slept == [5, 5]


def test_a_halted_gateway_is_not_asked_again():
    halted = [{"code": "gateway_halted", "path": "$", "detail": "a write failed"}]
    client, slept = answering(httpx.Response(503, json={"problems": halted}))

    with pytest.raises(SubmissionRefused):
        client.submit({"type": "witness.daily"}, {})

    assert slept == []
