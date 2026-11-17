"""Starting and stopping. A gateway answers at once and takes each chain's lease in the background,
so a replacement can start beside the gateway it replaces; until it holds a chain's lease and has
rebuilt that chain, a request waits a little and is then refused with 503. A gateway that stops
releases its leases, so its replacement takes over at once rather than after the lease expires."""

import logging
import threading
import time

import pytest
from fastapi.testclient import TestClient

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Gateways, Rejected, Settings
from sheaf_gateway.state import MemoryState
from sheaf_gateway.store import MemoryStore

from .test_api import Clock, header_caller
from .test_recovery import genesis, run

OTHER = "acme/claims-triage"


def gateways(store, states, *, wait=0.05):
    clock = Clock()
    served = Gateways(
        Gateway(
            Settings(chain=chain, bootstrap_caller=t.APPROVER["id"]),
            store,
            state=state,
            clock=clock,
        )
        for chain, state in states.items()
    )
    served.retry = 0.01
    for chain in states:
        served.chain(chain).start_wait = wait
    return served


class Gate(MemoryState):
    """A lease that is not granted until the test opens the gate."""

    def __init__(self):
        super().__init__()
        self.open = threading.Event()

    def acquire(self):
        assert self.open.wait(5)
        super().acquire()


def refused(call):
    with pytest.raises(Rejected) as error:
        call()
    return error.value


def test_until_it_holds_the_lease_a_starting_gateway_refuses_and_says_when_to_retry():
    state = MemoryState()
    state.acquire()  # the gateway being replaced
    served = gateways(MemoryStore(), {t.CHAIN: state})

    served.start()
    error = refused(lambda: served.upload_limit(t.APPROVER["id"], "data.json", chain=t.CHAIN))

    assert error.status == 503
    assert error.problems[0].code == "gateway_starting"
    assert error.headers["Retry-After"]
    served.close()


def test_a_request_waits_while_its_chain_starts():
    gate = Gate()
    served = gateways(MemoryStore(), {t.CHAIN: gate}, wait=5)
    served.start()
    answers = []
    waiting = threading.Thread(
        target=lambda: answers.append(
            served.upload_limit(t.APPROVER["id"], "data.json", chain=t.CHAIN)
        )
    )
    waiting.start()
    waiting.join(0.1)

    assert waiting.is_alive()
    gate.open.set()
    waiting.join(5)
    assert answers and answers[0] > 0
    served.close()


def test_a_gateway_that_stops_hands_its_chains_to_the_one_replacing_it():
    store, states = MemoryStore(), {t.CHAIN: MemoryState(), OTHER: MemoryState()}
    old = gateways(store, states)
    old.recover()
    config = genesis(old.chain(t.CHAIN))
    run(old.chain(t.CHAIN), t.AGENT["id"], t.opened(config["hash"]))
    head = old.chain(t.CHAIN).state.head

    new = gateways(store, states)
    new.start()
    assert not new.wait_started(0.1)

    old.close()

    assert new.wait_started(5)
    assert new.chain(t.CHAIN).state.head == head
    assert run(new.chain(t.CHAIN), t.AGENT["id"], t.ai_exchange())["seq"] == head[0] + 1
    stopped = refused(lambda: run(old.chain(t.CHAIN), t.AGENT["id"], t.ai_exchange()))
    assert stopped.status == 503
    new.close()


def test_a_lease_granted_after_the_gateway_stopped_is_given_back():
    gate = Gate()
    served = gateways(MemoryStore(), {t.CHAIN: gate})
    served.start()

    served.close()
    gate.open.set()

    assert served.wait_started(5)
    replacement = gateways(MemoryStore(), {t.CHAIN: gate})
    replacement.recover()  # the lease is free again


class FailsOnce(MemoryStore):
    """A read fails once, partway through rebuilding a chain, as a Blob request can."""

    def __init__(self):
        super().__init__()
        self.reads_left = None
        self._counting = threading.Lock()

    def read(self, path):
        with self._counting:
            fail = False
            if self.reads_left is not None:
                self.reads_left -= 1
                if self.reads_left == 0:
                    self.reads_left, fail = None, True
        if fail:
            raise OSError("the read failed")
        return super().read(path)


def test_a_chain_that_fails_to_start_is_retried_from_scratch():
    store, state = FailsOnce(), MemoryState()
    old = gateways(store, {t.CHAIN: state})
    old.recover()
    config = genesis(old.chain(t.CHAIN))
    run(old.chain(t.CHAIN), t.AGENT["id"], t.opened(config["hash"]))
    head = old.chain(t.CHAIN).state.head
    old.close()

    store.reads_left = 3  # after the first entry is rebuilt
    new = gateways(store, {t.CHAIN: state})
    new.start()

    assert new.wait_started(5)
    assert store.reads_left is None
    assert new.chain(t.CHAIN).state.head == head
    assert run(new.chain(t.CHAIN), t.AGENT["id"], t.ai_exchange())["seq"] == head[0] + 1


class Paused(MemoryStore):
    """Reads stop at the `at`-th until the test lets them carry on."""

    def __init__(self):
        super().__init__()
        self.at = None
        self.reached, self.go = threading.Event(), threading.Event()
        self._counting, self._count = threading.Lock(), 0

    def read(self, path):
        with self._counting:
            self._count += 1
            pause = self._count == self.at
        if pause:
            self.reached.set()
            assert self.go.wait(5)
        return super().read(path)


def test_a_gateway_stopped_while_it_rebuilds_a_chain_gives_up_and_releases_the_lease(caplog):
    caplog.set_level(logging.INFO, "sheaf.gateway")
    store, state = Paused(), MemoryState()
    old = gateways(store, {t.CHAIN: state})
    old.recover()
    config = genesis(old.chain(t.CHAIN))
    run(old.chain(t.CHAIN), t.AGENT["id"], t.opened(config["hash"]))
    for _ in range(40):
        run(old.chain(t.CHAIN), t.AGENT["id"], t.ai_exchange())
    head = old.chain(t.CHAIN).state.head
    old.close()

    store.at = store._count + 10
    new = gateways(store, {t.CHAIN: state})
    new.start()
    assert store.reached.wait(5)
    stopping = threading.Thread(target=new.close)
    stopping.start()
    deadline = time.monotonic() + 5
    while not new.chain(t.CHAIN)._stopping.is_set() and time.monotonic() < deadline:
        time.sleep(0.001)
    store.go.set()
    stopping.join(5)

    assert not stopping.is_alive()
    assert new.wait_started(5)
    rebuilt = new.chain(t.CHAIN).state.head
    assert rebuilt is None or rebuilt[0] < head[0]
    assert "started at" not in caplog.text
    state.acquire()  # released on stopping, so free to take


def test_a_chain_that_does_not_add_up_is_halted_on_start_and_the_others_serve():
    store, states = MemoryStore(), {t.CHAIN: MemoryState(), OTHER: MemoryState()}
    old = gateways(store, states)
    old.recover()
    genesis(old.chain(t.CHAIN))
    old.close()
    blob = paths.entry(paths.chain_dossier(t.WORKFLOW, old.chain(t.CHAIN).clock()), 1)
    store._files[blob] = store._files[blob].replace(b'"version"', b'"versioN"', 1)

    new = gateways(store, states)
    new.start()

    assert new.wait_started(5)
    halted = refused(lambda: new.upload_limit(t.APPROVER["id"], "data.json", chain=t.CHAIN))
    assert halted.problems[0].code == "gateway_halted"
    assert new.upload_limit(t.APPROVER["id"], "data.json", chain=OTHER) > 0


def test_the_app_answers_while_it_starts_and_releases_its_leases_when_it_stops():
    state = MemoryState()
    state.acquire()  # the gateway being replaced
    served = gateways(MemoryStore(), {t.CHAIN: state})

    with TestClient(create_app(served, authenticate=header_caller)) as client:
        health = client.get("/healthz")
        busy = client.post(
            "/v1/entries",
            content=t.mandate_bytes(t.ai_exchange()),
            headers={"X-Test-Caller": t.AGENT["id"]},
        )
        state.release()  # the gateway being replaced has stopped
        assert served.wait_started(5)

    assert health.status_code == 200
    assert busy.status_code == 503
    assert busy.json()["problems"][0]["code"] == "gateway_starting"
    assert int(busy.headers["Retry-After"]) > 0
    state.acquire()  # released on stopping, so free to take
