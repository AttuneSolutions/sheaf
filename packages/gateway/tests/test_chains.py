"""One gateway serves all of a tenant's chains, one per workflow. Each keeps its own mandate,
sequence, lease and journal; they share the store, and a fault in one does not stop the others."""

import pytest
from fastapi.testclient import TestClient

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Gateways, Settings
from sheaf_gateway.state import MemoryState
from sheaf_gateway.store import MemoryStore

from .test_api import (
    BOOTSTRAP,
    Clock,
    FailingStore,
    commit,
    header_caller,
    stage,
    submit_witness,
    upload,
)

OTHER = "acme/claims-triage"


class World:
    def __init__(self, store=None, states=None):
        self.store = store or MemoryStore()
        self.states = states or {chain: MemoryState() for chain in (t.CHAIN, OTHER)}
        self.clock = Clock()
        self.gateways = Gateways(
            Gateway(
                Settings(chain=chain, bootstrap_caller=BOOTSTRAP),
                self.store,
                state=self.states[chain],
                clock=self.clock,
            )
            for chain in (t.CHAIN, OTHER)
        )
        self.gateways.recover()
        self.client = TestClient(create_app(self.gateways, authenticate=header_caller))

    def genesis(self, chain):
        doc = t.mandate_document(chain=chain)
        stage(self.client, doc)
        config = commit(self.client, BOOTSTRAP, {**t.config_changed(doc), "chain": chain})
        assert config.status_code == 201, config.json()
        interim = submit_witness(
            self.client, *t.attested("interim", 1, config.json()["hash"], chain=chain)
        )
        assert interim.status_code == 201, interim.json()
        return config.json()

    def open_dossier(self, chain, config):
        for data in (t.REQUEST, t.RESPONSE):
            response = upload(
                self.client, t.AGENT["id"], data, "ai.exchange.raw", "application/json", chain=chain
            )
            assert response.status_code in (200, 201), response.json()
        return commit(self.client, t.AGENT["id"], {**t.opened(config["hash"]), "chain": chain})


def test_each_chain_keeps_its_own_mandate_and_sequence():
    world = World()
    case_review = world.genesis(t.CHAIN)
    claims = world.genesis(OTHER)

    opened = world.open_dossier(t.CHAIN, case_review)

    assert (case_review["seq"], claims["seq"], opened.json()["seq"]) == (1, 1, 3)
    assert world.gateways.chain(OTHER).state.head[0] == 2
    day = world.clock()
    assert world.store.list(paths.chain_segment("claims-triage", day)) == [
        paths.entry(paths.chain_segment("claims-triage", day), seq) for seq in (1, 2)
    ]


@pytest.mark.parametrize("chain", ["acme/payments", "globex/case-review"])
def test_an_entry_for_a_chain_this_gateway_does_not_serve_is_refused(chain):
    world = World()

    response = commit(world.client, BOOTSTRAP, {**t.notice(dossier=None), "chain": chain})

    assert response.status_code == 422
    assert response.json()["problems"][0]["code"] == "chain_unknown"


@pytest.mark.parametrize("chain", [None, 7])
def test_an_entry_without_a_usable_chain_is_refused_for_what_is_wrong_with_it(chain):
    world = World()

    response = commit(world.client, BOOTSTRAP, {**t.notice(dossier=None), "chain": chain})

    assert response.status_code == 422
    assert response.json()["problems"][0]["path"] == "$.chain"


def test_an_upload_names_the_chain_whose_mandate_it_is_checked_against():
    world = World()
    world.genesis(t.CHAIN)

    served = upload(world.client, t.AGENT["id"], t.REQUEST, "ai.exchange.raw", "application/json")
    unknown = upload(
        world.client,
        t.AGENT["id"],
        t.REQUEST,
        "ai.exchange.raw",
        "application/json",
        chain="acme/payments",
    )
    # claims-triage has no mandate in force yet, so nothing but its mandate may be uploaded.
    early = upload(
        world.client, t.AGENT["id"], t.RESPONSE, "ai.exchange.raw", "application/json", chain=OTHER
    )

    assert served.status_code == 201, served.json()
    assert unknown.status_code == 422 and unknown.json()["problems"][0]["code"] == "chain_unknown"
    assert early.status_code == 403


def test_a_failed_write_halts_only_its_own_chain():
    world = World(store=FailingStore())
    case_review = world.genesis(t.CHAIN)
    claims = world.genesis(OTHER)
    world.store.ready = True

    failed = world.open_dossier(t.CHAIN, case_review)
    other = world.open_dossier(OTHER, claims)
    again = commit(world.client, t.AGENT["id"], {**t.ai_exchange(), "chain": t.CHAIN})

    assert failed.status_code == 503
    assert other.status_code == 201, other.json()
    assert again.status_code == 503


def test_a_chain_that_does_not_add_up_is_halted_and_the_others_carry_on():
    first = World()
    first.genesis(t.CHAIN)
    claims = first.genesis(OTHER)
    for state in first.states.values():
        state.release()
    genesis_blob = paths.entry(paths.chain_dossier(t.WORKFLOW, first.clock()), 1)
    first.store._files[genesis_blob] = first.store._files[genesis_blob].replace(
        b'"version"', b'"versioN"', 1
    )

    world = World(store=first.store, states=first.states)
    corrupt = commit(world.client, t.AGENT["id"], {**t.ai_exchange(), "chain": t.CHAIN})
    other = world.open_dossier(OTHER, claims)

    upload_to_corrupt = upload(
        world.client, t.AGENT["id"], t.TRACE, "trace.otel", "application/json", chain=t.CHAIN
    )

    assert corrupt.status_code == 503
    assert corrupt.json()["problems"][0]["code"] == "gateway_halted"
    assert other.status_code == 201, other.json()
    # A halted chain's state is not trusted for anything, uploads included.
    assert upload_to_corrupt.status_code == 503


def test_one_gateway_serves_one_tenant_and_each_chain_once():
    def gateway(chain):
        return Gateway(Settings(chain=chain, bootstrap_caller=BOOTSTRAP), MemoryStore())

    with pytest.raises(ValueError):
        Gateways([gateway(t.CHAIN), gateway("globex/claims-triage")])
    with pytest.raises(ValueError):
        Gateways([gateway(t.CHAIN), gateway(t.CHAIN)])
    with pytest.raises(ValueError):
        Gateways([])
