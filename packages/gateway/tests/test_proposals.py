"""Proposals (7.6): a mandate change is staged, checked as the commit would be, and committed only
by an approver, as the approval of a pending proposal."""

import copy
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from sheaf_core import testing as t
from sheaf_core.mandate import PARTS
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import REFUSAL_CODES, Gateway, Settings
from sheaf_gateway.state import MemoryState
from sheaf_gateway.store import MemoryStore

from .test_api import (
    BOOTSTRAP,
    PROPOSER,
    Clock,
    commit,
    header_caller,
    problems,
    propose,
    stage,
    submit_witness,
    upload_mandate,
)

DOC = t.mandate_document()
SHA = t.artefact_sha256(t.mandate_bytes(DOC))


class World:
    def __init__(self, state=None, store=None):
        self.clock, self.store = Clock(), store or MemoryStore()
        self.state = state or MemoryState()
        self.gateway = Gateway(
            Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP),
            self.store,
            clock=self.clock,
            state=self.state,
        )
        self.gateway.recover()
        self.client = TestClient(create_app(self.gateway, authenticate=header_caller))

    def get(self, path, caller=PROPOSER, roles=("proposer",), person="yes"):
        headers = {"X-Test-Caller": caller, "X-Test-Person": person}
        if roles:
            headers["X-Test-Roles"] = ",".join(roles)
        return self.client.get(path, headers=headers)

    def withdraw(self, sha, caller=PROPOSER, roles=("proposer",)):
        headers = {"X-Test-Caller": caller, "X-Test-Roles": ",".join(roles), "X-Test-Person": "yes"}
        return self.client.delete(f"/v1/proposals/{sha}", headers=headers)

    def genesis(self):
        """The genesis staged, approved by the bootstrap caller and put in force."""
        stage(self.client, DOC)
        config = commit(self.client, BOOTSTRAP, t.config_changed(DOC))
        assert config.status_code == 201, config.json()
        interim = submit_witness(self.client, *t.attested("interim", 1, config.json()["hash"]))
        assert interim.status_code == 201, interim.json()
        return config.json()

    def change(self, version, **policy):
        """A new mandate replacing the genesis, its config.changed, and its digest."""
        new = copy.deepcopy(DOC)
        new["version"] = version
        new["policy"].update(policy)
        previous = {"version": DOC["version"], "config": self.gateway.state.in_force.config}
        entry = t.config_changed(new, previous=previous, old=DOC)
        return new, entry, t.artefact_sha256(t.mandate_bytes(new))


@pytest.fixture
def world():
    return World()


# -- staging ------------------------------------------------------------------------------------


def test_a_proposal_is_kept_with_everything_its_approval_needs(world):
    staged = stage(world.client, DOC)

    proposal = staged["proposal"]
    entry = t.config_changed(DOC)
    assert proposal["status"] == "pending"
    assert proposal["chain"] == t.CHAIN and proposal["mandate"] == SHA
    assert proposal["version"] == DOC["version"] and proposal["previous"] is None
    assert proposal["changed"] == list(PARTS)
    assert proposal["parts"] == entry["body"]["parts"]
    assert proposal["artefacts"] == entry["artefacts"]
    assert proposal["proposed_by"] == t.PROPOSER
    assert proposal["reason"] == "genesis"
    assert proposal["expires_at"] > proposal["proposed_at"]


def test_a_proposal_expires_after_fourteen_days_unless_it_says_otherwise(world):
    upload_mandate(world.client, DOC, caller=PROPOSER, roles=("proposer",))
    proposal = propose(world.client, DOC, expires_in_days=2).json()["proposal"]

    assert proposal["expires_at"][:10] == "2026-11-28"
    too_long = propose(world.client, {**DOC, "version": "x"}, expires_in_days=91)
    assert (too_long.status_code, problems(too_long)) == (422, ["proposal_invalid"])


def test_only_a_proposer_or_an_approver_stages_a_change(world):
    upload_mandate(world.client, DOC, caller=PROPOSER, roles=("proposer",))

    stranger = propose(world.client, DOC, caller="acme-someone", roles=())

    assert (stranger.status_code, problems(stranger)) == (403, ["caller_unknown"])
    assert propose(world.client, DOC, caller=BOOTSTRAP, roles=()).status_code == 201


def test_a_proposal_is_checked_as_its_commit_would_be(world):
    missing = propose(world.client, DOC)
    assert (missing.status_code, problems(missing)) == (422, ["artefact_unknown"])

    upload_mandate(world.client, DOC, caller=PROPOSER, roles=("proposer",))
    broken = copy.deepcopy(DOC)
    broken["witness_key"]["public_key_sha256"] = "0" * 64
    upload_mandate(world.client, broken, caller=PROPOSER, roles=("proposer",))
    response = propose(world.client, broken)

    assert response.status_code == 422
    assert problems(response) == ["trust_missing"]


def test_staging_the_same_proposal_again_returns_it(world):
    first = stage(world.client, DOC)

    again = propose(world.client, DOC)

    assert again.status_code == 200
    assert again.json()["proposal"] == first["proposal"]
    other = propose(world.client, DOC, reason="another reason")
    assert (other.status_code, problems(other)) == (409, ["proposal_exists"])


# -- committing a mandate change ----------------------------------------------------------------


def test_a_mandate_change_is_committed_only_as_the_approval_of_a_proposal(world):
    upload_mandate(world.client, DOC)

    refused = commit(world.client, BOOTSTRAP, t.config_changed(DOC))

    assert (refused.status_code, problems(refused)) == (403, ["proposal_required"])


def test_an_approved_proposal_names_its_entry(world):
    stage(world.client, DOC)
    config = commit(world.client, BOOTSTRAP, t.config_changed(DOC)).json()

    proposal = world.get(f"/v1/proposals/{SHA}").json()["proposal"]

    assert proposal["status"] == "approved"
    assert proposal["approved"] == {
        "seq": 1,
        "hash": config["hash"],
        "committed_at": config["committed_at"],
        "by": t.APPROVER,
    }


def test_the_entry_must_be_the_proposals_approval(world):
    stage(world.client, DOC)
    entry = t.config_changed(DOC, proposed_by={"kind": "person", "id": "acme-someone"})

    response = commit(world.client, BOOTSTRAP, entry)

    assert (response.status_code, problems(response)) == (422, ["proposal_mismatch"])
    entry = t.config_changed(DOC)
    entry["body"]["reason"] = "not what was proposed"
    response = commit(world.client, BOOTSTRAP, entry)
    assert (response.status_code, problems(response)) == (422, ["proposal_mismatch"])


def test_a_withdrawn_proposal_is_not_approved(world):
    stage(world.client, DOC)

    withdrawn = world.withdraw(SHA)
    response = commit(world.client, BOOTSTRAP, t.config_changed(DOC))

    assert withdrawn.status_code == 200
    assert withdrawn.json()["proposal"]["status"] == "withdrawn"
    assert withdrawn.json()["proposal"]["withdrawn_by"] == t.PROPOSER
    assert (response.status_code, problems(response)) == (409, ["proposal_not_pending"])


def test_an_expired_proposal_is_not_approved(world):
    stage(world.client, DOC)
    world.clock.now += timedelta(days=15)

    response = commit(world.client, BOOTSTRAP, t.config_changed(DOC))

    assert (response.status_code, problems(response)) == (409, ["proposal_not_pending"])
    assert world.get(f"/v1/proposals/{SHA}").json()["proposal"]["status"] == "expired"


def test_a_withdrawn_or_expired_proposal_may_be_staged_again(world):
    stage(world.client, DOC)
    world.withdraw(SHA)

    again = propose(world.client, DOC)

    assert again.status_code == 201
    assert again.json()["proposal"]["status"] == "pending"


def test_under_four_eyes_whoever_proposed_does_not_approve(world):
    upload_mandate(world.client, DOC)
    propose(world.client, DOC, caller=BOOTSTRAP, roles=())
    entry = t.config_changed(DOC, proposed_by=t.APPROVER)

    response = commit(world.client, BOOTSTRAP, entry)

    assert (response.status_code, problems(response)) == (422, ["four_eyes"])


def test_a_proposal_staged_before_another_change_is_superseded(world):
    world.genesis()
    first, first_entry, first_sha = world.change("2026.11.2", four_eyes=False)
    second, second_entry, second_sha = world.change("2026.11.3", source_capture="copy")
    for doc in (first, second):
        stage(world.client, doc, reason="new mandate")

    assert commit(world.client, BOOTSTRAP, first_entry).status_code == 201
    refused = commit(world.client, BOOTSTRAP, second_entry)

    statuses = {p["mandate"]: p["status"] for p in world.get("/v1/proposals").json()["proposals"]}
    assert statuses == {SHA: "approved", first_sha: "approved", second_sha: "superseded"}
    assert (refused.status_code, problems(refused)) == (409, ["proposal_not_pending"])


def test_nothing_is_staged_while_a_change_waits_for_its_witness(world):
    world.genesis()
    first, first_entry, _ = world.change("2026.11.2", four_eyes=False)
    stage(world.client, first, reason="new mandate")
    assert commit(world.client, BOOTSTRAP, first_entry).status_code == 201
    second, _, _ = world.change("2026.11.3", source_capture="copy")
    upload_mandate(world.client, second, caller=PROPOSER, roles=("proposer",))

    response = propose(world.client, second, reason="new mandate")

    assert (response.status_code, problems(response)) == (422, ["mandate_pending"])


def test_a_proposer_may_withdraw_only_their_own(world):
    stage(world.client, DOC)

    other = world.withdraw(SHA, caller="acme-proposer-2")

    assert (other.status_code, problems(other)) == (403, ["caller_unknown"])
    assert world.withdraw(SHA, caller=BOOTSTRAP, roles=()).status_code == 200


# -- reading proposals --------------------------------------------------------------------------


def test_proposals_are_read_by_proposers_and_approvers_only(world):
    stage(world.client, DOC)

    assert world.get("/v1/proposals", caller="acme-someone", roles=()).status_code == 403
    assert world.get(f"/v1/proposals/{SHA}", caller="acme-someone", roles=()).status_code == 403
    assert world.get("/v1/proposals", caller=BOOTSTRAP, roles=()).status_code == 200


def test_proposals_are_listed_by_chain_and_status(world):
    stage(world.client, DOC)

    pending = world.get(f"/v1/proposals?chain={t.CHAIN}&status=pending").json()["proposals"]
    approved = world.get("/v1/proposals?status=approved").json()["proposals"]

    assert [p["mandate"] for p in pending] == [SHA]
    assert approved == []
    unknown = world.get("/v1/proposals?status=nonsense")
    assert (unknown.status_code, problems(unknown)) == (422, ["proposal_invalid"])


def test_a_proposal_is_read_with_its_mandate_and_whether_the_caller_may_approve(world):
    stage(world.client, DOC)

    as_proposer = world.get(f"/v1/proposals/{SHA}").json()
    as_approver = world.get(f"/v1/proposals/{SHA}", caller=BOOTSTRAP, roles=()).json()

    assert as_proposer["mandate"] == DOC
    assert as_proposer["previous_mandate"] is None
    assert as_proposer["caller"]["may_approve"] is False
    assert as_approver["caller"] == {
        "id": BOOTSTRAP,
        "may_approve": True,
        "role": None,
        "refusal": None,
        "refusal_code": None,
    }
    assert world.get(f"/v1/proposals/{'0' * 64}").status_code == 404


def test_after_genesis_an_approver_approves_under_the_role_that_grants_it(world):
    world.genesis()
    new, _, sha = world.change("2026.11.2", four_eyes=False)
    stage(world.client, new, reason="new mandate")

    view = world.get(f"/v1/proposals/{sha}", caller="acme-approver-2", roles=("approver",))
    system = world.get(f"/v1/proposals/{sha}", caller=BOOTSTRAP, roles=(), person="no")

    assert view.json()["caller"]["may_approve"] is True
    assert view.json()["caller"]["role"] == "approver"
    assert view.json()["previous_mandate"] == DOC
    assert view.json()["proposal"]["previous"]["mandate"] == SHA
    assert system.json()["caller"]["may_approve"] is False


def test_whoever_proposed_is_told_they_may_not_approve_under_four_eyes(world):
    world.genesis()
    new, _, sha = world.change("2026.11.2", source_capture="copy")
    stage(world.client, new, reason="new mandate")

    view = world.get(f"/v1/proposals/{sha}", caller=PROPOSER, roles=("proposer", "approver"))

    assert view.json()["caller"]["may_approve"] is False
    assert "four eyes" in view.json()["caller"]["refusal"]
    assert view.json()["caller"]["refusal_code"] == "four_eyes"


def test_proposals_survive_a_restart(world):
    stage(world.client, DOC)
    world.gateway.close()

    restarted = World(state=world.state, store=world.store)

    assert restarted.get(f"/v1/proposals/{SHA}").json()["proposal"]["status"] == "pending"


def test_the_genesis_approver_reads_their_proposal_while_it_waits_for_its_witness(world):
    stage(world.client, DOC)
    assert commit(world.client, BOOTSTRAP, t.config_changed(DOC)).status_code == 201

    view = world.get(f"/v1/proposals/{SHA}", caller=BOOTSTRAP, roles=())

    assert view.status_code == 200
    assert view.json()["proposal"]["status"] == "approved"
    assert view.json()["caller"]["refusal_code"] == "proposal_not_pending"


def test_a_refusal_comes_with_a_code(world):
    stage(world.client, DOC)

    proposer = world.get(f"/v1/proposals/{SHA}").json()["caller"]
    system = world.get(f"/v1/proposals/{SHA}", caller=BOOTSTRAP, roles=(), person="no").json()

    assert proposer["refusal_code"] == "not_bootstrap"
    assert system["caller"]["refusal_code"] == "not_a_person"
    assert "not_an_approver" in REFUSAL_CODES and "mandate_pending" in REFUSAL_CODES


# -- a chain that is not running ------------------------------------------------------------------


class TwoChains:
    """acme/case-review and acme/claims-triage behind one gateway; the second is halted or still
    starting, so whether it holds a proposal cannot be known."""

    def __init__(self, other):
        from sheaf_gateway.gateway import Gateways

        self.store = MemoryStore()
        self.mine = Gateway(Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP), self.store)
        self.other = Gateway(
            Settings(chain="acme/claims-triage", bootstrap_caller=BOOTSTRAP), self.store
        )
        self.mine.recover()
        if other == "halted":
            self.other.recover()
            self.other._halt("chain_corrupt", "the stored chain does not add up")
        else:
            self.other._started.clear()
            self.other.start_wait = 0
        self.client = TestClient(
            create_app(Gateways([self.mine, self.other]), authenticate=header_caller)
        )

    def get(self, path, method="get"):
        headers = {"X-Test-Caller": PROPOSER, "X-Test-Roles": "proposer", "X-Test-Person": "yes"}
        return getattr(self.client, method)(path, headers=headers)


@pytest.mark.parametrize(
    ("other", "status", "code"),
    [("halted", 503, "gateway_halted"), ("starting", 503, "gateway_starting")],
)
def test_a_proposal_not_found_while_a_chain_is_not_running_is_unavailable_not_unknown(
    other, status, code
):
    world = TwoChains(other)
    stage(world.client, DOC)

    found = world.get(f"/v1/proposals/{SHA}")
    unknown = world.get(f"/v1/proposals/{'0' * 64}")
    withdrawn = world.get(f"/v1/proposals/{'0' * 64}", method="delete")

    assert found.status_code == 200
    assert (unknown.status_code, problems(unknown)) == (status, [code])
    assert (withdrawn.status_code, problems(withdrawn)) == (status, [code])
    if other == "starting":
        assert unknown.headers["Retry-After"] == "5"


def test_a_listing_names_the_chains_it_could_not_read(world):
    two = TwoChains("halted")
    stage(two.client, DOC)

    listing = two.get("/v1/proposals").json()

    assert [p["mandate"] for p in listing["proposals"]] == [SHA]
    assert listing["unavailable"] == ["acme/claims-triage"]
    assert world.get("/v1/proposals").json()["unavailable"] == []


def test_a_mandate_approved_in_the_past_may_be_staged_again_to_return_to_it(world):
    world.genesis()
    first, first_entry, first_sha = world.change("2026.11.2", four_eyes=False)
    stage(world.client, first, reason="new mandate")
    config = commit(world.client, BOOTSTRAP, first_entry).json()
    assert (
        submit_witness(world.client, *t.attested("interim", 3, config["hash"])).status_code == 201
    )

    # Back to the genesis mandate's exact bytes, which were approved once already.
    back = propose(world.client, DOC, reason="return to the first mandate")

    assert back.status_code == 201, back.json()
    assert back.json()["proposal"]["status"] == "pending"
    assert back.json()["proposal"]["previous"]["mandate"] == first_sha


def test_a_proposal_approved_and_still_the_latest_is_not_staged_again(world):
    stage(world.client, DOC)
    commit(world.client, BOOTSTRAP, t.config_changed(DOC))

    again = propose(world.client, DOC, reason="once more")

    assert again.status_code in (409, 422)
