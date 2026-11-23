"""Staging a mandate change as a proposal, and approving one, against a running gateway: the
person's (or workload's) own sign-in, the witness key the vault holds, a confirmation, and the
uploads, trust files, proposal and config.changed."""

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_admin.actions import NotApplied, approve, propose, render
from sheaf_admin.client import GatewayClient, GatewayRefused
from sheaf_admin.staging import load
from sheaf_core import paths
from sheaf_core import testing as t

from .conftest import APPROVER, NOW, PROPOSER, write_input


def stage(staged, client, *, vault_key=None, **kw):
    return propose(
        staged,
        client,
        vault_key=lambda key_id: t.witness_pem() if vault_key is None else vault_key,
        now=NOW,
        **kw,
    )


def approved(world, staged, client, *, confirm=lambda text, chain: True):
    return approve(staged.fingerprint, client, confirm=confirm, now=NOW)


def other_pem():
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


# -- proposing -------------------------------------------------------------------------------------


def test_propose_uploads_the_mandate_and_its_files_and_stages_it(input_file, make_world):
    world, staged = make_world(), load(input_file())

    proposal, created = stage(staged, world.client(PROPOSER))

    assert created is True
    assert proposal["status"] == "pending"
    assert proposal["mandate"] == staged.fingerprint
    assert proposal["proposed_by"] == {"kind": "person", "id": "acme-proposer-1"}
    for upload in staged.uploads:
        assert world.store.read(paths.artefact(upload.sha256)) == upload.data
    for path, data in staged.trust.items():
        assert world.store.trust(path) == data
    assert [p["mandate"] for p in world.proposals()] == [staged.fingerprint]
    assert world.gateway.state.head is None


def test_propose_again_returns_the_same_proposal(input_file, make_world):
    world, staged = make_world(), load(input_file())
    first, _ = stage(staged, world.client(PROPOSER))

    again, created = stage(staged, world.client(PROPOSER))

    assert (again, created) == (first, False)


def test_a_workload_may_propose(input_file, make_world):
    world, staged = make_world(), load(input_file())

    proposal, _ = stage(staged, world.client("app:acme-release-pipeline|proposer"))

    assert proposal["proposed_by"] == {"kind": "system", "id": "acme-release-pipeline"}


def test_propose_may_say_when_the_proposal_expires(input_file, make_world):
    world, staged = make_world(), load(input_file())

    proposal, _ = stage(staged, world.client(PROPOSER), expires_in_days=2)

    assert proposal["expires_at"].startswith("2026-11-28")


def test_a_mandate_with_problems_is_not_staged(input_file, make_world):
    world = make_world()
    staged = load(input_file(registry={"version": "9.9.9"}))

    with pytest.raises(NotApplied) as stopped:
        stage(staged, world.client(PROPOSER))

    assert "registry_unknown" in [p.code for p in stopped.value.problems]
    assert world.stored(staged) == [False, False, False]


def test_a_witness_key_that_is_not_the_one_in_the_vault_is_refused(input_file, make_world):
    # Approved, it could never be used: the interim witness would not verify, the mandate would
    # never apply, and the chain would take no other change while it waited.
    world, staged = make_world(), load(input_file())

    with pytest.raises(NotApplied, match="vault"):
        stage(staged, world.client(PROPOSER), vault_key=other_pem())

    assert world.stored(staged) == [False, False, False]
    assert world.proposals() == []


def test_the_vaults_key_may_be_written_another_way(input_file, make_world):
    # Key Vault's PEM and the one downloaded may differ in their bytes; the key is what counts.
    world, staged = make_world(), load(input_file())
    pem = t.witness_pem().replace(b"\n", b"\r\n")

    assert stage(staged, world.client(PROPOSER), vault_key=pem)[0]["status"] == "pending"


def test_a_caller_who_may_not_stage_is_refused_by_the_gateway(input_file, make_world):
    world, staged = make_world(), load(input_file())

    with pytest.raises(GatewayRefused) as refused:
        stage(staged, world.client("acme-someone"))

    assert refused.value.status == 403
    assert world.proposals() == []


class DropsThePropose(GatewayClient):
    def propose(self, request):
        raise httpx.ConnectError("the connection dropped")


def test_propose_run_again_after_it_stopped_partway_finishes_it(input_file, make_world):
    world, staged = make_world(), load(input_file())
    dropped = world.client(PROPOSER, cls=DropsThePropose)
    with pytest.raises(httpx.ConnectError):
        stage(staged, dropped)
    assert world.stored(staged) == [True, True, True]
    assert world.proposals() == []

    assert stage(staged, world.client(PROPOSER))[1] is True


# -- approving -------------------------------------------------------------------------------------


def test_the_bootstrap_caller_approves_the_genesis(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))

    receipt = approved(world, staged, world.client(APPROVER))

    assert receipt["seq"] == 1
    assert world.gateway.state.pending.document == staged.mandate
    assert world.gateway.state.pending.approved_by == APPROVER
    [proposal] = world.proposals()
    assert proposal["status"] == "approved"
    assert proposal["approved"]["seq"] == 1
    world.witness(receipt)
    assert world.gateway.state.in_force.config == receipt["hash"]


def test_the_approver_is_shown_what_they_approve(input_file, make_world):
    world, staged, shown = make_world(), load(input_file()), []
    stage(staged, world.client(PROPOSER))

    approved(
        world,
        staged,
        world.client(APPROVER),
        confirm=lambda text, chain: shown.append((text, chain)) or True,
    )

    [(text, chain)] = shown
    assert chain == t.CHAIN
    for expected in (
        staged.fingerprint,
        t.CHAIN,
        "2026.11.1",
        "acme-proposer-1",
        "genesis",
        "acme-review-agent may open a dossier",
        "Whoever proposes a change to this mandate may not also approve it.",
        t.KEY_ID,
        t.WITNESS["id"],
        staged.mandate["gateway"]["image"],
    ):
        assert expected in text


def test_nothing_is_written_unless_confirmed(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))

    with pytest.raises(NotApplied, match="not confirmed"):
        approved(world, staged, world.client(APPROVER), confirm=lambda text, chain: False)

    assert world.gateway.state.head is None


def test_someone_who_may_not_approve_is_refused_before_anything_is_written(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))

    with pytest.raises(NotApplied, match="bootstrap caller"):
        approved(world, staged, world.client(PROPOSER))

    assert world.gateway.state.head is None


def test_under_four_eyes_the_proposer_does_not_approve(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(APPROVER))

    with pytest.raises(NotApplied, match="four eyes"):
        approved(world, staged, world.client(APPROVER))

    assert world.gateway.state.head is None


def test_an_applications_token_is_refused_the_approver_signs_in_as_a_person(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))

    with pytest.raises(NotApplied, match="person"):
        approved(world, staged, world.client("app:" + APPROVER))

    assert world.gateway.state.head is None


def test_approving_again_is_harmless(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))
    first = approved(world, staged, world.client(APPROVER))
    world.witness(first)

    again = approved(world, staged, world.client(APPROVER))

    assert again["already"] is True
    assert (again["seq"], again["hash"]) == (first["seq"], first["hash"])
    assert world.gateway.state.head[0] == 2  # the genesis and its interim witness


class Records(GatewayClient):
    committed: list = []

    def commit(self, draft):
        Records.committed.append(draft)
        return super().commit(draft)


def test_a_later_change_is_approved_under_the_role_that_grants_it(tmp_path, make_world):
    world = make_world()
    genesis = load(write_input(tmp_path))
    stage(genesis, world.client(PROPOSER))
    world.witness(approved(world, genesis, world.client(APPROVER)))
    change = load(
        write_input(
            tmp_path,
            name="change.json",
            reason="A new gateway image.",
            version="2026.11.2",
            gateway={"image": "sha256:" + "1" * 64},
        )
    )
    proposal, _ = stage(change, world.client(PROPOSER))
    Records.committed = []

    receipt = approved(world, change, world.client("acme-approver-2|approver", cls=Records))

    assert receipt["seq"] == 3
    [draft] = Records.committed
    assert draft["actor"] == {"kind": "person", "id": "acme-approver-2", "role": "approver"}
    assert draft["body"]["previous"] == {
        "version": "2026.11.1",
        "config": world.gateway.state.in_force.config,
    }
    assert draft["body"]["changed"] == ["gateway"]
    assert draft["body"]["reason"] == "A new gateway image."
    assert proposal["previous"]["mandate"] == genesis.fingerprint


def test_the_text_of_a_change_says_what_changes(tmp_path, make_world):
    world = make_world()
    genesis = load(write_input(tmp_path))
    stage(genesis, world.client(PROPOSER))
    world.witness(approved(world, genesis, world.client(APPROVER)))
    change = load(
        write_input(
            tmp_path,
            name="change.json",
            version="2026.11.2",
            gateway={"image": "sha256:" + "1" * 64},
        )
    )
    stage(change, world.client(PROPOSER))

    text = render(world.client(APPROVER).proposal(change.fingerprint))

    assert "Gateway software" in text
    assert "sha256:" + "1" * 64 in text
    assert t.mandate_document()["gateway"]["image"] in text


def test_an_unknown_proposal_is_reported_by_the_gateway(make_world):
    world = make_world()

    with pytest.raises(GatewayRefused) as refused:
        approve("0" * 64, world.client(APPROVER), confirm=lambda text, chain: True, now=NOW)

    assert refused.value.status == 404


# -- review fixes ---------------------------------------------------------------------------------


def test_propose_stops_before_uploading_for_a_caller_who_may_not_stage(input_file, make_world):
    world, staged = make_world(), load(input_file())

    with pytest.raises(GatewayRefused) as refused:
        stage(staged, world.client("acme-someone"))

    assert refused.value.status == 403
    assert all(world.store.info(upload.sha256) is None for upload in staged.uploads)


class Tampering(GatewayClient):
    """A gateway that shows one mandate and asks for the approval of another."""

    def proposal(self, sha256):
        view = super().proposal(sha256)
        view["mandate"] = {**view["mandate"], "version": "9999.1.1"}
        return view


def test_approve_refuses_when_what_is_shown_is_not_what_is_committed(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))
    shown = []

    with pytest.raises(NotApplied, match="differs"):
        approve(
            staged.fingerprint,
            world.client(APPROVER, cls=Tampering),
            confirm=lambda text, chain: shown.append(text) or True,
            now=NOW,
        )

    assert shown == [] and world.gateway.state.head is None


def test_approve_takes_the_time_after_the_person_confirms(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))
    times = iter([NOW.replace(hour=11)])

    approve(
        staged.fingerprint,
        world.client(APPROVER),
        confirm=lambda t_, c: True,
        now=lambda: next(times),
    )

    committed = world.store.read(world.store.list(paths.chain_dossier(t.WORKFLOW, NOW))[0])
    assert b'"observed_at":"2026-11-26T11:00:00.000Z"' in committed


def test_a_refusal_before_approving_carries_the_gateways_code(input_file, make_world):
    world, staged = make_world(), load(input_file())
    stage(staged, world.client(PROPOSER))

    with pytest.raises(NotApplied) as refused:
        approve(
            staged.fingerprint,
            world.client("acme-approver-2|proposer"),
            confirm=lambda *a: True,
            now=NOW,
        )

    assert [p.code for p in refused.value.problems] == ["not_bootstrap"]
