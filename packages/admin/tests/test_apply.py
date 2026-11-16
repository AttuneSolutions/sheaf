"""Applying a genesis to a running gateway: the approver's own sign-in, the witness key the vault
holds, a confirmation, then the uploads, the trust files and the config.changed."""

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_admin.genesis import GatewayClient, GatewayRefused, NotApplied, apply, load
from sheaf_core import paths
from sheaf_core import testing as t

NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)


def run(genesis, client, *, vault_key=None, confirm=lambda summary: True):
    return apply(
        genesis,
        client,
        vault_key=lambda key_id: t.witness_pem() if vault_key is None else vault_key,
        confirm=confirm,
        now=NOW,
    )


def test_apply_commits_the_genesis_and_its_interim_witness_puts_the_mandate_in_force(
    genesis_file, make_world
):
    world, genesis = make_world(), load(genesis_file())
    receipt = run(genesis, world.client())

    assert receipt["seq"] == 1
    assert world.gateway.state.pending.document == genesis.mandate
    for upload in genesis.uploads:
        assert world.store.read(paths.artefact(upload.sha256)) == upload.data
    for path, data in genesis.trust.items():
        assert world.store.trust(path) == data

    witness, tokens = t.attested("interim", 1, receipt["hash"])
    body = {
        "entry": t.witness_draft(witness),
        "tokens": {name: base64.b64encode(data).decode() for name, data in tokens.items()},
    }
    world.gateway.commit_witness(t.WITNESS["id"], json.dumps(body).encode())
    assert world.gateway.state.in_force.document == genesis.mandate
    assert world.gateway.state.in_force.config == receipt["hash"]


def test_the_confirmation_is_shown_what_is_about_to_be_committed(genesis_file, make_world):
    world, genesis, shown = make_world(), load(genesis_file()), []
    run(genesis, world.client(), confirm=lambda summary: shown.append(summary) or True)
    [summary] = shown
    for expected in (
        t.CHAIN,
        "2026.11.1",
        t.APPROVER["id"],
        genesis.uploads[0].sha256,
        t.KEY_ID,
        t.WITNESS["id"],
        "tsa-a (CH)",
        "tsa-b (JP)",
        "regulated-record P7Y",
        genesis.mandate["gateway"]["image"],
        "clear",
    ):
        assert expected in summary


def test_nothing_is_written_unless_confirmed(genesis_file, make_world):
    world, genesis = make_world(), load(genesis_file())
    with pytest.raises(NotApplied, match="not confirmed"):
        run(genesis, world.client(), confirm=lambda summary: False)
    assert world.stored(genesis) == [False, False, False]
    assert world.gateway.state.head is None


def test_a_genesis_with_problems_is_not_sent(genesis_file, make_world):
    world = make_world()
    genesis = load(genesis_file(registry={"version": "9.9.9"}))
    with pytest.raises(NotApplied) as stopped:
        run(genesis, world.client())
    assert "registry_unknown" in [p.code for p in stopped.value.problems]
    assert world.stored(genesis) == [False, False, False]


def test_someone_else_signed_in_is_refused_before_anything_is_written(genesis_file, make_world):
    world, genesis = make_world(), load(genesis_file())
    with pytest.raises(NotApplied, match="acme-someone-else"):
        run(genesis, world.client(token="acme-someone-else"))
    assert world.stored(genesis) == [False, False, False]


def test_an_applications_token_is_refused_the_approver_signs_in_as_a_person(
    genesis_file, make_world
):
    world, genesis = make_world(), load(genesis_file())
    with pytest.raises(NotApplied, match="person"):
        run(genesis, world.client(token="app:" + t.APPROVER["id"]))
    assert world.stored(genesis) == [False, False, False]


def test_a_witness_key_that_is_not_the_one_in_the_vault_is_refused(genesis_file, make_world):
    # Committed, it could never be used: the interim witness would not verify, the mandate would
    # never apply, and a locked container cannot take the genesis back.
    world, genesis = make_world(), load(genesis_file())
    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(NotApplied, match="vault"):
        run(genesis, world.client(), vault_key=pem)
    assert world.stored(genesis) == [False, False, False]


def test_the_vaults_key_may_be_written_another_way(genesis_file, make_world):
    # Key Vault's PEM and the one downloaded may differ in their bytes; the key is what counts.
    world, genesis = make_world(), load(genesis_file())
    pem = t.witness_pem().replace(b"\n", b"\r\n")
    assert run(genesis, world.client(), vault_key=pem)["seq"] == 1


def test_the_gateways_refusal_is_reported_with_its_problems(genesis_file, make_world):
    world, genesis = make_world(bootstrap="acme-another-approver"), load(genesis_file())
    with pytest.raises(GatewayRefused) as refused:
        run(genesis, world.client())
    assert refused.value.status == 403
    assert refused.value.problems[0]["code"] == "mandate_not_in_force"


class DropsTheCommit(GatewayClient):
    def commit(self, draft):
        raise httpx.ConnectError("the connection dropped")


def test_apply_run_again_after_it_stopped_partway_finishes_the_genesis(genesis_file, make_world):
    world, genesis = make_world(), load(genesis_file())
    dropped = DropsTheCommit(world.http, "http://testserver", token=lambda: t.APPROVER["id"])
    with pytest.raises(httpx.ConnectError):
        run(genesis, dropped)
    assert world.stored(genesis) == [True, True, True]
    assert world.gateway.state.head is None

    assert run(genesis, world.client())["seq"] == 1


def test_a_second_genesis_is_refused(genesis_file, make_world):
    world, genesis = make_world(), load(genesis_file())
    run(genesis, world.client())
    with pytest.raises(GatewayRefused):
        run(genesis, world.client())
    assert world.gateway.state.head[0] == 1
