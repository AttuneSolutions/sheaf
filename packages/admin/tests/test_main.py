"""The command line: `sheaf-admin check|propose|proposals|withdraw|approve|whoami`."""

import io
import json

import pytest

from sheaf_admin import __main__ as cli
from sheaf_core import testing as t

from .conftest import APPROVER, PROPOSER


@pytest.fixture
def world(monkeypatch, make_world):
    world = make_world()
    world.token = PROPOSER
    seen = {}

    def connect(url, scope, credential):
        seen["gateway"] = (url, scope, credential)
        return world.client(world.token)

    def vault_key(vault_url, key_id, credential):
        seen["vault"] = (vault_url, key_id, credential)
        return t.witness_pem()

    monkeypatch.setattr(cli, "connect", connect)
    monkeypatch.setattr(cli, "vault_key", vault_key)
    for name in (
        "SHEAF_GATEWAY_URL",
        "SHEAF_GATEWAY_SCOPE",
        "SHEAF_KEY_VAULT_URL",
        "SHEAF_CREDENTIAL",
    ):
        monkeypatch.delenv(name, raising=False)
    world.seen = seen
    return world


GATEWAY = [
    "--gateway",
    "https://acme-sheaf-gateway.example",
    "--scope",
    "api://00000000-0000-0000-0000-000000000001/.default",
]
VAULT = ["--key-vault", "https://acme-sheaf-kv.vault.azure.net"]


def witnessed(world):
    """The interim witness of the mandate change waiting for one."""
    pending = world.gateway.state.pending
    world.witness({"seq": pending.seq, "hash": pending.config})


def proposed(world, path):
    world.token = PROPOSER
    assert cli.main(["propose", str(path), *GATEWAY, *VAULT]) == 0
    return world.proposals()[-1]["mandate"]


# -- check -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("command", [["check"], ["genesis", "check"]])
def test_check_reports_a_good_mandate_and_what_it_holds(input_file, capsys, command):
    assert cli.main([*command, str(input_file())]) == 0
    out = capsys.readouterr().out
    assert t.CHAIN in out
    assert "no problems" in out
    assert "acme-review-agent may open a dossier" in out  # in plain language
    assert t.KEY_ID in out  # and in full
    assert "propose" in out  # what the gateway checks next


def test_check_reports_each_problem(input_file, capsys):
    path = input_file(registry={"version": "9.9.9"})
    assert cli.main(["check", str(path)]) == 1
    assert "registry_unknown" in capsys.readouterr().out


def test_input_that_cannot_be_read_is_reported_without_a_traceback(tmp_path, capsys):
    assert cli.main(["check", str(tmp_path / "missing.json")]) == 1
    assert "missing.json" in capsys.readouterr().err


# -- propose, proposals, withdraw ------------------------------------------------------------------


def test_propose_stages_the_mandate_and_prints_its_fingerprint(input_file, world, capsys):
    assert cli.main(["propose", str(input_file()), *GATEWAY, *VAULT]) == 0

    [proposal] = world.proposals()
    out = capsys.readouterr().out
    assert proposal["mandate"] in out
    assert "pending" in out
    assert proposal["expires_at"] in out
    assert f"sheaf-admin approve {proposal['mandate']}" in out
    assert world.seen["vault"] == ("https://acme-sheaf-kv.vault.azure.net", t.KEY_ID, "cli")


def test_propose_may_say_when_it_expires(input_file, world):
    cli.main(["propose", str(input_file()), *GATEWAY, *VAULT, "--expires-in-days", "3"])

    assert world.proposals()[0]["expires_at"].startswith("2026-11-29")


def test_propose_needs_the_vault(input_file, world):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["propose", str(input_file()), *GATEWAY])
    assert stopped.value.code == 2
    assert world.proposals() == []


def test_proposals_lists_the_pending_ones(input_file, world, capsys):
    sha256 = proposed(world, input_file())
    capsys.readouterr()

    assert cli.main(["proposals", *GATEWAY]) == 0

    [line] = capsys.readouterr().out.strip().splitlines()
    for expected in (t.CHAIN, "2026.11.1", sha256, "pending", "acme-proposer-1"):
        assert expected in line


def test_proposals_may_list_every_status(input_file, world, capsys):
    sha256 = proposed(world, input_file())
    cli.main(["withdraw", sha256, *GATEWAY])
    capsys.readouterr()

    cli.main(["proposals", *GATEWAY])
    assert capsys.readouterr().out.strip() == "No proposals."
    cli.main(["proposals", *GATEWAY, "--status", "all", "--chain", t.CHAIN])
    assert "withdrawn" in capsys.readouterr().out


def test_withdraw_withdraws_a_pending_proposal(input_file, world, capsys):
    sha256 = proposed(world, input_file())

    assert cli.main(["withdraw", sha256, *GATEWAY]) == 0

    assert world.proposals()[0]["status"] == "withdrawn"
    assert "Withdrew" in capsys.readouterr().out


# -- approve ---------------------------------------------------------------------------------------


def test_approve_asks_for_the_chain_name_then_commits(input_file, world, monkeypatch, capsys):
    sha256 = proposed(world, input_file())
    world.token = APPROVER
    monkeypatch.setattr("sys.stdin", io.StringIO(t.CHAIN + "\n"))

    assert cli.main(["approve", sha256, *GATEWAY]) == 0

    out = capsys.readouterr().out
    assert "seq 1" in out
    assert "witness" in out  # what to do next: start the witness job
    assert "acme-review-agent may open a dossier" in out
    assert world.gateway.state.head[0] == 1


def test_approve_stops_when_the_chain_name_is_not_typed(input_file, world, monkeypatch, capsys):
    sha256 = proposed(world, input_file())
    world.token = APPROVER
    monkeypatch.setattr("sys.stdin", io.StringIO("yes\n"))

    assert cli.main(["approve", sha256, *GATEWAY]) == 1

    assert world.gateway.state.head is None
    assert "not confirmed" in capsys.readouterr().err


def test_approve_with_yes_does_not_ask(input_file, world):
    sha256 = proposed(world, input_file())
    world.token = APPROVER

    assert cli.main(["approve", sha256, *GATEWAY, "--yes"]) == 0
    assert world.gateway.state.head[0] == 1


def test_approving_an_approved_proposal_says_so(input_file, world, capsys):
    sha256 = proposed(world, input_file())
    world.token = APPROVER
    cli.main(["approve", sha256, *GATEWAY, "--yes"])
    witnessed(world)
    capsys.readouterr()

    assert cli.main(["approve", sha256, *GATEWAY, "--yes"]) == 0

    assert "already approved" in capsys.readouterr().out
    assert world.gateway.state.head[0] == 2  # the genesis and its interim witness


def test_a_proposer_who_may_not_approve_is_told_why(input_file, world, capsys):
    sha256 = proposed(world, input_file())

    assert cli.main(["approve", sha256, *GATEWAY, "--yes"]) == 1

    assert "bootstrap caller" in capsys.readouterr().err
    assert world.gateway.state.head is None


# -- signing in and reaching the gateway -----------------------------------------------------------


def test_the_gateway_and_vault_may_come_from_the_environment(input_file, world, monkeypatch):
    monkeypatch.setenv("SHEAF_GATEWAY_URL", "https://from-env.example")
    monkeypatch.setenv("SHEAF_GATEWAY_SCOPE", "api://from-env/.default")
    monkeypatch.setenv("SHEAF_KEY_VAULT_URL", "https://from-env.vault.azure.net")
    monkeypatch.setenv("SHEAF_CREDENTIAL", "managed")

    assert cli.main(["propose", str(input_file())]) == 0

    assert world.seen["gateway"] == (
        "https://from-env.example",
        "api://from-env/.default",
        "managed",
    )
    assert world.seen["vault"][2] == "managed"


def test_commands_that_reach_the_gateway_need_it_and_its_scope(world):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["proposals"])
    assert stopped.value.code == 2


def test_the_gateway_is_reached_over_https_only(input_file, world):
    # The caller's token goes with every request.
    plain = ["--gateway", "http://acme-sheaf-gateway.example", *GATEWAY[2:]]
    with pytest.raises(SystemExit) as stopped:
        cli.main(["propose", str(input_file()), *plain, *VAULT])
    assert stopped.value.code == 2
    assert world.proposals() == []


def test_the_credential_is_the_azure_cli_or_a_managed_identity(world, monkeypatch):
    built = []

    class Managed:
        def __init__(self, **kw):
            built.append(kw)

    monkeypatch.setattr("azure.identity.ManagedIdentityCredential", Managed)
    monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-4000-8000-0000000000c3")

    assert isinstance(cli.credential("managed"), Managed)
    assert built == [{"client_id": "00000000-0000-4000-8000-0000000000c3"}]
    with pytest.raises(SystemExit):
        cli.main(["whoami", *GATEWAY, "--credential", "password"])


def test_whoami_shows_the_identity_entries_must_name(world, capsys):
    world.token = APPROVER
    assert cli.main(["whoami", *GATEWAY]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown == {"id": APPROVER, "person": True, "roles": []}


# -- refusals --------------------------------------------------------------------------------------


def test_a_refusal_by_the_gateway_is_reported_with_its_problems(input_file, world, capsys):
    sha256 = proposed(world, input_file())
    world.token = APPROVER
    cli.main(["approve", sha256, *GATEWAY, "--yes"])
    witnessed(world)
    capsys.readouterr()

    assert cli.main(["withdraw", sha256, *GATEWAY]) == 1

    err = capsys.readouterr().err
    assert "409" in err
    assert "proposal_not_pending" in err


def test_a_refused_upload_explains_the_likely_causes(input_file, world, capsys):
    world.token = "acme-someone"

    assert cli.main(["propose", str(input_file()), *GATEWAY, *VAULT]) == 1

    err = capsys.readouterr().err
    assert "proposer" in err
    assert "SHEAF_BOOTSTRAP_CALLER" in err


def test_a_change_waiting_for_its_witness_explains_what_to_do(tmp_path, world, capsys):
    from .conftest import write_input

    sha256 = proposed(world, write_input(tmp_path))
    world.token = APPROVER
    cli.main(["approve", sha256, *GATEWAY, "--yes"])
    change = write_input(
        tmp_path, name="change.json", version="2026.11.2", gateway={"image": "sha256:" + "1" * 64}
    )
    world.token = PROPOSER
    capsys.readouterr()

    assert cli.main(["propose", str(change), *GATEWAY, *VAULT]) == 1

    err = capsys.readouterr().err
    assert "mandate_pending" in err
    assert "witness job" in err


def test_proposals_names_a_chain_it_could_not_read(input_file, world, capsys, monkeypatch):
    proposed(world, input_file())
    capsys.readouterr()
    world.gateway._halt("chain_corrupt", "the stored chain does not add up")

    assert cli.main(["proposals", *GATEWAY]) == 0

    out = capsys.readouterr()
    assert out.out.strip() == "No proposals."
    assert f"Not read: {t.CHAIN} is starting or halted" in out.err


@pytest.mark.parametrize(
    "code", ["trust_conflict", "gateway_starting", "proposal_unknown", "proposal_mismatch"]
)
def test_likely_refusals_come_with_a_hint(code):
    assert code in cli.HINTS
