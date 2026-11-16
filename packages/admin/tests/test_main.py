"""The command line: `sheaf-admin genesis check|apply` and `sheaf-admin whoami`."""

import io
import json

import pytest

from sheaf_admin import __main__ as cli
from sheaf_core import testing as t


@pytest.fixture
def world(monkeypatch, make_world):
    world = make_world()
    seen = {}

    def connect(url, scope):
        seen["gateway"] = (url, scope)
        return world.client()

    def vault_key(vault_url, key_id):
        seen["vault"] = (vault_url, key_id)
        return t.witness_pem()

    monkeypatch.setattr(cli, "connect", connect)
    monkeypatch.setattr(cli, "vault_key", vault_key)
    for name in ("SHEAF_GATEWAY_URL", "SHEAF_GATEWAY_SCOPE", "SHEAF_KEY_VAULT_URL"):
        monkeypatch.delenv(name, raising=False)
    world.seen = seen
    return world


GATEWAY = [
    "--gateway",
    "https://acme-sheaf-gateway.example",
    "--scope",
    "api://00000000-0000-0000-0000-000000000001/.default",
    "--key-vault",
    "https://acme-sheaf-kv.vault.azure.net",
]


def test_check_reports_a_good_genesis_and_what_it_holds(genesis_file, capsys):
    assert cli.main(["genesis", "check", str(genesis_file())]) == 0
    out = capsys.readouterr().out
    assert t.CHAIN in out
    assert "no problems" in out


def test_check_reports_each_problem(genesis_file, capsys):
    path = genesis_file(registry={"version": "9.9.9"})
    assert cli.main(["genesis", "check", str(path)]) == 1
    assert "registry_unknown" in capsys.readouterr().out


def test_input_that_cannot_be_read_is_reported_without_a_traceback(tmp_path, capsys):
    assert cli.main(["genesis", "check", str(tmp_path / "missing.json")]) == 1
    assert "missing.json" in capsys.readouterr().err


def test_apply_asks_for_the_chain_name_then_commits(genesis_file, world, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(t.CHAIN + "\n"))
    assert cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY]) == 0
    out = capsys.readouterr().out
    assert "seq 1" in out
    assert "witness" in out  # what to do next: start the witness job
    assert world.gateway.state.head[0] == 1
    assert world.seen["vault"] == ("https://acme-sheaf-kv.vault.azure.net", t.KEY_ID)


def test_apply_stops_when_the_chain_name_is_not_typed(genesis_file, world, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("yes\n"))
    assert cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY]) == 1
    assert world.gateway.state.head is None
    assert "not confirmed" in capsys.readouterr().err


def test_apply_with_yes_does_not_ask(genesis_file, world):
    assert cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY, "--yes"]) == 0
    assert world.gateway.state.head[0] == 1


def test_the_gateway_and_vault_may_come_from_the_environment(genesis_file, world, monkeypatch):
    monkeypatch.setenv("SHEAF_GATEWAY_URL", "https://from-env.example")
    monkeypatch.setenv("SHEAF_GATEWAY_SCOPE", "api://from-env/.default")
    monkeypatch.setenv("SHEAF_KEY_VAULT_URL", "https://from-env.vault.azure.net")
    assert cli.main(["genesis", "apply", str(genesis_file()), "--yes"]) == 0
    assert world.seen["gateway"] == ("https://from-env.example", "api://from-env/.default")


def test_apply_needs_the_gateway_its_scope_and_the_vault(genesis_file, world):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["genesis", "apply", str(genesis_file()), "--yes"])
    assert stopped.value.code == 2


def test_a_refusal_by_the_gateway_is_reported_with_its_problems(genesis_file, world, capsys):
    cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY, "--yes"])
    assert cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY, "--yes"]) == 1
    err = capsys.readouterr().err
    assert "403" in err
    assert "mandate_not_in_force" in err


def test_whoami_shows_the_identity_entries_must_name(world, capsys):
    assert cli.main(["whoami", *GATEWAY[:4]]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown == {"id": t.APPROVER["id"], "person": True, "roles": []}


def test_the_gateway_is_reached_over_https_only(genesis_file, world):
    # The approver's token goes with every request.
    plain = ["--gateway", "http://acme-sheaf-gateway.example", *GATEWAY[2:]]
    with pytest.raises(SystemExit) as stopped:
        cli.main(["genesis", "apply", str(genesis_file()), *plain, "--yes"])
    assert stopped.value.code == 2
    assert world.gateway.state.head is None


def test_a_refused_upload_explains_the_two_likely_causes(genesis_file, world, capsys):
    cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY, "--yes"])
    cli.main(["genesis", "apply", str(genesis_file()), *GATEWAY, "--yes"])
    err = capsys.readouterr().err
    assert "SHEAF_BOOTSTRAP_CALLER" in err
    assert "already" in err
