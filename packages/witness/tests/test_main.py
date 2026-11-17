import pytest

from sheaf_witness.__main__ import settings_from


def test_the_job_refuses_to_start_without_its_settings():
    with pytest.raises(SystemExit, match="SHEAF_GATEWAY_URL"):
        settings_from({"SHEAF_CHAINS": "acme/case-review"})


def test_the_job_reads_its_settings_from_the_environment():
    env = {
        "SHEAF_CHAINS": "acme/case-review, acme/claims-triage",
        "SHEAF_GATEWAY_URL": "https://gateway.example",
        "SHEAF_GATEWAY_SCOPE": "api://sheaf-gateway/.default",
        "SHEAF_CONTAINER_URL": "https://account.blob.core.windows.net/evidence",
        "SHEAF_KEY_VAULT_URL": "https://vault.vault.azure.net",
        "SHEAF_WITNESS_IDENTITY": "acme-witness",
    }

    settings = settings_from(env)

    assert settings.chains == ("acme/case-review", "acme/claims-triage")
    assert settings.retry_for == 6 * 3600


def test_a_chain_that_fails_does_not_stop_the_others():
    from sheaf_witness.__main__ import witness_each

    seen = []

    def run(chain):
        seen.append(chain)
        if chain == "acme/case-review":
            raise RuntimeError("an authority is down")
        return [{"seq": 9}]

    failed = witness_each(("acme/case-review", "acme/claims-triage"), run)

    assert seen == ["acme/case-review", "acme/claims-triage"]
    assert failed == ["acme/case-review"]


def test_the_job_is_a_command_of_its_own():
    # So the job runs as `sheaf-witness`: `az containerapp job create --args "-m" ...` cannot
    # pass an argument that starts with a dash.
    from importlib.metadata import entry_points

    from sheaf_witness.__main__ import main

    [script] = [e for e in entry_points(group="console_scripts") if e.name == "sheaf-witness"]
    assert script.load() is main
