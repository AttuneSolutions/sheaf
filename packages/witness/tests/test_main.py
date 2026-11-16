import pytest

from sheaf_witness.__main__ import settings_from


def test_the_job_refuses_to_start_without_its_settings():
    with pytest.raises(SystemExit, match="SHEAF_GATEWAY_URL"):
        settings_from({"SHEAF_CHAIN": "acme/case-review"})


def test_the_job_reads_its_settings_from_the_environment():
    env = {
        "SHEAF_CHAIN": "acme/case-review",
        "SHEAF_GATEWAY_URL": "https://gateway.example",
        "SHEAF_GATEWAY_SCOPE": "api://sheaf-gateway/.default",
        "SHEAF_CONTAINER_URL": "https://account.blob.core.windows.net/evidence",
        "SHEAF_KEY_VAULT_URL": "https://vault.vault.azure.net",
        "SHEAF_WITNESS_IDENTITY": "acme-witness",
    }

    settings = settings_from(env)

    assert settings.chain == "acme/case-review"
    assert settings.retry_for == 6 * 3600
