import logging

import pytest
from fastapi.testclient import TestClient

from sheaf_core import testing as t
from sheaf_gateway.entra import EntraAuthenticator
from sheaf_gateway.hooks import refuse_all
from sheaf_gateway.main import (
    authenticator_from,
    configure_logging,
    create,
    gateway_from,
    pseudonyms_from,
)
from sheaf_gateway.pseudonyms import MemoryPseudonyms

BASE = {
    "SHEAF_CHAINS": t.CHAIN,
    "SHEAF_BOOTSTRAP_CALLER": t.APPROVER["id"],
    "SHEAF_IDENTIFIERS": "clear",
}


def test_the_gateway_needs_a_store_named():
    with pytest.raises(RuntimeError, match="SHEAF_STORE"):
        gateway_from(BASE)


def test_azure_needs_the_account_and_a_chosen_immutability_mode():
    with pytest.raises(RuntimeError, match="SHEAF_STORAGE_URL, SHEAF_IMMUTABILITY"):
        gateway_from({**BASE, "SHEAF_STORE": "azure"})


def test_memory_starts_empty():
    gateways = gateway_from({**BASE, "SHEAF_STORE": "memory"})

    assert gateways.chain(t.CHAIN).state.head is None


def test_the_app_starts_its_chains_when_it_starts(monkeypatch):
    for name, value in {**BASE, "SHEAF_STORE": "memory"}.items():
        monkeypatch.setenv(name, value)
    app = create()

    with TestClient(app):
        assert app.state.gateway.wait_started(5)


def test_the_azure_sdk_logs_only_warnings():
    # At INFO it logs every request and response, which fills the log workspace under load.
    configure_logging()

    assert logging.getLogger("azure").level == logging.WARNING


def test_one_gateway_serves_every_chain_it_is_given():
    gateways = gateway_from(
        {**BASE, "SHEAF_STORE": "memory", "SHEAF_CHAINS": f"{t.CHAIN}, acme/claims-triage"}
    )

    assert gateways.chains == (t.CHAIN, "acme/claims-triage")


@pytest.mark.parametrize("chains", ["", " , ", "case-review", "acme/case-review,globex/claims"])
def test_the_chains_are_one_tenants_named_in_full(chains):
    with pytest.raises((RuntimeError, ValueError)):
        gateway_from({**BASE, "SHEAF_STORE": "memory", "SHEAF_CHAINS": chains})


def test_without_entra_settings_every_request_is_refused():
    assert authenticator_from({}) is refuse_all


def test_with_entra_settings_tokens_are_validated():
    authenticate = authenticator_from(
        {"SHEAF_ENTRA_TENANT": "tenant-id", "SHEAF_ENTRA_AUDIENCE": "client-id"}
    )

    assert isinstance(authenticate, EntraAuthenticator)
    assert authenticate.issuer == "https://login.microsoftonline.com/tenant-id/v2.0"


def test_the_identifiers_mode_is_chosen_not_defaulted():
    with pytest.raises(RuntimeError, match="SHEAF_IDENTIFIERS"):
        pseudonyms_from({"SHEAF_STORE": "memory"})


def test_pseudonymised_identifiers_need_a_key_vault():
    with pytest.raises(RuntimeError, match="SHEAF_KEY_VAULT_URL"):
        pseudonyms_from({"SHEAF_STORE": "azure", "SHEAF_IDENTIFIERS": "pseudonymised"})


def test_a_pseudonymised_memory_gateway_starts():
    env = {**BASE, "SHEAF_STORE": "memory", "SHEAF_IDENTIFIERS": "pseudonymised"}
    pseudonyms = pseudonyms_from(env)

    assert isinstance(pseudonyms, MemoryPseudonyms)
    assert gateway_from(env, pseudonyms).chain(t.CHAIN).state.head is None
