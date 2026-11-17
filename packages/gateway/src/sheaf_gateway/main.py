"""Start the gateway from the environment: `uvicorn --factory sheaf_gateway.main:create`.

    SHEAF_CHAINS             the tenant's chains, comma-separated: {tenant}/{workflow},...
    SHEAF_BOOTSTRAP_CALLER   the identity that may write each chain's genesis config.changed
    SHEAF_STORE              "azure", or "memory" to smoke-test the image (nothing survives)
    SHEAF_STORAGE_URL        azure: the storage account, https://{account}.blob.core.windows.net
    SHEAF_IMMUTABILITY       azure: "Locked" (the standard, section 4), or "Unlocked" to test
    SHEAF_IDENTIFIERS        "clear" or "pseudonymised", as the mandate declares (5.7)
    SHEAF_KEY_VAULT_URL      pseudonymised: the vault holding each person's pseudonym secret
    SHEAF_ENTRA_TENANT       the tenant's Entra ID tenant ID, whose tokens callers present
    SHEAF_ENTRA_AUDIENCE     the gateway's application (client) ID, the tokens' audience
    AZURE_CLIENT_ID          azure: the gateway's managed identity, if user-assigned

One gateway serves all of the tenant's chains (7.1). It answers at once and, in the background,
takes each chain's lease and rebuilds its state from the container (`Gateways.start`); a chain
the container does not hold unbroken is halted, and the others carry on. When it stops it
releases the leases. Without the two Entra settings it refuses every request.
"""

import logging
import os
import re
from collections.abc import Mapping

from fastapi import FastAPI

from sheaf_gateway.app import create_app
from sheaf_gateway.entra import EntraAuthenticator
from sheaf_gateway.gateway import Gateway, Gateways, Settings
from sheaf_gateway.hooks import Authenticator, refuse_all
from sheaf_gateway.pseudonyms import (
    KeyVaultPseudonyms,
    MemoryPseudonyms,
    Pseudonymiser,
    RecordedIdentities,
)
from sheaf_gateway.state import GatewayState, MemoryState
from sheaf_gateway.store import MemoryStore, Store

log = logging.getLogger("sheaf.gateway")


def pseudonyms_from(env: Mapping[str, str]) -> Pseudonymiser | None:
    identifiers = env.get("SHEAF_IDENTIFIERS")
    if identifiers not in ("clear", "pseudonymised"):
        raise RuntimeError('SHEAF_IDENTIFIERS is "clear" or "pseudonymised", as the mandate says')
    if identifiers == "clear":
        return None
    if env.get("SHEAF_STORE") == "memory":
        return MemoryPseudonyms()
    if not env.get("SHEAF_KEY_VAULT_URL"):
        raise RuntimeError("SHEAF_IDENTIFIERS=pseudonymised needs SHEAF_KEY_VAULT_URL")
    from azure.identity import ManagedIdentityCredential
    from azure.keyvault.secrets import SecretClient

    credential = ManagedIdentityCredential(client_id=env.get("AZURE_CLIENT_ID"))
    return KeyVaultPseudonyms(SecretClient(env["SHEAF_KEY_VAULT_URL"], credential))


def chains_from(env: Mapping[str, str]) -> list[str]:
    """`SHEAF_CHAINS`: the tenant's chains this gateway serves, comma-separated, in full."""
    chains = [chain.strip() for chain in env.get("SHEAF_CHAINS", "").split(",") if chain.strip()]
    if not chains or any(not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", chain) for chain in chains):
        raise RuntimeError("SHEAF_CHAINS names each chain in full, as tenant/workflow")
    return chains


def gateway_from(env: Mapping[str, str], pseudonyms: Pseudonymiser | None = None) -> Gateways:
    """One gateway for the tenant: every chain in `SHEAF_CHAINS`, over one store, each with its
    own lease and journal (7.1)."""
    chains = chains_from(env)
    kind = env.get("SHEAF_STORE")
    if kind == "memory":
        log.warning("SHEAF_STORE=memory: nothing written survives a restart")
        store: Store = MemoryStore()

        def state_for(workflow: str) -> GatewayState:
            return MemoryState()

    elif kind == "azure":
        missing = [
            name for name in ("SHEAF_STORAGE_URL", "SHEAF_IMMUTABILITY") if not env.get(name)
        ]
        if missing:
            raise RuntimeError(f"SHEAF_STORE=azure needs {', '.join(missing)}")
        from azure.identity import ManagedIdentityCredential
        from azure.storage.blob import BlobServiceClient

        from sheaf_gateway.azure import AzureState, BlobReader, BlobStore

        credential = ManagedIdentityCredential(client_id=env.get("AZURE_CLIENT_ID"))
        service = BlobServiceClient(env["SHEAF_STORAGE_URL"], credential=credential)
        evidence = service.get_container_client("evidence")
        store = BlobStore(
            evidence,
            immutability=env["SHEAF_IMMUTABILITY"],
            reader=BlobReader(evidence.url, credential).read,
        )
        state_container = service.get_container_client("gateway-state")

        def state_for(workflow: str) -> GatewayState:
            return AzureState(state_container, workflow)

    else:
        raise RuntimeError('SHEAF_STORE is "azure", or "memory" to smoke-test the image')
    gateways = Gateways(
        Gateway(settings, store, state=state_for(settings.workflow), pseudonyms=pseudonyms)
        for settings in (
            Settings(
                chain=chain,
                bootstrap_caller=env["SHEAF_BOOTSTRAP_CALLER"],
                identifiers=env.get("SHEAF_IDENTIFIERS", ""),
            )
            for chain in chains
        )
    )
    return gateways


def authenticator_from(
    env: Mapping[str, str], pseudonyms: Pseudonymiser | None = None
) -> Authenticator:
    tenant, audience = env.get("SHEAF_ENTRA_TENANT"), env.get("SHEAF_ENTRA_AUDIENCE")
    if tenant and audience:
        entra = EntraAuthenticator(tenant, audience)
        return entra if pseudonyms is None else RecordedIdentities(entra, pseudonyms)
    log.warning("SHEAF_ENTRA_TENANT and SHEAF_ENTRA_AUDIENCE are not set: every request is refused")
    return refuse_all


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO)
    # The Azure SDK logs every request and response at INFO, which would fill the log workspace.
    logging.getLogger("azure").setLevel(logging.WARNING)


def create() -> FastAPI:
    configure_logging()
    pseudonyms = pseudonyms_from(os.environ)
    return create_app(
        gateway_from(os.environ, pseudonyms),
        authenticate=authenticator_from(os.environ, pseudonyms),
    )
