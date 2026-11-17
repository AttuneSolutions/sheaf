"""Run the witness job once: `python -m sheaf_witness`. Scheduled as an Azure Container Apps job
with its own managed identity (7.5), from the same image as the gateway."""

import logging
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version

log = logging.getLogger("sheaf_witness")

REQUIRED = (
    "SHEAF_CHAINS",
    "SHEAF_GATEWAY_URL",
    "SHEAF_GATEWAY_SCOPE",
    "SHEAF_CONTAINER_URL",
    "SHEAF_KEY_VAULT_URL",
    "SHEAF_WITNESS_IDENTITY",
)


@dataclass(frozen=True)
class JobSettings:
    chains: tuple[str, ...]
    gateway_url: str
    gateway_scope: str
    container_url: str
    key_vault_url: str
    identity: str
    retry_for: float


def settings_from(env: Mapping[str, str]) -> JobSettings:
    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        raise SystemExit(f"the witness job needs {', '.join(missing)}")
    return JobSettings(
        chains=tuple(c.strip() for c in env["SHEAF_CHAINS"].split(",") if c.strip()),
        gateway_url=env["SHEAF_GATEWAY_URL"],
        gateway_scope=env["SHEAF_GATEWAY_SCOPE"],
        container_url=env["SHEAF_CONTAINER_URL"],
        key_vault_url=env["SHEAF_KEY_VAULT_URL"],
        identity=env["SHEAF_WITNESS_IDENTITY"],
        retry_for=float(env.get("SHEAF_RETRY_SECONDS", 6 * 3600)),
    )


class BlobContainer:
    """The `evidence` container through the Azure SDK, read only."""

    def __init__(self, client) -> None:
        self.client = client

    def read(self, path: str) -> bytes | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            return self.client.download_blob(path).readall()
        except ResourceNotFoundError:
            return None

    def list(self, prefix: str) -> list[str]:
        return sorted(item.name for item in self.client.walk_blobs(name_starts_with=prefix))


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO)
    # The Azure SDK logs every request and response at INFO, which would fill the log workspace.
    logging.getLogger("azure").setLevel(logging.WARNING)


def main() -> None:
    configure_logging()
    settings = settings_from(os.environ)

    import httpx
    from azure.identity import ManagedIdentityCredential
    from azure.storage.blob import ContainerClient

    from sheaf_witness.catalogue import catalogue
    from sheaf_witness.job import GatewayClient, run_once
    from sheaf_witness.signer import key_vault_signer
    from sheaf_witness.stamp import Stamper

    credential = ManagedIdentityCredential(client_id=os.environ.get("AZURE_CLIENT_ID"))
    container = BlobContainer(
        ContainerClient.from_container_url(settings.container_url, credential=credential)
    )
    http = httpx.Client(timeout=60)

    def bearer() -> dict[str, str]:
        return {"Authorization": f"Bearer {credential.get_token(settings.gateway_scope).token}"}

    signers: dict[str, object] = {}

    def signer_for(key_id: str):
        if key_id not in signers:
            signers[key_id] = key_vault_signer(key_id, settings.key_vault_url, credential)
        return signers[key_id]

    intervals = {a.authority: a.min_interval_seconds for a in catalogue().values()}
    gateway = GatewayClient(http, settings.gateway_url, headers=bearer)
    stamper = Stamper(http, retry_for=settings.retry_for, min_interval=intervals)
    actor = {"kind": "system", "id": settings.identity, "version": version("sheaf-witness")}
    now = datetime.now(UTC)

    def run(chain: str) -> list[dict]:
        return run_once(
            container,
            gateway,
            signer_for=signer_for,
            stamper=stamper,
            chain=chain,
            actor=actor,
            now=now,
        )

    failed = witness_each(settings.chains, run)
    if failed:
        raise SystemExit(f"not witnessed: {', '.join(failed)}")


def witness_each(chains: Sequence[str], run: Callable[[str], list[dict]]) -> list[str]:
    """Witness each chain in turn. One that fails is logged and the others still run; the
    chains that failed are returned, so the job ends in failure and the next run retries them."""
    failed = []
    for chain in chains:
        try:
            for receipt in run(chain):
                log.info("%s: witness committed at seq %s", chain, receipt["seq"])
        except Exception:
            log.exception("%s: not witnessed", chain)
            failed.append(chain)
    return failed


if __name__ == "__main__":
    main()
