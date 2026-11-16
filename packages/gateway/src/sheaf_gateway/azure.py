"""The `evidence` and `gateway-state` containers on Azure Blob Storage (section 4, 7.1).

Version-level immutability, locked before go-live. Every blob is a block blob written once; its
retention is set at write and only ever extended, through the whole of its last day. Append blobs
are not used: under version-level immutability Azure refuses appends and sealing once any policy
applies, as the live check of 16 November 2026 showed.
"""

import contextlib
import logging
import threading
import time as clock
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import ContentSettings, ImmutabilityPolicy

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo
from sheaf_core.canonical import strict_loads
from sheaf_gateway.state import LeaseHeld
from sheaf_gateway.store import BlobConflict

log = logging.getLogger("sheaf.gateway")

MODES = ("Locked", "Unlocked")


class BlobStore:
    def __init__(self, container: Any, *, immutability: str) -> None:
        if immutability not in MODES:
            raise ValueError(f"the immutability mode is one of {', '.join(MODES)}")
        self.container, self.immutability = container, immutability

    def _blob(self, path: str) -> Any:
        return self.container.get_blob_client(path)

    def info(self, sha256: str) -> ArtefactInfo | None:
        try:
            properties = self._blob(paths.artefact(sha256)).get_blob_properties()
        except ResourceNotFoundError:
            return None
        metadata = properties.metadata
        return ArtefactInfo(
            sha256=sha256,
            kind=metadata["kind"],
            media_type=properties.content_settings.content_type,
            bytes=properties.size,
            sensitivity=metadata["sensitivity"],
            declared_schema=metadata.get("declared_schema") or None,
        )

    def json(self, sha256: str) -> Any:
        data = self.read(paths.artefact(sha256))
        if data is None:
            raise KeyError(sha256)
        return strict_loads(data)

    def put_artefact(self, info: ArtefactInfo, data: bytes) -> bool:
        metadata = {"kind": info.kind, "sensitivity": info.sensitivity}
        if info.declared_schema:
            metadata["declared_schema"] = info.declared_schema
        try:
            self._blob(paths.artefact(info.sha256)).upload_blob(
                data,
                overwrite=False,
                content_settings=ContentSettings(content_type=info.media_type),
                metadata=metadata,
                tags={"kind": info.kind, "sensitivity": info.sensitivity},
            )
        except ResourceExistsError:
            return False
        return True

    def retain(self, path: str, until: date) -> None:
        expiry = datetime.combine(until + timedelta(days=1), time(0), UTC)
        blob = self._blob(path)
        current = blob.get_blob_properties().immutability_policy.expiry_time
        if current is not None and current >= expiry:
            return
        blob.set_immutability_policy(
            ImmutabilityPolicy(expiry_time=expiry, policy_mode=self.immutability)
        )

    def put_blob(self, path: str, data: bytes, content_type: str) -> bool:
        try:
            self._blob(path).upload_blob(
                data, overwrite=False, content_settings=ContentSettings(content_type=content_type)
            )
        except ResourceExistsError:
            if self.read(path) != data:
                raise BlobConflict(path) from None
            return False
        return True

    def read(self, path: str) -> bytes | None:
        try:
            return self._blob(path).download_blob().readall()
        except ResourceNotFoundError:
            return None

    def trust(self, path: str) -> bytes | None:
        return self.read(path) if path.startswith("trust/") else None

    def list(self, prefix: str) -> list[str]:
        return sorted(
            item.name for item in self.container.walk_blobs(name_starts_with=prefix, delimiter="/")
        )


class AzureState:
    """The chain-head lease, the journal and the idempotency receipts, in the `gateway-state`
    container. Receipts are under `receipts/{workflow}/`, apart from the lease and the journal,
    so a lifecycle rule can delete old ones by prefix (deployment guide, section 4)."""

    LEASE_SECONDS = 60

    def __init__(self, container: Any, workflow: str) -> None:
        self._container, self._workflow = container, workflow
        self._lease_blob = container.get_blob_client(f"chains/{workflow}/lease")
        self._journal = container.get_blob_client(f"chains/{workflow}/journal.json")
        self._lease: Any = None
        self._renewed = 0.0
        self._stop = threading.Event()

    def acquire(self, wait: float = LEASE_SECONDS + 10) -> None:
        """Take the lease, waiting out one a crashed gateway left behind."""
        from azure.storage.blob import BlobLeaseClient

        # Another gateway's lease on the blob refuses the upload too (LeaseIdMissing).
        with contextlib.suppress(ResourceExistsError, HttpResponseError):
            self._lease_blob.upload_blob(b"", overwrite=False)
        deadline = clock.monotonic() + wait
        while True:
            lease = BlobLeaseClient(self._lease_blob)
            try:
                lease.acquire(lease_duration=self.LEASE_SECONDS)
                break
            except HttpResponseError as error:
                if clock.monotonic() > deadline:
                    raise LeaseHeld("another gateway holds the chain-head lease") from error
                clock.sleep(5)
        self._lease, self._renewed = lease, clock.monotonic()
        threading.Thread(target=self._renew, daemon=True, name="lease").start()

    def _renew(self) -> None:
        while not self._stop.wait(self.LEASE_SECONDS / 4):
            try:
                self._lease.renew()
                self._renewed = clock.monotonic()
            except Exception:
                log.exception("the chain-head lease was not renewed")

    def release(self) -> None:
        """Stop renewing and free the lease, so another gateway can take it at once."""
        self._stop.set()
        if self._lease is not None:
            self._lease.release()
            self._lease = None

    def held(self) -> bool:
        return (
            self._lease is not None and clock.monotonic() - self._renewed < self.LEASE_SECONDS / 2
        )

    def write_journal(self, data: bytes) -> None:
        self._journal.upload_blob(data, overwrite=True)

    def read_journal(self) -> bytes | None:
        try:
            return self._journal.download_blob().readall()
        except ResourceNotFoundError:
            return None

    def clear_journal(self) -> None:
        with contextlib.suppress(ResourceNotFoundError):
            self._journal.delete_blob()

    def _receipt(self, name: str) -> Any:
        return self._container.get_blob_client(f"receipts/{self._workflow}/{name}.json")

    def read_receipt(self, name: str) -> bytes | None:
        try:
            return self._receipt(name).download_blob().readall()
        except ResourceNotFoundError:
            return None

    def write_receipt(self, name: str, data: bytes) -> None:
        self._receipt(name).upload_blob(data, overwrite=True)
