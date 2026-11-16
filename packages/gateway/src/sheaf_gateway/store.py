"""Where the gateway writes: the `evidence` container (section 4). Every blob is written once.

`MemoryStore` is for tests; `sheaf_gateway.azure.BlobStore` is the Azure Blob store.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Protocol

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo
from sheaf_core.canonical import strict_loads


class Store(Protocol):
    def info(self, sha256: str) -> ArtefactInfo | None:
        """The receipt of an uploaded artefact, or None."""

    def json(self, sha256: str) -> Any:
        """A JSON artefact's parsed content."""

    def put_artefact(self, info: ArtefactInfo, data: bytes) -> bool:
        """Store an artefact's exact bytes once. False if that SHA-256 was already stored."""

    def retain(self, path: str, until: date) -> None:
        """Extend a blob's retention to at least `until`. Never shortens it."""

    def put_blob(self, path: str, data: bytes, content_type: str) -> bool:
        """Write a block blob once. False if it already holds exactly these bytes; raises
        BlobConflict if it holds others."""

    def trust(self, path: str) -> bytes | None:
        """A file in `trust/`, or None."""

    def read(self, path: str) -> bytes | None:
        """A blob's bytes, or None."""

    def list(self, prefix: str) -> list[str]:
        """The names one level below `prefix`, as a Blob listing with "/" as the delimiter."""


class BlobConflict(Exception):
    """A write-once blob already holds other bytes."""


class MemoryStore:
    def __init__(self) -> None:
        self._artefacts: dict[str, ArtefactInfo] = {}
        self._files: dict[str, bytes] = {}
        self.content_types: dict[str, str] = {}
        self.retention: dict[str, date] = {}

    def info(self, sha256: str) -> ArtefactInfo | None:
        return self._artefacts.get(sha256)

    def json(self, sha256: str) -> Any:
        return strict_loads(self._files[paths.artefact(sha256)])

    def put_artefact(self, info: ArtefactInfo, data: bytes) -> bool:
        if info.sha256 in self._artefacts:
            return False
        self._files[paths.artefact(info.sha256)] = bytes(data)
        self._artefacts[info.sha256] = info
        return True

    def retain(self, path: str, until: date) -> None:
        self.retention[path] = max(until, self.retention.get(path, until))

    def put_blob(self, path: str, data: bytes, content_type: str) -> bool:
        existing = self._files.get(path)
        if existing is not None:
            if existing != data:
                raise BlobConflict(path)
            return False
        self._files[path] = bytes(data)
        self.content_types[path] = content_type
        return True

    def trust(self, path: str) -> bytes | None:
        return self._files.get(path) if path.startswith("trust/") else None

    def read(self, path: str) -> bytes | None:
        return self._files.get(path)

    def list(self, prefix: str) -> list[str]:
        found = set()
        for name in self._files:
            if name.startswith(prefix):
                rest = name[len(prefix) :]
                found.add(prefix + rest.split("/")[0] + "/" if "/" in rest else name)
        return sorted(found)

    # For tests.
    def blob(self, path: str) -> bytes:
        return self._files[path]
