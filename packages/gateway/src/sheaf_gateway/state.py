"""The gateway's own mutable state (7.1): the chain-head lease, so a chain has one writer; the
write-ahead journal, so a restart can finish an entry a crash left half-written (7.2 step 3); and
the receipts kept for idempotency keys, so a retry after a restart gets the first receipt rather
than a second entry (7.2 step 2); and the proposals staged for its mandate (7.6). All live in the
`gateway-state` container, never in `evidence`."""

from typing import Protocol


class LeaseHeld(Exception):
    """Another gateway holds the chain-head lease."""


class GatewayState(Protocol):
    def acquire(self) -> None:
        """Take the chain-head lease, or raise LeaseHeld."""

    def held(self) -> bool:
        """Whether this gateway still holds the lease."""

    def release(self) -> None:
        """Give up the lease, so another gateway can take it at once. Never raises: a lease
        that cannot be released expires by itself."""

    def write_journal(self, data: bytes) -> None: ...

    def read_journal(self) -> bytes | None: ...

    def clear_journal(self) -> None: ...

    def read_receipt(self, name: str) -> bytes | None:
        """The receipt kept for an idempotency key, by the name the gateway gives it, or None."""

    def write_receipt(self, name: str, data: bytes) -> None:
        """Keep a receipt. Writing the same one again, as finishing from the journal does, is
        harmless."""

    def read_proposal(self, sha256: str) -> bytes | None:
        """The proposal staged for the mandate with this SHA-256, or None."""

    def write_proposal(self, sha256: str, data: bytes) -> None:
        """Keep a proposal, replacing any kept for the same mandate."""

    def list_proposals(self) -> list[bytes]:
        """Every proposal kept for this chain."""


class MemoryState:
    """For tests and the memory store: nothing survives the process."""

    def __init__(self) -> None:
        self._taken = False
        self._lost = False
        self._journal: bytes | None = None
        self._receipts: dict[str, bytes] = {}
        self._proposals: dict[str, bytes] = {}

    def acquire(self) -> None:
        if self._taken:
            raise LeaseHeld("another gateway holds the chain-head lease")
        self._taken, self._lost = True, False

    def held(self) -> bool:
        return not self._lost

    def write_journal(self, data: bytes) -> None:
        self._journal = data

    def read_journal(self) -> bytes | None:
        return self._journal

    def clear_journal(self) -> None:
        self._journal = None

    def read_receipt(self, name: str) -> bytes | None:
        return self._receipts.get(name)

    def write_receipt(self, name: str, data: bytes) -> None:
        self._receipts[name] = data

    def read_proposal(self, sha256: str) -> bytes | None:
        return self._proposals.get(sha256)

    def write_proposal(self, sha256: str, data: bytes) -> None:
        self._proposals[sha256] = data

    def list_proposals(self) -> list[bytes]:
        return [self._proposals[name] for name in sorted(self._proposals)]

    def release(self) -> None:
        self._taken = False

    # For tests.
    def lose(self) -> None:
        self._lost = True
