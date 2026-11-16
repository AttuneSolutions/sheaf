"""The gateway's own mutable state (7.1): the chain-head lease, so a chain has one writer, and the
write-ahead journal, so a restart can finish an entry a crash left half-written (7.2 step 3).
Both live in the `gateway-state` container, never in `evidence`."""

from typing import Protocol


class LeaseHeld(Exception):
    """Another gateway holds the chain-head lease."""


class GatewayState(Protocol):
    def acquire(self) -> None:
        """Take the chain-head lease, or raise LeaseHeld."""

    def held(self) -> bool:
        """Whether this gateway still holds the lease."""

    def write_journal(self, data: bytes) -> None: ...

    def read_journal(self) -> bytes | None: ...

    def clear_journal(self) -> None: ...


class MemoryState:
    """For tests and the memory store: nothing survives the process."""

    def __init__(self) -> None:
        self._taken = False
        self._lost = False
        self._journal: bytes | None = None

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

    # For tests.
    def release(self) -> None:
        self._taken = False

    def lose(self) -> None:
        self._lost = True
