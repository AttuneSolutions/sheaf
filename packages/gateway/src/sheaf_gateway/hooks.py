"""What the gateway leaves to others: who the caller is, witness verification, and events."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from starlette.requests import Request


@dataclass(frozen=True)
class Caller:
    """Who the gateway authenticated: the identity an entry's actor must name, and the app roles
    its token holds (the Entra ID `roles` claim), any of which an entry's actor may name."""

    id: str
    roles: frozenset[str] = frozenset()
    person: bool | None = None
    """A person (a delegated token) or a system (an app-only token); None if not known."""


class Authenticator(Protocol):
    def __call__(self, request: Request) -> Caller | None:
        """The authenticated caller, or None."""


def refuse_all(request: Request) -> None:
    """The default until Entra workload identity validation is built (7.1): nobody may write."""
    return None


class Publisher(Protocol):
    def publish(self, event: Mapping[str, Any]) -> None:
        """A content-free hint that an entry was committed (7.2 step 4, 8)."""


class NoEvents:
    def publish(self, event: Mapping[str, Any]) -> None:
        pass
