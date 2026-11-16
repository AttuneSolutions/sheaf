"""Staff identifiers as keyed pseudonyms (5.7; MIO-STD-01 4.6.2, 4.6.3).

When a tenant's mandate seals identifiers as pseudonyms, a person is recorded as
`ps-` and the first 128 bits of HMAC-SHA256, keyed by a secret of their own in the tenant's Key
Vault, over their Entra object ID. The gateway creates the secret the first time it sees the
person. Destroying it erases them: their pseudonym no longer links to anyone. Workload identities
are not personal data and stay in clear.

The gateway never rewrites an entry: it works out the identity an entry must name, and refuses
one that names another. A caller learns its own from `GET /v1/me`.
"""

import hashlib
import hmac
import secrets
import threading
from typing import Any, Protocol

from starlette.requests import Request

from sheaf_gateway.hooks import Authenticator, Caller

PREFIX = "ps-"


def pseudonym_of(secret: bytes, name: str) -> str:
    return PREFIX + hmac.new(secret, name.encode(), hashlib.sha256).hexdigest()[:32]


def subject_name(system: str, object_: str, id_: str) -> str:
    """One subject record: its system, object and id, unambiguously joined."""
    return "\x00".join((system, object_, id_))


class Pseudonymiser(Protocol):
    def pseudonym(self, object_id: str) -> str:
        """The person's pseudonym, creating their secret if they have none yet."""

    def subject(self, system: str, object_: str, id_: str) -> str:
        """The subject record's pseudonym, under a secret of its own."""


class MemoryPseudonyms:
    """For tests: secrets in memory."""

    def __init__(self) -> None:
        self._secrets: dict[str, bytes] = {}

    def pseudonym(self, object_id: str) -> str:
        secret = self._secrets.setdefault(object_id, secrets.token_bytes(32))
        return pseudonym_of(secret, object_id)

    def destroy(self, object_id: str) -> None:
        self._secrets.pop(object_id, None)

    def subject(self, system: str, object_: str, id_: str) -> str:
        name = subject_name(system, object_, id_)
        secret = self._secrets.setdefault(f"subject:{name}", secrets.token_bytes(32))
        return pseudonym_of(secret, name)

    def destroy_subject(self, system: str, object_: str, id_: str) -> None:
        self._secrets.pop(f"subject:{subject_name(system, object_, id_)}", None)


class KeyVaultPseudonyms:
    """Each person's secret is a Key Vault secret `sheaf-person-{object id}`, created once and
    never replaced: a new one would give the same person a second pseudonym."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self._cache: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def pseudonym(self, object_id: str) -> str:
        return pseudonym_of(self._secret(f"sheaf-person-{object_id}"), object_id)

    def subject(self, system: str, object_: str, id_: str) -> str:
        # The secret's name must not carry the subject's id; its unkeyed digest stands in.
        name = subject_name(system, object_, id_)
        digest = hashlib.sha256(name.encode()).hexdigest()
        return pseudonym_of(self._secret(f"sheaf-subject-{digest}"), name)

    def _secret(self, name: str) -> bytes:
        from azure.core.exceptions import ResourceNotFoundError

        with self._lock:
            secret = self._cache.get(name)
            if secret is None:
                try:
                    secret = bytes.fromhex(self.client.get_secret(name).value)
                except ResourceNotFoundError:
                    secret = secrets.token_bytes(32)
                    self.client.set_secret(name, secret.hex(), content_type="sheaf pseudonym key")
                self._cache[name] = secret
        return secret


class RecordedIdentities:
    """Wraps the authenticator so a person is the pseudonym their entries must name."""

    def __init__(self, authenticate: Authenticator, pseudonyms: Pseudonymiser) -> None:
        self.authenticate, self.pseudonyms = authenticate, pseudonyms

    def __call__(self, request: Request) -> Caller | None:
        caller = self.authenticate(request)
        if caller is None or not caller.person:
            return caller
        return Caller(self.pseudonyms.pseudonym(caller.id), caller.roles, person=True)
