"""Who the caller is (7.1): an Entra ID access token for the gateway, presented as a bearer token.

The caller is the token's `oid`, the object ID of the managed identity, service principal or
person, which is what an entry's `actor.id` must be (5.1); its app roles are the `roles` claim.
A token counts only if it is signed (RS256) by one of the tenant's published keys, was issued by
the tenant's v2 endpoint for the gateway's own application, and is within its validity. Anything
else is no caller, and the gateway answers 401.
"""

import json
import logging
import threading
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import jwt
from starlette.requests import Request

from sheaf_gateway.hooks import Caller

log = logging.getLogger("sheaf.gateway")

MAX_HEADER = 16 * 1024
LEEWAY = 60
"""Seconds of clock skew allowed on `exp` and `nbf`."""
REFRESH_AFTER = 24 * 3600
"""Fetch the signing keys again after this long, as Microsoft rotates them."""
UNKNOWN_KEY_COOLDOWN = 300
FAILED_FETCH_COOLDOWN = 30
"""Seconds to wait after the keys could not be fetched, so callers cannot queue a fetch each."""
"""An unknown key ID fetches the keys again at most this often, so junk tokens cannot make the
gateway hammer the tenant's key endpoint."""


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 (a fixed https URL)
        return response.read(1024 * 1024)


class EntraAuthenticator:
    def __init__(
        self,
        tenant_id: str,
        audience: str,
        *,
        fetch: Callable[[str], bytes] = _fetch,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.tenant_id, self.audience = tenant_id, audience
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self.keys_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self.fetch, self.clock = fetch, clock
        self._keys: dict[str, Any] = {}
        self._fetched: datetime | None = None
        self._forced: datetime | None = None
        self._failed: datetime | None = None
        self._lock = threading.Lock()

    def __call__(self, request: Request) -> Caller | None:
        header = request.headers.get("authorization") or ""
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token or len(header) > MAX_HEADER:
            return None
        try:
            key = self._key(jwt.get_unverified_header(token).get("kid"))
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["exp", "iss", "aud", "tid", "oid"],
                    # Checked below against this gateway's clock.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
            log.info("refused a token: %s", type(error).__name__)
            return None
        return self._caller(claims)

    def _caller(self, claims: dict[str, Any]) -> Caller | None:
        now = self.clock().timestamp()
        oid, roles = claims["oid"], claims.get("roles", [])
        if (
            claims["tid"] != self.tenant_id
            or not isinstance(claims["exp"], int)
            or claims["exp"] < now - LEEWAY
            or (
                "nbf" in claims
                and (not isinstance(claims["nbf"], int) or claims["nbf"] > now + LEEWAY)
            )
            or not isinstance(oid, str)
            or not oid
            or not isinstance(roles, list)
            or not all(isinstance(role, str) for role in roles)
        ):
            log.info("refused a token: claims")
            return None
        # A delegated token carries scopes (`scp`) and acts for a person; an app-only one does not.
        return Caller(oid, frozenset(roles), person="scp" in claims)

    def _key(self, kid: Any) -> Any:
        if not isinstance(kid, str):
            return None
        with self._lock:
            now = self.clock()
            stale = self._fetched is None or (now - self._fetched).total_seconds() > REFRESH_AFTER
            unknown = kid not in self._keys and (
                self._forced is None or (now - self._forced).total_seconds() > UNKNOWN_KEY_COOLDOWN
            )
            failing = (
                self._failed is not None
                and (now - self._failed).total_seconds() <= FAILED_FETCH_COOLDOWN
            )
            if (stale or unknown) and not failing:
                if unknown and not stale:
                    self._forced = now
                self._refresh(now)
            return self._keys.get(kid)

    def _refresh(self, now: datetime) -> None:
        try:
            published = json.loads(self.fetch(self.keys_url))["keys"]
            keys = {}
            for item in published:
                if item.get("kty") == "RSA" and isinstance(item.get("kid"), str):
                    keys[item["kid"]] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(item))
        except Exception:
            log.exception("the tenant's signing keys could not be fetched")
            self._failed = now
            return
        self._keys, self._fetched, self._failed = keys, now, None
