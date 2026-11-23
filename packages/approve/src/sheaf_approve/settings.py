"""What sheaf-approve needs to know, from the environment:

    SHEAF_GATEWAY_URL        https://<gateway fqdn>, the gateway's internal address
    SHEAF_ENTRA_TENANT       the tenant's Entra ID tenant ID
    SHEAF_APPROVE_CLIENT_ID  this service's own app registration (a single-page app)
    SHEAF_GATEWAY_SCOPE      the gateway's scope, api://<gateway app id>/user_impersonation
    SHEAF_APPROVE_URL        the address people open, through the reverse proxy: the redirect URI,
                             https://<host>/, served at its root
    SHEAF_CHAINS             the chains whose proposals it shows, {tenant}/{workflow},...

and, optionally, where it listens: SHEAF_APPROVE_HOST (default 0.0.0.0) and SHEAF_APPROVE_PORT
(default 8080). It refuses to start without any of the six, or with any setting it cannot use.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

NAMES = (
    "SHEAF_GATEWAY_URL",
    "SHEAF_ENTRA_TENANT",
    "SHEAF_APPROVE_CLIENT_ID",
    "SHEAF_GATEWAY_SCOPE",
    "SHEAF_APPROVE_URL",
    "SHEAF_CHAINS",
)
_CHAIN = re.compile(r"[a-z0-9-]+/[a-z0-9-]+")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DOMAIN = re.compile(r"(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
_SCOPE = re.compile(r"api://[A-Za-z0-9][A-Za-z0-9.-]*(/[A-Za-z0-9._~-]+)+")
_SHARED_TENANTS = ("common", "organizations", "consumers")
"""Entra ID's multi-tenant endpoints: a sign-in there is not the tenant's."""
_LOCAL = ("localhost", "127.0.0.1")


@dataclass(frozen=True)
class Settings:
    gateway_url: str
    tenant: str
    client_id: str
    scope: str
    """The gateway's delegated scope: the person's token is for the gateway, not for this
    service, which only relays it."""
    redirect_uri: str
    chains: tuple[str, ...]

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Settings":
        missing = [name for name in NAMES if not env.get(name, "").strip()]
        if missing:
            raise RuntimeError(f"sheaf-approve needs {', '.join(missing)}")
        value = {name: env[name].strip() for name in NAMES}

        gateway = value["SHEAF_GATEWAY_URL"].rstrip("/")
        parts = _url(gateway, "SHEAF_GATEWAY_URL")
        if parts.scheme != "https" or parts.path:
            raise RuntimeError(
                "SHEAF_GATEWAY_URL is https://<gateway fqdn>: each person's token goes with it"
            )
        published = value["SHEAF_APPROVE_URL"]
        parts = _url(published, "SHEAF_APPROVE_URL")
        local = parts.scheme == "http" and parts.hostname in _LOCAL
        if (parts.scheme != "https" and not local) or parts.path != "/":
            raise RuntimeError(
                "SHEAF_APPROVE_URL is https://<host>/, the page's root, as registered for "
                "sign-in (http:// only for localhost)"
            )
        tenant = value["SHEAF_ENTRA_TENANT"]
        if tenant.lower() in _SHARED_TENANTS or not (
            _GUID.fullmatch(tenant) or _DOMAIN.fullmatch(tenant)
        ):
            raise RuntimeError(
                "SHEAF_ENTRA_TENANT is the tenant's directory ID, or one of its domains"
            )
        if not _SCOPE.fullmatch(value["SHEAF_GATEWAY_SCOPE"]):
            raise RuntimeError(
                "SHEAF_GATEWAY_SCOPE is the gateway's one delegated scope, "
                "api://<gateway application id>/user_impersonation"
            )
        chains = tuple(c.strip() for c in value["SHEAF_CHAINS"].split(",") if c.strip())
        tenants = {chain.split("/")[0] for chain in chains}
        if not chains or not all(_CHAIN.fullmatch(c) for c in chains) or len(tenants) != 1:
            raise RuntimeError("SHEAF_CHAINS names one tenant's chains in full, as tenant/workflow")
        return cls(
            gateway_url=gateway,
            tenant=value["SHEAF_ENTRA_TENANT"],
            client_id=value["SHEAF_APPROVE_CLIENT_ID"],
            scope=value["SHEAF_GATEWAY_SCOPE"],
            redirect_uri=published,
            chains=chains,
        )


def listen_from(env: Mapping[str, str]) -> tuple[str, int]:
    """Where the service listens: SHEAF_APPROVE_HOST and SHEAF_APPROVE_PORT."""
    host = env.get("SHEAF_APPROVE_HOST", "").strip() or "0.0.0.0"  # noqa: S104 (a container)
    port = env.get("SHEAF_APPROVE_PORT", "").strip() or "8080"
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise RuntimeError("SHEAF_APPROVE_PORT is a port number, from 1 to 65535")
    return host, int(port)


def _url(value: str, name: str) -> SplitResult:
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 (raises ValueError for a port that is not a number)
    except ValueError as error:
        raise RuntimeError(f"{name} is not an address: {error}") from None
    if not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise RuntimeError(f"{name} is an address with a host and no user, query or fragment")
    return parts
