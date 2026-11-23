"""The gateway's HTTP interface (7.2, 7.6), as the person or workload signed in."""

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from sheaf_admin.staging import Upload


class GatewayRefused(Exception):
    def __init__(self, status: int, problems: Any):
        super().__init__(f"the gateway answered {status}: {problems}")
        self.status, self.problems = status, problems


class GatewayClient:
    def __init__(self, client: httpx.Client, base_url: str, *, token: Callable[[], str]) -> None:
        self.client, self.base_url, self.token = client, base_url.rstrip("/"), token

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token()}", **kwargs.pop("headers", {})}
        response = self.client.request(method, f"{self.base_url}{path}", headers=headers, **kwargs)
        if response.status_code not in (200, 201):
            try:
                problems = response.json().get("problems")
            except ValueError:
                problems = response.text[:500]
            raise GatewayRefused(response.status_code, problems)
        return response

    def _send(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request(method, path, **kwargs).json()

    def me(self) -> dict[str, Any]:
        return self._send("GET", "/v1/me")

    def upload(self, chain: str, upload: Upload) -> dict[str, Any]:
        headers = {
            "Content-Type": upload.media_type,
            "Sheaf-Kind": upload.kind,
            "Sheaf-Sensitivity": upload.sensitivity,
            "Sheaf-Chain": chain,
            "Idempotency-Key": upload.sha256,
        }
        return self._send(
            "PUT", f"/v1/artefacts/{upload.sha256}", content=upload.data, headers=headers
        )

    def put_trust(self, path: str, data: bytes) -> dict[str, Any]:
        headers = {"Content-Type": "application/octet-stream"}
        relative = path.removeprefix("trust/")
        return self._send("PUT", f"/v1/trust/{relative}", content=data, headers=headers)

    def propose(self, request: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        """Stage a proposal. Returns it, and whether it is new rather than staged already."""
        response = self._request("POST", "/v1/proposals", json=dict(request))
        return response.json()["proposal"], response.status_code == 201

    def proposals(self, *, chain: str | None = None, status: str | None = None) -> list[dict]:
        return self.listing(chain=chain, status=status)[0]

    def listing(
        self, *, chain: str | None = None, status: str | None = None
    ) -> tuple[list[dict], list[str]]:
        """The proposals, and the chains the gateway could not read them from: starting or
        halted."""
        params = {k: v for k, v in (("chain", chain), ("status", status)) if v is not None}
        found = self._send("GET", "/v1/proposals", params=params)
        return found["proposals"], found.get("unavailable", [])

    def proposal(self, sha256: str) -> dict[str, Any]:
        """A proposal, its mandate, the one it replaces, and whether the caller may approve it."""
        return self._send("GET", f"/v1/proposals/{sha256}")

    def withdraw(self, sha256: str) -> dict[str, Any]:
        return self._send("DELETE", f"/v1/proposals/{sha256}")["proposal"]

    def commit(self, draft: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps(draft).encode()
        key = hashlib.sha256(body).hexdigest()
        headers = {"Content-Type": "application/json", "Idempotency-Key": key}
        return self._send("POST", "/v1/entries", content=body, headers=headers)
