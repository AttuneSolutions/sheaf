"""The approval page and its API (standard 7.6), same origin, behind the tenant's reverse proxy.

    GET  /, /app.js, /app.css             the page; no inline script or style
    GET  /api/config                      what the page needs to sign the person in
    GET  /api/me                          who the gateway sees: relays /v1/me
    GET  /api/proposals                   the pending proposals of the chains served here
    GET  /api/proposals/{sha256}          one, in plain language, as a diff and as a technical
                                          summary, with its fingerprint and whether the person
                                          may approve it
    POST /api/proposals/{sha256}/approve  {confirm, fingerprint}: commit its config.changed
                                          through the gateway, with the person's own token
    GET  /healthz                         up, and nothing more

Every /api call but config carries the person's Entra ID access token for the gateway, as
`Authorization: Bearer`, which the page holds in memory only. The service relays it to the
gateway for that request and keeps nothing: it holds no Azure credential, writes nowhere, and
never logs a token or a sign-in code (the code returns in the address's fragment, which never
reaches a server). The gateway decides who may approve; the service checks the typed chain name
and the fingerprint shown, so what was shown is what is committed.

A refusal is {"error": code, "detail": text}, or, passed on from the gateway, {"error":
"gateway_refused", "status", "problems"} with the gateway's status.
"""

import hashlib
import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from sheaf_approve.settings import Settings
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.describe import describe, diff, technical
from sheaf_core.digest import is_artefact_digest
from sheaf_core.proposal import approval_draft, shown_differs

log = logging.getLogger("sheaf.approve")
access = logging.getLogger("sheaf.approve.access")

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://login.microsoftonline.com; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/pico.css": ("vendor/pico.indigo.min.css", "text/css; charset=utf-8"),
}
"""The page, its script and styles, all served from here, never from a CDN. `pico.css` is Pico
CSS 2.1.1 (https://picocss.com, MIT; its licence is beside it in static/vendor), the indigo
theme, copied unchanged from the npm tarball @picocss/pico@2.1.1, whose integrity is
    sha512-kIDugA7Ps4U+2BHxiNHmvgPIQDWPDU4IeU6TNRdvXQM1uZX+FibqDQT2xUOnnO2yq/LUHcwnGlu1hvf4KfXnMg==
It draws its icons as data: SVG images, hence `img-src 'self' data:` in the CSP."""
MAX_BODY = 4096
MAX_AUTHORIZATION = 16 * 1024
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]+")
"""What a bearer token may hold (RFC 6750 b64token, loosely): anything else is refused before it
reaches the gateway."""
RECEIPT = ("seq", "hash", "committed_at")
TIMEOUT = httpx.Timeout(25.0, connect=10.0, pool=5.0)
"""Each call to the gateway: shorter than a reverse proxy's usual upstream timeout, so the person
hears from this service rather than from the proxy."""
COMMIT_BY = 20.0
"""Seconds from an approval's start after which its checks are taken as stale and the commit is
not sent: with the commit's own timeout, the whole stays inside the proxy's."""


class Refused(Exception):
    def __init__(self, http_status: int, error: str, detail: str = "", **extra: Any) -> None:
        super().__init__(f"{http_status} {error}")
        self.status, self.error, self.detail, self.extra = http_status, error, detail, extra

    @property
    def outcome(self) -> str:
        if self.error == "gateway_refused" and self.extra.get("problems"):
            first = self.extra["problems"][0]
            return f"gateway_refused:{first.get('code') if isinstance(first, dict) else '?'}"
        return self.error

    def response(self) -> JSONResponse:
        body = {"error": self.error, "detail": self.detail, **self.extra}
        return JSONResponse(body, status_code=self.status)


class Gateway:
    """The gateway's API, called with the person's own token."""

    def __init__(self, http: httpx.Client, base_url: str) -> None:
        self.http, self.base_url = http, base_url.rstrip("/")

    def send(self, method: str, path: str, token: str, **kwargs: Any) -> Any:
        headers = {"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})}
        try:
            response = self.http.request(
                method, f"{self.base_url}{path}", headers=headers, **kwargs
            )
        except httpx.TransportError:
            # Its message names the address, never the token; keep it out of the answer.
            log.warning("the gateway did not answer %s %s", method, path.split("?")[0])
            raise Refused(
                502, "gateway_unreachable", "the gateway did not answer: try again shortly"
            ) from None
        try:
            answer = response.json()
        except ValueError:
            answer = None
        if response.status_code not in (200, 201):
            problems = answer.get("problems") if isinstance(answer, dict) else None
            raise Refused(
                response.status_code,
                "gateway_refused",
                f"the gateway refused ({response.status_code})",
                status=response.status_code,
                problems=problems if isinstance(problems, list) else [],
            )
        if not isinstance(answer, dict):
            raise Refused(502, "gateway_bad_answer", "the gateway's answer was not understood")
        return answer


class Service:
    def __init__(
        self,
        settings: Settings,
        gateway: Gateway,
        clock: Callable[[], datetime],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings, self.gateway, self.clock = settings, gateway, clock
        self.monotonic = monotonic

    def config(self) -> dict[str, Any]:
        settings = self.settings
        return {
            "tenant": settings.tenant,
            "client_id": settings.client_id,
            "scope": f"{settings.scope} openid profile",
            "redirect_uri": settings.redirect_uri,
            "authority": settings.authority,
            "chains": list(settings.chains),
        }

    def me(self, authorization: str | None) -> dict[str, Any]:
        return self.gateway.send("GET", "/v1/me", _bearer(authorization))

    def proposals(self, authorization: str | None) -> dict[str, Any]:
        """The pending proposals of every chain served here that the person may read, and the
        chains the gateway could not read them from, starting or halted, so that a chain it
        could not read is never shown as having nothing pending."""
        token = _bearer(authorization)
        found, unavailable, readable, refused = [], [], 0, None
        for chain in self.settings.chains:
            params = {"chain": chain, "status": "pending"}
            try:
                found += self.gateway.send("GET", "/v1/proposals", token, params=params)[
                    "proposals"
                ]
                readable += 1
            except Refused as error:
                if error.status == 503:
                    unavailable.append(chain)
                    continue
                if error.status != 403:
                    raise
                refused = error
        if not readable and not unavailable and refused is not None:
            raise refused
        return {"proposals": found, "unavailable": unavailable}

    def show(self, sha256: str, authorization: str | None) -> dict[str, Any]:
        """A proposal as the person reads it before approving: in plain language, as what
        changes, and as an engineer checks it, always with its fingerprint."""
        token = _bearer(authorization)
        found = self._proposal(sha256, token)
        mandate, previous = found["mandate"], found["previous_mandate"]
        return {
            "proposal": found["proposal"],
            "fingerprint": sha256,
            "genesis": previous is None,
            "caller": found["caller"],
            "plain": describe(mandate),
            "diff": diff(previous, mandate),
            "technical": [list(row) for row in technical(mandate, sha256)],
        }

    def approve(self, sha256: str, authorization: str | None, raw: bytes) -> dict[str, Any]:
        """Approve a proposal, logging the attempt whatever its outcome."""
        seen = {"who": "unknown", "chain": "unknown"}
        outcome = "failed"
        try:
            result = self._approve(sha256, authorization, raw, seen)
            outcome = "already_approved" if result.get("already") else "approved"
            return result
        except Refused as error:
            outcome = error.outcome
            raise
        finally:
            log.info(
                "approval attempt: by=%s proposal=%s chain=%s outcome=%s",
                seen["who"],
                sha256 if is_artefact_digest(sha256) else "-",
                seen["chain"],
                outcome,
            )

    def _approve(
        self, sha256: str, authorization: str | None, raw: bytes, seen: dict[str, str]
    ) -> dict[str, Any]:
        began = self.monotonic()
        token = _bearer(authorization)
        body = _approval(raw)
        _check_digest(sha256)
        if body["fingerprint"] != sha256:
            raise Refused(
                409,
                "fingerprint_mismatch",
                "this is not the fingerprint of the proposal shown: reload it and read it again",
            )
        me = self.gateway.send("GET", "/v1/me", token)
        seen["who"] = str(me.get("id"))
        if me.get("person") is not True:
            raise Refused(
                403, "not_a_person", "an approver signs in as a person, with their own account"
            )
        found = self._proposal(sha256, token)
        proposal, caller = found["proposal"], found["caller"]
        seen["chain"] = proposal["chain"]
        status, approved = proposal["status"], proposal.get("approved") or {}
        if status == "approved" and approved.get("by", {}).get("id") == me["id"]:
            # A run that stopped after the gateway committed: it is done.
            return {"approved": {k: approved[k] for k in RECEIPT}, "already": True}
        if status == "approved":
            by = approved.get("by", {}).get("id")
            detail = (
                f"it is already approved, by {by} at seq {approved.get('seq')}"
                if by
                else "it is already approved: reload the proposal to see by whom"
            )
            raise Refused(409, "proposal_approved", detail)
        if status != "pending":
            raise Refused(409, "proposal_not_pending", f"the proposal is {status}")
        if body["confirm"] != proposal["chain"]:
            raise Refused(
                422,
                "confirmation_mismatch",
                f"type the chain's name, {proposal['chain']}, to approve it",
            )
        if not caller.get("may_approve"):
            # The gateway decides who may approve, and says why not as a code and a sentence.
            code = caller.get("refusal_code")
            refusal = caller.get("refusal") or "you may not approve this change"
            if code == "proposal_not_pending":
                raise Refused(409, "proposal_not_pending", refusal)
            if code == "not_a_person":
                raise Refused(403, "not_a_person", refusal)
            raise Refused(403, "not_an_approver", refusal, refusal_code=code)
        draft = approval_draft(
            proposal, approver=me["id"], role=caller.get("role"), observed_at=self.clock()
        )
        if self.monotonic() - began > COMMIT_BY:
            raise Refused(
                504,
                "gateway_slow",
                "the gateway was too slow to check the approval, so it was not sent: try again",
            )
        content = json.dumps(draft).encode()
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": hashlib.sha256(content).hexdigest(),
        }
        try:
            receipt = self.gateway.send(
                "POST", "/v1/entries", token, content=content, headers=headers
            )
        except Refused as error:
            if error.error != "gateway_unreachable":
                raise
            raise Refused(
                502,
                "gateway_unreachable",
                "the gateway did not answer the approval. Reload the proposal: if the approval "
                "reached it, the proposal shows approved; if not, approve it again",
            ) from None
        return {"approved": {k: receipt[k] for k in RECEIPT}}

    def _proposal(self, sha256: str, token: str) -> dict[str, Any]:
        """A proposal as the gateway sends it, refused unless the mandates it comes with are
        exactly what approving it commits, so a person never signs other than what they read."""
        _check_digest(sha256)
        found = self.gateway.send("GET", f"/v1/proposals/{sha256}", token)
        proposal, mandate = found.get("proposal"), found.get("mandate")
        previous, caller = found.get("previous_mandate"), found.get("caller")
        if (
            not isinstance(proposal, dict)
            or not isinstance(mandate, dict)
            or not isinstance(caller, dict)
            or not (previous is None or isinstance(previous, dict))
        ):
            raise Refused(502, "gateway_bad_answer", "the gateway's answer was not understood")
        chain = proposal.get("chain")
        if chain not in self.settings.chains or proposal.get("mandate") != sha256:
            raise Refused(404, "proposal_unknown", f"this page does not approve changes to {chain}")
        try:
            differ = shown_differs(proposal, mandate, previous)
        except (KeyError, TypeError, AttributeError):
            raise Refused(
                502, "gateway_bad_answer", "the gateway's answer was not understood"
            ) from None
        if differ:
            raise Refused(
                502,
                "gateway_inconsistent",
                "the mandate the gateway sent is not the one its proposal commits (it differs "
                f"in {', '.join(differ)}): nothing is shown or approved",
            )
        return found


def create_app(
    settings: Settings,
    http: httpx.Client,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> FastAPI:
    service = Service(settings, Gateway(http, settings.gateway_url), clock, monotonic)
    static = {
        path: ((resources.files("sheaf_approve") / "static" / name).read_bytes(), media_type)
        for path, (name, media_type) in STATIC.items()
    }
    app = FastAPI(title="Sheaf approvals", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            log.exception("could not answer %s %s", request.method, _printable(request.url.path))
            response = JSONResponse(
                {"error": "internal", "detail": "the service could not answer"}, status_code=500
            )
        response.headers.update(HEADERS)
        # Method, path and status only: never the query, which a sign-in could carry, nor a
        # header, which carries the person's token.
        access.info("%s %s %s", request.method, _printable(request.url.path), response.status_code)
        return response

    @app.exception_handler(Refused)
    async def refused(request: Request, error: Refused) -> JSONResponse:
        return error.response()

    def page(path: str) -> Callable[[], Response]:
        data, media_type = static[path]

        async def serve() -> Response:
            return Response(data, media_type=media_type)

        return serve

    for path in static:
        app.add_api_route(path, page(path), methods=["GET"], include_in_schema=False)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/config")
    async def config() -> dict[str, Any]:
        return service.config()

    @app.get("/api/me")
    async def me(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(service.me, _authorization(request))

    @app.get("/api/proposals")
    async def proposals(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(service.proposals, _authorization(request))

    @app.get("/api/proposals/{sha256}")
    async def show(sha256: str, request: Request) -> dict[str, Any]:
        return await run_in_threadpool(service.show, sha256, _authorization(request))

    @app.post("/api/proposals/{sha256}/approve")
    async def approve(sha256: str, request: Request) -> dict[str, Any]:
        raw = await _read_body(request)
        return await run_in_threadpool(service.approve, sha256, _authorization(request), raw)

    return app


def _authorization(request: Request) -> str | None:
    return request.headers.get("authorization")


def _bearer(authorization: str | None) -> str:
    header = authorization or ""
    scheme, _, token = header.partition(" ")
    if (
        scheme.lower() != "bearer"
        or len(header) > MAX_AUTHORIZATION
        or not header.isascii()
        or not TOKEN.fullmatch(token)
    ):
        raise Refused(401, "unauthenticated", "sign in first")
    return token


def _approval(raw: bytes) -> Mapping[str, str]:
    detail = 'an approval is {"confirm": the chain name, "fingerprint": the one shown}'
    try:
        body = strict_loads(raw)
    except InvalidJSON:
        raise Refused(422, "invalid_request", detail) from None
    if (
        not isinstance(body, dict)
        or set(body) != {"confirm", "fingerprint"}
        or not all(isinstance(value, str) for value in body.values())
    ):
        raise Refused(422, "invalid_request", detail)
    return body


def _check_digest(sha256: str) -> None:
    if not is_artefact_digest(sha256):
        raise Refused(422, "sha256_format", "a fingerprint is 64 lower-case hex digits")


async def _read_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise Refused(413, "too_large", f"the limit is {MAX_BODY} bytes")
    return bytes(body)


def _printable(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:300]
