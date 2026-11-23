"""The gateway's HTTP interface (7.2): upload an artefact, commit an entry.

    PUT  /v1/artefacts/{sha256}   the artefact's exact bytes
         Content-Type             its media type, without parameters
         Sheaf-Kind               its kind (6)
         Sheaf-Sensitivity        client_pii, staff_pii or none
         Sheaf-Chain              the chain whose mandate it is checked against
         Idempotency-Key          required
         -> 201 (stored) or 200 (already stored): the artefact receipt

    POST /v1/entries              the entry without seq, prev, committed_at and hash
         Idempotency-Key          optional; a retry with the same key and body gets the first
                                  receipt, even after a restart
         -> 201: {seq, hash, committed_at}

    POST /v1/witnesses            {entry, tokens}: a witness entry and its time-stamp responses
    PUT  /v1/trust/{path}         a trust file a mandate names (witness key, authority root)
    GET  /v1/me                   the identity the caller's entries must name
    POST /v1/pseudonyms           {system, object, id}: a subject as entries must name it

    POST   /v1/proposals          {chain, mandate, reason, expires_in_days?}: stage a mandate
                                  change (7.6) -> 201 (staged) or 200 (already staged)
    GET    /v1/proposals          ?chain=&status=: the proposals the caller may read, and the
                                  chains starting or halted, whose proposals it could not read
    GET    /v1/proposals/{sha256} a proposal, its mandate, the mandate it replaces, and whether
                                  the caller may approve it
    DELETE /v1/proposals/{sha256} withdraw it
    GET    /v1/status             how each chain stands (7.7), for the status role

A rejection is 4xx with {"problems": [{code, path, detail}]}: 401 no caller, 403 not permitted,
404 no such proposal, 409 an idempotency key or an artefact declared two ways or a proposal not
pending, 413 too large, 422 invalid; 503 when a
write failed partway or the chain-head lease was lost, until the gateway restarts, and 503 with
Retry-After while the chain is starting.

The app answers as soon as it is up and starts its chains in the background (`Gateways.start`),
so a gateway replacing another can start beside it; when it stops, it releases their leases.
"""

import hashlib
import threading
import time
from collections import Counter
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.digest import is_artefact_digest
from sheaf_core.problems import Problem
from sheaf_core.trust import MAX_BYTES as TRUST_MAX_BYTES
from sheaf_gateway.gateway import (
    MAX_ENTRY_BYTES,
    MAX_PROPOSAL_BYTES,
    MAX_WITNESS_BYTES,
    Gateway,
    Gateways,
    Rejected,
)
from sheaf_gateway.hooks import Authenticator, Caller, refuse_all


def create_app(gateway: Gateway | Gateways, authenticate: Authenticator = refuse_all) -> FastAPI:
    if isinstance(gateway, Gateway):
        gateway = Gateways([gateway])
    served = gateway

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        served.start()
        yield
        await run_in_threadpool(served.close)

    # No API description is served: callers are known workloads, and the contract is 7.2.
    app = FastAPI(
        title="Sheaf write gateway",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.gateway = gateway
    refusals = Refusals()

    @app.exception_handler(Rejected)
    async def rejected(request: Request, error: Rejected) -> JSONResponse:
        if error.problems:
            refusals.record(error.problems[0].code)
        shown = error.problems[:MAX_PROBLEMS]
        problems = [{"code": p.code, "path": p.path, "detail": p.detail[:500]} for p in shown]
        if len(error.problems) > MAX_PROBLEMS:
            more = len(error.problems) - MAX_PROBLEMS
            problems.append({"code": "more", "path": "$", "detail": f"{more} more not shown"})
        return JSONResponse({"problems": problems}, status_code=error.status, headers=error.headers)

    def caller(request: Request) -> Caller:
        identity = authenticate(request)
        if identity is None or not identity.id:
            raise Rejected(401, [Problem("unauthenticated", "$", "no authenticated caller")])
        return identity

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    # `who` is declared first: FastAPI resolves dependencies before it checks headers, so an
    # unauthenticated request gets 401 and learns nothing about what a request needs.
    @app.put("/v1/artefacts/{sha256}")
    async def upload(
        sha256: str,
        request: Request,
        who: Annotated[Caller, Depends(caller)],
        content_type: Annotated[str, Header()],
        sheaf_kind: Annotated[str, Header()],
        sheaf_sensitivity: Annotated[str, Header()],
        sheaf_chain: Annotated[str, Header()],
        idempotency_key: Annotated[str, Header()],
    ) -> JSONResponse:
        if not is_artefact_digest(sha256):
            raise Rejected(422, [Problem("sha256_format", "sha256", "64 lower-case hex digits")])
        # In the thread pool: it may wait for the chain to start.
        limit = await run_in_threadpool(
            gateway.upload_limit, who.id, sheaf_kind, chain=sheaf_chain, roles=who.roles
        )
        data = await _read_body(request, limit)
        receipt, created = await run_in_threadpool(
            gateway.upload,
            who.id,
            data,
            chain=sheaf_chain,
            sha256=sha256,
            kind=sheaf_kind,
            media_type=content_type,
            sensitivity=sheaf_sensitivity,
            idempotency_key=idempotency_key,
            roles=who.roles,
        )
        return JSONResponse(receipt, status_code=201 if created else 200)

    @app.post("/v1/entries")
    async def commit(
        request: Request,
        who: Annotated[Caller, Depends(caller)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        raw = await _read_body(request, MAX_ENTRY_BYTES)
        receipt, created = await run_in_threadpool(
            gateway.commit, who.id, raw, idempotency_key, roles=who.roles, person=who.person
        )
        return JSONResponse(receipt, status_code=201 if created else 200)

    @app.get("/v1/me")
    async def me(who: Annotated[Caller, Depends(caller)]) -> dict:
        """The identity the caller's entries must name in `actor.id`, and its roles."""
        return {"id": who.id, "person": who.person, "roles": sorted(who.roles)}

    @app.post("/v1/pseudonyms")
    async def pseudonym(request: Request, who: Annotated[Caller, Depends(caller)]) -> dict:
        """A subject's pseudonym, where the tenant pseudonymises identifiers (5.7)."""
        subject = _parse_json(await _read_body(request, 4096))
        return await run_in_threadpool(gateway.subject_pseudonym, who.id, subject, roles=who.roles)

    @app.put("/v1/trust/{path:path}")
    async def trust(
        path: str, request: Request, who: Annotated[Caller, Depends(caller)]
    ) -> JSONResponse:
        data = await _read_body(request, TRUST_MAX_BYTES)
        created = await run_in_threadpool(
            gateway.put_trust, who.id, f"trust/{path}", data, roles=who.roles
        )
        receipt = {"path": f"trust/{path}", "sha256": hashlib.sha256(data).hexdigest()}
        return JSONResponse(receipt, status_code=201 if created else 200)

    @app.post("/v1/proposals")
    async def stage(request: Request, who: Annotated[Caller, Depends(caller)]) -> JSONResponse:
        raw = await _read_body(request, MAX_PROPOSAL_BYTES)
        proposal, created = await run_in_threadpool(
            gateway.propose, who.id, raw, roles=who.roles, person=who.person
        )
        return JSONResponse({"proposal": proposal}, status_code=201 if created else 200)

    @app.get("/v1/proposals")
    async def proposals(
        who: Annotated[Caller, Depends(caller)],
        chain: str | None = None,
        status: str | None = None,
    ) -> dict:
        found = await run_in_threadpool(
            gateway.proposals, who.id, chain=chain, status=status, roles=who.roles
        )
        # A chain that is starting or halted is not read; say so, rather than list it as empty.
        unavailable = [] if chain is not None else gateway.unavailable()
        return {"proposals": found, "unavailable": unavailable}

    @app.get("/v1/proposals/{sha256}")
    async def proposal(sha256: str, who: Annotated[Caller, Depends(caller)]) -> dict:
        return await run_in_threadpool(
            gateway.proposal, who.id, sha256, roles=who.roles, person=who.person
        )

    @app.delete("/v1/proposals/{sha256}")
    async def withdraw(sha256: str, who: Annotated[Caller, Depends(caller)]) -> dict:
        found = await run_in_threadpool(
            gateway.withdraw, who.id, sha256, roles=who.roles, person=who.person
        )
        return {"proposal": found}

    @app.get("/v1/status")
    async def status(who: Annotated[Caller, Depends(caller)]) -> dict:
        report = await run_in_threadpool(gateway.status, who.id, roles=who.roles)
        return {**report, "refusals": refusals.counts()}

    @app.post("/v1/witnesses")
    async def witness(
        request: Request,
        who: Annotated[Caller, Depends(caller)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        raw = await _read_body(request, MAX_WITNESS_BYTES)
        receipt, created = await run_in_threadpool(
            gateway.commit_witness, who.id, raw, idempotency_key, roles=who.roles
        )
        return JSONResponse(receipt, status_code=201 if created else 200)

    return app


MAX_PROBLEMS = 50


class Refusals:
    """Requests refused in the last day, counted by the code of their first problem, for status
    (7.7). Held in memory, as a count per code for each hour, so a flood of one refusal cannot
    push the others out and memory stays bounded. A restart starts counting again, and says
    when."""

    WINDOW = 24 * 3600
    BUCKET = 3600

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._since = clock()
        self._hours: dict[int, Counter[str]] = {}
        self._lock = threading.Lock()

    def record(self, code: str) -> None:
        with self._lock:
            hour = int(self._clock() // self.BUCKET)
            self._hours.setdefault(hour, Counter())[code] += 1
            self._forget(hour)

    def counts(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            self._forget(int(now // self.BUCKET))
            counted: Counter[str] = Counter()
            for codes in self._hours.values():
                counted.update(codes)
        since = max(self._since, now - self.WINDOW)
        return {
            "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since)),
            "last_24h": dict(sorted(counted.items())),
        }

    def _forget(self, hour: int) -> None:
        oldest = hour - self.WINDOW // self.BUCKET + 1
        for stale in [h for h in self._hours if h < oldest]:
            del self._hours[stale]


def _parse_json(raw: bytes) -> Any:
    try:
        return strict_loads(raw)
    except InvalidJSON as error:
        raise Rejected(422, [Problem("invalid_json", "$", str(error))]) from error


async def _read_body(request: Request, limit: int) -> bytes:
    """Read at most `limit` bytes, refusing a larger body before reading it where possible."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise Rejected(413, [Problem("too_large", "bytes", f"the limit is {limit} bytes")])
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise Rejected(413, [Problem("too_large", "bytes", f"the limit is {limit} bytes")])
    return bytes(body)
