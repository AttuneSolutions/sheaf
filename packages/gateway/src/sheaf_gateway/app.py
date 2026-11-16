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

A rejection is 4xx with {"problems": [{code, path, detail}]}: 401 no caller, 403 not permitted,
409 an idempotency key or an artefact declared two ways, 413 too large, 422 invalid; 503 when a
write failed partway or the chain-head lease was lost, until the gateway restarts.
"""

import hashlib
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
    MAX_WITNESS_BYTES,
    Gateway,
    Gateways,
    Rejected,
)
from sheaf_gateway.hooks import Authenticator, Caller, refuse_all


def create_app(gateway: Gateway | Gateways, authenticate: Authenticator = refuse_all) -> FastAPI:
    if isinstance(gateway, Gateway):
        gateway = Gateways([gateway])
    # No API description is served: callers are known workloads, and the contract is 7.2.
    app = FastAPI(
        title="Sheaf write gateway",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(Rejected)
    async def rejected(request: Request, error: Rejected) -> JSONResponse:
        shown = error.problems[:MAX_PROBLEMS]
        problems = [{"code": p.code, "path": p.path, "detail": p.detail[:500]} for p in shown]
        if len(error.problems) > MAX_PROBLEMS:
            more = len(error.problems) - MAX_PROBLEMS
            problems.append({"code": "more", "path": "$", "detail": f"{more} more not shown"})
        return JSONResponse({"problems": problems}, status_code=error.status)

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
        limit = gateway.upload_limit(who.id, sheaf_kind, chain=sheaf_chain, roles=who.roles)
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
