import base64
import copy
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from sheaf_approve.app import create_app
from sheaf_approve.settings import Settings
from sheaf_core import testing as t
from sheaf_core.digest import artefact_sha256
from sheaf_gateway.app import create_app as gateway_app
from sheaf_gateway.gateway import Gateway
from sheaf_gateway.gateway import Settings as GatewaySettings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.store import MemoryStore

GATEWAY = "https://gateway.acme.example"
PUBLISHED = "https://approve.acme.example/"
TENANT_ID = "00000000-0000-4000-8000-00000000aaaa"
CLIENT_ID = "00000000-0000-4000-8000-00000000bbbb"
SCOPE = "api://00000000-0000-4000-8000-00000000cccc/user_impersonation"

BOOTSTRAP = t.APPROVER["id"]
PROPOSER = t.PROPOSER["id"]


def token(identity, *roles, person=True, secret=""):
    """A test bearer token, `person~<id>~<role>+<role>[~<anything>]`, or `app~` for an
    application: only characters a bearer token may hold. The gateway's real authenticator
    validates an Entra ID token instead."""
    text = f"{'person' if person else 'app'}~{identity}~{'+'.join(roles)}"
    return f"{text}~{secret}" if secret else text


APPROVER_TOKEN = token(BOOTSTRAP)
PROPOSER_TOKEN = token(PROPOSER, "proposer")
WITNESS_TOKEN = token(t.WITNESS["id"], person=False)


def bearer(request):
    """The gateway's test authenticator, reading `token`."""
    text = request.headers.get("Authorization", "").removeprefix("Bearer ")
    kind, _, rest = text.partition("~")
    identity, _, rest = rest.partition("~")
    roles = rest.partition("~")[0]
    if kind not in ("person", "app") or not identity:
        return None
    return Caller(identity, frozenset(r for r in roles.split("+") if r), person=kind == "person")


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def auth(value):
    return {"Authorization": f"Bearer {value}"}


class World:
    """A gateway for acme/case-review over HTTP, and sheaf-approve in front of it."""

    def __init__(self, *, chains=(t.CHAIN,), http=None):
        self.clock, self.store = Clock(), MemoryStore()
        self.gateway = Gateway(
            GatewaySettings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP),
            self.store,
            clock=self.clock,
        )
        self.gateway.recover()
        self.gateway_http = TestClient(gateway_app(self.gateway, authenticate=bearer))
        self.settings = Settings(
            gateway_url=GATEWAY,
            tenant=TENANT_ID,
            client_id=CLIENT_ID,
            scope=SCOPE,
            redirect_uri=PUBLISHED,
            chains=tuple(chains),
        )
        self.app = create_app(self.settings, http or self.gateway_http)
        self.client = TestClient(self.app, base_url=PUBLISHED.rstrip("/"))

    # -- the gateway, directly ---------------------------------------------------------------

    def call(self, method, path, value, **kwargs):
        headers = {**auth(value), **kwargs.pop("headers", {})}
        return self.gateway_http.request(method, f"{GATEWAY}{path}", headers=headers, **kwargs)

    def upload(self, doc, value=PROPOSER_TOKEN):
        for data, kind, media_type in (
            (t.mandate_bytes(doc), "data.json", "application/json"),
            (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
            (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
        ):
            sha256 = artefact_sha256(data)
            headers = {
                "Content-Type": media_type,
                "Sheaf-Kind": kind,
                "Sheaf-Sensitivity": "none",
                "Sheaf-Chain": doc["chain"],
                "Idempotency-Key": sha256,
            }
            response = self.call(
                "PUT", f"/v1/artefacts/{sha256}", value, content=data, headers=headers
            )
            assert response.status_code in (200, 201), response.json()
        for path, data in t.trust_files(doc).items():
            response = self.call("PUT", f"/v1/{path}", value, content=data)
            assert response.status_code in (200, 201), response.json()

    def stage(self, doc, *, reason="genesis", value=PROPOSER_TOKEN, **fields):
        """Upload `doc` and propose it, as a proposer by default. Returns its fingerprint."""
        self.upload(doc, value)
        sha256 = artefact_sha256(t.mandate_bytes(doc))
        body = {"chain": doc["chain"], "mandate": sha256, "reason": reason, **fields}
        response = self.call("POST", "/v1/proposals", value, json=body)
        assert response.status_code in (200, 201), response.json()
        return sha256

    def proposal(self, sha256):
        return self.call("GET", f"/v1/proposals/{sha256}", APPROVER_TOKEN).json()["proposal"]

    def witness(self, seq, entry_hash):
        """Commit the interim witness that puts the mandate at `seq` in force."""
        witness, tokens = t.attested("interim", seq, entry_hash)
        body = {
            "entry": t.witness_draft(witness),
            "tokens": {n: base64.b64encode(d).decode() for n, d in tokens.items()},
        }
        response = self.call("POST", "/v1/witnesses", WITNESS_TOKEN, content=json.dumps(body))
        assert response.status_code == 201, response.json()

    def head(self):
        return self.gateway.state.head

    # -- sheaf-approve -----------------------------------------------------------------------

    def get(self, path, value=APPROVER_TOKEN):
        return self.client.get(path, headers=auth(value) if value else {})

    def approve(self, sha256, value=APPROVER_TOKEN, *, confirm=t.CHAIN, fingerprint=None):
        body = {"confirm": confirm, "fingerprint": fingerprint or sha256}
        headers = auth(value) if value else {}
        return self.client.post(f"/api/proposals/{sha256}/approve", json=body, headers=headers)

    def genesis(self):
        """The genesis staged by the proposer, approved through the page, and witnessed."""
        sha256 = self.stage(t.mandate_document())
        approved = self.approve(sha256)
        assert approved.status_code == 200, approved.json()
        receipt = approved.json()["approved"]
        self.witness(receipt["seq"], receipt["hash"])
        return receipt

    def change(self, version="2026.11.2", **models):
        """A new mandate replacing the genesis: its model version changed."""
        doc = copy.deepcopy(t.mandate_document())
        doc["version"] = version
        doc["models"][0].update(models or {"model_version": "2026-06-01"})
        return doc


@pytest.fixture
def world():
    return World()


def forwarding(world, *, refuse=None, lose_answer=None, change=None):
    """An httpx client that passes requests on to the world's gateway, except those `refuse`
    names, which fail as an unreachable gateway does; those `lose_answer` names reach the
    gateway, but their answer is lost to a timeout. `change` may rewrite an answer's JSON."""

    def handle(request):
        if refuse is not None and refuse(request):
            raise httpx.ConnectError("connection refused", request=request)
        answer = world.gateway_http.request(
            request.method, str(request.url), headers=request.headers, content=request.content
        )
        if lose_answer is not None and lose_answer(request):
            raise httpx.ReadTimeout("timed out", request=request)
        content = answer.content
        if change is not None:
            content = json.dumps(change(request, answer.json())).encode()
        return httpx.Response(
            answer.status_code,
            content=content,
            headers={"content-type": answer.headers.get("content-type", "application/json")},
        )

    return httpx.Client(transport=httpx.MockTransport(handle))
