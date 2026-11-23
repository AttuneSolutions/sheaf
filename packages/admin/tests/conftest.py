import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sheaf_admin.client import GatewayClient
from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.state import MemoryState
from sheaf_gateway.store import MemoryStore

NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)

PROPOSER = "acme-proposer-1|proposer"
"""The tokens tests sign in with: `id|role,role`, and `app:` before an application's."""
APPROVER = t.APPROVER["id"]


def write_input(
    directory: Path, *, name: str = "genesis.json", reason: str | None = None, **overrides
) -> Path:
    """The input for a mandate of acme/case-review: `t.mandate_document()`, with each file the
    mandate names by its SHA-256 named by its path instead, and those files beside it."""
    files = {
        "instructions/review.md": t.INSTRUCTIONS,
        "schemas/findings.json": t.FINDINGS_SCHEMA,
        "witness.pem": t.witness_pem(),
        **{f"roots/{authority}.der": t.authority(authority).root for authority, _ in t.AUTHORITIES},
    }
    for relative, data in files.items():
        (directory / relative).parent.mkdir(parents=True, exist_ok=True)
        (directory / relative).write_bytes(data)
    mandate = t.mandate_document()
    key = mandate["witness_key"]
    mandate.update(
        instructions=[{"name": "review-instructions", "file": "instructions/review.md"}],
        schemas=[{"id": "acme.findings/1", "file": "schemas/findings.json"}],
        witness_key={
            "key_id": key["key_id"],
            "algorithm": key["algorithm"],
            "public_key": "witness.pem",
            "identity": key["identity"],
        },
        authorities={
            **mandate["authorities"],
            "list": [
                {**listed, "roots": [f"roots/{listed['authority']}.der"]}
                for listed in mandate["authorities"]["list"]
            ],
        },
    )
    mandate.update(overrides)
    doc = {"mandate": mandate} if reason is None else {"reason": reason, "mandate": mandate}
    path = directory / name
    path.write_text(json.dumps(doc, indent=2))
    return path


@pytest.fixture
def input_file(tmp_path):
    def write(**overrides) -> Path:
        return write_input(tmp_path, **overrides)

    return write


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def bearer(request):
    # Test only: the bearer token is the caller's id, then "|" and its app roles; "app:" marks an
    # application's token.
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        return None
    person = not token.startswith("app:")
    identity, _, roles = token.removeprefix("app:").partition("|")
    return Caller(identity, frozenset(r for r in roles.split(",") if r), person=person)


class World:
    def __init__(self, bootstrap=APPROVER):
        self.store, self.state = MemoryStore(), MemoryState()
        self.gateway = Gateway(
            Settings(chain=t.CHAIN, bootstrap_caller=bootstrap),
            self.store,
            state=self.state,
            clock=Clock(),
        )
        self.gateway.recover()
        self.http = TestClient(create_app(self.gateway, authenticate=bearer))

    def client(self, token=APPROVER, cls=GatewayClient):
        return cls(self.http, "http://testserver", token=lambda: token)

    def stored(self, staged):
        return [self.store.info(upload.sha256) is not None for upload in staged.uploads]

    def proposals(self):
        return [json.loads(data) for data in self.state.list_proposals()]

    def witness(self, receipt):
        """The interim witness that puts a committed mandate in force."""
        witness, tokens = t.attested("interim", receipt["seq"], receipt["hash"])
        body = {
            "entry": t.witness_draft(witness),
            "tokens": {name: base64.b64encode(data).decode() for name, data in tokens.items()},
        }
        self.gateway.commit_witness(t.WITNESS["id"], json.dumps(body).encode())


@pytest.fixture
def make_world():
    """A gateway for acme/case-review, over HTTP, whose bootstrap caller is `bootstrap`."""
    return World
