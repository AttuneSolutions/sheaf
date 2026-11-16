import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sheaf_admin.genesis import GatewayClient
from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.store import MemoryStore

NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)


def write_genesis(directory: Path, *, approver: str = t.APPROVER["id"], **overrides) -> Path:
    """The genesis input for acme/case-review: `t.mandate_document()`, with each file the mandate
    names by its SHA-256 named by its path instead, and those files beside it."""
    files = {
        "instructions/review.md": t.INSTRUCTIONS,
        "schemas/findings.json": t.FINDINGS_SCHEMA,
        "witness.pem": t.witness_pem(),
        **{f"roots/{name}.der": t.authority(name).root for name, _ in t.AUTHORITIES},
    }
    for name, data in files.items():
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(data)
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
    path = directory / "genesis.json"
    path.write_text(json.dumps({"approver": approver, "mandate": mandate}, indent=2))
    return path


@pytest.fixture
def genesis_file(tmp_path):
    def write(**overrides) -> Path:
        return write_genesis(tmp_path, **overrides)

    return write


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def bearer(request):
    # Test only: the bearer token is the caller's id; "app:" marks an application's token.
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        return None
    if token.startswith("app:"):
        return Caller(token.removeprefix("app:"), person=False)
    return Caller(token, person=True)


class World:
    def __init__(self, bootstrap=t.APPROVER["id"]):
        self.store = MemoryStore()
        self.gateway = Gateway(
            Settings(chain=t.CHAIN, bootstrap_caller=bootstrap), self.store, clock=Clock()
        )
        self.gateway.recover()
        self.http = TestClient(create_app(self.gateway, authenticate=bearer))

    def client(self, token=t.APPROVER["id"]):
        return GatewayClient(self.http, "http://testserver", token=lambda: token)

    def stored(self, genesis):
        return [self.store.info(upload.sha256) is not None for upload in genesis.uploads]


@pytest.fixture
def make_world():
    """A gateway for acme/case-review, over HTTP, whose bootstrap caller is `bootstrap`."""
    return World
