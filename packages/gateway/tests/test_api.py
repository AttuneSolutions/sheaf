import base64
import json
from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.canonical import canonicalize, strict_loads
from sheaf_core.chain import check_chain, entry_line
from sheaf_core.digest import artefact_sha256
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.store import MemoryStore

BOOTSTRAP = t.APPROVER["id"]


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


class Events:
    def __init__(self):
        self.published = []

    def publish(self, event):
        self.published.append(event)


def header_caller(request):
    # Test only. The gateway's real authenticator validates an Entra ID token and reads its roles.
    identity = request.headers.get("X-Test-Caller")
    if not identity:
        return None
    roles = request.headers.get("X-Test-Roles", "")
    return Caller(identity, frozenset(role for role in roles.split(",") if role))


@pytest.fixture
def parts():
    store, events, clock = MemoryStore(), Events(), Clock()
    gateway = Gateway(
        Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP),
        store,
        events=events,
        clock=clock,
    )
    client = TestClient(create_app(gateway, authenticate=header_caller))
    return client, store, events, clock


@pytest.fixture
def client(parts):
    return parts[0]


def upload(
    client,
    caller,
    data,
    kind,
    media_type,
    *,
    sensitivity="none",
    sha256=None,
    key=None,
    roles=(),
    chain=t.CHAIN,
):
    sha256 = sha256 or artefact_sha256(data)
    key = key or f"upload-{sha256}"
    headers = {
        "X-Test-Caller": caller,
        "Content-Type": media_type,
        "Sheaf-Kind": kind,
        "Sheaf-Sensitivity": sensitivity,
        "Sheaf-Chain": chain,
        "Idempotency-Key": key,
    }
    if roles:
        headers["X-Test-Roles"] = ",".join(roles)
    return client.put(f"/v1/artefacts/{sha256}", content=data, headers=headers)


def commit(client, caller, entry, *, key=None, raw=None, roles=()):
    headers = {"X-Test-Caller": caller, "Content-Type": "application/json"}
    if key:
        headers["Idempotency-Key"] = key
    if roles:
        headers["X-Test-Roles"] = ",".join(roles)
    body = raw if raw is not None else t.mandate_bytes(entry)
    return client.post("/v1/entries", content=body, headers=headers)


def put_trust(client, caller, path, data):
    return client.put(
        f"/v1/{path}",
        content=data,
        headers={"X-Test-Caller": caller, "Content-Type": "application/octet-stream"},
    )


def upload_mandate(client, doc, caller=None):
    """Upload everything a config.changed for `doc` needs: the mandate, its instructions and
    schema, and the trust files it names."""
    caller = caller or BOOTSTRAP
    for data, kind, media_type in (
        (t.mandate_bytes(doc), "data.json", "application/json"),
        (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
        (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
    ):
        response = upload(client, caller, data, kind, media_type, chain=doc["chain"])
        assert response.status_code in (200, 201), response.json()
    for path, data in t.trust_files(doc).items():
        response = put_trust(client, caller, path, data)
        assert response.status_code in (200, 201), response.json()


def submit_witness(client, witness, tokens, *, caller=None, key=None, raw=None):
    headers = {"X-Test-Caller": caller or t.WITNESS["id"], "Content-Type": "application/json"}
    if key:
        headers["Idempotency-Key"] = key
    body = raw
    if body is None:
        body = json.dumps(
            {
                "entry": t.witness_draft(witness),
                "tokens": {name: base64.b64encode(data).decode() for name, data in tokens.items()},
            }
        ).encode()
    return client.post("/v1/witnesses", content=body, headers=headers)


def genesis(client):
    doc = t.mandate_document()
    upload_mandate(client, doc)
    config = commit(client, BOOTSTRAP, t.config_changed(doc))
    assert config.status_code == 201, config.json()
    interim = submit_witness(client, *t.attested("interim", 1, config.json()["hash"]))
    assert interim.status_code == 201, interim.json()
    return config.json()


def test_the_artefacts_a_chain_level_entry_refers_to_are_kept_as_chain(parts):
    client, store, _, _ = parts
    genesis(client)

    # The mandate and its schema: P7Y, the longest class, from the day written.
    for data in (t.mandate_bytes(t.mandate_document()), t.FINDINGS_SCHEMA):
        assert store.retention[paths.artefact(t.artefact_sha256(data))] == date(2033, 11, 26)


def upload_examples(client):
    for data in (t.REQUEST, t.RESPONSE):
        assert (
            upload(client, t.AGENT["id"], data, "ai.exchange.raw", "application/json").status_code
            == 201
        )


def problems(response):
    return [p["code"] for p in response.json()["problems"]]


# -- the happy path ---------------------------------------------------------------------------


def test_health(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_a_dossier_from_genesis_to_seal(parts):
    client, store, events, _ = parts
    config = genesis(client)
    upload_examples(client)

    opened = commit(client, t.AGENT["id"], t.opened(config["hash"]))
    exchange = commit(client, t.AGENT["id"], t.ai_exchange())
    sealed = commit(client, t.AGENT["id"], t.sealed(3, 2))

    assert [r.status_code for r in (opened, exchange, sealed)] == [201, 201, 201]
    assert [r.json()["seq"] for r in (opened, exchange, sealed)] == [3, 4, 5]

    opened_at = datetime.fromisoformat(opened.json()["committed_at"])
    folder = paths.dossier(t.WORKFLOW, opened_at, t.DOSSIER)
    names = store.list(folder)
    assert names == [paths.entry(folder, seq) for seq in (3, 4, 5)]
    entries = [strict_loads(store.blob(name)) for name in names]
    assert [e["type"] for e in entries] == ["dossier.opened", "ai.exchange", "dossier.sealed"]
    assert all(entry_line(e) == store.blob(n) for e, n in zip(entries, names, strict=True))
    until = date(2033, 11, 26)
    assert all(store.retention[name] == until for name in names)

    chain_folder = paths.chain_dossier(t.WORKFLOW, opened_at)
    chain_level = [strict_loads(store.blob(name)) for name in store.list(chain_folder)]
    assert check_chain(sorted(chain_level + entries, key=lambda e: e["seq"])) == []

    day = paths.chain_segment(t.WORKFLOW, opened_at)
    segment = [strict_loads(store.blob(name)) for name in store.list(day)]
    assert [s["seq"] for s in segment] == [1, 2, 3, 4, 5]
    assert set(segment[0]) == {"seq", "dossier", "type", "hash"}
    # Chain-level blobs and segments are kept for the longest class: P7Y from the day written.
    assert store.retention[paths.entry(day, 1)] == date(2033, 11, 26)
    assert store.retention[paths.entry(chain_folder, 1)] == date(2033, 11, 26)

    assert events.published[-1] == {
        "tenant": t.TENANT,
        "workflow": t.WORKFLOW,
        "seq": 5,
        "dossier": t.DOSSIER,
        "type": "dossier.sealed",
        "hash": sealed.json()["hash"],
    }


def test_an_artefact_receipt_is_what_an_entry_refers_to(client):
    response = upload(client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown")

    assert response.status_code == 201
    assert response.json() == {
        "sha256": artefact_sha256(t.INSTRUCTIONS),
        "kind": "text.markdown",
        "media_type": "text/markdown",
        "bytes": len(t.INSTRUCTIONS),
        "sensitivity": "none",
    }
    assert (
        upload(client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown").status_code
        == 200
    )


# -- who may write ----------------------------------------------------------------------------


def test_without_credentials_nothing_is_written():
    gateway = Gateway(Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP), MemoryStore())
    client = TestClient(create_app(gateway))

    assert upload(client, BOOTSTRAP, b"x", "text.plain", "text/plain").status_code == 401
    assert commit(client, BOOTSTRAP, t.notice()).status_code == 401


def test_before_genesis_only_the_bootstrap_caller_writes(client):
    doc = t.mandate_document()

    assert (
        upload(
            client, t.AGENT["id"], t.mandate_bytes(doc), "data.json", "application/json"
        ).status_code
        == 403
    )
    assert commit(client, t.AGENT["id"], t.config_changed(doc)).status_code == 403


def test_a_caller_submits_only_entries_naming_it_as_actor(client):
    genesis(client)

    response = commit(client, t.APP["id"], t.decision(t.stand_in("x")))

    assert response.status_code == 403
    assert problems(response) == ["actor_not_caller"]


def test_before_genesis_the_bootstrap_caller_is_the_approver(client):
    doc = t.mandate_document()
    upload(client, BOOTSTRAP, t.mandate_bytes(doc), "data.json", "application/json")
    upload(client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown")
    entry = t.config_changed(doc)
    entry["actor"] = dict(t.ADMIN)

    response = commit(client, t.ADMIN["id"], entry)

    assert response.status_code == 422
    assert problems(response) == ["approver_not_actor"]


def test_a_person_decides_under_a_role_their_token_holds(client):
    config = genesis(client)
    upload_examples(client)
    assert commit(client, t.AGENT["id"], t.opened(config["hash"])).status_code == 201
    assert commit(client, t.AGENT["id"], t.ai_exchange()).status_code == 201
    decision = t.decision(artefact_sha256(t.RESPONSE))

    refused = commit(client, t.REVIEWER["id"], decision)
    accepted = commit(client, t.REVIEWER["id"], decision, roles=["reviewer"])

    assert (refused.status_code, problems(refused)) == (403, ["role_not_held"])
    assert accepted.status_code == 201, accepted.json()


def test_a_caller_granted_by_role_uploads_what_the_role_writes(client):
    genesis(client)
    doc = t.mandate_document(version="2026.11.2")
    approver = "acme-approver-2"

    refused = upload(client, approver, t.mandate_bytes(doc), "data.json", "application/json")
    accepted = upload(
        client, approver, t.mandate_bytes(doc), "data.json", "application/json", roles=["approver"]
    )

    assert (refused.status_code, problems(refused)) == (403, ["caller_unknown"])
    assert accepted.status_code == 201, accepted.json()


def test_findings_are_checked_against_the_tenant_schema_in_force(client):
    genesis(client)
    invalid = b'{"$schema":"acme.findings/1","findings":[1]}'
    unnamed = b'{"$schema":"acme.findings/2","findings":[]}'

    accepted = upload(client, t.AGENT["id"], t.FINDINGS, "data.json", "application/json")
    refused = upload(client, t.AGENT["id"], invalid, "data.json", "application/json")
    unknown = upload(client, t.AGENT["id"], unnamed, "data.json", "application/json")

    assert accepted.status_code == 201, accepted.json()
    assert (refused.status_code, problems(refused)) == (422, ["schema"])
    assert (unknown.status_code, problems(unknown)) == (422, ["schema_unregistered"])


def test_a_caller_writes_only_the_types_its_policy_lists(client):
    genesis(client)

    response = commit(client, t.REVIEWER["id"], t.notice(actor=t.REVIEWER), roles=["reviewer"])

    assert response.status_code == 403
    assert problems(response) == ["type_not_permitted"]


def test_only_kinds_the_policy_allows_are_uploaded(client):
    genesis(client)

    response = upload(client, t.AGENT["id"], b"\x89PNG\r\n\x1a\n", "image.raster", "image/png")

    assert response.status_code == 403
    assert problems(response) == ["kind_not_permitted"]


def test_an_upload_over_the_policy_limit_is_refused_before_it_is_read(client):
    genesis(client)

    response = upload(client, t.AGENT["id"], b"x" * (1024 * 1024 + 1), "text.plain", "text/plain")

    assert response.status_code == 413


# -- validate and reject ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "kind", "media_type", "code"),
    [
        (b"%PDF-1.7\n", "text.markdown", "text/markdown", "type_mismatch"),
        (b"caf\xe9", "text.markdown", "text/markdown", "not_utf8"),
        (b'{"$schema": "acme.unknown/1"}', "data.json", "application/json", "schema_unregistered"),
        (b"x", "video.mp4", "video/mp4", "kind_unknown"),
        (b'{"a": 1}', "data.json", "text/plain", "media_type_mismatch"),
    ],
)
def test_an_artefact_that_fails_its_checks_is_not_stored(parts, data, kind, media_type, code):
    client, store, _, _ = parts

    response = upload(client, BOOTSTRAP, data, kind, media_type)

    assert response.status_code == 422
    assert problems(response) == [code]
    assert store.info(artefact_sha256(data)) is None


def test_the_declared_sha256_must_match_the_bytes(client):
    response = upload(
        client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown", sha256=t.stand_in("y")
    )

    assert response.status_code == 422
    assert problems(response) == ["sha256_mismatch"]


def test_an_artefact_address_is_a_sha256(client):
    assert (
        upload(client, BOOTSTRAP, b"x", "text.plain", "text/plain", sha256="nope").status_code
        == 422
    )


def test_an_upload_names_an_idempotency_key(client):
    response = client.put(
        f"/v1/artefacts/{artefact_sha256(b'x')}",
        content=b"x",
        headers={
            "X-Test-Caller": BOOTSTRAP,
            "Content-Type": "text/plain",
            "Sheaf-Kind": "text.plain",
            "Sheaf-Sensitivity": "none",
            "Sheaf-Chain": t.CHAIN,
        },
    )

    assert response.status_code == 422
    assert "idempotency-key" in str(response.json()).lower()


def test_an_entry_is_one_unambiguous_json_object(client):
    response = commit(client, BOOTSTRAP, None, raw=b'{"type": "notice", "type": "notice"}')

    assert response.status_code == 422
    assert problems(response) == ["invalid_json"]


def test_a_fraction_in_an_entry_is_refused(client):
    genesis(client)
    entry = t.notice()
    entry["body"]["detail"] = 0.5

    response = commit(client, t.AGENT["id"], entry)

    assert response.status_code == 422
    assert "number" in problems(response)


def test_a_caller_cannot_set_chain_fields(client):
    genesis(client)
    entry = {**t.notice(dossier=None), "seq": 99}

    assert commit(client, BOOTSTRAP, entry).status_code == 422


def test_rules_that_need_the_chain_are_enforced(client):
    genesis(client)

    response = commit(client, t.AGENT["id"], t.notice())

    assert response.status_code == 422
    assert problems(response) == ["dossier_unknown"]


def test_a_witness_is_submitted_with_its_tokens_not_as_a_bare_entry(client):
    doc = t.mandate_document()
    upload_mandate(client, doc)
    config = commit(client, BOOTSTRAP, t.config_changed(doc)).json()
    witness, _ = t.attested("interim", 1, config["hash"])

    response = commit(client, t.WITNESS["id"], t.witness_draft(witness))

    assert response.status_code == 422
    assert problems(response) == ["witness_tokens_required"]


# -- retries ----------------------------------------------------------------------------------


def test_a_retried_commit_returns_the_first_receipt(client):
    genesis(client)
    entry = t.notice(dossier=None)
    entry["actor"] = t.ADMIN

    first = commit(client, t.ADMIN["id"], entry, key="retry-1")
    again = commit(client, t.ADMIN["id"], entry, key="retry-1")

    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()


def test_an_idempotency_key_is_not_reused_for_another_entry(client):
    genesis(client)
    entry = t.notice(dossier=None, actor=t.ADMIN)
    other = t.notice(dossier=None, actor=t.ADMIN)
    other["body"]["detail"] = "something else"

    assert commit(client, t.ADMIN["id"], entry, key="retry-1").status_code == 201
    response = commit(client, t.ADMIN["id"], other, key="retry-1")

    assert response.status_code == 409


def test_an_idempotency_key_names_one_artefact(client):
    first = upload(client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown", key="u1")
    other = upload(client, BOOTSTRAP, b"# Other\n", "text.markdown", "text/markdown", key="u1")

    assert (first.status_code, other.status_code) == (201, 409)


def test_the_same_bytes_are_not_stored_under_two_declarations(client):
    upload(client, BOOTSTRAP, t.INSTRUCTIONS, "text.markdown", "text/markdown")

    response = upload(
        client,
        BOOTSTRAP,
        t.INSTRUCTIONS,
        "text.markdown",
        "text/markdown",
        sensitivity="client_pii",
    )

    assert response.status_code == 409
    assert problems(response) == ["artefact_conflict"]


def test_while_the_genesis_mandate_waits_only_the_bootstrap_caller_writes(client):
    doc = t.mandate_document()
    upload_mandate(client, doc)
    assert commit(client, BOOTSTRAP, t.config_changed(doc)).status_code == 201
    assert commit(client, t.AGENT["id"], t.notice(dossier=None)).status_code == 403
    assert commit(client, BOOTSTRAP, t.notice(dossier=None, actor=t.APPROVER)).status_code == 201


# -- review fixes -----------------------------------------------------------------------------


class FailingStore(MemoryStore):
    """Fails once, on the first append to a chain segment, as a Blob write can."""

    def __init__(self):
        super().__init__()
        self.failed = False

    def put_blob(self, path, data, content_type):
        if path.startswith("chain/") and not self.failed and self.ready:
            self.failed = True
            raise OSError("blob write failed")
        return super().put_blob(path, data, content_type)

    ready = False


def test_after_a_failed_write_the_gateway_refuses_every_commit():
    store = FailingStore()
    gateway = Gateway(
        Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP),
        store,
        clock=Clock(),
    )
    client = TestClient(create_app(gateway, authenticate=header_caller))
    genesis(client)
    head = gateway.state.head
    store.ready = True
    entry = t.notice(dossier=None, actor=t.ADMIN)

    failed = commit(client, t.ADMIN["id"], entry)
    again = commit(client, t.ADMIN["id"], entry)

    assert (failed.status_code, problems(failed)) == (503, ["write_failed"])
    assert (again.status_code, problems(again)) == (503, ["gateway_halted"])
    assert gateway.state.head == head


def test_a_failing_event_publisher_does_not_fail_a_committed_entry():
    class Broken:
        def publish(self, event):
            raise OSError("event bus down")

    gateway = Gateway(
        Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP),
        MemoryStore(),
        events=Broken(),
        clock=Clock(),
    )
    client = TestClient(create_app(gateway, authenticate=header_caller))
    config = commit_genesis_config(client)

    assert config.status_code == 201


def commit_genesis_config(client):
    doc = t.mandate_document()
    upload_mandate(client, doc)
    return commit(client, BOOTSTRAP, t.config_changed(doc))


def test_an_entry_body_has_a_size_limit(client):
    response = commit(client, BOOTSTRAP, None, raw=b" " * (5 * 1024 * 1024) + b"{}")

    assert response.status_code == 413


def test_json_too_deep_to_parse_is_rejected_not_a_server_error(client):
    response = commit(client, BOOTSTRAP, None, raw=b"[" * 200_000)

    assert (response.status_code, problems(response)) == (422, ["invalid_json"])


def test_a_rejection_does_not_echo_a_huge_value_back(client):
    entry = t.notice(dossier=None)
    entry["body"]["event"] = "x" * (2 * 1024 * 1024)

    response = commit(client, BOOTSTRAP, entry)

    assert response.status_code == 422
    assert len(response.content) < 10_000


def test_a_mandate_can_be_replaced_even_if_its_policy_omits_the_mandate_kinds(client):
    doc = t.mandate_document()
    del doc["policy"]["kinds"]["text.markdown"]
    upload_mandate(client, doc)
    config = commit(client, BOOTSTRAP, t.config_changed(doc)).json()
    assert submit_witness(client, *t.attested("interim", 1, config["hash"])).status_code == 201

    new = t.mandate_document(version="2026.12.1", gateway={"image": "sha256:" + "1" * 64})
    assert (
        upload(client, BOOTSTRAP, t.mandate_bytes(new), "data.json", "application/json").status_code
        == 201
    )
    previous = {"version": doc["version"], "config": config["hash"]}
    response = commit(client, BOOTSTRAP, t.config_changed(new, old=doc, previous=previous))

    assert response.status_code == 201, response.json()


def test_credentials_are_checked_before_anything_else(client):
    gateway = Gateway(Settings(chain=t.CHAIN, bootstrap_caller=BOOTSTRAP), MemoryStore())
    closed = TestClient(create_app(gateway))

    assert closed.put(f"/v1/artefacts/{artefact_sha256(b'x')}", content=b"x").status_code == 401


def test_the_api_description_is_not_served(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# -- trust files and witnesses (7.2 step 5) ----------------------------------------------------


def configured(client):
    doc = t.mandate_document()
    upload_mandate(client, doc)
    return commit(client, BOOTSTRAP, t.config_changed(doc)).json()


def test_a_mandate_applies_only_once_its_trust_files_are_stored(client):
    doc = t.mandate_document()
    for data, kind, media_type in (
        (t.mandate_bytes(doc), "data.json", "application/json"),
        (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
        (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
    ):
        upload(client, BOOTSTRAP, data, kind, media_type)

    response = commit(client, BOOTSTRAP, t.config_changed(doc))

    assert response.status_code == 422
    assert set(problems(response)) == {"trust_missing"}


def test_a_trust_file_is_checked_and_stored_once(parts):
    client, store, _, _ = parts
    path, data = next(iter(t.trust_files().items()))
    other_key = t.FakeAuthority("other").root

    first = put_trust(client, BOOTSTRAP, path, data)
    again = put_trust(client, BOOTSTRAP, path, data)
    junk = put_trust(client, BOOTSTRAP, "trust/tsa/tsa-a/" + "0" * 64 + ".der", other_key)

    assert (first.status_code, again.status_code) == (201, 200)
    assert store.trust(path) == data
    assert (junk.status_code, problems(junk)) == (422, ["trust_sha256_mismatch"])


def test_only_a_caller_that_may_change_the_mandate_stores_trust_files(client):
    genesis(client)
    path, data = next(iter(t.trust_files().items()))

    response = put_trust(client, t.AGENT["id"], path, data)

    assert response.status_code == 403


def test_a_witness_and_its_tokens_are_written_where_the_standard_says(parts):
    client, store, _, _ = parts
    config = configured(client)
    witness, tokens = t.attested("interim", 1, config["hash"])

    response = submit_witness(client, witness, tokens)

    assert response.status_code == 201, response.json()
    for name, data in tokens.items():
        assert store.blob(paths.interim_token(t.WORKFLOW, 1, name)) == data
    assert store.blob(paths.witness_interim(t.WORKFLOW, 1)) == canonicalize(witness)


def test_a_witness_whose_token_does_not_match_is_refused(client):
    config = configured(client)
    witness, tokens = t.attested("interim", 1, config["hash"])
    tokens["tsa-a"], tokens["tsa-b"] = tokens["tsa-b"], tokens["tsa-a"]

    response = submit_witness(client, witness, tokens)

    assert response.status_code == 422
    assert problems(response) == ["token_mismatch", "token_mismatch"]


def test_a_witness_missing_a_token_is_refused(client):
    config = configured(client)
    witness, tokens = t.attested("interim", 1, config["hash"])
    del tokens["tsa-a"]

    response = submit_witness(client, witness, tokens)

    assert (response.status_code, problems(response)) == (422, ["token_missing"])


def test_a_witness_submission_is_an_entry_and_base64_tokens(client):
    configured(client)
    bad = submit_witness(client, None, None, raw=b'{"entry": {}, "tokens": {"tsa-a": "%%%"}}')
    extra = submit_witness(client, None, None, raw=b'{"entry": {}, "tokens": {}, "more": 1}')

    assert (bad.status_code, problems(bad)) == (422, ["token_encoding"])
    assert (extra.status_code, problems(extra)) == (422, ["submission_invalid"])


def test_only_the_witness_identity_submits_witnesses(client):
    config = configured(client)
    witness, tokens = t.attested("interim", 1, config["hash"])

    response = submit_witness(client, witness, tokens, caller=t.AGENT["id"])

    assert response.status_code == 403
