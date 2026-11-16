import re

import pytest
from fastapi.testclient import TestClient

from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.pseudonyms import MemoryPseudonyms, RecordedIdentities
from sheaf_gateway.store import MemoryStore

APPROVER_OID = "00000000-0000-4000-8000-0000000000a1"
AGENT_OID = "00000000-0000-4000-8000-0000000000a2"
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:+/=-]*$")


def test_a_pseudonym_is_stable_per_person_and_says_nothing_about_them():
    pseudonyms = MemoryPseudonyms()
    first = pseudonyms.pseudonym(APPROVER_OID)

    assert pseudonyms.pseudonym(APPROVER_OID) == first
    assert pseudonyms.pseudonym(AGENT_OID) != first
    assert re.fullmatch(r"ps-[0-9a-f]{32}", first) and IDENTITY.match(first)
    assert APPROVER_OID not in first


def test_destroying_a_persons_secret_unlinks_their_pseudonym():
    pseudonyms = MemoryPseudonyms()
    before = pseudonyms.pseudonym(APPROVER_OID)

    pseudonyms.destroy(APPROVER_OID)

    assert pseudonyms.pseudonym(APPROVER_OID) != before


def test_people_are_recorded_by_pseudonym_and_systems_in_clear():
    pseudonyms = MemoryPseudonyms()
    recorded = RecordedIdentities(lambda request: request, pseudonyms)

    person = recorded(Caller(APPROVER_OID, frozenset({"approver"}), person=True))
    system = recorded(Caller(AGENT_OID, person=False))

    assert person == Caller(
        pseudonyms.pseudonym(APPROVER_OID), frozenset({"approver"}), person=True
    )
    assert system == Caller(AGENT_OID, person=False)
    assert recorded(None) is None


def pseudonymised_world():
    pseudonyms = MemoryPseudonyms()
    settings = Settings(chain=t.CHAIN, bootstrap_caller=APPROVER_OID, identifiers="pseudonymised")
    gateway = Gateway(settings, MemoryStore(), pseudonyms=pseudonyms)

    def header(request):
        oid = request.headers.get("X-Test-Oid")
        if not oid:
            return None
        return Caller(oid, person=request.headers.get("X-Test-Person") == "yes")

    client = TestClient(create_app(gateway, authenticate=RecordedIdentities(header, pseudonyms)))
    return gateway, client, pseudonyms


def as_person(oid):
    return {"X-Test-Oid": oid, "X-Test-Person": "yes"}


def test_a_caller_learns_the_identity_its_entries_must_name():
    _, client, pseudonyms = pseudonymised_world()

    me = client.get("/v1/me", headers=as_person(APPROVER_OID)).json()

    assert me == {"id": pseudonyms.pseudonym(APPROVER_OID), "person": True, "roles": []}
    assert client.get("/v1/me").status_code == 401


def upload_genesis(gateway, caller, doc):
    for data, kind, media_type in (
        (t.mandate_bytes(doc), "data.json", "application/json"),
        (t.INSTRUCTIONS, "text.markdown", "text/markdown"),
        (t.FINDINGS_SCHEMA, "schema.json", "application/schema+json"),
    ):
        gateway.upload(
            caller,
            data,
            sha256=t.artefact_sha256(data),
            kind=kind,
            media_type=media_type,
            sensitivity="none",
            idempotency_key=t.artefact_sha256(data),
        )
    for path, data in t.trust_files(doc).items():
        gateway.put_trust(caller, path, data)


def genesis_as(pseudonym, doc):
    entry = t.config_changed(doc)
    person = {"kind": "person", "id": pseudonym}
    entry["actor"], entry["body"]["approved_by"] = person, person
    return entry


def test_the_bootstrap_person_writes_genesis_under_their_pseudonym():
    gateway, client, pseudonyms = pseudonymised_world()
    pseudonym = pseudonyms.pseudonym(APPROVER_OID)
    doc = t.mandate_document(
        personal_data={"identifiers": "pseudonymised", "basis": "Staff are pseudonymised."}
    )
    doc["authorities"]["assessment"]["by"] = {"kind": "person", "id": pseudonym}
    upload_genesis(gateway, pseudonym, doc)

    clear = genesis_as(APPROVER_OID, doc)
    in_clear = client.post(
        "/v1/entries", content=t.mandate_bytes(clear), headers=as_person(APPROVER_OID)
    )
    accepted = client.post(
        "/v1/entries",
        content=t.mandate_bytes(genesis_as(pseudonym, doc)),
        headers=as_person(APPROVER_OID),
    )

    assert in_clear.status_code == 403
    assert accepted.status_code == 201, accepted.json()


def test_a_mandate_declares_the_identifiers_the_gateway_records():
    gateway, client, pseudonyms = pseudonymised_world()
    pseudonym = pseudonyms.pseudonym(APPROVER_OID)
    doc = t.mandate_document()  # says "clear"
    upload_genesis(gateway, pseudonym, doc)

    response = client.post(
        "/v1/entries",
        content=t.mandate_bytes(genesis_as(pseudonym, doc)),
        headers=as_person(APPROVER_OID),
    )

    assert response.status_code == 422
    assert [p["code"] for p in response.json()["problems"]] == ["identifiers_mismatch"]


def test_pseudonymised_identifiers_need_somewhere_to_keep_the_secrets():
    with pytest.raises(ValueError):
        Gateway(
            Settings(chain=t.CHAIN, bootstrap_caller="x", identifiers="pseudonymised"),
            MemoryStore(),
        )


# -- subject pseudonyms ------------------------------------------------------------------------

SUBJECT = {"system": "crm", "object": "Case", "id": "C104233"}


def test_a_subject_has_one_pseudonym_per_record_until_its_secret_is_destroyed():
    pseudonyms = MemoryPseudonyms()
    first = pseudonyms.subject("crm", "Case", "C104233")

    assert pseudonyms.subject("crm", "Case", "C104233") == first
    assert pseudonyms.subject("crm", "Case", "C104234") != first
    assert pseudonyms.subject("erp", "Case", "C104233") != first
    assert re.fullmatch(r"ps-[0-9a-f]{32}", first)
    pseudonyms.destroy_subject("crm", "Case", "C104233")
    assert pseudonyms.subject("crm", "Case", "C104233") != first


def in_force(gateway, client, pseudonyms):
    pseudonym = pseudonyms.pseudonym(APPROVER_OID)
    doc = t.mandate_document(
        personal_data={"identifiers": "pseudonymised", "basis": "Staff and clients pseudonymised."}
    )
    doc["authorities"]["assessment"]["by"] = {"kind": "person", "id": pseudonym}
    doc["policy"]["callers"].append({"id": AGENT_OID, "types": ["dossier.opened"]})
    upload_genesis(gateway, pseudonym, doc)
    config = client.post(
        "/v1/entries",
        content=t.mandate_bytes(genesis_as(pseudonym, doc)),
        headers=as_person(APPROVER_OID),
    )
    assert config.status_code == 201, config.json()
    import base64
    import json

    witness, tokens = t.attested("interim", 1, config.json()["hash"])
    body = {
        "entry": t.witness_draft(witness),
        "tokens": {n: base64.b64encode(d).decode() for n, d in tokens.items()},
    }
    gateway.commit_witness(t.WITNESS["id"], json.dumps(body).encode())


def as_system(oid):
    return {"X-Test-Oid": oid, "X-Test-Person": "no"}


def test_a_caller_the_mandate_knows_gets_a_subjects_pseudonym():
    gateway, client, pseudonyms = pseudonymised_world()
    in_force(gateway, client, pseudonyms)

    response = client.post("/v1/pseudonyms", json=SUBJECT, headers=as_system(AGENT_OID))

    assert response.status_code == 200, response.json()
    assert response.json() == {**SUBJECT, "id": pseudonyms.subject("crm", "Case", "C104233")}


def test_a_stranger_gets_no_pseudonym():
    gateway, client, pseudonyms = pseudonymised_world()
    in_force(gateway, client, pseudonyms)

    response = client.post("/v1/pseudonyms", json=SUBJECT, headers=as_system("someone-else"))

    assert response.status_code == 403


def test_no_pseudonym_before_a_mandate_is_in_force():
    _, client, _ = pseudonymised_world()

    response = client.post("/v1/pseudonyms", json=SUBJECT, headers=as_system(AGENT_OID))

    assert response.status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {"system": "crm", "object": "Case"},
        {**SUBJECT, "id": 7},
        {**SUBJECT, "more": "x"},
        [],
        {**SUBJECT, "object": "Case\x00C104233"},
    ],
)
def test_a_pseudonym_request_is_a_subject(body):
    gateway, client, pseudonyms = pseudonymised_world()
    in_force(gateway, client, pseudonyms)

    response = client.post("/v1/pseudonyms", json=body, headers=as_system(AGENT_OID))

    assert response.status_code == 422


def test_a_gateway_recording_identifiers_in_clear_makes_no_pseudonyms():
    gateway = Gateway(Settings(chain=t.CHAIN, bootstrap_caller=APPROVER_OID), MemoryStore())
    client = TestClient(create_app(gateway, authenticate=lambda r: Caller(AGENT_OID, person=False)))

    response = client.post("/v1/pseudonyms", json=SUBJECT)

    assert response.status_code == 422
    assert response.json()["problems"][0]["code"] == "not_pseudonymised"
