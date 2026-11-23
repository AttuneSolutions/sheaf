"""Building a mandate from what a person writes, and checking it offline with the rules the gateway
runs, before anything is staged."""

import hashlib
import json
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sheaf_admin.staging import InputError, load
from sheaf_core import testing as t
from sheaf_core.canonical import strict_loads
from sheaf_core.digest import artefact_sha256
from sheaf_core.mandate import PARTS, part_digests
from sheaf_core.proposal import STAND_IN_APPROVER
from sheaf_witness import catalogue

NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)


def test_the_mandate_names_each_file_by_its_sha256(input_file):
    genesis = load(input_file())
    assert genesis.mandate == t.mandate_document()
    assert genesis.chain == t.CHAIN
    assert genesis.fingerprint == artefact_sha256(genesis.uploads[0].data)


def test_the_uploads_are_the_mandate_its_instructions_and_its_schemas(input_file):
    genesis = load(input_file())
    described = [(u.role, u.kind, u.media_type, u.sensitivity) for u in genesis.uploads]
    assert described == [
        ("mandate", "data.json", "application/json", "none"),
        ("instructions", "text.markdown", "text/markdown", "none"),
        ("schema", "schema.json", "application/schema+json", "none"),
    ]
    mandate, instructions, schema = genesis.uploads
    assert strict_loads(mandate.data) == genesis.mandate
    assert (instructions.data, schema.data) == (t.INSTRUCTIONS, t.FINDINGS_SCHEMA)
    assert mandate.sha256 == artefact_sha256(mandate.data)


def test_the_trust_files_are_the_witness_key_and_each_authority_root(input_file):
    assert load(input_file()).trust == t.trust_files()


def test_the_offline_check_is_of_a_genesis_config_changed_from_a_stand_in_approver(input_file):
    genesis = load(input_file())
    entry = genesis.draft(NOW)
    assert entry["type"] == "config.changed"
    assert (entry["chain"], entry["tenant"], entry["dossier"]) == (t.CHAIN, t.TENANT, None)
    assert entry["actor"] == {"kind": "person", "id": STAND_IN_APPROVER}
    assert entry["observed_at"] == "2026-11-26T09:00:00.000Z"
    assert entry["artefacts"] == [
        {
            "role": u.role,
            "kind": u.kind,
            "sha256": u.sha256,
            "bytes": len(u.data),
            "media_type": u.media_type,
            "sensitivity": "none",
        }
        for u in genesis.uploads
    ]
    assert entry["body"] == {
        "version": "2026.11.1",
        "previous": None,
        "changed": list(PARTS),
        "mandate": genesis.uploads[0].sha256,
        "parts": part_digests(t.mandate_document()),
        "proposed_by": {"kind": "system", "id": "sheaf-admin-check"},
        "approved_by": {"kind": "person", "id": STAND_IN_APPROVER},
        "reason": "genesis",
    }


def test_a_good_genesis_has_no_problems(input_file):
    assert load(input_file()).check(NOW) == []


def test_the_reason_may_be_given(tmp_path, input_file):
    path = input_file()
    doc = json.loads(path.read_text())
    path.write_text(json.dumps({**doc, "reason": "Case review starts recording."}))
    staged = load(path)
    assert staged.reason == "Case review starts recording."
    assert staged.request() == {
        "chain": t.CHAIN,
        "mandate": staged.fingerprint,
        "reason": "Case review starts recording.",
    }
    assert staged.request(expires_in_days=3)["expires_in_days"] == 3


def test_authorities_may_be_named_from_the_catalogue(input_file):
    assessment = t.mandate_document()["authorities"]["assessment"]
    names = [authority.authority for authority in catalogue.default()]
    genesis = load(input_file(authorities={"list": names, "assessment": assessment}))
    assert genesis.mandate["authorities"] == catalogue.default_authorities(
        by=assessment["by"], date=assessment["date"], statement=assessment["statement"]
    )
    for authority in catalogue.default():
        assert authority.trust_files().items() <= genesis.trust.items()
    assert genesis.check(NOW) == []


def test_an_authority_not_in_the_catalogue_is_refused(input_file):
    assessment = t.mandate_document()["authorities"]["assessment"]
    with pytest.raises(InputError, match="no-such-tsa.*freetsa"):
        load(input_file(authorities={"list": ["freetsa", "no-such-tsa"], "assessment": assessment}))


@pytest.mark.parametrize(
    ("part", "value", "where"),
    [
        (
            "instructions",
            [{"name": "review-instructions", "sha256": artefact_sha256(t.INSTRUCTIONS)}],
            r"\$\.mandate\.instructions\[0\]",
        ),
        (
            "schemas",
            [{"id": "acme.findings/1", "sha256": artefact_sha256(t.FINDINGS_SCHEMA)}],
            r"\$\.mandate\.schemas\[0\]",
        ),
    ],
)
def test_a_digest_in_place_of_its_file_is_refused(input_file, part, value, where):
    # The tool computes every digest from the bytes it uploads, so the two cannot disagree.
    with pytest.raises(InputError, match=where + ".*file"):
        load(input_file(**{part: value}))


def test_a_witness_key_digest_in_place_of_its_file_is_refused(input_file):
    key = {
        "key_id": t.KEY_ID,
        "algorithm": "ES256",
        "public_key_sha256": hashlib.sha256(t.witness_pem()).hexdigest(),
        "identity": t.WITNESS["id"],
    }
    with pytest.raises(InputError, match=r"\$\.mandate\.witness_key.*public_key"):
        load(input_file(witness_key=key))


def test_a_missing_file_is_refused(input_file):
    with pytest.raises(InputError, match=r"instructions/missing\.md"):
        load(input_file(instructions=[{"name": "review", "file": "instructions/missing.md"}]))


def test_the_approver_is_not_named_in_the_input(input_file):
    # Whoever approves the proposal is its approver, so the file cannot name one.
    path = input_file()
    doc = json.loads(path.read_text())
    path.write_text(json.dumps({"approver": t.APPROVER["id"], **doc}))
    with pytest.raises(InputError, match="approver.*whoever approves"):
        load(path)


def test_input_that_is_not_json_is_refused(tmp_path):
    path = tmp_path / "genesis.json"
    path.write_text('{"reason": "a", "reason": "b"}')
    with pytest.raises(InputError, match="genesis.json"):
        load(path)


def _p384_pem() -> bytes:
    return (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def _schema_with_id(schema_id: str) -> bytes:
    return json.dumps({**t.FINDINGS_SCHEMA_DOC, "$id": schema_id}).encode()


def _fraction(d):
    return {**d, "models": [{**d["models"][0], "parameters": {"temperature": 0.2}}]}


def _other_tenants_schema(d):
    return {**d, "schemas": [{"id": "globex.findings/1", "file": "schemas/findings.json"}]}


def _pseudonymised(d):
    return {**d, "personal_data": {**d["personal_data"], "identifiers": "pseudonymised"}}


def _one_jurisdiction(d):
    listed = [{**a, "jurisdiction": "CH"} for a in d["authorities"]["list"]]
    return {**d, "authorities": {**d["authorities"], "list": listed}}


def _unknown_registry(d):
    return {**d, "registry": {"version": "9.9.9"}}


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (_fraction, "number"),
        (_other_tenants_schema, "schema_tenant"),
        (_pseudonymised, "identifier_not_pseudonymised"),
        (_one_jurisdiction, "authorities_one_jurisdiction"),
        (_unknown_registry, "registry_unknown"),
    ],
)
def test_check_finds_what_the_gateway_would_refuse(input_file, change, code):
    path = input_file()
    doc = json.loads(path.read_text())
    path.write_text(json.dumps({**doc, "mandate": change(doc["mandate"])}))
    assert code in [problem.code for problem in load(path).check(NOW)]


def test_check_finds_a_witness_key_the_gateway_would_not_store(input_file, tmp_path):
    input_file()
    (tmp_path / "witness.pem").write_bytes(_p384_pem())
    problems = load(tmp_path / "genesis.json").check(NOW)
    assert [(p.code, p.path) for p in problems] == [
        ("trust_invalid", f"trust/witness-keys/{t.KEY_ID}.pem")
    ]


def test_check_finds_a_tenant_schema_whose_id_is_not_its_name(input_file, tmp_path):
    input_file()
    (tmp_path / "schemas" / "findings.json").write_bytes(_schema_with_id("urn:sheaf:acme.other/1"))
    problems = load(tmp_path / "genesis.json").check(NOW)
    assert [p.code for p in problems] == ["schema_id_mismatch"]


@pytest.mark.parametrize("name", ["../outside.md", "/etc/hostname", "escape.md"])
def test_a_named_file_must_be_inside_the_input_folder(input_file, tmp_path, name):
    outside = tmp_path.parent / "outside.md"
    outside.write_bytes(b"# not part of the mandate\n")
    path = input_file()
    (path.parent / "escape.md").symlink_to(outside)
    doc = json.loads(path.read_text())
    doc["mandate"]["instructions"][0]["file"] = name
    path.write_text(json.dumps(doc))

    with pytest.raises(InputError, match="inside"):
        load(path)
