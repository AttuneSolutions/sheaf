import copy
import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from sheaf_core import testing as t
from sheaf_core.entry import CHAIN_LEVEL_TYPES, TYPES
from sheaf_core.mandate import PARTS
from sheaf_core.schema import check_tenant_schemas, schema, schema_ids, validate


def test_every_schema_is_valid_json_schema_2020_12():
    for identifier in schema_ids():
        Draft202012Validator.check_schema(schema(identifier))


def test_each_schema_lives_at_the_path_its_identifier_names():
    root = files("sheaf_core") / "registry" / "schemas"
    for identifier in schema_ids():
        name, major = identifier.split("/")
        stored = json.loads((root / name / f"{major}.json").read_text("utf-8"))
        assert stored["$id"] == f"urn:sheaf:{identifier}"


def test_every_entry_type_has_a_schema_and_the_envelope_names_them_all():
    assert len(TYPES) == 15
    for entry_type in TYPES:
        assert f"sheaf.entry.{entry_type}/1" in schema_ids()


def test_chain_level_types_are_the_ones_the_standard_names():
    assert {
        "config.changed",
        "witness.daily",
        "witness.interim",
        "retention.expired",
    } == CHAIN_LEVEL_TYPES


def test_config_changed_names_exactly_the_mandate_parts():
    body = schema("sheaf.entry.config.changed/1")["properties"]["body"]
    assert body["properties"]["changed"]["items"]["enum"] == list(PARTS)
    assert body["required"].count("parts") == 1
    assert list(body["properties"]["parts"]["properties"]) == list(PARTS)

    mandate = schema("sheaf.mandate/1")
    assert [p for p in mandate["properties"] if p not in ("$schema", "chain", "version")] == list(
        PARTS
    )


@pytest.mark.parametrize("value", ["case-review\n", "case-review\r\n", "\ncase-review"])
def test_a_line_break_never_slips_past_a_pattern(value):
    # Python's `$` also matches before a final newline; ECMA-262's does not.
    problems = validate("sheaf.mandate/1", {"chain": f"acme/{value}"})
    assert any(p.path == "$.chain" for p in problems)


@pytest.mark.parametrize(
    "value",
    ["2026-02-30T00:00:00Z", "2026-11-26T23:59:60Z", "2026-11-26T18:04:11+00:00", "2026-11-26"],
)
def test_timestamps_are_real_utc_instants_written_with_z(value):
    problems = validate("sheaf.witness/1", {"interval": {"from": value, "to": value}})
    assert any(p.path == "$.interval.from" for p in problems)


def test_problems_carry_a_json_path_and_can_be_rebased():
    problems = validate("sheaf.witness/1", {"last_seq": 0}, path="$.body")
    assert any(p.path == "$.body.last_seq" and p.code == "schema" for p in problems)


# -- tenant schemas ---------------------------------------------------------------------------


def tenant(**changes):
    doc = copy.deepcopy(t.FINDINGS_SCHEMA_DOC)
    doc.update(changes)
    return {"acme.findings/1": doc}


def tenant_codes(schemas):
    return [p.code for p in check_tenant_schemas(schemas)]


def test_a_tenant_schema_may_refer_to_the_registry():
    assert check_tenant_schemas(tenant()) == []


def test_a_tenant_schema_is_identified_by_the_id_the_mandate_gives_it():
    assert tenant_codes(tenant(**{"$id": "urn:sheaf:acme.findings/2"})) == ["schema_id_mismatch"]


@pytest.mark.parametrize(
    "ref", ["https://example.com/findings.json", "urn:sheaf:acme.other/1", "#/$defs/missing"]
)
def test_a_tenant_schema_refers_only_to_what_the_record_holds(ref):
    assert tenant_codes(tenant(items={"$ref": ref})) == ["schema_ref_unresolved"]


def test_tenant_schemas_may_refer_to_each_other():
    schemas = tenant(properties={"findings": {"$ref": "urn:sheaf:acme.finding/1"}})
    schemas["acme.finding/1"] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:sheaf:acme.finding/1",
        "type": "array",
    }

    assert check_tenant_schemas(schemas) == []


def test_a_tenant_schema_is_a_valid_schema():
    assert tenant_codes(tenant(type=5)) == ["schema_invalid"]


def test_a_document_is_validated_against_a_tenant_schema():
    schemas = tenant()

    assert (
        validate("acme.findings/1", {"$schema": "acme.findings/1", "findings": []}, schemas=schemas)
        == []
    )
    problems = validate(
        "acme.findings/1", {"$schema": "acme.findings/1", "findings": [1]}, schemas=schemas
    )
    assert {(p.code, p.path) for p in problems} == {("schema", "$.findings[0]")}
