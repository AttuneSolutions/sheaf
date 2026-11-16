import json

import pytest

from sheaf_core import testing as t
from sheaf_core.artefact import check_artefact
from sheaf_core.digest import artefact_sha256

MiB = 1024 * 1024


def check(data, kind, media_type, *, sha256=None, sensitivity="none"):
    return check_artefact(
        data,
        sha256=sha256 or artefact_sha256(data),
        kind=kind,
        media_type=media_type,
        sensitivity=sensitivity,
    )


def codes(result):
    return [p.code for p in result[1]]


@pytest.mark.parametrize(
    ("data", "kind", "media_type"),
    [
        (b"plain words\n", "text.plain", "text/plain"),
        (b"# Heading\n\nText.\n", "text.markdown", "text/markdown"),
        (t.REQUEST, "ai.exchange.raw", "application/json"),
        (t.SOURCE, "record.snapshot", "application/json"),
        (t.mandate_bytes(t.mandate_document()), "data.json", "application/json"),
    ],
)
def test_valid_artefacts_get_a_receipt(data, kind, media_type):
    info, problems = check(data, kind, media_type, sensitivity="client_pii")

    assert problems == []
    assert info.sha256 == artefact_sha256(data)
    assert (info.kind, info.media_type, info.bytes) == (kind, media_type, len(data))
    assert info.sensitivity == "client_pii"


def test_a_data_json_receipt_records_the_schema_it_declares():
    info, _ = check(t.mandate_bytes(t.mandate_document()), "data.json", "application/json")

    assert info.declared_schema == "sheaf.mandate/1"


def test_the_declared_sha256_must_be_the_bytes():
    assert codes(check(b"x", "text.plain", "text/plain", sha256=t.stand_in("y"))) == [
        "sha256_mismatch"
    ]


def test_an_unregistered_kind_is_refused():
    assert codes(check(b"x", "message.email", "message/rfc822")) == ["kind_unknown"]


def test_a_media_type_the_kind_does_not_allow_is_refused():
    assert codes(check(b"x", "text.plain", "text/html")) == ["media_type_mismatch"]


def test_anything_over_the_kinds_limit_is_refused_not_truncated():
    assert codes(check(b"x" * (10 * MiB + 1), "text.plain", "text/plain")) == ["too_large"]


@pytest.mark.parametrize(
    ("data", "kind", "media_type"),
    [
        (b"%PDF-1.7\n", "text.plain", "text/plain"),
        (b"\x89PNG\r\n\x1a\n....", "data.json", "application/json"),
        (b"just text", "document.pdf", "application/pdf"),
        (b"\xff\xd8\xff\xe0....", "image.raster", "image/png"),
    ],
)
def test_the_real_type_is_sniffed_from_the_bytes(data, kind, media_type):
    assert codes(check(data, kind, media_type)) == ["type_mismatch"]


def test_text_must_be_utf8():
    assert codes(check(b"caf\xe9", "text.plain", "text/plain")) == ["not_utf8"]


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b"{", b'{"n": NaN}'])
def test_json_kinds_must_parse_unambiguously(data):
    assert codes(check(data, "ai.exchange.raw", "application/json")) == ["invalid_json"]


def test_data_json_declares_a_registered_schema():
    assert codes(check(b'{"a": 1}', "data.json", "application/json")) == ["schema_undeclared"]
    unregistered = b'{"$schema": "acme.unknown/1"}'
    assert codes(check(unregistered, "data.json", "application/json")) == ["schema_unregistered"]


def test_data_json_validates_against_its_schema():
    doc = t.mandate_document()
    del doc["gateway"]

    assert set(codes(check(json.dumps(doc).encode(), "data.json", "application/json"))) == {
        "schema"
    }


def test_a_record_snapshot_validates_against_its_schema():
    assert set(codes(check(b'{"system": "crm"}', "record.snapshot", "application/json"))) == {
        "schema"
    }


@pytest.mark.parametrize(
    ("data", "kind", "media_type"),
    [
        (b"%PDF-1.7\n", "document.pdf", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n....", "image.raster", "image/png"),
        (
            b"PK\x03\x04....",
            "document.office",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (t.TRACE, "trace.otel", "application/json"),
    ],
)
def test_kinds_whose_validators_are_not_built_yet_are_refused(data, kind, media_type):
    # Fail closed: an artefact nobody validated must never be stored (2).
    assert codes(check(data, kind, media_type)) == ["validator_unavailable"]


def test_sensitivity_is_one_the_standard_names():
    assert codes(check(b"x", "text.plain", "text/plain", sensitivity="secret")) == [
        "sensitivity_unknown"
    ]


# -- schemas ----------------------------------------------------------------------------------


def schema_upload(doc):
    data = json.dumps(doc).encode()
    return check_artefact(
        data,
        sha256=artefact_sha256(data),
        kind="schema.json",
        media_type="application/schema+json",
        sensitivity="none",
    )


def test_a_tenant_schema_is_stored_as_schema_json():
    info, problems = schema_upload(t.FINDINGS_SCHEMA_DOC)

    assert problems == []
    assert info.kind == "schema.json"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"$id": "urn:sheaf:sheaf.findings/1"}, "schema_id_reserved"),
        ({"$id": "https://example.com/findings.json"}, "schema_id_format"),
        ({"$schema": "http://json-schema.org/draft-07/schema#"}, "schema_dialect"),
        ({"type": 5}, "schema_invalid"),
    ],
)
def test_a_schema_json_is_a_2020_12_schema_with_a_tenant_id(changes, code):
    _, problems = schema_upload({**t.FINDINGS_SCHEMA_DOC, **changes})

    assert [p.code for p in problems] == [code]


def findings_upload(data, schemas=None):
    return check_artefact(
        data,
        sha256=artefact_sha256(data),
        kind="data.json",
        media_type="application/json",
        sensitivity="none",
        schemas=schemas,
    )


def test_data_json_may_declare_a_schema_of_the_mandate_in_force():
    info, problems = findings_upload(t.FINDINGS, {"acme.findings/1": t.FINDINGS_SCHEMA_DOC})

    assert problems == []
    assert info.declared_schema == "acme.findings/1"


def test_data_json_declaring_a_schema_no_mandate_names_is_refused():
    _, problems = findings_upload(t.FINDINGS)

    assert [p.code for p in problems] == ["schema_unregistered"]


def test_data_json_must_satisfy_the_tenant_schema_it_declares():
    data = b'{"$schema":"acme.findings/1","findings":[1]}'
    _, problems = findings_upload(data, {"acme.findings/1": t.FINDINGS_SCHEMA_DOC})

    assert [(p.code, p.path) for p in problems] == [("schema", "$.findings[0]")]
