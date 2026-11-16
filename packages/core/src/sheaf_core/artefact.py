"""Checking an artefact's bytes before it is stored (7.2 step 1), and again by the verifier (9).

The checks, in order: the kind is registered and allows the declared media type; the size is
within the kind's limit; the bytes have the declared SHA-256; the real type, sniffed from the
bytes, is the declared one; and the kind's validator passes. A kind whose validator is not built
yet is refused: no unvalidated evidence may be stored (2).
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.digest import artefact_sha256
from sheaf_core.kinds import kind as registered_kind
from sheaf_core.problems import Problem
from sheaf_core.schema import check_schema_document, schema_ids, validate


@dataclass(frozen=True)
class ArtefactInfo:
    """What an upload established about an artefact: its receipt (7.2 step 1)."""

    sha256: str
    kind: str
    media_type: str
    bytes: int
    sensitivity: str
    declared_schema: str | None = None
    """For `data.json`, the `$schema` the artefact declares."""


SENSITIVITIES = frozenset({"client_pii", "staff_pii", "none"})

DATA_SCHEMAS = frozenset({"sheaf.mandate/1"})
"""Schemas a `data.json` artefact may declare. Where a tenant registers its own (for example a
findings schema) is not yet settled."""

_OOXML = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)
_MAGIC: tuple[tuple[Callable[[bytes], bool], frozenset[str]], ...] = (
    (lambda b: b.startswith(b"%PDF-"), frozenset({"application/pdf"})),
    (lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"), frozenset({"image/png"})),
    (lambda b: b.startswith(b"\xff\xd8\xff"), frozenset({"image/jpeg"})),
    (lambda b: b[:4] == b"RIFF" and b[8:12] == b"WEBP", frozenset({"image/webp"})),
    (lambda b: b.startswith(b"PK\x03\x04"), _OOXML),
)
_BINARY = frozenset().union(*(types for _, types in _MAGIC))


def sniff(data: bytes) -> frozenset[str] | None:
    """The binary media types the bytes' signature allows, or None for no known signature."""
    for matches, types in _MAGIC:
        if matches(data):
            return types
    return None


def check_artefact(
    data: bytes,
    *,
    sha256: str,
    kind: str,
    media_type: str,
    sensitivity: str,
    schemas: Mapping[str, Any] | None = None,
) -> tuple[ArtefactInfo | None, list[Problem]]:
    """Check bytes against what the caller declared. A receipt only if there are no problems.
    `schemas` are the tenant schemas of the mandate in force, by identifier, which a `data.json`
    may declare as well as the registry's."""
    if sensitivity not in SENSITIVITIES:
        allowed = ", ".join(sorted(SENSITIVITIES))
        return None, [Problem("sensitivity_unknown", "sensitivity", f"one of {allowed}")]
    registered = registered_kind(kind)
    if registered is None:
        return None, [Problem("kind_unknown", "kind", f"{kind} is not registered")]
    if media_type not in registered["media_types"]:
        allowed = ", ".join(registered["media_types"])
        return None, [Problem("media_type_mismatch", "media_type", f"{kind} allows {allowed}")]
    if len(data) > registered["max_bytes"]:
        limit = registered["max_bytes"]
        return None, [Problem("too_large", "bytes", f"{kind} is limited to {limit} bytes")]
    if artefact_sha256(data) != sha256:
        return None, [Problem("sha256_mismatch", "sha256", "the bytes have another SHA-256")]

    signature = sniff(data)
    if (signature is None and media_type in _BINARY) or (
        signature is not None and media_type not in signature
    ):
        found = ", ".join(sorted(signature)) if signature else "no known binary signature"
        return None, [Problem("type_mismatch", "media_type", f"the bytes are {found}")]

    validator = _VALIDATORS.get(kind)
    if validator is None:
        detail = f"the {kind} validator is not built yet, so {kind} cannot be stored"
        return None, [Problem("validator_unavailable", "kind", detail)]
    if kind == "data.json":
        declared_schema, problems = _data_json(data, schemas or {})
    else:
        declared_schema, problems = validator(data)
    if problems:
        return None, problems
    info = ArtefactInfo(sha256, kind, media_type, len(data), sensitivity, declared_schema)
    return info, []


def _text(data: bytes) -> tuple[None, list[Problem]]:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        return None, [Problem("not_utf8", "$", str(error))]
    return None, []


def _json(data: bytes) -> tuple[Any, list[Problem]]:
    try:
        return strict_loads(data), []
    except InvalidJSON as error:
        return None, [Problem("invalid_json", "$", str(error))]


def _json_document(data: bytes) -> tuple[None, list[Problem]]:
    return None, _json(data)[1]


def _data_json(data: bytes, schemas: Mapping[str, Any]) -> tuple[str | None, list[Problem]]:
    value, problems = _json(data)
    if problems:
        return None, problems
    declared = value.get("$schema") if isinstance(value, dict) else None
    if not isinstance(declared, str):
        return None, [Problem("schema_undeclared", "$", "data.json declares its $schema")]
    if declared in DATA_SCHEMAS and declared in schema_ids():
        return declared, validate(declared, value)
    if declared in schemas:
        return declared, validate(declared, value, schemas=schemas)
    detail = f"{declared} is neither registered nor named in the mandate in force"
    return None, [Problem("schema_unregistered", "$.$schema", detail)]


def _schema_json(data: bytes) -> tuple[None, list[Problem]]:
    value, problems = _json(data)
    return None, problems or check_schema_document(value)


def _record_snapshot(data: bytes) -> tuple[None, list[Problem]]:
    value, problems = _json(data)
    return None, problems or validate("sheaf.record-snapshot/1", value)


# TODO(registry v1): ai.exchange.raw also checks the provider family is known; trace.otel,
# document.*, image.raster need their validators (6) before those kinds can be stored.
_VALIDATORS: dict[str, Callable[[bytes], tuple[Any, list[Problem]]]] = {
    "text.plain": _text,
    "text.markdown": _text,
    "data.json": _json_document,  # replaced in check_artefact, which knows the tenant schemas
    "schema.json": _schema_json,
    "record.snapshot": _record_snapshot,
    "ai.exchange.raw": _json_document,
}
