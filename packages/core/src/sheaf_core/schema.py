"""The registry's JSON Schemas (2020-12), and validation against them.

The schemas are JSON files under `registry/schemas/{name}/{major}.json`, so they can be copied
as they are into a tenant's container (section 4, `registry/`) and read by a verifier written in
any language. Each has the identifier `name/major` and the `$id` `urn:sheaf:name/major`.

A tenant's own schemas (`schema.json` artefacts named in its mandate, 5.6) have identifiers
`tenant.name/major` and the same `$id` form. They may refer to the registry and to each other,
and to nothing else: nothing is fetched.

Two departures from a plain validator, both so that Python agrees with ECMA-262 and with the
standard:
- `pattern`: Python's `$` also matches before a final newline, so "acme\\n" would pass
  `^[a-z]+$`. Here an end anchor must reach the end of the string.
- `format` is asserted for `date-time` and `date`, which the schemas also constrain by pattern,
  so 30 February and leap seconds are refused.
"""

import functools
import json
import re
from collections.abc import Iterator, Mapping
from datetime import date, datetime
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, SchemaError, ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend
from referencing import Registry
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012

from sheaf_core.problems import Problem

URN = "urn:sheaf:"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
TENANT_SCHEMA_ID = re.compile(r"[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*/[1-9][0-9]*")
"""A tenant schema's identifier: its tenant, a dot, a name, a slash and a major version."""
_ROOT = files("sheaf_core") / "registry"


def _pattern(
    validator: Validator, pattern: str, instance: Any, schema: dict[str, Any]
) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "string"):
        return
    match = re.search(pattern, instance)
    if match is None or (_ends_anchored(pattern) and match.end() != len(instance)):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


def _ends_anchored(pattern: str) -> bool:
    if not pattern.endswith("$"):
        return False
    backslashes = len(pattern[:-1]) - len(pattern[:-1].rstrip("\\"))
    return backslashes % 2 == 0


_FORMATS = FormatChecker(formats=())


@_FORMATS.checks("date-time", raises=ValueError)
def _date_time(instance: Any) -> bool:
    if isinstance(instance, str):
        datetime.fromisoformat(instance)
    return True


@_FORMATS.checks("date", raises=ValueError)
def _date(instance: Any) -> bool:
    if isinstance(instance, str):
        date.fromisoformat(instance)
    return True


_Validator = extend(Draft202012Validator, validators={"pattern": _pattern})


@functools.cache
def _schemas() -> dict[str, dict[str, Any]]:
    schemas = {}
    for directory in (_ROOT / "schemas").iterdir():
        for file in directory.iterdir():
            identifier = f"{directory.name}/{file.name.removesuffix('.json')}"
            schema = json.loads(file.read_text("utf-8"))
            if schema.get("$id") != URN + identifier:
                raise RuntimeError(f"{identifier}: $id is {schema.get('$id')!r}")
            schemas[identifier] = schema
    return schemas


@functools.cache
def _registry() -> Registry:
    resources = [(s["$id"], DRAFT202012.create_resource(s)) for s in _schemas().values()]
    return Registry().with_resources(resources)


def schema_ids() -> tuple[str, ...]:
    return tuple(sorted(_schemas()))


def schema(identifier: str) -> dict[str, Any]:
    return _schemas()[identifier]


@functools.cache
def validator(identifier: str) -> Validator:
    return _Validator(schema(identifier), registry=_registry(), format_checker=_FORMATS)


def validate(
    identifier: str,
    instance: Any,
    path: str = "$",
    *,
    schemas: Mapping[str, Any] | None = None,
) -> list[Problem]:
    """Every way `instance` fails the schema, each with its JSON path below `path`. `schemas` are
    the tenant schemas of the mandate in force, by identifier, for an identifier not in the
    registry."""
    if schemas and identifier in schemas:
        checker = _Validator(
            schemas[identifier], registry=_tenant_registry(schemas), format_checker=_FORMATS
        )
    else:
        checker = validator(identifier)
    errors = checker.iter_errors(instance)
    return [
        Problem("schema", path + error.json_path.removeprefix("$"), _message(error))
        for error in sorted(errors, key=lambda error: error.json_path)
    ]


def _message(error: ValidationError) -> str:
    # The schemas write "this property may not appear here" as {"not": {}}.
    if error.validator == "not" and error.validator_value == {}:
        return "not allowed here"
    # jsonschema quotes the offending value; never echo a large one back to the caller.
    message = error.message
    return message if len(message) <= 300 else message[:300] + "... (truncated)"


def _tenant_registry(schemas: Mapping[str, Any]) -> Registry:
    resources = [(URN + name, DRAFT202012.create_resource(doc)) for name, doc in schemas.items()]
    return _registry().with_resources(resources)


def check_schema_document(doc: Any, path: str = "$") -> list[Problem]:
    """Whether `doc` is a tenant schema on its own: a JSON Schema 2020-12 document whose `$id` is
    a tenant schema identifier outside the registry's `sheaf.` names."""
    if not isinstance(doc, dict):
        return [Problem("schema_invalid", path, "a schema is a JSON object")]
    if doc.get("$schema") != DIALECT:
        return [Problem("schema_dialect", f"{path}.$schema", f"a schema declares {DIALECT}")]
    identifier = doc.get("$id")
    name = identifier.removeprefix(URN) if isinstance(identifier, str) else ""
    if not (isinstance(identifier, str) and identifier.startswith(URN)) or not (
        TENANT_SCHEMA_ID.fullmatch(name)
    ):
        detail = "the $id is urn:sheaf:tenant.name/major"
        return [Problem("schema_id_format", f"{path}.$id", detail)]
    if name.startswith("sheaf."):
        return [Problem("schema_id_reserved", f"{path}.$id", "sheaf. names are the registry's")]
    try:
        Draft202012Validator.check_schema(doc, format_checker=Draft202012Validator.FORMAT_CHECKER)
    except SchemaError as error:
        return [Problem("schema_invalid", path, _message(error))]
    return []


def check_tenant_schemas(schemas: Mapping[str, Any], path: str = "$") -> list[Problem]:
    """Whether a mandate's tenant schemas, by identifier, are each a valid tenant schema with that
    identifier, and every `$ref` in them resolves to the registry or to one of them."""
    problems = []
    for name, doc in schemas.items():
        here = f"{path}[{name}]"
        found = check_schema_document(doc, here)
        if found:
            problems += found
            continue
        if doc["$id"] != URN + name:
            problems.append(Problem("schema_id_mismatch", f"{here}.$id", f"is not {URN}{name}"))
            continue
        resolver = _tenant_registry(schemas).resolver(base_uri=doc["$id"])
        for ref in sorted(set(_refs(doc))):
            try:
                resolver.lookup(ref)
            except Unresolvable:
                problems.append(
                    Problem("schema_ref_unresolved", here, f"{ref} is not in the record")
                )
    return problems


def _refs(value: Any) -> Iterator[str]:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            ref = item.get("$ref")
            if isinstance(ref, str):
                yield ref
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
