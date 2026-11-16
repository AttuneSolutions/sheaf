"""The mandate (section 5.6): its parts, their digests, its own consistency, and what it permits.

A mandate is one `data.json` artefact under schema `sheaf.mandate/1`, plus the instructions it
names as `text.markdown` artefacts. Each top-level property other than `$schema`, `chain` and
`version` is a **part**. A part's digest is the canonical digest of its JSON, so a part that
names an instructions artefact by its SHA-256 covers those bytes too. `config.changed` carries
the digest of each part and of the whole (the mandate artefact's SHA-256).
"""

import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

from sheaf_core.canonical import TooDeep, ValueNotAllowed, check_numbers
from sheaf_core.digest import canonical_digest
from sheaf_core.kinds import kind, registry_version
from sheaf_core.problems import Problem
from sheaf_core.schema import validate

SCHEMA_ID = "sheaf.mandate/1"
PARTS: tuple[str, ...] = (
    "policy",
    "instructions",
    "schemas",
    "models",
    "registry",
    "retention",
    "witness_interval",
    "witness_key",
    "authorities",
    "personal_data",
    "gateway",
)
_WITNESS_TYPES = ("witness.daily", "witness.interim")
PSEUDONYM = re.compile(r"ps-[0-9a-f]{32}")
"""A keyed pseudonym (5.7): how a person or subject is named under a mandate that pseudonymises."""


def part_digests(doc: Mapping[str, Any]) -> dict[str, str]:
    return {part: canonical_digest(doc[part]) for part in PARTS}


def changed_parts(old: Mapping[str, Any] | None, new: Mapping[str, Any]) -> list[str]:
    """The parts that differ, in `PARTS` order. Every part, for a genesis mandate."""
    if old is None:
        return list(PARTS)
    before, after = part_digests(old), part_digests(new)
    return [part for part in PARTS if before[part] != after[part]]


def check_mandate(doc: Any, path: str = "$") -> list[Problem]:
    """Check a mandate against `sheaf.mandate/1` and the registry, and for internal clashes."""
    try:
        check_numbers(doc, path)
    except ValueNotAllowed as error:
        # Each part is hashed in canonical form, which allows integers only (5.2).
        code = "too_deep" if isinstance(error, TooDeep) else "number"
        return [Problem(code, path, str(error))]
    except TypeError as error:
        return [Problem("number", path, str(error))]
    problems = validate(SCHEMA_ID, doc, path)
    if problems:
        return problems
    report = problems.append

    if doc["registry"]["version"] != registry_version():
        report(
            Problem(
                "registry_unknown",
                f"{path}.registry.version",
                f"this build knows registry {registry_version()} only",
            )
        )

    for name, limits in doc["policy"]["kinds"].items():
        here = f"{path}.policy.kinds.{name}"
        registered = kind(name)
        if registered is None:
            report(Problem("kind_unknown", here, f"{name} is not registered"))
        elif limits["max_bytes"] > registered["max_bytes"]:
            report(
                Problem(
                    "kind_limit",
                    f"{here}.max_bytes",
                    f"the registry limits {name} to {registered['max_bytes']} bytes",
                )
            )

    for code, where, names in (
        ("caller_duplicate", "policy.callers", [c["id"] for c in doc["policy"]["callers"]]),
        ("role_duplicate", "policy.roles", [r["role"] for r in doc["policy"]["roles"]]),
        ("instructions_duplicate", "instructions", [i["name"] for i in doc["instructions"]]),
        ("schema_duplicate", "schemas", [s["id"] for s in doc["schemas"]]),
        (
            "retention_class_duplicate",
            "retention.classes",
            [c["class"] for c in doc["retention"]["classes"]],
        ),
        (
            "authority_duplicate",
            "authorities.list",
            [a["authority"] for a in doc["authorities"]["list"]],
        ),
    ):
        for name, count in Counter(names).items():
            if count > 1:
                report(Problem(code, f"{path}.{where}", f"{name} appears {count} times"))

    jurisdictions = {a["jurisdiction"] for a in doc["authorities"]["list"]}
    if len(jurisdictions) < 2:
        report(
            Problem(
                "authorities_one_jurisdiction",
                f"{path}.authorities.list",
                "the authorities must be in at least two jurisdictions (5.5)",
            )
        )

    tenant = doc["chain"].split("/")[0]
    for index, named in enumerate(doc["schemas"]):
        if named["id"].split(".")[0] != tenant:
            report(
                Problem(
                    "schema_tenant",
                    f"{path}.schemas[{index}].id",
                    f"a tenant schema's id starts with {tenant}.",
                )
            )

    identity = doc["witness_key"]["identity"]
    if any(c["id"] == identity for c in doc["policy"]["callers"]):
        report(
            Problem(
                "witness_is_caller",
                f"{path}.policy.callers",
                "the witness identity submits witness entries only, and is not also a caller (7.5)",
            )
        )
    return problems


def granted_types(
    doc: Mapping[str, Any], caller: str | None, role: str | None = None
) -> frozenset[str] | None:
    """The entry types the policy grants `caller` by its id, and acting under `role`; None when
    neither is in the policy at all."""
    policy = doc["policy"]
    grants = [c["types"] for c in policy["callers"] if caller is not None and c["id"] == caller]
    grants += [r["types"] for r in policy["roles"] if role is not None and r["role"] == role]
    if not grants:
        return None
    return frozenset(entry_type for types in grants for entry_type in types)


def permits(doc: Mapping[str, Any], caller: str, draft: Mapping[str, Any]) -> list[Problem]:
    """Whether the mandate lets `caller`, as authenticated by the gateway, write `draft`.

    Witness entries come from the witness identity and from no one else; every other type from a
    caller the policy lists for it, by id or by the role the entry's actor names (which the
    gateway has checked the caller holds, `sheaf_core.entry.check_caller`). Each artefact must be
    of a kind the policy allows, within its size limit, except in `config.changed`, whose
    artefacts are the new mandate. `draft` must already have passed `check_draft`.
    """
    problems = []
    entry_type = draft["type"]
    identity = doc["witness_key"]["identity"]

    if entry_type in _WITNESS_TYPES:
        if caller != identity:
            problems.append(
                Problem("witness_identity", "$.type", "only the witness identity submits witnesses")
            )
    else:
        role = draft["actor"].get("role")
        granted = granted_types(doc, caller, role)
        if role is not None and granted_types(doc, None, role) is None:
            problems.append(Problem("role_unknown", "$.actor.role", f"{role} is not in the policy"))
        elif granted is None:
            code = "type_not_permitted" if caller == identity else "caller_unknown"
            problems.append(Problem(code, "$", f"{caller} may not write {entry_type}"))
        elif entry_type not in granted:
            problems.append(
                Problem("type_not_permitted", "$.type", f"{caller} may not write {entry_type}")
            )

    if entry_type == "config.changed":
        # Its artefacts are the new mandate, which the policy it replaces does not govern.
        return problems
    allowed = doc["policy"]["kinds"]
    for index, ref in enumerate(draft["artefacts"]):
        here = f"$.artefacts[{index}]"
        limits = allowed.get(ref["kind"])
        if limits is None:
            problems.append(
                Problem("kind_not_permitted", f"{here}.kind", f"{ref['kind']} is not allowed here")
            )
        elif ref["bytes"] > limits["max_bytes"]:
            problems.append(
                Problem(
                    "too_large",
                    f"{here}.bytes",
                    f"the policy limits {ref['kind']} to {limits['max_bytes']} bytes",
                )
            )
    return problems
