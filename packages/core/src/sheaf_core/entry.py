"""Checking one entry on its own (sections 5.1-5.3): the envelope, the body for its type, and
every rule that needs nothing but the entry.

`check_draft` is what the gateway runs on what a caller submits (7.2 step 2). `check_entry` is
what the verifier runs on a committed line. Rules that need the chain so far, the uploaded
artefacts or the mandate in force are in `sheaf_core.rules`.
"""

from collections.abc import Collection, Mapping
from typing import Any

from sheaf_core.canonical import TooDeep, ValueNotAllowed, check_numbers
from sheaf_core.kinds import kind
from sheaf_core.problems import Problem
from sheaf_core.schema import schema, validate
from sheaf_core.witness import check_witness

TYPES: tuple[str, ...] = tuple(
    schema("sheaf.entry/1")["$defs"]["caller_fields"]["properties"]["type"]["enum"]
)
CHAIN_LEVEL_TYPES = frozenset(
    {"config.changed", "witness.daily", "witness.interim", "retention.expired"}
)
"""Types that belong to no unit of work and always carry `"dossier": null`. A `notice` may be
either: in a dossier, or at chain level when it concerns no unit of work."""

WITNESS_TYPES = frozenset({"witness.daily", "witness.interim"})


def check_draft(draft: Any) -> list[Problem]:
    """Check an entry as a caller submits it: without seq, prev, committed_at or hash."""
    return _check(draft, "sheaf.draft/1")


def check_entry(entry: Any) -> list[Problem]:
    """Check a committed entry's shape. Its hash and links are `sheaf_core.chain`'s concern."""
    return _check(entry, "sheaf.entry/1")


def check_caller(
    draft: Mapping[str, Any],
    caller: str,
    roles: Collection[str] = (),
    *,
    person: bool | None = None,
) -> list[Problem]:
    """Whether `caller`, as authenticated by the gateway with the app `roles` its token holds, may
    submit `draft` at all (5.1). An entry's actor is the caller that submits it, so a person's
    decision or approval is submitted with that person's own credentials; and a role the actor
    names is one the caller holds. Whether the mandate grants the type is
    `sheaf_core.mandate.permits`. `draft` must already have passed `check_draft`."""
    actor = draft["actor"]
    if actor["id"] != caller:
        return [
            Problem(
                "actor_not_caller", "$.actor.id", "an entry's actor is the caller that submits it"
            )
        ]
    if person is not None and (actor["kind"] == "person") != person:
        detail = f"the caller is {'a person' if person else 'a system'}"
        return [Problem("actor_kind_mismatch", "$.actor.kind", detail)]
    if "role" in actor and actor["role"] not in roles:
        return [
            Problem("role_not_held", "$.actor.role", f"the caller does not hold {actor['role']}")
        ]
    return []


def _check(value: Any, schema_id: str) -> list[Problem]:
    if not isinstance(value, Mapping):
        return [Problem("schema", "$", "an entry is a JSON object")]
    try:
        check_numbers(value)
    except ValueNotAllowed as error:
        # Nothing more is checked: an entry that cannot be canonicalised cannot be hashed.
        return [Problem("too_deep" if isinstance(error, TooDeep) else "number", "$", str(error))]
    except TypeError as error:
        return [Problem("number", "$", str(error))]
    schema_problems = validate(schema_id, value)
    if schema_problems:
        return schema_problems
    return _cross_field(value)


def _cross_field(entry: Mapping[str, Any]) -> list[Problem]:
    """Rules that relate one field of a well-formed entry to another."""
    problems = []
    report = problems.append

    if entry["chain"].split("/")[0] != entry["tenant"]:
        report(Problem("chain_tenant", "$.chain", f"chain {entry['chain']} is not the tenant's"))

    for index, ref in enumerate(entry["artefacts"]):
        here = f"$.artefacts[{index}]"
        registered = kind(ref["kind"])
        if registered is None:
            report(Problem("kind_unknown", f"{here}.kind", f"{ref['kind']} is not registered"))
        elif ref["media_type"] not in registered["media_types"]:
            report(
                Problem(
                    "media_type_mismatch",
                    f"{here}.media_type",
                    f"{ref['kind']} allows {', '.join(registered['media_types'])}",
                )
            )
        elif ref["bytes"] > registered["max_bytes"]:
            report(
                Problem(
                    "too_large",
                    f"{here}.bytes",
                    f"{ref['kind']} is limited to {registered['max_bytes']} bytes",
                )
            )

    entry_type, body = entry["type"], entry["body"]

    if entry_type == "dossier.opened":
        subject_id = entry["subject"]["id"].casefold()
        if subject_id in entry["dossier"].casefold():
            report(
                Problem(
                    "dossier_names_subject",
                    "$.dossier",
                    "a dossier id outlives its dossier in the chain, so it never embeds the "
                    "subject's identifier (5.7)",
                )
            )

    if entry_type in ("source.read", "output.produced"):
        for index, ref in enumerate(entry["artefacts"]):
            if ref["sha256"] != body["sha256"]:
                report(
                    Problem(
                        "fingerprint_mismatch",
                        f"$.artefacts[{index}].sha256",
                        "the attached artefact is not the one whose fingerprint is recorded",
                    )
                )

    if entry_type == "config.changed":
        mandate = next(ref for ref in entry["artefacts"] if ref["role"] == "mandate")
        if mandate["sha256"] != body["mandate"]:
            report(
                Problem(
                    "mandate_mismatch",
                    "$.body.mandate",
                    "the mandate named is not the one attached",
                )
            )

    approvals = ("config.changed", "retention.expired")
    approver = {k: v for k, v in entry["actor"].items() if k != "role"}
    if entry_type in approvals and body["approved_by"] != approver:
        report(
            Problem(
                "approver_not_actor",
                "$.body.approved_by",
                "the approver submits the entry with their own credentials, so is its actor",
            )
        )

    if entry_type in WITNESS_TYPES:
        if body["chain"] != entry["chain"]:
            report(Problem("witness_chain", "$.body.chain", "a witness is for its own chain"))
        problems.extend(check_witness(body, "$.body"))

    return problems
