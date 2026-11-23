"""A mandate (5.6) in plain language, for the person asked to approve it, and what a change to
it changes.

Every sentence is generated from the mandate's own fields by the templates here, never written
by hand for a tenant, so what an approver reads follows what is signed. The fingerprint binds
the two: an approver is always shown the mandate's SHA-256 beside its description.

The output is plain strings, never markup: a mandate's text is shown as text.
"""

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from sheaf_core.mandate import PARTS, changed_parts

TITLES = {
    "policy": "Who may write to the record, and what",
    "instructions": "Instructions given to the model",
    "schemas": "The tenant's own data formats",
    "models": "Models",
    "registry": "Kinds of evidence",
    "retention": "How long the record is kept",
    "witness_interval": "How often the record is witnessed",
    "witness_key": "The witness key",
    "authorities": "Time-stamp authorities",
    "personal_data": "Personal data",
    "gateway": "Gateway software",
}

ENTRY_TYPES = {
    "dossier.opened": "open a dossier",
    "source.read": "record a source it read",
    "artefact.attached": "attach evidence",
    "ai.exchange": "record an AI request and response",
    "trace.recorded": "record a trace",
    "finding.drafted": "record draft findings",
    "output.produced": "record an output",
    "decision.recorded": "record a person's decision",
    "config.changed": "change this mandate",
    "correction": "correct an entry",
    "notice": "record a notice",
    "dossier.sealed": "seal a dossier",
    "retention.expired": "record that retention has expired",
}

KINDS = {
    "document.pdf": "PDF documents",
    "document.office": "Word and Excel documents",
    "document.rendition": "PDF renditions of other evidence",
    "image.raster": "images",
    "text.plain": "plain text",
    "text.markdown": "Markdown text",
    "data.json": "JSON data",
    "schema.json": "JSON Schemas",
    "record.snapshot": "snapshots of source records",
    "ai.exchange.raw": "AI requests and responses",
    "trace.otel": "traces",
}

SENSITIVITY = {
    "client_pii": "Evidence about clients",
    "staff_pii": "Evidence about staff",
    "none": "Other evidence",
}

UNSAID = "Changed in details these sentences do not show: see the technical summary."

SHORT = 16
"""Hexadecimal digits of a fingerprint shown in plain language; `technical` shows them all."""


def describe(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Each part of a valid mandate, in `PARTS` order: `{part, title, lines}`."""
    return [
        {"part": part, "title": TITLES[part], "lines": _DESCRIBE[part](doc[part])} for part in PARTS
    ]


def diff(old: Mapping[str, Any] | None, new: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Each part that differs between two valid mandates (every part, for a genesis), with the
    sentences that go and those that come: `{part, title, removed, added}`."""
    changes = []
    for part in changed_parts(old, new):
        before = [] if old is None else _DESCRIBE[part](old[part])
        after = _DESCRIBE[part](new[part])
        removed = [line for line in before if line not in after]
        added = [line for line in after if line not in before]
        if not removed and not added:
            # The part's digest changed, but in nothing the sentences say, or only in their
            # order or repetition: never let a change look like no change.
            added = [UNSAID]
        changes.append({"part": part, "title": TITLES[part], "removed": removed, "added": added})
    return changes


def technical(doc: Mapping[str, Any], mandate_sha256: str) -> list[tuple[str, str]]:
    """The mandate as an engineer checks it: identifiers and digests in full."""
    policy, key = doc["policy"], doc["witness_key"]
    return [
        ("chain", doc["chain"]),
        ("version", doc["version"]),
        ("mandate", mandate_sha256),
        ("identifiers", doc["personal_data"]["identifiers"]),
        *(("caller", f"{c['id']}: {', '.join(c['types'])}") for c in policy["callers"]),
        *(("role", f"{r['role']}: {', '.join(r['types'])}") for r in policy["roles"]),
        ("four eyes", "yes" if policy["four_eyes"] else "no"),
        *(("instructions", f"{i['name']} {i['sha256']}") for i in doc["instructions"]),
        *(("schema", f"{s['id']} {s['sha256']}") for s in doc["schemas"]),
        (
            "retention",
            ", ".join(f"{c['class']} {c['period']}" for c in doc["retention"]["classes"]),
        ),
        ("witness key", f"{key['key_id']}, public key SHA-256 {key['public_key_sha256']}"),
        ("witness identity", key["identity"]),
        *(
            ("authority", f"{a['authority']} ({a['jurisdiction']}) roots {', '.join(a['roots'])}")
            for a in doc["authorities"]["list"]
        ),
        ("gateway image", doc["gateway"]["image"]),
    ]


# -- one template per part ------------------------------------------------------------------------


def _policy(policy: Mapping[str, Any]) -> list[str]:
    lines = [f"{c['id']} may {_types(c['types'])}." for c in policy["callers"]]
    lines += [
        f"Anyone holding the app role {r['role']} may {_types(r['types'])}."
        for r in policy["roles"]
    ]
    if policy["four_eyes"]:
        lines.append("Whoever proposes a change to this mandate may not also approve it.")
    else:
        lines.append("Whoever proposes a change to this mandate may also approve it.")
    lines += [
        f"{_capital(KINDS.get(name, name))} may be stored, up to {_size(limits['max_bytes'])} "
        f"each ({name})."
        for name, limits in sorted(policy["kinds"].items())
    ]
    if policy["source_capture"] == "reference":
        lines.append("Source documents are referenced by fingerprint; they are not copied.")
    else:
        lines.append("Source documents are copied into the record.")
    for sensitivity, label in SENSITIVITY.items():
        roles = policy["sensitivity"][sensitivity]
        if not roles:
            who = "nobody"
        else:
            who = f"the app role{'s' if len(roles) > 1 else ''} {_and(roles)}"
        lines.append(f"{label} may be opened by {who}.")
    return lines


def _instructions(items: Sequence[Mapping[str, Any]]) -> list[str]:
    if not items:
        return ["The model is given no instructions."]
    return [f"{i['name']} (fingerprint {_short(i['sha256'])})." for i in items]


def _schemas(items: Sequence[Mapping[str, Any]]) -> list[str]:
    if not items:
        return ["The tenant has no data formats of its own."]
    return [f"{s['id']} (fingerprint {_short(s['sha256'])})." for s in items]


def _models(items: Sequence[Mapping[str, Any]]) -> list[str]:
    if not items:
        return ["No model is named."]
    lines = []
    for m in items:
        line = (
            f"{m['model']} version {m['model_version']}, deployment {m['deployment']}, "
            f"from {m['provider']} in {m['region']}"
        )
        parameters = ", ".join(f"{k} {_value(v)}" for k, v in sorted(m["parameters"].items()))
        lines.append(f"{line}, with {parameters}." if parameters else f"{line}.")
    return lines


def _registry(registry: Mapping[str, Any]) -> list[str]:
    return [f"Version {registry['version']} of the Sheaf kind registry."]


def _retention(retention: Mapping[str, Any]) -> list[str]:
    return [f"{c['class']}: kept for {_period(c['period'])}." for c in retention["classes"]]


def _witness_interval(interval: Mapping[str, Any]) -> list[str]:
    lines = ["The record is witnessed once a day, for each UTC day."]
    if interval["interim_after_sealed"]:
        lines.append("It is also witnessed after each dossier is sealed.")
    else:
        lines.append("It is not witnessed separately when a dossier is sealed.")
    return lines


def _witness_key(key: Mapping[str, Any]) -> list[str]:
    return [
        f"Witnesses are signed with the key {key['key_id']} ({key['algorithm']}, public key "
        f"fingerprint {_short(key['public_key_sha256'])}).",
        f"Only the identity {key['identity']} may submit them.",
    ]


def _authorities(authorities: Mapping[str, Any]) -> list[str]:
    lines = [
        f"{a['name']}, in {a['jurisdiction']}, at {a['url']} ({a['authority']}), "
        f"trusted through {_roots(a['roots'])}."
        for a in authorities["list"]
    ]
    assessment = authorities["assessment"]
    lines.append(
        f"Assessed by {assessment['by']['id']} on {assessment['date']}: {assessment['statement']}"
    )
    return lines


def _personal_data(personal: Mapping[str, Any]) -> list[str]:
    if personal["identifiers"] == "clear":
        first = "People and clients are recorded by their identifiers, in clear."
    else:
        first = "People and clients are recorded as keyed pseudonyms, not by their identifiers."
    return [first, f"Basis: {personal['basis']}"]


def _gateway(gateway: Mapping[str, Any]) -> list[str]:
    return [f"The gateway runs the image {gateway['image']}."]


_DESCRIBE = {
    "policy": _policy,
    "instructions": _instructions,
    "schemas": _schemas,
    "models": _models,
    "registry": _registry,
    "retention": _retention,
    "witness_interval": _witness_interval,
    "witness_key": _witness_key,
    "authorities": _authorities,
    "personal_data": _personal_data,
    "gateway": _gateway,
}


# -- wording ---------------------------------------------------------------------------------------


def _types(types: Sequence[str]) -> str:
    return _and([ENTRY_TYPES.get(t, t) for t in types])


def _and(words: Sequence[str]) -> str:
    """`a`, `a and b`, `a, b and c`."""
    return words[0] if len(words) == 1 else f"{', '.join(words[:-1])} and {words[-1]}"


def _roots(roots: Sequence[str]) -> str:
    named = ", ".join(_short(r) for r in roots)
    if len(roots) == 1:
        return f"its root certificate (fingerprint {named})"
    return f"its certificates (fingerprints {named})"


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:]


def _short(digest: str) -> str:
    return digest[:SHORT] + "…"


def _size(count: int) -> str:
    for unit, size in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if count % size == 0:
            return f"{count // size} {unit}"
    return f"{count} bytes"


def _period(period: str) -> str:
    """An ISO 8601 duration in years, months and days (`sheaf.mandate/1`), in words."""
    found = dict((unit, int(count)) for count, unit in re.findall(r"([0-9]+)([YMD])", period))
    words = []
    for unit, name in (("Y", "year"), ("M", "month"), ("D", "day")):
        if unit in found:
            count = found[unit]
            words.append(f"{count} {name}{'' if count == 1 else 's'}")
    return " and ".join(words) if words else period


def _value(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
