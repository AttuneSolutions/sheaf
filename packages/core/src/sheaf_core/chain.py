"""Linking entries into a chain, and checking a chain (sections 5.2 and 9).

`link_entry` is what the gateway does under the chain-head lease. `check_chain` is what the
verifier does, and reports every problem it finds rather than stopping at the first.
"""

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sheaf_core.canonical import InvalidJSON, ValueNotAllowed, canonicalize, strict_loads
from sheaf_core.digest import entry_hash, is_entry_digest
from sheaf_core.problems import Problem

CHAIN_FIELDS = ("seq", "prev", "committed_at", "hash")


@dataclass(frozen=True)
class ChainProblem:
    seq: int | None
    code: str
    detail: str


def link_entry(
    draft: Mapping[str, Any], *, seq: int, prev: str | None, committed_at: str
) -> dict[str, Any]:
    """Return a new entry: the caller's draft plus the fields only the gateway sets."""
    for field in CHAIN_FIELDS:
        if field in draft:
            raise ValueError(f"draft already carries `{field}`, which only the gateway sets")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError(f"seq must be an integer from 1, not {seq!r}")
    if seq == 1 and prev is not None:
        raise ValueError("the entry with seq 1 must have prev null")
    if seq > 1 and not is_entry_digest(prev):
        raise ValueError(f"prev for seq {seq} must be a sha256: digest, not {prev!r}")

    entry = copy.deepcopy(dict(draft))
    entry.update(seq=seq, prev=prev, committed_at=committed_at)
    entry["hash"] = entry_hash(entry)
    return entry


def entry_line(entry: Mapping[str, Any]) -> bytes:
    """One line of a dossier blob: the full entry in RFC 8785 form, then a newline."""
    return canonicalize(entry) + b"\n"


def segment_line(entry: Mapping[str, Any]) -> bytes:
    """One line of a daily chain segment (4): `seq`, `dossier`, `type` and `hash`. No content."""
    fields = {key: entry[key] for key in ("seq", "dossier", "type", "hash")}
    return canonicalize(fields) + b"\n"


def check_line(line: bytes) -> tuple[dict[str, Any] | None, list[Problem]]:
    """Parse one stored line and check it is its entry's RFC 8785 form, newline-terminated (5.2).

    A verifier reads lines with this, so two verifiers never read one line as two values.
    """
    try:
        entry = strict_loads(line)
    except InvalidJSON as error:
        return None, [Problem("invalid_json", "$", str(error))]
    if not isinstance(entry, dict):
        return None, [Problem("not_object", "$", "a line holds one entry, a JSON object")]
    try:
        canonical = entry_line(entry)
    except (ValueNotAllowed, TypeError) as error:
        return None, [Problem("number", "$", str(error))]
    if canonical != line:
        return None, [Problem("line_not_canonical", "$", "not the entry's RFC 8785 form")]
    return entry, []


def check_chain(
    entries: Iterable[Mapping[str, Any]],
    *,
    first_seq: int = 1,
    first_prev: str | None = None,
) -> list[ChainProblem]:
    """Check hashes, sequence and links for consecutive entries of one chain.

    By default the entries must start the chain. To check a later segment, pass the `seq` it
    should start at and the `hash` of the entry before it.
    """
    problems: list[ChainProblem] = []
    expected_seq, expected_prev, chain = first_seq, first_prev, None

    for entry in entries:
        if not isinstance(entry, Mapping):
            problems.append(ChainProblem(None, "not_object", "an entry is a JSON object"))
            continue
        seq = entry.get("seq")
        label = seq if isinstance(seq, int) and not isinstance(seq, bool) else None

        def report(code: str, detail: str, label: int | None = label) -> None:
            problems.append(ChainProblem(label, code, detail))

        if chain is None:
            chain = entry.get("chain")
        elif entry.get("chain") != chain:
            report("chain_mismatch", f"chain {entry.get('chain')!r}, expected {chain!r}")

        if label is None:
            report("seq_format", f"seq {seq!r} is not an integer")
        elif label != expected_seq:
            report("seq_gap", f"seq {label}, expected {expected_seq}")

        prev = entry.get("prev")
        if label == 1 and first_seq == 1 and prev is not None:
            report("genesis_prev", "the entry with seq 1 must have prev null")
        elif prev is None and expected_prev is not None:
            report("prev_mismatch", f"prev is null, expected {expected_prev}")
        elif prev is not None and not is_entry_digest(prev):
            report("prev_format", f"prev {prev!r} is not a sha256: digest")
        elif prev != expected_prev and not (label == 1 and first_seq == 1):
            report("prev_mismatch", f"prev {prev}, expected {expected_prev}")

        stored = entry.get("hash")
        try:
            computed = entry_hash(entry)
        except (ValueNotAllowed, TypeError) as error:
            computed = None
            report("hash_uncomputable", str(error))
        if not is_entry_digest(stored):
            report("hash_format", f"hash {stored!r} is not a sha256: digest")
        elif computed is not None and stored != computed:
            report("hash_mismatch", "hash does not match the entry's content")

        expected_seq = (label if label is not None else expected_seq) + 1
        expected_prev = stored

    return problems
