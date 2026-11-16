"""The authorities Sheaf knows, and the free default a mandate starts from.

Named authorities live here, never in the standard: the standard says a mandate names at least
two authorities in at least two jurisdictions (5.6), and a person approves which. The default is
free, so a small organisation still gets an independently time-stamped record; a tenant moves to
a paid or qualified authority with a `config.changed` that replaces the `authorities` part.
"""

import functools
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from sheaf_core import paths

_DATA = files("sheaf_witness")


@dataclass(frozen=True)
class Authority:
    authority: str
    name: str
    url: str
    jurisdiction: str
    operator: str
    parent: str
    hosting: str
    terms: str
    practice_statement: str
    audit_reference: str
    free_use: str
    min_interval_seconds: float
    roots: tuple[bytes, ...]
    """The DER certificates pinned for the authority: its roots."""

    def root_sha256s(self) -> list[str]:
        return [hashlib.sha256(root).hexdigest() for root in self.roots]

    def mandate_entry(self) -> dict[str, Any]:
        """The authority as the mandate's `authorities.list` names it."""
        return {
            "authority": self.authority,
            "name": self.name,
            "url": self.url,
            "jurisdiction": self.jurisdiction,
            "roots": self.root_sha256s(),
            "practice_statement": self.practice_statement,
            "audit_reference": self.audit_reference,
        }

    def trust_files(self) -> dict[str, bytes]:
        """The files to store in `trust/tsa/{authority}/` before the mandate naming it applies."""
        return {
            paths.tsa_certificate(self.authority, sha256): root
            for sha256, root in zip(self.root_sha256s(), self.roots, strict=True)
        }


@functools.cache
def _load() -> tuple[dict[str, Authority], tuple[str, ...]]:
    data = json.loads((_DATA / "authorities.json").read_text("utf-8"))
    known = {}
    for item in data["authorities"]:
        roots = tuple((_DATA / root).read_bytes() for root in item["roots"])
        known[item["authority"]] = Authority(**{**item, "roots": roots})
    return known, tuple(data["default"])


def catalogue() -> dict[str, Authority]:
    return dict(_load()[0])


def default() -> tuple[Authority, ...]:
    """The free production default: FreeTSA, Sectigo and DigiCert."""
    known, names = _load()
    return tuple(known[name] for name in names)


def default_authorities(*, by: Mapping[str, Any], date: str, statement: str) -> dict[str, Any]:
    """The mandate's `authorities` part for the free default. `by`, `date` and `statement` are the
    person's assessment against MIO-STD-01 5.3.2, which the record keeps and never checks."""
    return {
        "list": [authority.mandate_entry() for authority in default()],
        "assessment": {"by": dict(by), "date": date, "statement": statement},
    }
