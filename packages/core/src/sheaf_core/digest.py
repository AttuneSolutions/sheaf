"""Digests as the standard writes them (section 5.2).

Digests of canonical JSON (`prev`, `hash`, a witness imprint, a mandate part) are "sha256:" and
64 lowercase hex digits. Digests of stored bytes (an artefact reference's `sha256`, a time-stamp
token's `token_sha256`) are the 64 digits alone.
"""

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from sheaf_core.canonical import canonicalize

PREFIX = "sha256:"
_ENTRY_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ARTEFACT_DIGEST = re.compile(r"[0-9a-f]{64}")


def artefact_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    """ "sha256:" and the SHA-256 of a JSON value's RFC 8785 canonical bytes.

    Used for every digest taken over JSON rather than over stored bytes: an entry's `hash`, a
    witness imprint, and the digest of each mandate part.
    """
    return PREFIX + hashlib.sha256(canonicalize(value)).hexdigest()


def entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 of the RFC 8785 canonical entry without its `hash` field."""
    return canonical_digest({key: value for key, value in entry.items() if key != "hash"})


def is_entry_digest(value: object) -> bool:
    return isinstance(value, str) and _ENTRY_DIGEST.fullmatch(value) is not None


def is_artefact_digest(value: object) -> bool:
    return isinstance(value, str) and _ARTEFACT_DIGEST.fullmatch(value) is not None
