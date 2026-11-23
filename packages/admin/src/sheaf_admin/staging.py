"""A mandate (5.6) built from what a person writes, and checked offline with the rules the gateway
runs, before it is staged as a proposal (7.6).

The input is the mandate (`sheaf.mandate/1`) as the person means it, with one difference: where
the mandate gives the SHA-256 of a file, the input names the file. The digests are computed from
the bytes that are uploaded, so the two cannot disagree.

    {
      "reason": "genesis",
      "mandate": {
        "$schema": "sheaf.mandate/1",
        "chain": "acme/case-review",
        ...
        "instructions": [{"name": "review-instructions", "file": "instructions/review.md"}],
        "schemas": [{"id": "acme.findings/1", "file": "schemas/findings.json"}],
        "witness_key": {"key_id": "acme-witness/<version>", "algorithm": "ES256",
                        "public_key": "witness.pem", "identity": "<witness object ID>"},
        "authorities": {"list": ["freetsa", "sectigo", "digicert"], "assessment": {...}},
        ...
      }
    }

Paths are relative to the input file. `reason` is optional. An authority is named from the
witness's catalogue, or written out in full with `roots` as the paths of its DER certificates.
The input names no approver: whoever approves the proposal is its approver.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo, check_artefact
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.digest import artefact_sha256
from sheaf_core.mandate import changed_parts, check_mandate, part_digests
from sheaf_core.problems import Problem
from sheaf_core.proposal import STAND_IN_APPROVER, approval_draft
from sheaf_core.rules import ChainState
from sheaf_core.trust import check_trust_file
from sheaf_witness import catalogue

MANDATE = ("data.json", "application/json")
INSTRUCTIONS = ("text.markdown", "text/markdown")
SCHEMA = ("schema.json", "application/schema+json")

STAND_IN_PROPOSER = {"kind": "system", "id": "sheaf-admin-check"}
"""Who proposed, in the offline check: not the stand-in approver, so four eyes never objects."""


class InputError(Exception):
    """The input cannot be read. Nothing is checked or sent."""


@dataclass(frozen=True)
class Upload:
    role: str
    source: str
    """Where the bytes came from, for messages."""
    data: bytes
    kind: str
    media_type: str
    sensitivity: str = "none"

    @property
    def sha256(self) -> str:
        return artefact_sha256(self.data)

    def ref(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "kind": self.kind,
            "sha256": self.sha256,
            "bytes": len(self.data),
            "media_type": self.media_type,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class Staged:
    """A mandate ready to stage: the mandate, its uploads, and its trust files."""

    reason: str
    mandate: dict[str, Any]
    uploads: tuple[Upload, ...]
    """The mandate first, then its instructions and its schemas."""
    trust: dict[str, bytes] = field(default_factory=dict)
    """The witness key and each authority's roots, by their path in `trust/`."""

    @property
    def chain(self) -> str:
        return self.mandate["chain"]

    @property
    def fingerprint(self) -> str:
        """The mandate's SHA-256: what an approver is shown, and what the proposal is named by."""
        return self.uploads[0].sha256

    def request(self, *, expires_in_days: int | None = None) -> dict[str, Any]:
        """What `POST /v1/proposals` is sent to stage it."""
        request: dict[str, Any] = {
            "chain": self.chain,
            "mandate": self.fingerprint,
            "reason": self.reason,
        }
        if expires_in_days is not None:
            request["expires_in_days"] = expires_in_days
        return request

    def draft(self, observed_at: datetime) -> dict[str, Any]:
        """The `config.changed` the offline check runs the rules on: this mandate as a chain's
        genesis, from a stand-in approver. Against a chain with a mandate in force the gateway
        checks it again, as its change, when it is proposed."""
        proposal = {
            "chain": self.chain,
            "mandate": self.fingerprint,
            "version": self.mandate["version"],
            "previous": None,
            "changed": changed_parts(None, self.mandate),
            "parts": part_digests(self.mandate),
            "artefacts": [upload.ref() for upload in self.uploads],
            "proposed_by": STAND_IN_PROPOSER,
            "reason": self.reason,
        }
        return approval_draft(proposal, approver=STAND_IN_APPROVER, observed_at=observed_at)

    def check(self, now: datetime) -> list[Problem]:
        """Every problem the gateway would find from the files alone: the mandate, each upload
        and trust file, and its `config.changed` against the chain rules (`sheaf_core`)."""
        problems = check_mandate(self.mandate, "$.mandate")
        if problems:
            return problems
        uploaded = _Uploaded(self.trust)
        for upload in self.uploads:
            info, found = check_artefact(
                upload.data,
                sha256=upload.sha256,
                kind=upload.kind,
                media_type=upload.media_type,
                sensitivity=upload.sensitivity,
            )
            problems += [Problem(p.code, upload.source, p.detail) for p in found]
            if info is not None:
                uploaded.add(info, upload.data)
        for path, data in self.trust.items():
            problems += [Problem(p.code, path, p.detail) for p in check_trust_file(path, data)]
        if problems:
            return problems
        return ChainState(self.chain).check(self.draft(now), artefacts=uploaded, now=now)

    def witness_key_id(self) -> str:
        return self.mandate["witness_key"]["key_id"]

    def witness_key_pem(self) -> bytes:
        return self.trust[paths.witness_key(self.witness_key_id())]


class _Uploaded:
    """The uploads and trust files, as the chain rules read the gateway's store."""

    def __init__(self, trust: Mapping[str, bytes]) -> None:
        self._items: dict[str, tuple[ArtefactInfo, bytes]] = {}
        self._trust = trust

    def add(self, info: ArtefactInfo, data: bytes) -> None:
        self._items[info.sha256] = (info, data)

    def info(self, sha256: str) -> ArtefactInfo | None:
        item = self._items.get(sha256)
        return item[0] if item else None

    def json(self, sha256: str) -> Any:
        return strict_loads(self._items[sha256][1])

    def trust(self, path: str) -> bytes | None:
        return self._trust.get(path)


# -- reading the input ---------------------------------------------------------------------------


def load(path: Path | str) -> Staged:
    """Read an input and the files it names. Raises InputError."""
    path = Path(path)
    doc = _json(path)
    if not isinstance(doc, dict):
        raise InputError(f"{path}: a JSON object, with the mandate")
    if "approver" in doc:
        raise InputError(
            f"{path}: $.approver: no longer named here. A mandate change is staged as a "
            "proposal, and whoever approves it is its approver: remove approver"
        )
    unknown = sorted(set(doc) - {"reason", "mandate"})
    if unknown:
        raise InputError(f"{path}: unknown {', '.join(unknown)}")
    reason = doc.get("reason", "genesis")
    if not isinstance(reason, str) or not reason:
        raise InputError("$.reason: a sentence, or leave it out")
    source = doc.get("mandate")
    if not isinstance(source, dict) or not isinstance(source.get("chain"), str):
        raise InputError("$.mandate: the mandate, with its chain")

    files = _Files(path.parent)
    mandate, uploads, trust = _build(source, files)
    data = json.dumps(mandate, indent=2, ensure_ascii=False).encode() + b"\n"
    uploads.insert(0, Upload("mandate", "$.mandate", data, *MANDATE))
    unique = {(u.role, u.sha256): u for u in reversed(uploads)}
    ordered = tuple(u for u in uploads if unique[(u.role, u.sha256)] is u)
    return Staged(reason, mandate, ordered, trust)


def _json(path: Path) -> Any:
    try:
        return strict_loads(path.read_bytes())
    except OSError as error:
        raise InputError(f"{path}: {error.strerror}") from error
    except InvalidJSON as error:
        raise InputError(f"{path}: {error}") from error


class _Files:
    def __init__(self, base: Path) -> None:
        self.base = base

    def read(self, name: str, here: str) -> bytes:
        """A file the input names, which must be inside the input's folder once every link is
        followed: a mandate's files go into a record that cannot be changed, so a stray path
        must never bring something else in with them."""
        try:
            base = self.base.resolve()
            path = (self.base / name).resolve()
            if not path.is_relative_to(base):
                raise InputError(f"{here}: {name}: name a file inside {self.base}")
            return path.read_bytes()
        except OSError as error:
            raise InputError(f"{here}: {name}: {error.strerror}") from error


def _named_file(item: Any, here: str, key: str, digest: str) -> str:
    if isinstance(item, dict) and digest in item:
        raise InputError(
            f'{here}: name the file as "{key}", not its {digest}: '
            "the digest is computed from the bytes uploaded"
        )
    if not isinstance(item, dict) or not isinstance(item.get(key), str):
        raise InputError(f'{here}: name the file as "{key}"')
    return item[key]


def _swap(item: Mapping[str, Any], old: str, new: str, value: Any) -> dict[str, Any]:
    """`item` with `old` replaced by `new`, in the same place."""
    return {(new if k == old else k): (value if k == old else v) for k, v in item.items()}


def _items(source: Mapping[str, Any], name: str) -> list[Any]:
    value = source.get(name, [])
    if not isinstance(value, list):
        raise InputError(f"$.mandate.{name}: a list")
    return value


def _build(
    source: Mapping[str, Any], files: _Files
) -> tuple[dict[str, Any], list[Upload], dict[str, bytes]]:
    """The mandate with each file replaced by its digest, the uploads, and the trust files."""
    mandate, uploads, trust = dict(source), [], {}

    for part, role, (kind, media_type) in (
        ("instructions", "instructions", INSTRUCTIONS),
        ("schemas", "schema", SCHEMA),
    ):
        if part not in source:
            continue
        built = []
        for index, item in enumerate(_items(source, part)):
            here = f"$.mandate.{part}[{index}]"
            name = _named_file(item, here, "file", "sha256")
            data = files.read(name, here)
            uploads.append(Upload(role, name, data, kind, media_type))
            built.append(_swap(item, "file", "sha256", artefact_sha256(data)))
        mandate[part] = built

    key = source.get("witness_key")
    if key is not None:
        here = "$.mandate.witness_key"
        name = _named_file(key, here, "public_key", "public_key_sha256")
        pem = files.read(name, here)
        mandate["witness_key"] = _swap(key, "public_key", "public_key_sha256", _hex(pem))
        if isinstance(key.get("key_id"), str):
            trust[paths.witness_key(key["key_id"])] = pem

    authorities = source.get("authorities")
    if isinstance(authorities, dict) and isinstance(authorities.get("list"), list):
        listed = []
        for index, item in enumerate(authorities["list"]):
            here = f"$.mandate.authorities.list[{index}]"
            entry, files_for = _authority(item, here, files)
            listed.append(entry)
            trust.update(files_for)
        mandate["authorities"] = {**authorities, "list": listed}

    return mandate, uploads, trust


def _authority(item: Any, here: str, files: _Files) -> tuple[Any, dict[str, bytes]]:
    """An authority named from the catalogue, or written out with its roots' files."""
    if isinstance(item, str):
        known = catalogue.catalogue()
        if item not in known:
            raise InputError(
                f"{here}: {item} is not in the catalogue: {', '.join(sorted(known))}; "
                "or write it out in full"
            )
        return known[item].mandate_entry(), known[item].trust_files()
    if not isinstance(item, dict) or not isinstance(item.get("roots"), list):
        raise InputError(f'{here}: a catalogue name, or the authority with "roots" as files')
    roots, trust = [], {}
    for position, name in enumerate(item["roots"]):
        if not isinstance(name, str):
            raise InputError(f"{here}.roots[{position}]: the path of a DER certificate")
        data = files.read(name, f"{here}.roots[{position}]")
        roots.append(_hex(data))
        if isinstance(item.get("authority"), str):
            trust[paths.tsa_certificate(item["authority"], _hex(data))] = data
    return {**item, "roots": roots}, trust


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
