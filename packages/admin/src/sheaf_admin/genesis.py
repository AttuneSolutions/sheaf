"""A chain's genesis (5.6, 7.2): its first `config.changed`, built from what a person writes,
checked offline with the rules the gateway runs, then sent with the approver's own sign-in.

The input is the mandate (`sheaf.mandate/1`) as the person means it, with one difference: where
the mandate gives the SHA-256 of a file, the input names the file. The digests are computed from
the bytes that are uploaded, so the two cannot disagree.

    {
      "approver": "<the approver's object ID, as `sheaf-admin whoami` shows it>",
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

A genesis cannot be taken back: once the container is locked, the entry and every file it names
are kept for the retention period. So `apply` sends nothing until the offline check passes, the
gateway confirms who is signed in, the witness key file matches the key in Key Vault, and the
person confirms what is about to be committed.
"""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization

from sheaf_core import SPEC, paths
from sheaf_core.artefact import ArtefactInfo, check_artefact
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.digest import artefact_sha256
from sheaf_core.mandate import changed_parts, check_mandate, part_digests
from sheaf_core.problems import Problem
from sheaf_core.rules import ChainState
from sheaf_core.times import format_timestamp
from sheaf_core.trust import check_trust_file
from sheaf_witness import catalogue

MANDATE = ("data.json", "application/json")
INSTRUCTIONS = ("text.markdown", "text/markdown")
SCHEMA = ("schema.json", "application/schema+json")


class InputError(Exception):
    """The input cannot be read. Nothing is checked or sent."""


class NotApplied(Exception):
    """`apply` stopped before writing anything."""

    def __init__(self, reason: str, problems: list[Problem] | None = None):
        super().__init__(reason)
        self.problems = problems or []


class GatewayRefused(Exception):
    def __init__(self, status: int, problems: Any):
        super().__init__(f"the gateway answered {status}: {problems}")
        self.status, self.problems = status, problems


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
class Genesis:
    approver: str
    reason: str
    mandate: dict[str, Any]
    uploads: tuple[Upload, ...]
    """The mandate first, then its instructions and its schemas."""
    trust: dict[str, bytes] = field(default_factory=dict)
    """The witness key and each authority's roots, by their path in `trust/`."""

    @property
    def chain(self) -> str:
        return self.mandate["chain"]

    def draft(self, observed_at: datetime) -> dict[str, Any]:
        """The genesis `config.changed`, as the approver submits it."""
        approver = {"kind": "person", "id": self.approver}
        return {
            "spec": SPEC,
            "tenant": self.chain.split("/")[0],
            "chain": self.chain,
            "dossier": None,
            "type": "config.changed",
            "observed_at": format_timestamp(observed_at),
            "actor": approver,
            "artefacts": [upload.ref() for upload in self.uploads],
            "body": {
                "version": self.mandate["version"],
                "previous": None,
                "changed": changed_parts(None, self.mandate),
                "mandate": self.uploads[0].sha256,
                "parts": part_digests(self.mandate),
                "approved_by": approver,
                "reason": self.reason,
            },
        }

    def check(self, now: datetime) -> list[Problem]:
        """Every problem the gateway would find, from the files alone: the mandate, each upload
        and trust file, and the genesis entry against the chain rules (`sheaf_core`)."""
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

    def summary(self) -> str:
        """What is about to be committed, for the approver to read. The mandate must be valid."""
        doc, policy = self.mandate, self.mandate["policy"]
        mandate, key = self.uploads[0], doc["witness_key"]
        rows = [
            ("approver", self.approver),
            ("mandate", f"{mandate.sha256} ({len(mandate.data)} bytes)"),
            ("identifiers", doc["personal_data"]["identifiers"]),
            *(("caller", f"{c['id']}: {', '.join(c['types'])}") for c in policy["callers"]),
            *(("role", f"{r['role']}: {', '.join(r['types'])}") for r in policy["roles"]),
            *(("instructions", f"{i['name']} {i['sha256']}") for i in doc["instructions"]),
            *(("schema", f"{s['id']} {s['sha256']}") for s in doc["schemas"]),
            (
                "retention",
                ", ".join(f"{c['class']} {c['period']}" for c in doc["retention"]["classes"]),
            ),
            ("witness key", f"{key['key_id']}, public key SHA-256 {key['public_key_sha256']}"),
            ("witness identity", key["identity"]),
            (
                "authorities",
                ", ".join(
                    f"{a['authority']} ({a['jurisdiction']})" for a in doc["authorities"]["list"]
                ),
            ),
            ("gateway image", doc["gateway"]["image"]),
        ]
        lines = [f"Genesis of {self.chain}, mandate {doc['version']}"]
        lines += [f"  {name:<17} {value}" for name, value in rows]
        return "\n".join(lines)

    def witness_key_id(self) -> str:
        return self.mandate["witness_key"]["key_id"]

    def witness_key_pem(self) -> bytes:
        return self.trust[paths.witness_key(self.witness_key_id())]


class _Uploaded:
    """The genesis's uploads and trust files, as the chain rules read the gateway's store."""

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


def load(path: Path | str) -> Genesis:
    """Read a genesis input and the files it names. Raises InputError."""
    path = Path(path)
    doc = _json(path)
    if not isinstance(doc, dict):
        raise InputError(f"{path}: a JSON object, with approver and mandate")
    unknown = sorted(set(doc) - {"approver", "reason", "mandate"})
    if unknown:
        raise InputError(f"{path}: unknown {', '.join(unknown)}")
    approver, reason = doc.get("approver"), doc.get("reason", "genesis")
    if not isinstance(approver, str) or not approver:
        raise InputError("$.approver: the approver's object ID, as `sheaf-admin whoami` shows it")
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
    return Genesis(approver, reason, mandate, ordered, trust)


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
        try:
            return (self.base / name).read_bytes()
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


# -- sending it ----------------------------------------------------------------------------------


class GatewayClient:
    """The gateway's HTTP interface (7.2), as the approver."""

    def __init__(self, client: httpx.Client, base_url: str, *, token: Callable[[], str]) -> None:
        self.client, self.base_url, self.token = client, base_url.rstrip("/"), token

    def _send(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token()}", **kwargs.pop("headers", {})}
        response = self.client.request(method, f"{self.base_url}{path}", headers=headers, **kwargs)
        if response.status_code not in (200, 201):
            try:
                problems = response.json().get("problems")
            except ValueError:
                problems = response.text[:500]
            raise GatewayRefused(response.status_code, problems)
        return response.json()

    def me(self) -> dict[str, Any]:
        return self._send("GET", "/v1/me")

    def upload(self, chain: str, upload: Upload) -> dict[str, Any]:
        headers = {
            "Content-Type": upload.media_type,
            "Sheaf-Kind": upload.kind,
            "Sheaf-Sensitivity": upload.sensitivity,
            "Sheaf-Chain": chain,
            "Idempotency-Key": upload.sha256,
        }
        return self._send(
            "PUT", f"/v1/artefacts/{upload.sha256}", content=upload.data, headers=headers
        )

    def put_trust(self, path: str, data: bytes) -> dict[str, Any]:
        headers = {"Content-Type": "application/octet-stream"}
        relative = path.removeprefix("trust/")
        return self._send("PUT", f"/v1/trust/{relative}", content=data, headers=headers)

    def commit(self, draft: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps(draft).encode()
        headers = {"Content-Type": "application/json", "Idempotency-Key": _hex(body)}
        return self._send("POST", "/v1/entries", content=body, headers=headers)


def apply(
    genesis: Genesis,
    gateway: GatewayClient,
    *,
    vault_key: Callable[[str], bytes],
    confirm: Callable[[str], bool],
    now: datetime,
) -> dict[str, Any]:
    """Send the genesis: its uploads, its trust files, then its `config.changed`. Returns the
    gateway's receipt. Raises NotApplied, before anything is written, if the genesis has
    problems, the person signed in is not its approver, the witness key file is not the key in
    the vault, or the person does not confirm; and GatewayRefused if the gateway refuses.

    What is stored stays stored and the same bytes are accepted again, so a run that stopped
    partway is finished by running it again."""
    problems = genesis.check(now)
    if problems:
        raise NotApplied("the genesis has problems", problems)
    me = gateway.me()
    if me.get("person") is not True:
        raise NotApplied(
            "signed in as an application: the approver signs in as a person, with their own "
            "account (5.1)"
        )
    if me.get("id") != genesis.approver:
        raise NotApplied(
            f"signed in as {me.get('id')}, but the genesis names {genesis.approver} as approver"
        )
    key_id = genesis.witness_key_id()
    if not _same_key(vault_key(key_id), genesis.witness_key_pem()):
        raise NotApplied(
            f"the witness key file is not {key_id} in the vault: its interim witness would never "
            "verify, and the mandate would never apply"
        )
    if not confirm(genesis.summary()):
        raise NotApplied("not confirmed: nothing was written")
    for upload in genesis.uploads:
        gateway.upload(genesis.chain, upload)
    for path, data in genesis.trust.items():
        gateway.put_trust(path, data)
    return gateway.commit(genesis.draft(now))


def _same_key(first: bytes, second: bytes) -> bool:
    try:
        keys = [serialization.load_pem_public_key(pem) for pem in (first, second)]
        return keys[0].public_numbers() == keys[1].public_numbers()
    except (ValueError, TypeError, AttributeError):
        return False
