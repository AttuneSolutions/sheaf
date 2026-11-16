"""Builders for tests and examples: tenant `acme`, workflow `case-review`.

Shared by the core, gateway and verifier tests, so that each builds entries the same way. Nothing
in the gateway or the verifier imports this at run time.
"""

from __future__ import annotations

import functools
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sheaf_core import SPEC, paths
from sheaf_core.artefact import ArtefactInfo
from sheaf_core.canonical import strict_loads
from sheaf_core.chain import link_entry
from sheaf_core.digest import artefact_sha256, canonical_digest
from sheaf_core.mandate import PARTS, changed_parts
from sheaf_core.problems import Problem
from sheaf_core.rules import ChainState
from sheaf_core.times import format_timestamp, parse_timestamp
from sheaf_core.witness import AuthorityResult, time_attestation

TENANT = "acme"
WORKFLOW = "case-review"
CHAIN = "acme/case-review"
DOSSIER = "cr-20261126-7Q2MZK"
OBSERVED = "2026-11-26T18:04:09.881Z"

AGENT = {"kind": "system", "id": "acme-review-agent", "version": "1.3.0"}
APP = {"kind": "system", "id": "acme-review-app", "version": "2.0.1"}
ADMIN = {"kind": "system", "id": "acme-admin-tool", "version": "1.0.0"}
WITNESS = {"kind": "system", "id": "acme-witness", "version": "0.1.0"}
REVIEWER = {"kind": "person", "id": "acme-reviewer-1", "role": "reviewer"}
APPROVER = {"kind": "person", "id": "acme-approver-1"}

SUBJECT = {"system": "crm", "object": "Case", "id": "C104233"}
RETENTION = {"class": "regulated-record", "min_until": "2033-11-26"}
KEY_ID = "acme-witness/3f1c0d2e9a7b"
SIGNATURE = "c2lnbmVkLWJ5LXRoZS13aXRuZXNzLWtleQ"  # tests never verify signatures

REQUEST = b'{"messages":[{"role":"user","content":"Review the case."}]}'
RESPONSE = b'{"choices":[{"message":{"content":"No issues found."}}]}'
FINDINGS = b'{"$schema":"acme.findings/1","findings":[]}'
FINDINGS_SCHEMA_DOC: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:sheaf:acme.findings/1",
    "type": "object",
    "additionalProperties": False,
    "required": ["$schema", "findings"],
    "properties": {
        "$schema": {"const": "acme.findings/1"},
        "findings": {"type": "array", "items": {"$ref": "urn:sheaf:sheaf.defs/1#/$defs/text"}},
    },
}
FINDINGS_SCHEMA = json.dumps(FINDINGS_SCHEMA_DOC, indent=2).encode()
TRACE = b'{"resourceSpans":[]}'
OUTPUT = b"Review complete: no issues found.\n"
SOURCE = (
    b'{"system":"crm","object":"Case","id":"C104233","fields":{},'
    b'"retrieved_at":"2026-11-26T18:04:05Z"}'
)
INSTRUCTIONS = b"# Case review\n\nCheck each case against the review rules.\n"

AUTHORITIES = (("tsa-a", "CH"), ("tsa-b", "JP"))
STAMPED_AT = datetime(2026, 11, 27, 0, 3, 12, tzinfo=UTC)


def stand_in(label: str) -> str:
    """A fingerprint for something whose bytes a test does not need."""
    return artefact_sha256(label.encode())


def ref(data: bytes, *, role: str, kind: str, media_type: str, sensitivity: str = "none", **extra):
    return {
        "role": role,
        "kind": kind,
        "sha256": artefact_sha256(data),
        "bytes": len(data),
        "media_type": media_type,
        "sensitivity": sensitivity,
        **extra,
    }


def draft(
    type_: str,
    body: Mapping[str, Any],
    *,
    dossier: str | None = DOSSIER,
    artefacts: Iterable[Mapping[str, Any]] = (),
    actor: Mapping[str, Any] = AGENT,
    subject: Mapping[str, Any] = SUBJECT,
    retention: Mapping[str, Any] = RETENTION,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "spec": SPEC,
        "tenant": TENANT,
        "chain": CHAIN,
        "dossier": dossier,
        "type": type_,
        "observed_at": OBSERVED,
        "actor": dict(actor),
        "artefacts": [dict(item) for item in artefacts],
        "body": dict(body),
    }
    if dossier is not None:
        entry["subject"] = dict(subject)
        entry["retention"] = dict(retention)
    return entry


# -- one builder per entry type ---------------------------------------------------------------


def opened(mandate: str, *, source_capture: str = "reference", **kw) -> dict[str, Any]:
    body = {
        "workflow_version": "1.3.0",
        "trigger": {"kind": "event", "ref": "case-updated"},
        "mandate": mandate,
        "source_capture": source_capture,
    }
    return draft("dossier.opened", body, **kw)


def source_read(*, copy: bool = False, **kw) -> dict[str, Any]:
    body = {
        "source": {"system": "crm", "object": "Case", "id": "C104233", "version": "17"},
        "read": "case fields",
        "sha256": artefact_sha256(SOURCE),
    }
    artefacts = []
    if copy:
        artefacts = [
            ref(SOURCE, role="source", kind="record.snapshot", media_type="application/json")
        ]
    return draft("source.read", body, artefacts=artefacts, **kw)


def ai_request() -> dict[str, Any]:
    return ref(REQUEST, role="request", kind="ai.exchange.raw", media_type="application/json")


def ai_response() -> dict[str, Any]:
    return ref(RESPONSE, role="response", kind="ai.exchange.raw", media_type="application/json")


def ai_exchange(**kw) -> dict[str, Any]:
    body = {
        "provider": "azure-ai-foundry",
        "region": "example-region",
        "deployment": "case-review",
        "model": "example-model",
        "model_version": "2026-01-01",
        "parameters": {"temperature": "0.2", "max_output_tokens": 4000},
        "usage": {"input_tokens": 1200, "output_tokens": 80},
        "finish_reason": "stop",
        "content_filter": {},
    }
    return draft("ai.exchange", body, artefacts=[ai_request(), ai_response()], **kw)


def artefact_attached(artefact: Mapping[str, Any], **kw) -> dict[str, Any]:
    return draft("artefact.attached", {"reason": "the case file"}, artefacts=[artefact], **kw)


def trace_recorded(**kw) -> dict[str, Any]:
    trace = ref(TRACE, role="trace", kind="trace.otel", media_type="application/json")
    body = {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_count": 12}
    return draft("trace.recorded", body, artefacts=[trace], **kw)


def findings_ref() -> dict[str, Any]:
    return ref(FINDINGS, role="findings", kind="data.json", media_type="application/json")


def finding_drafted(*, schema: str = "acme.findings/1", **kw) -> dict[str, Any]:
    return draft("finding.drafted", {"schema": schema}, artefacts=[findings_ref()], **kw)


def output_ref() -> dict[str, Any]:
    return ref(OUTPUT, role="output", kind="text.plain", media_type="text/plain")


def output_produced(*, attach: bool = True, **kw) -> dict[str, Any]:
    body = {
        "destination": {"system": "crm", "location": "Case C104233 / review note"},
        "sha256": artefact_sha256(OUTPUT),
    }
    return draft("output.produced", body, artefacts=[output_ref()] if attach else [], **kw)


def decision(decided: str, *, choice: str = "approve", **kw) -> dict[str, Any]:
    body: dict[str, Any] = {"decision": choice, "decided": decided, "reason": "checked"}
    if choice == "approve_with_edits":
        body["edits"] = "reworded the second finding"
    kw.setdefault("actor", REVIEWER)
    return draft("decision.recorded", body, **kw)


def correction(corrects: str, **kw) -> dict[str, Any]:
    return draft("correction", {"corrects": corrects, "reason": "wrong case version"}, **kw)


def notice(**kw) -> dict[str, Any]:
    return draft("notice", {"event": "retry", "detail": "model timed out; retrying"}, **kw)


def sealed(entries: int, artefacts: int, *, status: str = "completed", **kw) -> dict[str, Any]:
    body = {"status": status, "entries": entries, "artefacts": artefacts}
    return draft("dossier.sealed", body, **kw)


def retention_expired(
    *, dossiers: Sequence[str] = (), artefacts: Sequence[str] = (), min_until="2033-11-26"
) -> dict[str, Any]:
    body = {
        "class": "regulated-record",
        "min_until": min_until,
        "policy_version": "2026.1",
        "dossiers": list(dossiers),
        "artefacts": list(artefacts),
        "approved_by": APPROVER,
    }
    return draft("retention.expired", body, dossier=None, actor=APPROVER)


# -- the mandate ------------------------------------------------------------------------------


def mandate_document(**overrides: Any) -> dict[str, Any]:
    """A complete genesis mandate for acme/case-review. Keyword arguments replace parts."""
    dossier_types = [
        "dossier.opened",
        "source.read",
        "artefact.attached",
        "ai.exchange",
        "trace.recorded",
        "finding.drafted",
        "output.produced",
        "correction",
        "notice",
        "dossier.sealed",
    ]
    mib = 1024 * 1024
    doc: dict[str, Any] = {
        "$schema": "sheaf.mandate/1",
        "chain": CHAIN,
        "version": "2026.11.1",
        "policy": {
            "callers": [
                {"id": AGENT["id"], "types": dossier_types},
                {"id": APP["id"], "types": ["output.produced"]},
                {"id": APPROVER["id"], "types": ["config.changed", "retention.expired"]},
                {"id": ADMIN["id"], "types": ["notice"]},
            ],
            "roles": [
                {"role": "reviewer", "types": ["decision.recorded"]},
                {"role": "approver", "types": ["config.changed", "retention.expired"]},
            ],
            "kinds": {
                "ai.exchange.raw": {"max_bytes": 20 * mib},
                "data.json": {"max_bytes": 5 * mib},
                "document.pdf": {"max_bytes": 50 * mib},
                "record.snapshot": {"max_bytes": 5 * mib},
                "text.markdown": {"max_bytes": mib},
                "text.plain": {"max_bytes": mib},
                "trace.otel": {"max_bytes": 20 * mib},
            },
            "source_capture": "reference",
            "sensitivity": {
                "client_pii": ["case-reviewer"],
                "staff_pii": ["case-review-admin"],
                "none": ["case-reviewer", "case-review-admin"],
            },
        },
        "instructions": [{"name": "review-instructions", "sha256": artefact_sha256(INSTRUCTIONS)}],
        "schemas": [{"id": "acme.findings/1", "sha256": artefact_sha256(FINDINGS_SCHEMA)}],
        "models": [
            {
                "provider": "azure-ai-foundry",
                "region": "example-region",
                "deployment": "case-review",
                "model": "example-model",
                "model_version": "2026-01-01",
                "parameters": {"temperature": "0.2"},
            }
        ],
        "registry": {"version": "1.0.0"},
        "retention": {
            "classes": [
                {"class": "regulated-record", "period": "P7Y"},
                {"class": "working-file", "period": "P1Y"},
            ]
        },
        "witness_interval": {"interval": "daily", "interim_after_sealed": False},
        "witness_key": {
            "key_id": KEY_ID,
            "algorithm": "ES256",
            "public_key_sha256": hashlib.sha256(witness_pem()).hexdigest(),
            "identity": WITNESS["id"],
        },
        "authorities": {
            "list": [
                {
                    "authority": name,
                    "name": f"Example authority {name}",
                    "url": f"https://{name}.example/tsa",
                    "jurisdiction": jurisdiction,
                    "roots": [hashlib.sha256(authority(name).root).hexdigest()],
                    "practice_statement": f"https://{name}.example/practice",
                    "audit_reference": f"{name}-audit-2026",
                }
                for name, jurisdiction in AUTHORITIES
            ],
            "assessment": {
                "by": APPROVER,
                "date": "2026-11-20",
                "statement": "No single order or treaty reaches both authorities.",
            },
        },
        "personal_data": {
            "identifiers": "clear",
            "basis": "Record-keeping obligation: the record must show who decided.",
        },
        "gateway": {"image": "sha256:" + stand_in("gateway image")},
    }
    doc.update(overrides)
    return doc


def mandate_bytes(doc: Mapping[str, Any]) -> bytes:
    # Deliberately not canonical: the gateway stores the bytes it is given.
    return json.dumps(doc, indent=2).encode()


def mandate_ref(doc: Mapping[str, Any]) -> dict[str, Any]:
    return ref(mandate_bytes(doc), role="mandate", kind="data.json", media_type="application/json")


def schema_ref(data: bytes = FINDINGS_SCHEMA) -> dict[str, Any]:
    return ref(data, role="schema", kind="schema.json", media_type="application/schema+json")


def instructions_ref(data: bytes = INSTRUCTIONS) -> dict[str, Any]:
    return ref(data, role="instructions", kind="text.markdown", media_type="text/markdown")


def config_changed(
    doc: Mapping[str, Any],
    *,
    previous: Mapping[str, Any] | None = None,
    old: Mapping[str, Any] | None = None,
    instructions: Sequence[bytes] = (INSTRUCTIONS,),
    schemas: Sequence[bytes] = (FINDINGS_SCHEMA,),
) -> dict[str, Any]:
    body = {
        "version": doc["version"],
        "previous": dict(previous) if previous is not None else None,
        "changed": changed_parts(old, doc),
        "mandate": artefact_sha256(mandate_bytes(doc)),
        # Tolerates a missing part, so a test can submit a broken mandate to the rules.
        "parts": {part: canonical_digest(doc.get(part)) for part in PARTS},
        "approved_by": APPROVER,
        "reason": "genesis" if previous is None else "new mandate",
    }
    artefacts = [
        mandate_ref(doc),
        *(instructions_ref(data) for data in instructions),
        *(schema_ref(data) for data in schemas),
    ]
    return draft("config.changed", body, dossier=None, artefacts=artefacts, actor=APPROVER)


# -- witnesses --------------------------------------------------------------------------------


def results(
    gen_time: str = "2026-11-27T00:03:12Z", authorities=AUTHORITIES
) -> list[AuthorityResult]:
    return [
        AuthorityResult(
            authority=name,
            jurisdiction=jurisdiction,
            obtained=True,
            qualified=False,
            gen_time=gen_time,
            token_sha256=stand_in(f"{name} token {gen_time}"),
        )
        for name, jurisdiction in authorities
    ]


def witness(
    which: str,
    last_seq: int,
    last_hash: str,
    *,
    interval: tuple[str, str] | None = None,
    authorities: Sequence[AuthorityResult] | None = None,
    key_id: str = KEY_ID,
    chain: str = CHAIN,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "spec": SPEC,
        "chain": chain,
        "witness": which,
        "last_seq": last_seq,
        "last_hash": last_hash,
        "key_id": key_id,
    }
    if interval is not None:
        body["interval"] = {"from": interval[0], "to": interval[1]}
    body["signature"] = SIGNATURE
    body["time_attestation"] = time_attestation(body, authorities or results())
    return body


def witness_draft(body: Mapping[str, Any], *, actor: Mapping[str, Any] = WITNESS):
    return draft(f"witness.{body['witness']}", body, dossier=None, actor=actor)


def examples() -> dict[str, dict[str, Any]]:
    """One valid draft of every entry type, for checks that need no chain."""
    some_hash = "sha256:" + stand_in("an entry")
    doc = mandate_document()
    return {
        "dossier.opened": opened(some_hash),
        "source.read": source_read(),
        "artefact.attached": artefact_attached(
            ref(
                b"%PDF-1.7 ...", role="case-file", kind="document.pdf", media_type="application/pdf"
            )
        ),
        "ai.exchange": ai_exchange(),
        "trace.recorded": trace_recorded(),
        "finding.drafted": finding_drafted(),
        "output.produced": output_produced(),
        "decision.recorded": decision(artefact_sha256(FINDINGS)),
        "config.changed": config_changed(doc),
        "correction": correction(some_hash),
        "notice": notice(),
        "dossier.sealed": sealed(6, 4),
        "witness.daily": witness_draft(
            witness(
                "daily",
                18342,
                some_hash,
                interval=("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z"),
            )
        ),
        "witness.interim": witness_draft(witness("interim", 18342, some_hash)),
        "retention.expired": retention_expired(dossiers=[DOSSIER]),
    }


# -- an artefact store and a chain, driven the way the gateway drives them --------------------


class MemoryArtefacts:
    """Uploaded artefacts, held in memory."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[ArtefactInfo, bytes]] = {}
        self._trust: dict[str, bytes] = {}

    def add(self, data: bytes, *, kind: str, media_type: str, sensitivity: str = "none"):
        declared = None
        if kind == "data.json":
            declared = strict_loads(data).get("$schema")
        info = ArtefactInfo(
            sha256=artefact_sha256(data),
            kind=kind,
            media_type=media_type,
            bytes=len(data),
            sensitivity=sensitivity,
            declared_schema=declared,
        )
        self._items[info.sha256] = (info, data)
        return info

    def info(self, sha256: str) -> ArtefactInfo | None:
        item = self._items.get(sha256)
        return item[0] if item else None

    def json(self, sha256: str) -> Any:
        return strict_loads(self._items[sha256][1])

    def put_trust(self, path: str, data: bytes) -> None:
        self._trust[path] = data

    def trust(self, path: str) -> bytes | None:
        return self._trust.get(path)


class Rejected(Exception):
    def __init__(self, problems: list[Problem]):
        super().__init__("; ".join(f"{p.code} at {p.path}: {p.detail}" for p in problems))
        self.problems = problems


class Scenario:
    """A chain driven the way the gateway drives it: check, link under the head, apply."""

    def __init__(self, start: datetime = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)):
        self.state = ChainState(CHAIN)
        self.store = MemoryArtefacts()
        self.entries: list[dict[str, Any]] = []
        self.now = start

    def upload(self, *payloads: bytes, kind: str, media_type: str, sensitivity: str = "none"):
        for data in payloads:
            self.store.add(data, kind=kind, media_type=media_type, sensitivity=sensitivity)

    def problems(self, entry: Mapping[str, Any]) -> list[Problem]:
        return self.state.check(entry, artefacts=self.store, now=self.now)

    def codes(self, entry: Mapping[str, Any]) -> list[str]:
        return [problem.code for problem in self.problems(entry)]

    def commit(self, entry: Mapping[str, Any]) -> dict[str, Any]:
        problems = self.problems(entry)
        if problems:
            raise Rejected(problems)
        head = self.state.head
        linked = link_entry(
            entry,
            seq=head[0] + 1 if head else 1,
            prev=head[1] if head else None,
            committed_at=format_timestamp(self.now),
        )
        self.state.apply(linked, artefacts=self.store)
        self.entries.append(linked)
        self.now += timedelta(seconds=1)
        return linked

    def config(self, doc: Mapping[str, Any] | None = None, **kw) -> dict[str, Any]:
        """A config.changed draft, with its mandate and instructions uploaded."""
        doc = doc or mandate_document()
        self.store.add(mandate_bytes(doc), kind="data.json", media_type="application/json")
        for data in kw.get("instructions", (INSTRUCTIONS,)):
            self.store.add(data, kind="text.markdown", media_type="text/markdown")
        for data in kw.get("schemas", (FINDINGS_SCHEMA,)):
            self.store.add(data, kind="schema.json", media_type="application/schema+json")
        if kw.pop("trust", True):
            for path, data in trust_files(doc).items():
                self.store.put_trust(path, data)
        return config_changed(doc, **{k: v for k, v in kw.items() if k != "trust"})

    def interim(self, seq: int | None = None, **kw) -> dict[str, Any]:
        seq = seq or self.state.head[0]
        target = self.entries[seq - 1]
        gen = format_timestamp(self.now)
        return witness_draft(
            witness("interim", seq, target["hash"], authorities=results(gen), **kw)
        )

    def daily(self, day: date, **kw) -> dict[str, Any]:
        start = datetime.combine(day, time(0), tzinfo=UTC)
        end = start + timedelta(days=1)
        before = [e for e in self.entries if parse_timestamp(e["committed_at"]) < end]
        last = before[-1]
        interval = (f"{start:%Y-%m-%d}T00:00:00Z", f"{end:%Y-%m-%d}T00:00:00Z")
        body = witness(
            "daily",
            last["seq"],
            last["hash"],
            interval=interval,
            authorities=results(format_timestamp(self.now)),
            **kw,
        )
        return witness_draft(body)

    def genesis(self, doc: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Commit the genesis config.changed and its interim witness. Returns the config entry."""
        config = self.commit(self.config(doc))
        self.commit(self.interim())
        return config

    def open(self, dossier: str = DOSSIER, **kw) -> dict[str, Any]:
        mandate = self.state.in_force.config
        return self.commit(opened(mandate, dossier=dossier, **kw))

    def upload_standard(self) -> None:
        """Upload the example artefacts the per-type builders refer to."""
        self.upload(REQUEST, RESPONSE, kind="ai.exchange.raw", media_type="application/json")
        self.upload(TRACE, kind="trace.otel", media_type="application/json")
        self.upload(FINDINGS, kind="data.json", media_type="application/json")
        self.upload(OUTPUT, kind="text.plain", media_type="text/plain")
        self.upload(SOURCE, kind="record.snapshot", media_type="application/json")


# -- a time-stamp authority -------------------------------------------------------------------


class FakeAuthority:
    """An RFC 3161 authority for tests: its own root and time-stamping certificate, and a
    responder that stamps whatever imprint it is sent. Never a real authority's keys."""

    def __init__(self, name: str) -> None:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        self.name = name
        start, end = datetime(2026, 1, 1, tzinfo=UTC), datetime(2036, 1, 1, tzinfo=UTC)
        root_key, self._key = (
            ec.generate_private_key(ec.SECP256R1()),
            ec.generate_private_key(ec.SECP256R1()),
        )

        def subject(common: str) -> cx509.Name:
            return cx509.Name(
                [
                    cx509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Example {name}"),
                    cx509.NameAttribute(NameOID.COMMON_NAME, common),
                ]
            )

        root = (
            cx509.CertificateBuilder()
            .subject_name(subject("Root"))
            .issuer_name(subject("Root"))
            .public_key(root_key.public_key())
            .serial_number(1)
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256())
        )
        signer = (
            cx509.CertificateBuilder()
            .subject_name(subject("Time Stamping"))
            .issuer_name(root.subject)
            .public_key(self._key.public_key())
            .serial_number(2)
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(
                cx509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .sign(root_key, hashes.SHA256())
        )
        self.root = root.public_bytes(serialization.Encoding.DER)
        self._signer = signer.public_bytes(serialization.Encoding.DER)
        self._serial = 0

    def respond(self, request: bytes, *, at: datetime) -> bytes:
        """The DER response to a DER request, stamped at `at`."""
        import hashlib

        from asn1crypto import cms, tsp
        from asn1crypto import x509 as ax509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        asked = tsp.TimeStampReq.load(request)
        self._serial += 1
        info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": "1.3.6.1.4.1.99999.1",
                "message_imprint": asked["message_imprint"],
                "serial_number": self._serial,
                "gen_time": at,
                "nonce": asked["nonce"].native,
            }
        )
        signer = ax509.Certificate.load(self._signer)
        attributes = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["tst_info"]},
                {"type": "message_digest", "values": [hashlib.sha256(info.dump()).digest()]},
                {
                    "type": "signing_certificate_v2",
                    "values": [{"certs": [{"cert_hash": hashlib.sha256(self._signer).digest()}]}],
                },
            ]
        )
        signature = self._key.sign(b"\x31" + attributes.dump()[1:], ec.ECDSA(hashes.SHA256()))
        signed = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {"content_type": "tst_info", "content": info},
                "certificates": [signer],
                "signer_infos": [
                    {
                        "version": "v1",
                        "sid": cms.SignerIdentifier(
                            {
                                "issuer_and_serial_number": {
                                    "issuer": signer.issuer,
                                    "serial_number": signer.serial_number,
                                }
                            }
                        ),
                        "digest_algorithm": {"algorithm": "sha256"},
                        "signed_attrs": attributes,
                        "signature_algorithm": {"algorithm": "sha256_ecdsa"},
                        "signature": signature,
                    }
                ],
            }
        )
        return tsp.TimeStampResp(
            {
                "status": {"status": "granted"},
                "time_stamp_token": {"content_type": "signed_data", "content": signed},
            }
        ).dump()


# -- the witness key and signed, stamped witnesses ---------------------------------------------


@functools.cache
def authority(name: str) -> FakeAuthority:
    """The test authority of that name, the same one for the whole test run."""
    return FakeAuthority(name)


@functools.cache
def _witness_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def witness_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization

    return (
        _witness_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def trust_files(doc: Mapping[str, Any] | None = None) -> dict[str, bytes]:
    """The `trust/` files a mandate names: its witness key and its authorities' roots."""
    doc = doc or mandate_document()
    files = {paths.witness_key(doc["witness_key"]["key_id"]): witness_pem()}
    for listed in doc["authorities"]["list"]:
        root = authority(listed["authority"]).root
        files[paths.tsa_certificate(listed["authority"], hashlib.sha256(root).hexdigest())] = root
    return files


def attested(
    which: str,
    last_seq: int,
    last_hash: str,
    *,
    interval: tuple[str, str] | None = None,
    down: Iterable[str] = (),
    key_id: str = KEY_ID,
    at: datetime = STAMPED_AT,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """A witness signed with the test witness key and stamped by the test authorities, except
    those `down`, with the tokens by authority."""
    from sheaf_core.tsp import check_token, request
    from sheaf_core.witness import imprint_bytes, sign_es256, signing_input

    body: dict[str, Any] = {"spec": SPEC, "chain": CHAIN, "witness": which}
    if interval is not None:
        body["interval"] = {"from": interval[0], "to": interval[1]}
    body.update({"last_seq": last_seq, "last_hash": last_hash, "key_id": key_id})
    body["signature"] = sign_es256(_witness_key(), signing_input(body))
    imprint, unavailable = imprint_bytes(body), set(down)
    results, tokens = [], {}
    for name, jurisdiction in AUTHORITIES:
        if name in unavailable:
            results.append(
                AuthorityResult(
                    authority=name,
                    jurisdiction=jurisdiction,
                    obtained=False,
                    unavailable_reason="HTTP 503; 12 attempts over 21600 s",
                )
            )
            continue
        response = authority(name).respond(request(imprint, 1), at=at)
        token, _ = check_token(response, imprint=imprint, roots=[authority(name).root])
        results.append(
            AuthorityResult(
                authority=name,
                jurisdiction=jurisdiction,
                obtained=True,
                qualified=token.qualified,
                gen_time=at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                token_sha256=hashlib.sha256(response).hexdigest(),
            )
        )
        tokens[name] = response
    body["time_attestation"] = time_attestation(body, results)
    return body, tokens
