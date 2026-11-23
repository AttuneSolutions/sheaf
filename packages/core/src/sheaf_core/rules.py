"""The rules the gateway enforces that need more than the entry (sections 5.3 and 5.5-5.7).

`ChainState` is what the rules know about one chain, built by applying each committed entry in
order. The gateway keeps one and checks each draft against it under the chain-head lease; the
verifier builds one by replaying a container and checks each entry the same way. Neither has a
copy of the rules of its own.

Uploaded artefacts are not in the chain (an artefact exists before an entry names it), so they
come from an `Artefacts` store the caller supplies. The mandate in force is rebuilt from the
chain and that store alone (5.6).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any, Protocol

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo
from sheaf_core.canonical import InvalidJSON
from sheaf_core.entry import check_draft
from sheaf_core.mandate import PARTS, PSEUDONYM, changed_parts, check_mandate, part_digests
from sheaf_core.mandate import SCHEMA_ID as MANDATE_SCHEMA
from sheaf_core.problems import Problem
from sheaf_core.schema import check_tenant_schemas, validate
from sheaf_core.times import parse_date, parse_timestamp, require_aware


class Artefacts(Protocol):
    def info(self, sha256: str) -> ArtefactInfo | None:
        """The artefact uploaded with this SHA-256, or None."""

    def json(self, sha256: str) -> Any:
        """The parsed content of a JSON artefact. Raises KeyError if absent."""

    def trust(self, path: str) -> bytes | None:
        """The bytes of a file in `trust/`, or None."""


@dataclass(frozen=True)
class Mandate:
    config: str
    """The `hash` of the `config.changed` entry that carried it."""
    seq: int
    version: str
    document: Mapping[str, Any]
    schemas: Mapping[str, Any] = field(default_factory=dict)
    """The tenant schemas the mandate names, by identifier."""
    mandate: str = ""
    """The SHA-256 of the mandate artefact: its fingerprint."""
    approved_by: str = ""
    committed_at: str = ""
    """When its `config.changed` was committed, as the entry says."""


@dataclass(frozen=True)
class WitnessSeen:
    """The last witness entry of one kind, as a status report shows it: identifiers, times and
    authority names only."""

    seq: int
    committed_at: str
    last_seq: int
    interval_to: str | None
    """A daily witness's end, as written; None for an interim one."""
    attested: tuple[str, ...]
    """The authorities whose tokens it lists as obtained, in its order."""


@dataclass(frozen=True)
class _Entry:
    seq: int
    hash: str
    type: str
    dossier: str | None
    committed_at: datetime


@dataclass
class _Dossier:
    opened_at: datetime
    subject: Mapping[str, Any]
    retention: Mapping[str, Any]
    source_capture: str
    entries: int = 1
    sealed: bool = False
    expired: bool = False
    artefacts: set[str] = field(default_factory=set)
    fingerprints: set[str] = field(default_factory=set)
    """Every SHA-256 the dossier names: its artefacts, and the fingerprints recorded in
    `source.read` and `output.produced`. What a decision or a rendition may refer to."""


class ChainState:
    def __init__(self, chain: str):
        self.chain = chain
        self.in_force: Mandate | None = None
        self.pending: Mandate | None = None
        """A mandate committed but not yet interim-witnessed, so not yet applied (5.6)."""
        self._entries: list[_Entry] = []
        self._by_hash: dict[str, _Entry] = {}
        self._dossiers: dict[str, _Dossier] = {}
        self._referrers: dict[str, set[str | None]] = {}
        self._expired_artefacts: set[str] = set()
        self._interims: set[int] = set()
        self._last_daily_end: datetime | None = None
        self._last_witness: dict[str, WitnessSeen] = {}

    @property
    def head(self) -> tuple[int, str] | None:
        """The `seq` and `hash` of the last entry, or None for an empty chain."""
        return (self._entries[-1].seq, self._entries[-1].hash) if self._entries else None

    def last_witness(self, entry_type: str) -> WitnessSeen | None:
        """The last `witness.daily` or `witness.interim` committed, or None."""
        return self._last_witness.get(entry_type)

    @property
    def last_daily_end(self) -> datetime | None:
        """Where the last daily witness ended, or None before the first."""
        return self._last_daily_end

    @property
    def head_at(self) -> datetime | None:
        """When the last entry was committed, or None for an empty chain."""
        return self._entries[-1].committed_at if self._entries else None

    @property
    def genesis_at(self) -> datetime | None:
        """When the chain's first entry was committed."""
        return self._entries[0].committed_at if self._entries else None

    def opened_at(self, dossier_id: str) -> datetime | None:
        """When a dossier's `dossier.opened` was committed: where its blob is filed (4)."""
        dossier = self._dossiers.get(dossier_id)
        return dossier.opened_at if dossier else None

    def governing(self) -> Mandate | None:
        """The mandate whose policy decides who may write an entry other than a witness: the
        one in force. None until the genesis mandate's interim witness is committed."""
        return self.in_force

    def witness_mandate(self, draft: Mapping[str, Any]) -> Mandate | None:
        """The mandate a witness is checked against: its key, identity and authorities.

        The interim witness that applies a pending mandate uses that new mandate. Every other
        witness uses the mandate in force (9 step 3), or the genesis mandate before there is one.
        """
        body = draft["body"]
        applies_pending = (
            draft["type"] == "witness.interim"
            and self.pending is not None
            and body.get("last_seq") == self.pending.seq
        )
        if applies_pending or self.in_force is None:
            return self.pending
        return self.in_force

    def check(self, draft: Any, *, artefacts: Artefacts, now: datetime) -> list[Problem]:
        """Every problem with committing `draft` next. Does not change the state.

        `now` is the gateway's clock, which becomes `committed_at`; a verifier passes the
        entry's own `committed_at`.
        """
        now = require_aware(now).astimezone(UTC)
        problems = check_draft(draft)
        if problems:
            return problems
        return _Check(self, draft, artefacts, now).run()

    def apply(self, entry: Mapping[str, Any], *, artefacts: Artefacts) -> None:
        """Record a committed entry. It must follow the head and have passed `check`."""
        expected = len(self._entries) + 1
        if entry["seq"] != expected:
            raise ValueError(f"seq {entry['seq']} does not follow the head; expected {expected}")
        head_hash = self._entries[-1].hash if self._entries else None
        if entry["prev"] != head_hash:
            raise ValueError(f"prev {entry['prev']} is not the head's hash {head_hash}")
        if entry["chain"] != self.chain:
            raise ValueError(f"entry is for chain {entry['chain']}, not {self.chain}")

        entry_type, body, dossier_id = entry["type"], entry["body"], entry["dossier"]

        # Every lookup that can fail comes first, so a refused entry changes nothing.
        committed_at = parse_timestamp(entry["committed_at"])
        opened = entry_type == "dossier.opened"
        if dossier_id is not None and not opened and dossier_id not in self._dossiers:
            raise ValueError(f"dossier {dossier_id} was never opened")
        document = None
        schemas: dict[str, Any] = {}
        if entry_type == "config.changed":
            try:
                document = artefacts.json(body["mandate"])
            except (KeyError, InvalidJSON) as error:
                raise ValueError(f"mandate {body['mandate']} cannot be read: {error}") from error
            for named in document["schemas"]:
                try:
                    schemas[named["id"]] = artefacts.json(named["sha256"])
                except (KeyError, InvalidJSON) as error:
                    raise ValueError(f"schema {named['id']} cannot be read: {error}") from error
        if entry_type == "retention.expired":
            unknown = [d for d in body["dossiers"] if d not in self._dossiers]
            if unknown:
                raise ValueError(f"dossier {unknown[0]} was never opened")
        daily_end = None
        if entry_type == "witness.daily":
            daily_end = parse_timestamp(body["interval"]["to"])

        record = _Entry(
            seq=entry["seq"],
            hash=entry["hash"],
            type=entry_type,
            dossier=dossier_id,
            committed_at=committed_at,
        )
        self._entries.append(record)
        self._by_hash[record.hash] = record

        refs = [ref["sha256"] for ref in entry["artefacts"]]
        for sha256 in refs:
            self._referrers.setdefault(sha256, set()).add(dossier_id)

        if dossier_id is not None:
            if entry_type == "dossier.opened":
                self._dossiers[dossier_id] = _Dossier(
                    opened_at=committed_at,
                    subject=entry["subject"],
                    retention=entry["retention"],
                    source_capture=body["source_capture"],
                )
            else:
                self._dossiers[dossier_id].entries += 1
            dossier = self._dossiers[dossier_id]
            dossier.artefacts.update(refs)
            dossier.fingerprints.update(refs)
            if entry_type in ("source.read", "output.produced"):
                dossier.fingerprints.add(body["sha256"])
            if entry_type == "dossier.sealed":
                dossier.sealed = True
        elif entry_type == "config.changed":
            self.pending = Mandate(
                config=record.hash,
                seq=record.seq,
                version=body["version"],
                document=document,
                schemas=schemas,
                mandate=body["mandate"],
                approved_by=body["approved_by"]["id"],
                committed_at=entry["committed_at"],
            )
        elif entry_type in ("witness.daily", "witness.interim"):
            self._last_witness[entry_type] = WitnessSeen(
                seq=record.seq,
                committed_at=entry["committed_at"],
                last_seq=body["last_seq"],
                interval_to=body["interval"]["to"] if daily_end is not None else None,
                attested=tuple(
                    a["authority"] for a in body["time_attestation"]["authorities"] if a["obtained"]
                ),
            )
            if entry_type == "witness.daily":
                self._last_daily_end = daily_end
            else:
                self._interims.add(body["last_seq"])
                if self.pending is not None and body["last_seq"] == self.pending.seq:
                    self.in_force, self.pending = self.pending, None
        elif entry_type == "retention.expired":
            for expired in body["dossiers"]:
                self._dossiers[expired].expired = True
            self._expired_artefacts.update(body["artefacts"])


class _Check:
    """One draft checked against one state."""

    def __init__(self, state: ChainState, draft: Mapping[str, Any], artefacts: Artefacts, now):
        self.state = state
        self.draft = draft
        self.body = draft["body"]
        self.artefacts = artefacts
        self.now: datetime = now
        self.dossier: _Dossier | None = None
        self.problems: list[Problem] = []

    def report(self, code: str, path: str, detail: str) -> None:
        self.problems.append(Problem(code, path, detail))

    def run(self) -> list[Problem]:
        state, entry_type = self.state, self.draft["type"]
        if self.draft["chain"] != state.chain:
            self.report("chain_mismatch", "$.chain", f"this gateway writes {state.chain}")
            return self.problems
        if not state._entries:
            if entry_type != "config.changed":
                self.report(
                    "genesis_required",
                    "$.type",
                    "the first entry of a chain is a config.changed with no previous version",
                )
                return self.problems
        elif state.in_force is None and entry_type not in (
            "config.changed",
            "witness.daily",
            "witness.interim",
            "notice",
        ):
            self.report(
                "mandate_not_in_force",
                "$.type",
                "no mandate is in force until the genesis mandate's interim witness is committed",
            )
            return self.problems

        self._identifier_rules()
        self._dossier_rules()
        self._artefact_rules()
        rule: Callable[[], None] | None = getattr(self, "_" + entry_type.replace(".", "_"), None)
        if rule is not None:
            rule()
        return self.problems

    # -- every entry ---------------------------------------------------------------------------

    def _identifier_rules(self) -> None:
        """Under a mandate that pseudonymises identifiers, a person and a subject are named only
        by pseudonym (5.7). A config.changed is held to the mandate it carries."""
        document = None
        if self.draft["type"] == "config.changed":
            ref = next(r for r in self.draft["artefacts"] if r["role"] == "mandate")
            try:
                document = self.artefacts.json(ref["sha256"])
                pseudonymised = document["personal_data"]["identifiers"] == "pseudonymised"
            except (KeyError, InvalidJSON, TypeError):
                return  # the config.changed rules report an unreadable mandate
        else:
            governing = self.state.governing()
            pseudonymised = (
                governing is not None
                and governing.document["personal_data"]["identifiers"] == "pseudonymised"
            )
        if not pseudonymised:
            return
        actor, subject = self.draft["actor"], self.draft.get("subject")
        if actor["kind"] == "person" and not PSEUDONYM.fullmatch(actor["id"]):
            self.report("identifier_not_pseudonymised", "$.actor.id", "a person is a pseudonym")
        if subject is not None and not PSEUDONYM.fullmatch(subject["id"]):
            self.report("identifier_not_pseudonymised", "$.subject.id", "a subject is a pseudonym")
        proposer = self.body.get("proposed_by") if document is not None else None
        if proposer and proposer["kind"] == "person" and not PSEUDONYM.fullmatch(proposer["id"]):
            here = "$.body.proposed_by.id"
            self.report("identifier_not_pseudonymised", here, "a person is a pseudonym")
        if document is not None:
            assessor = document["authorities"]["assessment"]["by"]["id"]
            if not PSEUDONYM.fullmatch(assessor):
                self.report(
                    "identifier_not_pseudonymised",
                    "$.artefacts",
                    "the mandate's assessor is a pseudonym",
                )

    def _dossier_rules(self) -> None:
        dossier_id = self.draft["dossier"]
        if dossier_id is None:
            return
        known = self.state._dossiers.get(dossier_id)
        if self.draft["type"] == "dossier.opened":
            if known is not None:
                self.report("dossier_exists", "$.dossier", f"{dossier_id} is already open")
            return
        if known is None:
            self.report("dossier_unknown", "$.dossier", f"no dossier {dossier_id} was opened")
            return
        if known.expired:
            self.report("dossier_expired", "$.dossier", f"{dossier_id} has expired")
            return
        self.dossier = known
        if known.sealed:
            self.report("dossier_sealed", "$.dossier", f"{dossier_id} is sealed")
        if self.draft["subject"] != known.subject:
            self.report("subject_mismatch", "$.subject", "not the subject the dossier opened with")
        if self.draft["retention"] != known.retention:
            self.report(
                "retention_mismatch", "$.retention", "not the retention the dossier opened with"
            )

    def _artefact_rules(self) -> None:
        refs = self.draft["artefacts"]
        for index, ref in enumerate(refs):
            here, sha256 = f"$.artefacts[{index}]", ref["sha256"]
            if sha256 in self.state._expired_artefacts:
                self.report("artefact_expired", here, "named in a retention.expired entry")
                continue
            info = self.artefacts.info(sha256)
            if info is None:
                self.report("artefact_unknown", here, "not uploaded to this tenant")
                continue
            differ = [
                f
                for f in ("kind", "media_type", "bytes", "sensitivity")
                if getattr(info, f) != ref[f]
            ]
            if differ:
                self.report(
                    "artefact_mismatch", here, f"differs from the upload in {', '.join(differ)}"
                )
            if "rendition_of" in ref:
                named = self.dossier.fingerprints if self.dossier else set()
                others = {r["sha256"] for r in refs if r is not ref}
                if ref["rendition_of"] not in named | others:
                    self.report(
                        "rendition_unknown",
                        f"{here}.rendition_of",
                        "a rendition is of an artefact in the same dossier",
                    )

    # -- one method per entry type that has rules needing the state ----------------------------

    def _dossier_opened(self) -> None:
        mandate = self.state.in_force
        if self.body["mandate"] != mandate.config:
            self.report(
                "mandate_not_in_force",
                "$.body.mandate",
                f"the mandate in force is {mandate.config}",
            )
        policy = mandate.document["policy"]
        if self.body["source_capture"] != policy["source_capture"]:
            self.report(
                "source_capture_mismatch",
                "$.body.source_capture",
                f"the policy in force says {policy['source_capture']}",
            )
        classes = {c["class"] for c in mandate.document["retention"]["classes"]}
        if self.draft["retention"]["class"] not in classes:
            self.report(
                "retention_class_unknown",
                "$.retention.class",
                f"the mandate's classes are {', '.join(sorted(classes))}",
            )

    def _source_read(self) -> None:
        if self.dossier is None:
            return
        policy, attached = self.dossier.source_capture, bool(self.draft["artefacts"])
        if policy == "reference" and attached:
            self.report("source_copied", "$.artefacts", "the reference policy copies no source")
        elif policy == "copy" and not attached:
            self.report("source_not_copied", "$.artefacts", "the copy policy attaches the source")

    def _finding_drafted(self) -> None:
        sha256, name = self.draft["artefacts"][0]["sha256"], self.body["schema"]
        info = self.artefacts.info(sha256)
        if info is None:
            return
        if info.declared_schema != name:
            self.report(
                "findings_schema_mismatch",
                "$.body.schema",
                f"the findings artefact declares {info.declared_schema}",
            )
            return
        mandate = self.state.governing()
        schemas = mandate.schemas if mandate is not None else {}
        if name not in schemas:
            self.report(
                "schema_unknown", "$.body.schema", "the mandate in force names no such schema"
            )
            return
        try:
            invalid = validate(name, self.artefacts.json(sha256), schemas=schemas)
        except (KeyError, InvalidJSON) as error:
            self.report("findings_invalid", "$.artefacts[0]", str(error))
            return
        if invalid:
            detail = "; ".join(f"{p.path}: {p.detail}" for p in invalid[:5])
            self.report("findings_invalid", "$.artefacts[0]", detail)

    def _decision_recorded(self) -> None:
        if self.dossier is not None and self.body["decided"] not in self.dossier.fingerprints:
            self.report(
                "decided_unknown",
                "$.body.decided",
                "a decision is on something this dossier names",
            )

    def _correction(self) -> None:
        target = self.state._by_hash.get(self.body["corrects"])
        if target is None:
            self.report("target_unknown", "$.body.corrects", "no such entry in this chain")
        elif target.dossier is None:
            self.report(
                "target_chain_level",
                "$.body.corrects",
                "a chain-level entry is superseded by a new one of its type, not corrected",
            )
        else:
            dossier = self.state._dossiers[target.dossier]
            if dossier.expired:
                self.report("target_expired", "$.body.corrects", "the entry's dossier has expired")
            elif target.dossier != self.draft["dossier"]:
                if not dossier.sealed:
                    self.report(
                        "target_open_elsewhere",
                        "$.body.corrects",
                        f"{target.dossier} is open: correct it there",
                    )
                if dossier.subject != self.draft.get("subject"):
                    self.report(
                        "target_subject",
                        "$.body.corrects",
                        "a correction made elsewhere is for the same subject",
                    )

    def _dossier_sealed(self) -> None:
        if self.dossier is None:
            return
        expected = {"entries": self.dossier.entries + 1, "artefacts": len(self.dossier.artefacts)}
        for name, count in expected.items():
            if self.body[name] != count:
                self.report("count_mismatch", f"$.body.{name}", f"the dossier has {count}")

    def _config_changed(self) -> None:
        state, body = self.state, self.body
        genesis = not state._entries
        if genesis:
            if body["previous"] is not None:
                self.report(
                    "genesis_previous", "$.body.previous", "the genesis mandate has no previous"
                )
        else:
            if state.pending is not None:
                self.report(
                    "mandate_pending",
                    "$.type",
                    "the last mandate change is waiting for its interim witness",
                )
            current = state.in_force
            if body["previous"] is None:
                self.report("previous_required", "$.body.previous", "name the mandate replaced")
            elif current is not None and body["previous"] != {
                "version": current.version,
                "config": current.config,
            }:
                self.report(
                    "previous_mismatch",
                    "$.body.previous",
                    f"the mandate in force is {current.version} at {current.config}",
                )
            if current is not None and body["version"] == current.version:
                self.report(
                    "version_unchanged", "$.body.version", "a new mandate has a new version"
                )

        refs = self.draft["artefacts"]
        index, ref = next((i, r) for i, r in enumerate(refs) if r["role"] == "mandate")
        here = f"$.artefacts[{index}]"
        info = self.artefacts.info(ref["sha256"])
        if info is None:
            return
        if info.declared_schema != MANDATE_SCHEMA:
            self.report("mandate_schema", here, f"the mandate declares {info.declared_schema}")
            return
        try:
            doc = self.artefacts.json(ref["sha256"])
        except (KeyError, InvalidJSON) as error:
            self.report("mandate_invalid", here, str(error))
            return
        invalid = check_mandate(doc)
        if invalid:
            detail = "; ".join(f"{p.path}: {p.detail}" for p in invalid)
            self.report("mandate_invalid", here, detail)
            return

        if doc["chain"] != state.chain:
            self.report("mandate_chain", here, f"the mandate is for {doc['chain']}")
        if doc["version"] != body["version"]:
            self.report("mandate_version", "$.body.version", f"the mandate is {doc['version']}")
        digests = part_digests(doc)
        for part in PARTS:
            if body["parts"][part] != digests[part]:
                self.report("part_digest_mismatch", f"$.body.parts.{part}", f"is {digests[part]}")

        old = None if genesis or state.in_force is None else state.in_force.document
        # The mandate in force decides, so a change cannot turn four eyes off for itself; the
        # genesis mandate decides for itself.
        governing = doc if old is None else old
        same = body["proposed_by"]["id"] == body["approved_by"]["id"]
        if governing["policy"]["four_eyes"] and same:
            self.report(
                "four_eyes",
                "$.body.approved_by",
                "whoever proposed a mandate change may not approve it (the mandate's four_eyes)",
            )
        expected = changed_parts(old, doc)
        if set(body["changed"]) != set(expected):
            self.report(
                "changed_mismatch",
                "$.body.changed",
                f"the parts that changed are {', '.join(expected) or 'none'}",
            )

        for part, role in (("instructions", "instructions"), ("schemas", "schema")):
            named = {item["sha256"] for item in doc[part]}
            attached = {r["sha256"] for r in refs if r["role"] == role}
            if named != attached:
                missing, extra = sorted(named - attached), sorted(attached - named)
                self.report(
                    "mandate_incomplete",
                    "$.artefacts",
                    f"{part} missing {missing or 'none'}, not named {extra or 'none'}",
                )
                return

        schemas = {}
        for named in doc["schemas"]:
            if self.artefacts.info(named["sha256"]) is None:
                return
            try:
                schemas[named["id"]] = self.artefacts.json(named["sha256"])
            except (KeyError, InvalidJSON) as error:
                self.report("mandate_invalid", "$.artefacts", f"{named['id']}: {error}")
                return
        for problem in check_tenant_schemas(schemas, "$.schemas"):
            self.report(problem.code, problem.path, problem.detail)

        # The witness key and the authorities' roots are stored before the mandate applies, so
        # its interim witness, and every later one, can be checked (7.2 step 5).
        key = doc["witness_key"]
        named = {paths.witness_key(key["key_id"]): key["public_key_sha256"]}
        for listed in doc["authorities"]["list"]:
            for sha256 in listed["roots"]:
                named[paths.tsa_certificate(listed["authority"], sha256)] = sha256
        for trust_path, sha256 in named.items():
            stored = self.artefacts.trust(trust_path)
            if stored is None or hashlib.sha256(stored).hexdigest() != sha256:
                self.report("trust_missing", here, f"{trust_path} is not stored")

    def _witness_daily(self) -> None:
        if not self._witness_common():
            return
        state, body = self.state, self.body
        start = parse_timestamp(body["interval"]["from"])
        end = parse_timestamp(body["interval"]["to"])
        if end > self.now:
            self.report("interval_not_ended", "$.body.interval.to", "the day has not ended")
        genesis_day = datetime.combine(state._entries[0].committed_at.date(), time(0), UTC)
        expected = state._last_daily_end or genesis_day
        if start != expected:
            self.report(
                "interval_gap",
                "$.body.interval.from",
                f"the next day to witness starts {expected.isoformat()}",
            )
        last = state._entries[body["last_seq"] - 1]
        following = state._entries[last.seq] if last.seq < len(state._entries) else None
        if last.committed_at >= end or (following is not None and following.committed_at < end):
            self.report(
                "witness_boundary",
                "$.body.last_seq",
                "a daily witness ends at the last entry committed before the interval ends",
            )

    def _witness_interim(self) -> None:
        if not self._witness_common():
            return
        state, body = self.state, self.body
        if body["last_seq"] in state._interims:
            self.report("interim_duplicate", "$.body.last_seq", "already interim-witnessed")
        target = state._entries[body["last_seq"] - 1]
        after_sealed = state.witness_mandate(self.draft).document["witness_interval"][
            "interim_after_sealed"
        ]
        if not (
            target.type == "config.changed" or (target.type == "dossier.sealed" and after_sealed)
        ):
            self.report(
                "interim_target",
                "$.body.last_seq",
                "an interim witness follows a config.changed, or a dossier.sealed if the "
                "mandate says so",
            )

    def _witness_common(self) -> bool:
        """Rules for both witness types. False if `last_seq` names no entry yet."""
        state, body = self.state, self.body
        doc = state.witness_mandate(self.draft).document
        key = doc["witness_key"]
        if self.draft["actor"]["id"] != key["identity"]:
            self.report(
                "witness_identity", "$.actor.id", "witnesses come from the witness identity"
            )
        if body["key_id"] != key["key_id"]:
            self.report(
                "witness_key_mismatch", "$.body.key_id", f"the mandate's key is {key['key_id']}"
            )
        listed = sorted(
            (a["authority"], a["jurisdiction"]) for a in body["time_attestation"]["authorities"]
        )
        expected = sorted((a["authority"], a["jurisdiction"]) for a in doc["authorities"]["list"])
        if listed != expected:
            self.report(
                "authorities_mismatch",
                "$.body.time_attestation.authorities",
                "every authority in the mandate is asked and listed, and no other",
            )
        if body["last_seq"] > len(state._entries):
            self.report("witness_ahead", "$.body.last_seq", "names an entry not yet committed")
            return False
        if state._entries[body["last_seq"] - 1].hash != body["last_hash"]:
            self.report(
                "witness_hash_mismatch", "$.body.last_hash", "not the hash of the entry at last_seq"
            )
        return True

    def _retention_expired(self) -> None:
        state, body = self.state, self.body
        limit = parse_date(body["min_until"])
        if limit >= self.now.date():
            self.report(
                "retention_not_passed",
                "$.body.min_until",
                "retention passes the day after min_until",
            )
        listed = set(body["dossiers"])
        for index, dossier_id in enumerate(body["dossiers"]):
            here = f"$.body.dossiers[{index}]"
            dossier = state._dossiers.get(dossier_id)
            if dossier is None:
                self.report("dossier_unknown", here, f"no dossier {dossier_id} was opened")
            elif dossier.expired:
                self.report("already_expired", here, f"{dossier_id} has already expired")
            elif not dossier.sealed:
                self.report("dossier_open", here, f"{dossier_id} is not sealed")
            else:
                if dossier.retention["class"] != body["class"]:
                    self.report(
                        "retention_class_mismatch",
                        here,
                        f"{dossier_id} is {dossier.retention['class']}",
                    )
                if parse_date(dossier.retention["min_until"]) > limit:
                    self.report(
                        "retention_not_passed",
                        here,
                        f"{dossier_id} is kept until {dossier.retention['min_until']}",
                    )
        for index, sha256 in enumerate(body["artefacts"]):
            here = f"$.body.artefacts[{index}]"
            referrers = state._referrers.get(sha256)
            if referrers is None:
                self.report("artefact_unknown", here, "no entry in this chain refers to it")
            elif None in referrers:
                self.report(
                    "artefact_chain_level",
                    here,
                    "a chain-level entry refers to it, so it is kept as long as the chain",
                )
            elif sha256 in state._expired_artefacts:
                self.report("already_expired", here, "already named in a retention.expired")
            else:
                live = sorted(
                    d for d in referrers if d not in listed and not state._dossiers[d].expired
                )
                if live:
                    self.report("artefact_live", here, f"still referred to by {', '.join(live)}")
