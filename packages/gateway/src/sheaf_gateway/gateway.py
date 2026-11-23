"""The gateway's pipeline (7.2), independent of the web framework.

1. Upload: check the declared artefact against the policy and its bytes against its kind, then
   store it.
2. Commit: parse the entry strictly, check it on its own, check the caller may write it, check
   it against the chain, and for a witness verify its signature and tokens.
3. Chain: holding the chain-head lease, link it to the head, record it in the write-ahead
   journal, write its entry blob, its segment record and any witness files, each once and each
   under its own retention, apply it to the chain state, keep its receipt for the caller's
   idempotency key, then clear the journal.
4. Return the receipt and publish a content-free event.

Receipts for idempotency keys are kept in `gateway-state` beside the journal, not in memory, so a
retry that arrives after a restart gets the first receipt rather than committing a second entry.

A mandate change is staged first, as a proposal (7.6), checked as its commit would be; its
`config.changed` is then accepted only as the approval of that pending proposal. Proposals are
the gateway's own state, like the journal, never the record. Status (7.7) reports how each chain
stands without a word of its content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from datetime import time as midnight
from typing import Any

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo, check_artefact
from sheaf_core.canonical import InvalidJSON, canonicalize, strict_loads
from sheaf_core.chain import entry_line, link_entry, segment_line
from sheaf_core.digest import is_artefact_digest
from sheaf_core.entry import WITNESS_TYPES, check_caller, check_draft
from sheaf_core.kinds import kind as registered_kind
from sheaf_core.mandate import SCHEMA_ID as MANDATE_SCHEMA
from sheaf_core.mandate import changed_parts, check_mandate, granted_types, part_digests, permits
from sheaf_core.problems import Problem
from sheaf_core.proposal import STAND_IN_APPROVER, STATUSES, approval_draft
from sheaf_core.rules import ChainState, Mandate, WitnessSeen
from sheaf_core.times import add_period, format_timestamp, parse_date, parse_timestamp
from sheaf_core.trust import check_trust_file
from sheaf_core.witness import check_attestation
from sheaf_gateway.hooks import NoEvents, Publisher
from sheaf_gateway.pseudonyms import Pseudonymiser
from sheaf_gateway.recovery import ChainCorrupt, replay
from sheaf_gateway.state import GatewayState, LeaseHeld, MemoryState
from sheaf_gateway.store import BlobConflict, Store

log = logging.getLogger("sheaf.gateway")

MAX_ENTRY_BYTES = 4 * 1024 * 1024
"""The largest entry body accepted. A retention.expired listing 10,000 dossiers and 10,000
artefacts is under 2 MiB."""

MAX_AUTHORITIES = 16
"""The most authorities a mandate may name (`sheaf.mandate/1`)."""
MAX_TOKEN_BYTES = 64 * 1024
MAX_WITNESS_BYTES = MAX_AUTHORITIES * 2 * MAX_TOKEN_BYTES + 64 * 1024
MANDATE_PART_KINDS = frozenset({"data.json", "text.markdown", "schema.json"})
"""What a mandate is made of (5.6). Whoever may stage a mandate change may upload these, so a
new mandate can be uploaded whatever the policy it replaces allows."""

PROPOSER_ROLE = "proposer"
"""The app role that may stage a mandate change, withdraw it, and read proposals (7.6)."""
STATUS_ROLE = "status"
"""The app role that may read `GET /v1/status`, and nothing else (7.7)."""
PROPOSAL_DAYS = 14
"""How long a proposal waits for its approver, unless it says otherwise."""
MAX_PROPOSAL_DAYS = 90
MAX_PROPOSAL_BYTES = 16 * 1024
MAX_REASON = 4096
"""As `reason` in `config.changed`."""
REFUSAL_CODES = (
    "proposal_not_pending",
    "not_a_person",
    "not_bootstrap",
    "mandate_pending",
    "not_an_approver",
    "four_eyes",
)
"""Why `GET /v1/proposals/{sha256}` says the caller may not approve, as codes a client can
explain without reading the sentence beside them."""
DAILY_GRACE = timedelta(hours=8)
"""How long after its day ends a daily witness is overdue: the witness job starts shortly after
midnight UTC and keeps asking unanswered authorities for six hours (7.2)."""


@dataclass(frozen=True)
class Settings:
    chain: str
    """`{tenant}/{workflow}`: the one chain this gateway writes."""
    bootstrap_caller: str
    """The identity that may write the genesis `config.changed`, and nothing after it: an Entra
    object ID, recorded through `identifiers` like any other person."""
    identifiers: str = "clear"
    """"clear" or "pseudonymised" (5.7), as every mandate on this chain must declare."""

    @property
    def tenant(self) -> str:
        return self.chain.split("/")[0]

    @property
    def workflow(self) -> str:
        return self.chain.split("/")[1]


class Rejected(Exception):
    def __init__(
        self, status: int, problems: list[Problem], headers: Mapping[str, str] | None = None
    ):
        super().__init__(f"{status}: {problems}")
        self.status = status
        self.problems = problems
        self.headers = dict(headers or {})


def _reject(status: int, code: str, path: str, detail: str) -> Rejected:
    return Rejected(status, [Problem(code, path, detail)])


def _receipt_name(scope: str, caller: str, key: str) -> str:
    """Where the receipt for a caller's idempotency key is kept: a digest, so neither the caller
    nor the key has to be a safe blob name. Uploads and entries keep their keys apart."""
    return hashlib.sha256(json.dumps([scope, caller, key]).encode()).hexdigest()


def _entry_receipt(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {k: entry[k] for k in ("seq", "hash", "committed_at")}


class Gateway:
    START_WAIT = 30.0
    """How long a request waits for its chain to start before it is refused with 503."""
    RETRY_AFTER = 5
    """The seconds a caller refused while the chain starts is told to wait."""
    STATUS_WAIT = 2.0
    """How long a status report waits for a write in progress before reading without it."""

    def __init__(
        self,
        settings: Settings,
        store: Store,
        *,
        events: Publisher | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        state: GatewayState | None = None,
        pseudonyms: Pseudonymiser | None = None,
    ):
        self.settings = settings
        self.store = store
        self.events = events or NoEvents()
        self.clock = clock
        self._own = state or MemoryState()
        """The lease and the journal (7.1). `recover` takes the lease."""
        self.state = ChainState(settings.chain)
        if settings.identifiers not in ("clear", "pseudonymised"):
            raise ValueError('identifiers are "clear" or "pseudonymised"')
        self.pseudonyms = pseudonyms
        if settings.identifiers == "pseudonymised":
            if pseudonyms is None:
                raise ValueError("pseudonymised identifiers need the pseudonym secrets")
            self._bootstrap = pseudonyms.pseudonym(settings.bootstrap_caller)
        else:
            self._bootstrap = settings.bootstrap_caller
        self._lock = threading.Lock()
        self._halted: str | None = None
        """Why the gateway stopped committing, after a write failed partway."""
        self._halt_code: str | None = None
        """`_halted` as a code, for status: it never carries a dossier's or a subject's id."""
        self._started_info: dict[str, Any] | None = None
        """When the chain last started and how long its rebuild took, for status."""
        self._started = threading.Event()
        self._started.set()
        """Cleared while the chain starts in the background (`Gateways.start`)."""
        self.start_wait = self.START_WAIT
        self._leased = False
        self._recovered = False
        self._stopping = threading.Event()
        """Set by `close` before it waits for the lock, so a rebuild in progress gives up."""

    # -- start ---------------------------------------------------------------------------------

    def recover(self) -> None:
        """Take the chain-head lease, rebuild the chain state from the container, and finish an
        entry a crash left half-written, from the journal. Refuses to start (ChainCorrupt) if the
        container does not hold an unbroken chain, and raises LeaseHeld while another gateway
        holds the lease. Called again after any other failure, it rebuilds from scratch. A
        gateway that stops meanwhile gives up, leaving the chain unstarted."""
        if not self._leased:
            self._own.acquire()
            with self._lock:
                if self._stopping.is_set():
                    # Stopped while waiting for the lease: give it straight back.
                    self._own.release()
                    self._give_up()
                    return
                self._leased = True
        with self._lock:
            began = time.monotonic()
            try:
                self._rebuild()
            except _Stopping:
                self._give_up()
                return
            self._recovered = True
            self._started_info = {
                "at": format_timestamp(datetime.now(UTC)),
                "seconds": round(time.monotonic() - began, 3),
            }

    def _give_up(self) -> None:
        """The gateway is stopping before the chain started: refuse everything from now on,
        before `close` takes the lock, and keep nothing of a rebuild left half done. The caller
        holds the lock."""
        self.state = ChainState(self.settings.chain)
        if self._halted is None:
            self._halt("stopping", "the gateway is stopping")

    def _halt(self, code: str, reason: str) -> None:
        self._halted, self._halt_code = reason, code

    def _rebuild(self) -> None:
        """Replay the container into a fresh chain state, then finish from the journal. The
        caller holds the lock."""
        self.state = ChainState(self.settings.chain)
        try:
            for entry in replay(self.store, self.settings.workflow):
                if self._stopping.is_set():
                    raise _Stopping
                self.state.apply(entry, artefacts=self.store)
        except ValueError as error:
            raise ChainCorrupt(str(error)) from error
        journal = self._own.read_journal()
        if journal is None:
            return
        record = json.loads(journal)
        entry = record["entry"]
        files = {
            path: (base64.b64decode(data), media_type)
            for path, (data, media_type) in record["files"].items()
        }
        head = self.state.head
        if entry["seq"] == (head[0] + 1 if head else 1):
            if entry["prev"] != (head[1] if head else None):
                raise ChainCorrupt(f"the journal's seq {entry['seq']} does not follow the head")
            log.warning("finishing seq %s from the journal", entry["seq"])
            self._write(entry, files)
            self._keep_receipt(record.get("receipt"), entry)
            self._mark_approved(record.get("proposal"), entry)
        elif head and entry["seq"] == head[0]:
            # Its segment record was written, so the replay holds it, but its witness files
            # or retention may not have been: write them again, without applying it twice.
            if entry["hash"] != head[1]:
                raise ChainCorrupt(f"the journal's seq {entry['seq']} differs from the chain")
            log.warning("finishing seq %s from the journal", entry["seq"])
            self._write(entry, files, apply=False)
            self._keep_receipt(record.get("receipt"), entry)
            self._mark_approved(record.get("proposal"), entry)
        elif entry["seq"] > (head[0] + 1 if head else 1):
            raise ChainCorrupt(f"the journal holds seq {entry['seq']}, past the head")
        self._own.clear_journal()

    def close(self) -> None:
        """Stop: refuse anything more, once any write in progress has finished or a rebuild in
        progress has given up, and release the chain-head lease, so a gateway replacing this one
        takes the chain at once rather than when the lease expires."""
        self._stopping.set()
        with self._lock:
            if self._halted is None:
                self._halt("stopping", "the gateway is stopping")
            if self._leased:
                self._leased = False
                self._own.release()

    @property
    def running(self) -> bool:
        return self._started.is_set() and self._halted is None and self._recovered

    # -- 1. upload ----------------------------------------------------------------------------

    def upload_limit(self, caller: str, kind: str, *, roles: Collection[str] = ()) -> int:
        """The most bytes `caller`, holding `roles`, may upload as `kind`. Raises Rejected if none
        at all."""
        self._check_running()
        registered = registered_kind(kind)
        if registered is None:
            raise _reject(422, "kind_unknown", "kind", f"{kind} is not registered")
        mandate = self.state.in_force
        if kind in MANDATE_PART_KINDS and self._may_stage(caller, roles):
            return registered["max_bytes"]
        if mandate is None:
            detail = "until genesis, only a mandate's parts are uploaded"
            raise _reject(403, "mandate_not_in_force", "kind", detail)
        if not any(granted_types(mandate.document, caller, role) for role in (None, *roles)):
            raise _reject(403, "caller_unknown", "$", f"{caller} is not in the policy")
        limits = mandate.document["policy"]["kinds"].get(kind)
        if limits is None:
            raise _reject(403, "kind_not_permitted", "kind", f"{kind} is not allowed here")
        return limits["max_bytes"]

    def upload(
        self,
        caller: str,
        data: bytes,
        *,
        sha256: str,
        kind: str,
        media_type: str,
        sensitivity: str,
        idempotency_key: str,
        roles: Collection[str] = (),
    ) -> tuple[dict[str, Any], bool]:
        """Check and store an artefact. Returns its receipt, and whether it was new."""
        self._check_running()
        if len(data) > self.upload_limit(caller, kind, roles=roles):
            raise _reject(413, "too_large", "bytes", f"over the limit for {kind}")
        mandate = self.state.in_force
        info, problems = check_artefact(
            data,
            sha256=sha256,
            kind=kind,
            media_type=media_type,
            sensitivity=sensitivity,
            schemas=mandate.schemas if mandate is not None else None,
        )
        if problems:
            raise Rejected(422, problems)
        assert info is not None
        with self._lock:
            name = _receipt_name("upload", caller, idempotency_key)
            earlier = self._recall(name)
            if earlier is not None and earlier["request"] != sha256:
                raise _reject(
                    409, "idempotency_conflict", "Idempotency-Key", "used for another artefact"
                )
            stored = self.store.info(sha256)
            if stored is not None and _receipt(stored) != _receipt(info):
                # Same bytes, declared differently: keep the first, never transform it.
                raise _reject(
                    409, "artefact_conflict", "$", f"already stored as {_receipt(stored)}"
                )
            created = self.store.put_artefact(info, data)
            if earlier is None:
                try:
                    self._remember(name, sha256, _receipt(info))
                except Exception as error:
                    # The artefact is stored; a retry with the same key and bytes completes.
                    log.exception("the receipt for an upload was not kept")
                    raise _reject(
                        503,
                        "state_unavailable",
                        "Idempotency-Key",
                        "the receipt was not kept; retry",
                    ) from error
        return _receipt(info), created

    # -- 2-4. commit --------------------------------------------------------------------------

    def commit(
        self,
        caller: str,
        raw: bytes,
        idempotency_key: str | None = None,
        *,
        roles: Collection[str] = (),
        person: bool | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Check, chain and store an entry. Returns its receipt, and whether it is new."""
        draft = _parse(raw)
        request = hashlib.sha256(raw).hexdigest()
        return self._commit(caller, roles, draft, request, idempotency_key, None, person)

    def commit_witness(
        self,
        caller: str,
        raw: bytes,
        idempotency_key: str | None = None,
        *,
        roles: Collection[str] = (),
    ) -> tuple[dict[str, Any], bool]:
        """Check a witness entry and its time-stamp tokens, chain it, and write the witness file
        and the tokens (7.2 step 5). The submission is `{"entry": ..., "tokens": {authority:
        base64 of the response exactly as received}}`."""
        submission = _parse(raw)
        if (
            not isinstance(submission, dict)
            or set(submission) != {"entry", "tokens"}
            or not isinstance(submission["tokens"], dict)
            or len(submission["tokens"]) > MAX_AUTHORITIES
        ):
            detail = f"a witness submission is {{entry, tokens}}, at most {MAX_AUTHORITIES} tokens"
            raise _reject(422, "submission_invalid", "$", detail)
        tokens = {}
        for name, text in submission["tokens"].items():
            try:
                if not isinstance(text, str) or len(text) > 2 * MAX_TOKEN_BYTES:
                    raise ValueError("not a base64 string of a token")
                tokens[name] = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError) as error:
                raise _reject(422, "token_encoding", f"$.tokens.{name}", str(error)) from error
        request = hashlib.sha256(raw).hexdigest()
        return self._commit(
            caller, roles, submission["entry"], request, idempotency_key, tokens, False
        )

    def _commit(
        self,
        caller: str,
        roles: Collection[str],
        draft: Any,
        request: str,
        idempotency_key: str | None,
        tokens: dict[str, bytes] | None,
        person: bool | None,
    ) -> tuple[dict[str, Any], bool]:
        self._check_running()
        with self._lock:
            if self._halted is not None:
                raise _reject(503, "gateway_halted", "$", self._halted)
            name = None
            if idempotency_key is not None:
                name = _receipt_name("entry", caller, idempotency_key)
                earlier = self._recall(name)
                if earlier is not None:
                    if earlier["request"] != request:
                        raise _reject(
                            409,
                            "idempotency_conflict",
                            "Idempotency-Key",
                            "used for another entry",
                        )
                    return earlier["receipt"], False

            problems = check_draft(draft)
            if problems:
                raise Rejected(422, problems)
            witness = draft["type"] in WITNESS_TYPES
            if witness and tokens is None:
                detail = "a witness is submitted with its tokens to /v1/witnesses"
                raise _reject(422, "witness_tokens_required", "$.type", detail)
            if tokens is not None and not witness:
                raise _reject(422, "not_a_witness", "$.type", "only witnesses are submitted here")
            problems = check_caller(draft, caller, roles, person=person)
            if problems:
                raise Rejected(403, problems)
            self._check_permitted(caller, draft)
            now = self.clock()
            approves = None
            if draft["type"] == "config.changed":
                approves = self._approving(draft, now)
            problems = self.state.check(draft, artefacts=self.store, now=now)
            if problems:
                raise Rejected(422, problems)
            if draft["type"] == "config.changed":
                declared = self.store.json(draft["body"]["mandate"])["personal_data"]["identifiers"]
                if declared != self.settings.identifiers:
                    detail = f"this gateway records identifiers {self.settings.identifiers}"
                    raise _reject(422, "identifiers_mismatch", "$.body.mandate", detail)
            files: dict[str, tuple[bytes, str]] = {}
            if witness:
                mandate = self.state.witness_mandate(draft)
                problems = check_attestation(
                    draft["body"],
                    mandate.document,
                    tokens=tokens,
                    trust=self.store.trust,
                    path="$.body",
                )
                if problems:
                    raise Rejected(422, problems)
                files = self._witness_files(draft["body"], tokens)

            remember = None if name is None else {"name": name, "request": request}
            entry = self._chain(draft, now, files, remember, approves)
            receipt = _entry_receipt(entry)

        event = {
            "tenant": self.settings.tenant,
            "workflow": self.settings.workflow,
            "seq": entry["seq"],
            "dossier": entry["dossier"],
            "type": entry["type"],
            "hash": entry["hash"],
        }
        try:
            self.events.publish(event)
        except Exception:
            # Events are hints (8): the entry is committed, and readers catch up from the chain.
            log.exception("event for seq %s not published", entry["seq"])
        return receipt, True

    def _witness_files(
        self, witness: dict[str, Any], tokens: dict[str, bytes]
    ) -> dict[str, tuple[bytes, str]]:
        """The witness file and each token, where section 4 files them."""
        workflow = self.settings.workflow
        if witness["witness"] == "daily":
            day = parse_timestamp(witness["interval"]["from"]).date()
            files = {
                paths.witness_daily(workflow, day): (canonicalize(witness), "application/json")
            }
            token_path = lambda name: paths.daily_token(workflow, day, name)  # noqa: E731
        else:
            seq = witness["last_seq"]
            files = {
                paths.witness_interim(workflow, seq): (canonicalize(witness), "application/json")
            }
            token_path = lambda name: paths.interim_token(workflow, seq, name)  # noqa: E731
        for name, data in tokens.items():
            files[token_path(name)] = (data, "application/timestamp-reply")
        return files

    # -- subject pseudonyms (5.7) ---------------------------------------------------------------

    def subject_pseudonym(
        self, caller: str, subject: Any, *, roles: Collection[str] = ()
    ) -> dict[str, str]:
        """The subject as entries must name it under a mandate that pseudonymises: its id
        replaced by its pseudonym. Only for a caller the mandate in force grants something."""
        self._check_running()
        if self.settings.identifiers != "pseudonymised" or self.pseudonyms is None:
            raise _reject(
                422, "not_pseudonymised", "$", "this gateway records identifiers in clear"
            )
        if (
            not isinstance(subject, dict)
            or set(subject) != {"system", "object", "id"}
            or not all(
                isinstance(v, str) and 0 < len(v) <= 256 and "\x00" not in v
                for v in subject.values()
            )
        ):
            raise _reject(422, "subject_invalid", "$", "a subject is {system, object, id}")
        mandate = self.state.in_force
        if mandate is None or not any(
            granted_types(mandate.document, caller, role) for role in (None, *roles)
        ):
            raise _reject(403, "caller_unknown", "$", f"{caller} is not in the policy in force")
        pseudonym = self.pseudonyms.subject(subject["system"], subject["object"], subject["id"])
        return {**subject, "id": pseudonym}

    # -- trust files ---------------------------------------------------------------------------

    def put_trust(
        self, caller: str, path: str, data: bytes, *, roles: Collection[str] = ()
    ) -> bool:
        """Store a witness key or a pinned authority certificate in `trust/`, once, before the
        mandate naming it is committed. Whoever may stage a mandate change may store these."""
        self._check_running()
        if not self._may_stage(caller, roles):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not stage a mandate change")
        problems = check_trust_file(path, data)
        if problems:
            raise Rejected(422, problems)
        media_type = "application/x-pem-file" if path.endswith(".pem") else "application/pkix-cert"
        with self._lock:
            try:
                return self.store.put_blob(path, data, media_type)
            except BlobConflict as error:
                raise _reject(
                    409, "trust_conflict", "path", "another file is stored there"
                ) from error

    # -- 7.6 proposals ---------------------------------------------------------------------------

    def _may_stage(self, caller: str, roles: Collection[str]) -> bool:
        """Whether `caller` may stage a mandate change, upload its parts and trust files, and
        read proposals: a proposer, or anyone who may change the mandate, which until the
        genesis mandate is in force is the bootstrap caller."""
        return (
            PROPOSER_ROLE in roles
            or self._may_write(caller, roles, "config.changed")
            or (self.state.in_force is None and caller == self._bootstrap)
        )

    def propose(
        self,
        caller: str,
        request: Any,
        *,
        roles: Collection[str] = (),
        person: bool | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Stage a mandate change: `{chain, mandate, reason, expires_in_days?}`, its parts and
        trust files already uploaded. It is checked against the chain as its `config.changed`
        would be, with a stand-in approver, and kept as a proposal. Returns the proposal, and
        whether it is new: staging the same one again returns it."""
        self._check_running()
        fields = _proposal_request(request)
        if fields["chain"] != self.settings.chain:
            detail = f"this gateway's chain here is {self.settings.chain}"
            raise _reject(422, "chain_unknown", "$.chain", detail)
        if not self._may_stage(caller, roles):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not propose a mandate change")
        sha256 = fields["mandate"]
        with self._lock:
            if self._halted is not None:
                raise _reject(503, "gateway_halted", "$", self._halted)
            now = self.clock()
            doc = self._proposed_mandate(sha256)
            current = self.state.in_force
            manifest = {
                "chain": self.settings.chain,
                "mandate": sha256,
                "version": doc["version"],
                "previous": None
                if current is None
                else {
                    "version": current.version,
                    "config": current.config,
                    "mandate": current.mandate,
                },
                "changed": changed_parts(None if current is None else current.document, doc),
                "parts": part_digests(doc),
                "artefacts": self._mandate_refs(sha256, doc),
                "proposed_by": {"kind": "person" if person else "system", "id": caller},
                "proposed_at": format_timestamp(now),
                "reason": fields["reason"],
                "expires_at": format_timestamp(now + timedelta(days=fields["expires_in_days"])),
                "status": "pending",
            }
            draft = approval_draft(manifest, approver=STAND_IN_APPROVER, observed_at=now)
            problems = self.state.check(draft, artefacts=self.store, now=now)
            if problems:
                raise Rejected(422, problems)
            earlier = self._proposal(sha256)
            if earlier is not None:
                status = self._status(earlier, now)
                same = (earlier["proposed_by"], earlier["reason"]) == (
                    manifest["proposed_by"],
                    manifest["reason"],
                )
                if status == "pending" and same:
                    return self._view(earlier, now), False
                # One approved in the past may be staged again, to return to it; not one that
                # is still the latest mandate change.
                latest = {m.mandate for m in (self.state.pending, self.state.in_force) if m}
                if status == "pending" or (status == "approved" and sha256 in latest):
                    detail = f"this mandate is already proposed, and {status}"
                    raise _reject(409, "proposal_exists", "$.mandate", detail)
            self._keep_proposal(manifest)
        log.info("%s: proposal %s staged by %s", self.settings.chain, sha256, caller)
        return self._view(manifest, now), True

    def proposals(
        self, caller: str, *, roles: Collection[str] = (), status: str | None = None
    ) -> list[dict[str, Any]]:
        """This chain's proposals, each with its status now, optionally only those `status`."""
        self._check_running()
        if not self._may_stage(caller, roles):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not read proposals")
        now = self.clock()
        views = [self._view(json.loads(data), now) for data in self._stored_proposals()]
        return [view for view in views if status is None or view["status"] == status]

    def proposal(
        self,
        caller: str,
        sha256: str,
        *,
        roles: Collection[str] = (),
        person: bool | None = None,
    ) -> dict[str, Any] | None:
        """A proposal, the mandate it proposes and the one it would replace, and whether
        `caller` may approve it; or None if this chain has no such proposal."""
        self._check_running()
        if not self._may_stage(caller, roles):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not read proposals")
        manifest = self._proposal(sha256)
        if manifest is None:
            return None
        view = self._view(manifest, self.clock())
        doc = self.store.json(sha256)
        previous = manifest["previous"]
        return {
            "proposal": view,
            "mandate": doc,
            "previous_mandate": None if previous is None else self.store.json(previous["mandate"]),
            "caller": self._approval(caller, roles, person, view, doc),
        }

    def withdraw(
        self,
        caller: str,
        sha256: str,
        *,
        roles: Collection[str] = (),
        person: bool | None = None,
    ) -> dict[str, Any] | None:
        """Withdraw a pending proposal: its proposer, or anyone who may approve it. None if this
        chain has no such proposal."""
        self._check_running()
        if not self._may_stage(caller, roles):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not read proposals")
        with self._lock:
            manifest = self._proposal(sha256)
            if manifest is None:
                return None
            now = self.clock()
            status = self._status(manifest, now)
            if status != "pending":
                raise _reject(409, "proposal_not_pending", "$", f"the proposal is {status}")
            mine = manifest["proposed_by"]["id"] == caller
            if not (mine or self._may_write(caller, roles, "config.changed")):
                detail = "a proposal is withdrawn by its proposer or by an approver"
                raise _reject(403, "caller_unknown", "$", detail)
            manifest = {
                **manifest,
                "status": "withdrawn",
                "withdrawn_by": {"kind": "person" if person else "system", "id": caller},
                "withdrawn_at": format_timestamp(now),
            }
            self._keep_proposal(manifest)
        log.info("%s: proposal %s withdrawn by %s", self.settings.chain, sha256, caller)
        return self._view(manifest, now)

    def _proposed_mandate(self, sha256: str) -> dict[str, Any]:
        """The mandate a proposal names, uploaded and valid. Raises Rejected otherwise."""
        info = self.store.info(sha256)
        if info is None:
            raise _reject(422, "artefact_unknown", "$.mandate", "upload the mandate first")
        if info.kind != "data.json" or info.declared_schema != MANDATE_SCHEMA:
            detail = f"a mandate is a data.json declaring {MANDATE_SCHEMA}"
            raise _reject(422, "mandate_schema", "$.mandate", detail)
        doc = self.store.json(sha256)
        problems = check_mandate(doc, "$.mandate")
        if problems:
            raise Rejected(422, problems)
        if doc["chain"] != self.settings.chain:
            raise _reject(422, "mandate_chain", "$.mandate", f"the mandate is for {doc['chain']}")
        if doc["personal_data"]["identifiers"] != self.settings.identifiers:
            detail = f"this gateway records identifiers {self.settings.identifiers}"
            raise _reject(422, "identifiers_mismatch", "$.mandate", detail)
        return doc

    def _mandate_refs(self, sha256: str, doc: Mapping[str, Any]) -> list[dict[str, Any]]:
        """The artefact references a mandate's `config.changed` attaches (5.6): the mandate,
        then its instructions, then its schemas, as uploaded."""
        named = [("mandate", sha256)]
        named += [("instructions", item["sha256"]) for item in doc["instructions"]]
        named += [("schema", item["sha256"]) for item in doc["schemas"]]
        refs, problems = [], []
        for role, digest in dict.fromkeys(named):
            info = self.store.info(digest)
            if info is None:
                problems.append(
                    Problem("artefact_unknown", f"$.{role}", f"{digest} is not uploaded")
                )
                continue
            refs.append({"role": role, **_receipt(info)})
        if problems:
            raise Rejected(422, problems)
        return refs

    def _approving(self, draft: Mapping[str, Any], now: datetime) -> str:
        """The proposal a `config.changed` approves: pending, and exactly what its approval is.
        Raises Rejected otherwise. The caller holds the lock."""
        sha256 = draft["body"]["mandate"]
        manifest = self._proposal(sha256)
        if manifest is None:
            detail = "a mandate change is committed only as the approval of a staged proposal"
            raise _reject(403, "proposal_required", "$.body.mandate", detail)
        status = self._status(manifest, now)
        if status != "pending":
            raise _reject(
                409, "proposal_not_pending", "$.body.mandate", f"the proposal is {status}"
            )
        expected = approval_draft(
            manifest,
            approver=draft["actor"]["id"],
            role=draft["actor"].get("role"),
            observed_at=now,
        )
        differ = [k for k in sorted(set(draft) | set(expected)) if draft.get(k) != expected.get(k)]
        differ = [k for k in differ if k not in ("observed_at", "body")]
        body, wanted = draft["body"], expected["body"]
        differ += [
            f"body.{k}" for k in sorted(set(body) | set(wanted)) if body.get(k) != wanted.get(k)
        ]
        if differ:
            detail = f"not the proposal's approval: it differs in {', '.join(differ)}"
            raise _reject(422, "proposal_mismatch", "$", detail)
        return sha256

    def _approval(
        self,
        caller: str,
        roles: Collection[str],
        person: bool | None,
        view: Mapping[str, Any],
        doc: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Whether `caller` may approve the proposal now, and under which role; or why not."""
        found: dict[str, Any] = {
            "id": caller,
            "may_approve": False,
            "role": None,
            "refusal": None,
            "refusal_code": None,
        }

        def refuse(code: str, detail: str) -> None:
            found.update(refusal=detail, refusal_code=code)

        role = None
        if view["status"] != "pending":
            refuse("proposal_not_pending", f"the proposal is {view['status']}")
        elif person is False:
            refuse("not_a_person", "an approver signs in as a person, with their own account")
        elif self.state.head is None:
            governing = doc
            if caller != self._bootstrap:
                refuse("not_bootstrap", "only the gateway's bootstrap caller approves a genesis")
        elif (mandate := self.state.governing()) is None:
            refuse("mandate_pending", "the last mandate change is waiting for its interim witness")
        else:
            governing = mandate.document
            if "config.changed" not in (granted_types(governing, caller) or ()):
                role = next(
                    (
                        r
                        for r in sorted(roles)
                        if "config.changed" in (granted_types(governing, None, r) or ())
                    ),
                    None,
                )
                if role is None:
                    refuse("not_an_approver", "the mandate in force does not let you change it")
        if found["refusal"] is None:
            if governing["policy"]["four_eyes"] and view["proposed_by"]["id"] == caller:
                refuse(
                    "four_eyes",
                    "you proposed this change, and the mandate asks for four eyes: "
                    "someone else approves it",
                )
            else:
                found.update(may_approve=True, role=role)
        return found

    def _status(self, manifest: Mapping[str, Any], now: datetime) -> str:
        """A proposal's status now (`sheaf_core.proposal.STATUSES`)."""
        if manifest["status"] in ("approved", "withdrawn"):
            return manifest["status"]
        state = self.state
        if any(
            m is not None and m.mandate == manifest["mandate"]
            for m in (state.pending, state.in_force)
        ):
            return "approved"
        if now >= parse_timestamp(manifest["expires_at"]):
            return "expired"
        latest = state.pending or state.in_force
        previous = manifest["previous"]
        if (latest and latest.config) != (previous and previous["config"]):
            return "superseded"
        return "pending"

    def _view(self, manifest: Mapping[str, Any], now: datetime) -> dict[str, Any]:
        return {**manifest, "status": self._status(manifest, now)}

    def _mark_approved(self, sha256: str | None, entry: Mapping[str, Any]) -> None:
        """Note on the proposal a `config.changed` approved which entry approved it. Part of the
        entry's journalled writes."""
        if sha256 is None:
            return
        manifest = self._proposal(sha256)
        if manifest is None or manifest.get("approved", {}).get("hash") == entry["hash"]:
            return
        approved = {
            "seq": entry["seq"],
            "hash": entry["hash"],
            "committed_at": entry["committed_at"],
            "by": entry["body"]["approved_by"],
        }
        self._keep_proposal({**manifest, "status": "approved", "approved": approved})

    def _proposal(self, sha256: str) -> dict[str, Any] | None:
        try:
            data = self._own.read_proposal(sha256)
        except Exception as error:
            log.exception("a proposal could not be read")
            raise _reject(503, "state_unavailable", "$", "the proposals cannot be read") from error
        return None if data is None else json.loads(data)

    def _stored_proposals(self) -> list[bytes]:
        try:
            return self._own.list_proposals()
        except Exception as error:
            log.exception("the proposals could not be listed")
            raise _reject(503, "state_unavailable", "$", "the proposals cannot be read") from error

    def _keep_proposal(self, manifest: Mapping[str, Any]) -> None:
        try:
            self._own.write_proposal(manifest["mandate"], json.dumps(manifest).encode())
        except Exception as error:
            log.exception("a proposal could not be kept")
            raise _reject(503, "state_unavailable", "$", "the proposal was not kept") from error

    # -- 7.7 status ------------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """How this chain stands: counts, sequence numbers, times, fingerprints, versions and
        codes, never an entry's content nor a dossier's or a subject's identifier."""
        state = "running" if self.running else "starting"
        if self._halted is not None:
            state = "halted"
        report: dict[str, Any] = {
            "chain": self.settings.chain,
            "state": state,
            "halted": None if self._halt_code is None else {"code": self._halt_code},
            "started": self._started_info,
            "lease_held": self._leased and self._own.held(),
            "head": None,
            "mandate": None,
            "witness": None,
        }
        if state != "running":
            return report
        now = self.clock()
        # A snapshot between commits, so the head, its time and the witnesses agree; waiting a
        # little at most, since a status reader must never hang behind a slow write.
        locked = self._lock.acquire(timeout=self.STATUS_WAIT)
        try:
            chain = self.state
            head, head_at = chain.head, chain.head_at
            in_force, pending_mandate = chain.in_force, chain.pending
            daily = chain.last_witness("witness.daily")
            interim = chain.last_witness("witness.interim")
            start, genesis_at = chain.last_daily_end, chain.genesis_at
        finally:
            if locked:
                self._lock.release()
        if head is not None:
            report["head"] = {"seq": head[0], "committed_at": format_timestamp(head_at)}
        try:
            pending = sum(
                1
                for data in self._own.list_proposals()
                if self._status(json.loads(data), now) == "pending"
            )
        except Exception:
            log.exception("the proposals could not be counted")
            pending = None
        report["mandate"] = {
            "in_force": _mandate_status(in_force),
            "pending": _mandate_status(pending_mandate),
            "proposals_pending": pending,
        }
        if start is None and genesis_at is not None:
            start = datetime.combine(genesis_at.date(), midnight(0), UTC)
        due = None if start is None else start + timedelta(days=1) + DAILY_GRACE
        report["witness"] = {
            "daily": _witness_status(daily),
            "interim": _witness_status(interim),
            "daily_due_by": None if due is None else format_timestamp(due),
            "daily_overdue": due is not None and now > due,
        }
        return report

    def _check_running(self) -> None:
        """A chain serves nothing until it has started: a request waits a little for it, and is
        then refused and told when to try again. A halted chain's state is not trusted for
        anything until the gateway restarts."""
        started = self._started.wait(self.start_wait)
        if started and self._halted is not None:
            raise _reject(503, "gateway_halted", "$", self._halted)
        if not started or not self._recovered:
            # Only a chain rebuilt in full is served: never one whose rebuild gave up or failed.
            detail = "the gateway is starting: taking the chain-head lease and rebuilding the chain"
            raise Rejected(
                503,
                [Problem("gateway_starting", "$", detail)],
                {"Retry-After": str(self.RETRY_AFTER)},
            )

    def _may_write(self, caller: str, roles: Collection[str], entry_type: str) -> bool:
        if self.state.head is None:
            return caller == self._bootstrap and entry_type == "config.changed"
        mandate = self.state.governing()
        if mandate is None:
            return False
        return any(
            entry_type in (granted_types(mandate.document, caller, role) or ())
            for role in (None, *roles)
        )

    def _check_permitted(self, caller: str, draft: dict[str, Any]) -> None:
        if self.state.head is None:
            if not self._may_write(caller, (), draft["type"]):
                raise _reject(
                    403,
                    "caller_unknown",
                    "$",
                    "only the bootstrap caller writes the genesis config.changed",
                )
            return
        if draft["type"] in WITNESS_TYPES:
            mandate = self.state.witness_mandate(draft)
        else:
            mandate = self.state.governing()
        if mandate is None:
            # The genesis mandate is waiting for its interim witness: no policy is in force yet.
            if caller != self._bootstrap:
                raise _reject(403, "caller_unknown", "$", "no mandate is in force yet")
            return
        problems = permits(mandate.document, caller, draft)
        if problems:
            raise Rejected(403, problems)

    def _chain(
        self,
        draft: dict[str, Any],
        now: datetime,
        files: dict[str, tuple[bytes, str]],
        remember: dict[str, str] | None = None,
        approves: str | None = None,
    ) -> dict[str, Any]:
        """Link the entry to the head, journal it, write it, keep its receipt for the
        idempotency key in `remember`, and mark the proposal it `approves` approved. The caller
        holds the lock."""
        if not self._own.held():
            self._halt(
                "lease_lost", "the chain-head lease was lost; another gateway may be writing"
            )
            raise _reject(503, "lease_lost", "$", self._halted)
        head = self.state.head
        entry = link_entry(
            draft,
            seq=head[0] + 1 if head else 1,
            prev=head[1] if head else None,
            committed_at=format_timestamp(now),
        )
        journal = json.dumps(
            {
                "entry": entry,
                "files": {
                    path: [base64.b64encode(data).decode(), media_type]
                    for path, (data, media_type) in files.items()
                },
                "receipt": remember,
                "proposal": approves,
            }
        ).encode()
        # A write that fails partway stops the gateway: committing again would reuse this seq
        # and fork the record. On restart, `recover` finishes the entry from the journal.
        try:
            self._own.write_journal(journal)
            self._write(entry, files)
            self._keep_receipt(remember, entry)
            self._mark_approved(approves, entry)
            self._own.clear_journal()
        except Exception as error:
            self._halt(
                "write_failed", f"a write failed at seq {entry['seq']}; restart to finish it"
            )
            log.exception("halted: write failed at seq %s", entry["seq"])
            raise _reject(503, "write_failed", "$", self._halted) from error
        return entry

    # -- idempotency receipts (7.2 steps 1 and 2) -------------------------------------------------

    def _recall(self, name: str) -> dict[str, Any] | None:
        """The receipt kept for an idempotency key, or None. Raises Rejected (503) if the
        receipts cannot be read: going on could commit a retry a second time."""
        try:
            data = self._own.read_receipt(name)
        except Exception as error:
            log.exception("the idempotency receipts could not be read")
            raise _reject(
                503, "state_unavailable", "Idempotency-Key", "the receipts cannot be read; retry"
            ) from error
        return None if data is None else json.loads(data)

    def _remember(self, name: str, request: str, receipt: dict[str, Any]) -> None:
        data = json.dumps({"request": request, "receipt": receipt}, sort_keys=True).encode()
        self._own.write_receipt(name, data)

    def _keep_receipt(self, remember: dict[str, str] | None, entry: dict[str, Any]) -> None:
        """Keep a committed entry's receipt, if it was submitted with an idempotency key. This is
        part of the entry's journalled writes, so a crash before it is finished on restart."""
        if remember is not None:
            self._remember(remember["name"], remember["request"], _entry_receipt(entry))

    def _write(
        self,
        entry: dict[str, Any],
        files: dict[str, tuple[bytes, str]],
        *,
        apply: bool = True,
    ) -> None:
        """Write the entry's blob, then its segment record, then any witness files, each once and
        with its retention; then apply it, unless the replay already has. Every write is of fixed
        bytes to a fixed path, so finishing a half-written entry from the journal repeats them
        harmlessly."""
        committed = parse_timestamp(entry["committed_at"])
        workflow, dossier_id = self.settings.workflow, entry["dossier"]
        chain_until = self._chain_until(entry, committed)
        if dossier_id is None:
            folder, until = paths.chain_dossier(workflow, committed), chain_until
        else:
            opened = self.state.opened_at(dossier_id) or committed
            folder = paths.dossier(workflow, opened, dossier_id)
            until = parse_date(entry["retention"]["min_until"])
        segment = paths.entry(paths.chain_segment(workflow, committed), entry["seq"])
        writes = [
            (paths.entry(folder, entry["seq"]), entry_line(entry), "application/json", until),
            (segment, segment_line(entry), "application/json", chain_until),
            *((path, data, media, chain_until) for path, (data, media) in files.items()),
        ]
        for path, data, media_type, keep in writes:
            self.store.put_blob(path, data, media_type)
            self.store.retain(path, keep)
        for ref in entry["artefacts"]:
            self.store.retain(paths.artefact(ref["sha256"]), until)
        if entry["type"] == "config.changed":
            for path in _trust_paths(self.store.json(entry["body"]["mandate"])):
                self.store.retain(path, chain_until)
        if apply:
            self.state.apply(entry, artefacts=self.store)

    def _chain_until(self, entry: dict[str, Any], committed: datetime) -> date:
        """How long chain-level blobs written now are kept: the longest retention class of the
        mandate in force (of the new one, for a config.changed), from the day written."""
        if entry["type"] == "config.changed":
            mandate = self.store.json(entry["body"]["mandate"])
        else:
            governing = self.state.governing() or self.state.pending
            if governing is None:
                raise ValueError("no mandate says how long the chain is kept")
            mandate = governing.document
        day = committed.date()
        return max(add_period(day, c["period"]) for c in mandate["retention"]["classes"])


class Gateways:
    """One tenant's gateway (7.1): a `Gateway` for each of its chains, one per workflow, sharing
    the store. A request reaches the chain it names, and a fault halts only that chain."""

    RETRY = 5.0
    """Seconds between attempts to start a chain that could not start yet."""

    def __init__(self, gateways: Iterable[Gateway]) -> None:
        self.retry = self.RETRY
        self._closing = threading.Event()
        self._by_chain: dict[str, Gateway] = {}
        for gateway in gateways:
            if gateway.settings.chain in self._by_chain:
                raise ValueError(f"{gateway.settings.chain} is served twice")
            self._by_chain[gateway.settings.chain] = gateway
        if not self._by_chain:
            raise ValueError("a gateway serves at least one chain")
        if len({gateway.settings.tenant for gateway in self._by_chain.values()}) != 1:
            raise ValueError("a gateway serves one tenant's chains")
        self._started_at = format_timestamp(datetime.now(UTC))

    @property
    def chains(self) -> tuple[str, ...]:
        return tuple(self._by_chain)

    def recover(self) -> None:
        """Recover each chain now. One that does not add up is halted, holding its lease so
        nothing else writes to it, and the others carry on."""
        for chain, gateway in self._by_chain.items():
            try:
                gateway.recover()
            except ChainCorrupt as error:
                _halt(chain, gateway, error)

    def start(self) -> None:
        """Recover each chain in the background, so the gateway answers at once. A gateway
        replacing another starts beside it: it cannot take a chain's lease until the other one
        stops, and the other one does not stop until this one answers. Until a chain has
        started, a request for it waits a little and is then refused with 503."""
        for chain, gateway in self._by_chain.items():
            if gateway._recovered or gateway._halted is not None:
                continue
            gateway._started.clear()
            threading.Thread(
                target=self._start, args=(chain, gateway), daemon=True, name=f"start {chain}"
            ).start()

    def _start(self, chain: str, gateway: Gateway) -> None:
        began = time.monotonic()
        try:
            while not self._closing.is_set():
                try:
                    gateway.recover()
                except LeaseHeld:
                    log.info("%s: another gateway still holds the chain-head lease", chain)
                except ChainCorrupt as error:
                    _halt(chain, gateway, error)
                    return
                except Exception:
                    log.exception("%s did not start; trying again", chain)
                else:
                    if gateway._recovered:
                        head = gateway.state.head
                        took = time.monotonic() - began
                        log.info("%s started at seq %s in %.1fs", chain, head and head[0], took)
                    else:
                        log.info("%s: stopped before it started", chain)
                    return
                self._closing.wait(self.retry)
        finally:
            gateway._started.set()

    def wait_started(self, timeout: float | None = None) -> bool:
        """Wait until no chain is still starting. False if one still is after `timeout`."""
        deadline = None if timeout is None else time.monotonic() + timeout
        for gateway in self._by_chain.values():
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            if not gateway._started.wait(left):
                return False
        return True

    def close(self) -> None:
        """Stop every chain and release its lease (`Gateway.close`)."""
        self._closing.set()
        for gateway in self._by_chain.values():
            gateway._stopping.set()  # every rebuild gives up now, not when its turn comes
        for chain, gateway in self._by_chain.items():
            try:
                gateway.close()
            except Exception:
                log.exception("%s: the chain-head lease was not released", chain)

    def chain(self, chain: Any) -> Gateway:
        gateway = self._by_chain.get(chain) if isinstance(chain, str) else None
        if gateway is None:
            raise _reject(
                422, "chain_unknown", "$.chain", f"this gateway does not serve {str(chain)[:100]}"
            )
        return gateway

    def upload_limit(
        self, caller: str, kind: str, *, chain: str, roles: Collection[str] = ()
    ) -> int:
        return self.chain(chain).upload_limit(caller, kind, roles=roles)

    def upload(
        self, caller: str, data: bytes, *, chain: str, **declared: Any
    ) -> tuple[dict[str, Any], bool]:
        return self.chain(chain).upload(caller, data, **declared)

    def commit(
        self,
        caller: str,
        raw: bytes,
        idempotency_key: str | None = None,
        *,
        roles: Collection[str] = (),
        person: bool | None = None,
    ) -> tuple[dict[str, Any], bool]:
        draft = _parse(raw)
        gateway = self._for(draft.get("chain") if isinstance(draft, dict) else None)
        return gateway.commit(caller, raw, idempotency_key, roles=roles, person=person)

    def commit_witness(
        self,
        caller: str,
        raw: bytes,
        idempotency_key: str | None = None,
        *,
        roles: Collection[str] = (),
    ) -> tuple[dict[str, Any], bool]:
        submission = _parse(raw)
        entry = submission.get("entry") if isinstance(submission, dict) else None
        gateway = self._for(entry.get("chain") if isinstance(entry, dict) else None)
        return gateway.commit_witness(caller, raw, idempotency_key, roles=roles)

    def _for(self, chain: Any) -> Gateway:
        """The gateway for a request's `chain`. A request with no usable chain goes to the first,
        whose own checks say exactly what is wrong with it and refuse it."""
        if isinstance(chain, str):
            return self.chain(chain)
        return next(iter(self._by_chain.values()))

    def put_trust(
        self, caller: str, path: str, data: bytes, *, roles: Collection[str] = ()
    ) -> bool:
        """Trust files are the tenant's, not a chain's: whoever may change any running chain's
        mandate may store them. Each is written once and pinned by its SHA-256 in the mandate
        that names it, so a wrong file is never trusted: the mandate naming it is refused."""
        running = [g for g in self._by_chain.values() if g.running]
        permitted = [g for g in running if g._may_stage(caller, roles)]
        chosen = (permitted or running or list(self._by_chain.values()))[0]
        return chosen.put_trust(caller, path, data, roles=roles)

    # -- 7.6 proposals, across the tenant's chains -----------------------------------------------

    def propose(
        self, caller: str, raw: bytes, *, roles: Collection[str] = (), person: bool | None = None
    ) -> tuple[dict[str, Any], bool]:
        request = _parse(raw)
        gateway = self._for(request.get("chain") if isinstance(request, dict) else None)
        return gateway.propose(caller, request, roles=roles, person=person)

    def proposals(
        self,
        caller: str,
        *,
        chain: str | None = None,
        status: str | None = None,
        roles: Collection[str] = (),
    ) -> list[dict[str, Any]]:
        """The proposals of every running chain the caller may read, or of `chain` alone. Which
        chains could not be read is `unavailable()`."""
        if status is not None and status not in STATUSES:
            detail = f"a status is one of {', '.join(STATUSES)}"
            raise _reject(422, "proposal_invalid", "status", detail)
        chosen = [self.chain(chain)] if chain is not None else self._running()
        found, readable, refused = [], 0, None
        for gateway in chosen:
            try:
                found += gateway.proposals(caller, roles=roles, status=status)
                readable += 1
            except Rejected as error:
                if error.status != 403:
                    raise
                refused = error
        if not readable and refused is not None:
            raise refused
        return found

    def proposal(
        self, caller: str, sha256: str, *, roles: Collection[str] = (), person: bool | None = None
    ) -> dict[str, Any]:
        _check_digest(sha256)
        refused = None
        for gateway in self._running():
            try:
                found = gateway.proposal(caller, sha256, roles=roles, person=person)
            except Rejected as error:
                if error.status != 403:
                    raise
                refused = error
                continue
            if found is not None:
                return found
        self._check_all_running()
        readable = [g for g in self._running() if g._may_stage(caller, roles)]
        if not readable and refused is not None:
            raise refused
        raise _reject(404, "proposal_unknown", "$", "no chain this gateway serves has it")

    def withdraw(
        self, caller: str, sha256: str, *, roles: Collection[str] = (), person: bool | None = None
    ) -> dict[str, Any]:
        _check_digest(sha256)
        readable = [g for g in self._running() if g._may_stage(caller, roles)]
        for gateway in readable:
            found = gateway.withdraw(caller, sha256, roles=roles, person=person)
            if found is not None:
                return found
        self._check_all_running()
        if not readable:
            raise _reject(403, "caller_unknown", "$", f"{caller} may not read proposals")
        raise _reject(404, "proposal_unknown", "$", "no chain this gateway serves has it")

    def _running(self) -> list[Gateway]:
        return [g for g in self._by_chain.values() if g.running]

    def unavailable(self) -> list[str]:
        """The chains not serving now: still starting, or halted."""
        return [chain for chain, g in self._by_chain.items() if not g.running]

    def _check_all_running(self) -> None:
        """Before saying a proposal is not there: refuse with 503, as the chain itself would,
        while a chain that may hold it is starting or halted, so a proposal on it is never
        reported unknown."""
        stopped = [g for g in self._by_chain.values() if not g.running]
        if any(g._halted is None for g in stopped):
            detail = "a chain that may hold it is starting"
            raise Rejected(
                503,
                [Problem("gateway_starting", "$", detail)],
                {"Retry-After": str(Gateway.RETRY_AFTER)},
            )
        if stopped:
            raise _reject(503, "gateway_halted", "$", "a chain that may hold it is halted")

    # -- 7.7 status --------------------------------------------------------------------------------

    def status(self, caller: str, *, roles: Collection[str] = ()) -> dict[str, Any]:
        """How each chain stands, for the `status` role, a proposer, or anyone who may change a
        running chain's mandate."""
        # Roles first: status matters most when no chain is running to say who may change it.
        may = (
            STATUS_ROLE in roles
            or PROPOSER_ROLE in roles
            or any(g._may_stage(caller, roles) for g in self._running())
        )
        if not may:
            raise _reject(403, "caller_unknown", "$", "reading status needs the status role")
        store = next(iter(self._by_chain.values())).store
        return {
            "gateway": {"started_at": self._started_at},
            "storage": {"immutability": getattr(store, "immutability", None)},
            "chains": [gateway.status() for gateway in self._by_chain.values()],
        }

    def subject_pseudonym(
        self, caller: str, subject: Any, *, roles: Collection[str] = ()
    ) -> dict[str, str]:
        """For a caller that any chain's mandate in force grants something."""
        refused: Rejected | None = None
        running = [g for g in self._by_chain.values() if g.running]
        for gateway in running or list(self._by_chain.values()):
            try:
                return gateway.subject_pseudonym(caller, subject, roles=roles)
            except Rejected as error:
                if error.status != 403:
                    raise
                refused = error
        assert refused is not None
        raise refused


class _Stopping(Exception):
    """The gateway is stopping: a rebuild in progress gives up."""


def _halt(chain: str, gateway: Gateway, error: ChainCorrupt) -> None:
    log.critical("halted %s: the stored chain does not add up: %s", chain, error)
    gateway._halt("chain_corrupt", f"the stored chain does not add up: {error}")


def _trust_paths(mandate: dict[str, Any]) -> list[str]:
    found = [paths.witness_key(mandate["witness_key"]["key_id"])]
    for listed in mandate["authorities"]["list"]:
        found += [paths.tsa_certificate(listed["authority"], sha) for sha in listed["roots"]]
    return found


def _parse(raw: bytes) -> Any:
    try:
        return strict_loads(raw)
    except InvalidJSON as error:
        raise _reject(422, "invalid_json", "$", str(error)) from error


def _receipt(info: ArtefactInfo) -> dict[str, Any]:
    return {
        "sha256": info.sha256,
        "kind": info.kind,
        "media_type": info.media_type,
        "bytes": info.bytes,
        "sensitivity": info.sensitivity,
    }


def _proposal_request(request: Any) -> dict[str, Any]:
    """A proposal as staged: `{chain, mandate, reason, expires_in_days?}`."""
    required, allowed = (
        {"chain", "mandate", "reason"},
        {"chain", "mandate", "reason", "expires_in_days"},
    )
    if not isinstance(request, dict) or not required <= set(request) or set(request) - allowed:
        detail = "a proposal is {chain, mandate, reason}, and optionally expires_in_days"
        raise _reject(422, "proposal_invalid", "$", detail)
    if not is_artefact_digest(request["mandate"]):
        raise _reject(422, "proposal_invalid", "$.mandate", "the mandate's SHA-256, 64 hex digits")
    reason = request["reason"]
    if not isinstance(reason, str) or not 0 < len(reason) <= MAX_REASON:
        raise _reject(422, "proposal_invalid", "$.reason", f"a sentence, at most {MAX_REASON} long")
    days = request.get("expires_in_days", PROPOSAL_DAYS)
    if type(days) is not int or not 1 <= days <= MAX_PROPOSAL_DAYS:
        detail = f"whole days, from 1 to {MAX_PROPOSAL_DAYS}"
        raise _reject(422, "proposal_invalid", "$.expires_in_days", detail)
    return {
        "chain": request["chain"],
        "mandate": request["mandate"],
        "reason": reason,
        "expires_in_days": days,
    }


def _check_digest(sha256: str) -> None:
    if not is_artefact_digest(sha256):
        raise _reject(422, "sha256_format", "sha256", "64 lower-case hex digits")


def _mandate_status(mandate: Mandate | None) -> dict[str, Any] | None:
    if mandate is None:
        return None
    return {
        "version": mandate.version,
        "fingerprint": mandate.mandate,
        "config": mandate.config,
        "seq": mandate.seq,
        "committed_at": mandate.committed_at,
        "approved_by": mandate.approved_by,
    }


def _witness_status(seen: WitnessSeen | None) -> dict[str, Any] | None:
    if seen is None:
        return None
    return {
        "seq": seen.seq,
        "committed_at": seen.committed_at,
        "last_seq": seen.last_seq,
        "interval_to": seen.interval_to,
        "attested": list(seen.attested),
    }
