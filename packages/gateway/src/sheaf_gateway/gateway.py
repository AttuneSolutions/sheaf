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
from datetime import UTC, date, datetime
from typing import Any

from sheaf_core import paths
from sheaf_core.artefact import ArtefactInfo, check_artefact
from sheaf_core.canonical import InvalidJSON, canonicalize, strict_loads
from sheaf_core.chain import entry_line, link_entry, segment_line
from sheaf_core.entry import WITNESS_TYPES, check_caller, check_draft
from sheaf_core.kinds import kind as registered_kind
from sheaf_core.mandate import granted_types, permits
from sheaf_core.problems import Problem
from sheaf_core.rules import ChainState
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
"""What a mandate is made of (5.6). Whoever may write `config.changed` may upload these, so a
new mandate can be uploaded whatever the policy it replaces allows."""


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
                    return
                self._leased = True
        with self._lock:
            try:
                self._rebuild()
            except _Stopping:
                return
            self._recovered = True

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
        elif head and entry["seq"] == head[0]:
            # Its segment record was written, so the replay holds it, but its witness files
            # or retention may not have been: write them again, without applying it twice.
            if entry["hash"] != head[1]:
                raise ChainCorrupt(f"the journal's seq {entry['seq']} differs from the chain")
            log.warning("finishing seq %s from the journal", entry["seq"])
            self._write(entry, files, apply=False)
            self._keep_receipt(record.get("receipt"), entry)
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
                self._halted = "the gateway is stopping"
            if self._leased:
                self._leased = False
                self._own.release()

    @property
    def running(self) -> bool:
        return self._started.is_set() and self._halted is None

    # -- 1. upload ----------------------------------------------------------------------------

    def upload_limit(self, caller: str, kind: str, *, roles: Collection[str] = ()) -> int:
        """The most bytes `caller`, holding `roles`, may upload as `kind`. Raises Rejected if none
        at all."""
        self._check_running()
        registered = registered_kind(kind)
        if registered is None:
            raise _reject(422, "kind_unknown", "kind", f"{kind} is not registered")
        mandate = self.state.in_force
        if kind in MANDATE_PART_KINDS and self._may_write(caller, roles, "config.changed"):
            return registered["max_bytes"]
        if mandate is None:
            raise _reject(
                403, "mandate_not_in_force", "kind", "until genesis, only the mandate is uploaded"
            )
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
            entry = self._chain(draft, now, files, remember)
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
        mandate naming it is committed. Whoever may write `config.changed` may store these."""
        self._check_running()
        if not self._may_write(caller, roles, "config.changed"):
            raise _reject(403, "caller_unknown", "$", f"{caller} may not change the mandate")
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

    def _check_running(self) -> None:
        """A chain serves nothing until it has started: a request waits a little for it, and is
        then refused and told when to try again. A halted chain's state is not trusted for
        anything until the gateway restarts."""
        if not self._started.wait(self.start_wait):
            detail = "the gateway is starting: taking the chain-head lease and rebuilding the chain"
            raise Rejected(
                503,
                [Problem("gateway_starting", "$", detail)],
                {"Retry-After": str(self.RETRY_AFTER)},
            )
        if self._halted is not None:
            raise _reject(503, "gateway_halted", "$", self._halted)

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
    ) -> dict[str, Any]:
        """Link the entry to the head, journal it, write it, and keep its receipt for the
        idempotency key in `remember`. The caller holds the lock."""
        if not self._own.held():
            self._halted = "the chain-head lease was lost; another gateway may be writing"
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
            }
        ).encode()
        # A write that fails partway stops the gateway: committing again would reuse this seq
        # and fork the record. On restart, `recover` finishes the entry from the journal.
        try:
            self._own.write_journal(journal)
            self._write(entry, files)
            self._keep_receipt(remember, entry)
            self._own.clear_journal()
        except Exception as error:
            self._halted = f"a write failed at seq {entry['seq']}; restart to finish it"
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
        permitted = [g for g in running if g._may_write(caller, roles, "config.changed")]
        chosen = (permitted or running or list(self._by_chain.values()))[0]
        return chosen.put_trust(caller, path, data, roles=roles)

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
    gateway._halted = f"the stored chain does not add up: {error}"


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
