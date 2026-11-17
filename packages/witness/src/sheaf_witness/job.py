"""The witness job (7.2 step 5, 7.5): run on a schedule, with its own identity, which may read the
container, sign with the witness key, and submit witness entries, and nothing else.

Each run is stateless. It reads the chain-level entries (the `_chain/` folders: every mandate and
every witness so far), then:
1. witnesses each `config.changed` that has no interim witness yet, with that mandate's key and
   authorities, so the change can apply;
2. witnesses each UTC day that has ended and has no daily witness, in order, from where the last
   one ended (the genesis day for the first). It follows that day's segment records in order
   from the last witnessed `seq`, and refuses to sign if the chain does not continue unbroken.
"""

import base64
import hashlib
import json
import time as clock
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Protocol

import httpx

from sheaf_core import SPEC, paths
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.chain import check_line, segment_line
from sheaf_core.digest import entry_hash
from sheaf_core.times import format_timestamp, parse_timestamp
from sheaf_witness import build
from sheaf_witness.signer import Signer
from sheaf_witness.stamp import Stamper


class ChainBroken(Exception):
    """The chain does not continue unbroken from the last witness: nothing is signed."""


class SubmissionRefused(Exception):
    def __init__(self, status: int, problems: Any):
        super().__init__(f"the gateway answered {status}: {problems}")
        self.status, self.problems = status, problems


class Container(Protocol):
    """The witness's read-only view of the `evidence` container."""

    def read(self, path: str) -> bytes | None:
        """A blob's bytes, or None."""

    def list(self, prefix: str) -> list[str]:
        """The names one level below `prefix`, as a Blob listing with "/" as the delimiter."""


class GatewayClient:
    def __init__(
        self,
        client: httpx.Client,
        base_url: str,
        *,
        headers: Callable[[], Mapping[str, str]],
        wait_for_start: float = 600.0,
        sleep: Callable[[float], None] = clock.sleep,
    ) -> None:
        self.client, self.base_url, self.headers = client, base_url.rstrip("/"), headers
        self.wait_for_start, self.sleep = wait_for_start, sleep
        """How long to keep asking a gateway that answers it is still starting: one scaled to
        zero rebuilds each chain before it serves it."""

    def submit(self, entry: Mapping[str, Any], tokens: Mapping[str, bytes]) -> dict[str, Any]:
        """Submit a witness entry and its tokens. A retry of the same bytes gets the first
        receipt, because the idempotency key is their digest."""
        body = json.dumps(
            {
                "entry": entry,
                "tokens": {name: base64.b64encode(data).decode() for name, data in tokens.items()},
            }
        ).encode()
        headers = {
            **self.headers(),
            "Content-Type": "application/json",
            "Idempotency-Key": hashlib.sha256(body).hexdigest(),
        }
        waited = 0.0
        while True:
            response = self.client.post(
                f"{self.base_url}/v1/witnesses", content=body, headers=headers
            )
            delay = _starting(response)
            if delay is None or waited + delay > self.wait_for_start:
                break
            self.sleep(delay)
            waited += delay
        if response.status_code not in (200, 201):
            try:
                problems = response.json().get("problems")
            except ValueError:
                problems = response.text[:500]
            raise SubmissionRefused(response.status_code, problems)
        return response.json()


def run_once(
    container: Container,
    gateway: GatewayClient,
    *,
    signer_for: Callable[[str], Signer],
    stamper: Stamper,
    chain: str,
    actor: Mapping[str, Any],
    now: datetime,
) -> list[dict[str, Any]]:
    """Witness whatever is due, and return the gateway's receipts."""
    workflow = chain.split("/", 1)[1]
    entries = _chain_level(container, workflow)
    if not entries:
        return []
    by_seq = {entry["seq"]: entry for entry in entries}
    receipts = []

    def submit(witness: dict[str, Any], mandate: Mapping[str, Any]) -> None:
        authorities = mandate["authorities"]["list"]
        roots = build.roots_for(authorities, lambda path: container.read(path) or b"")
        attested, tokens = build.attest(witness, authorities, roots, stamper)
        entry = {
            "spec": SPEC,
            "tenant": chain.split("/", 1)[0],
            "chain": chain,
            "dossier": None,
            "type": f"witness.{witness['witness']}",
            "observed_at": format_timestamp(now),
            "actor": dict(actor),
            "artefacts": [],
            "body": attested,
        }
        receipts.append(gateway.submit(entry, tokens))

    interims = {e["body"]["last_seq"] for e in entries if e["type"] == "witness.interim"}
    in_force = None
    for config in (e for e in entries if e["type"] == "config.changed"):
        mandate = _mandate(container, config)
        if config["seq"] not in interims:
            signer = signer_for(mandate["witness_key"]["key_id"])
            submit(build.interim(chain, config["seq"], config["hash"], signer), mandate)
        in_force = mandate
    if in_force is None:
        return receipts

    dailies = [e["body"] for e in entries if e["type"] == "witness.daily"]
    if dailies:
        day = parse_timestamp(dailies[-1]["interval"]["to"]).date()
        last = (dailies[-1]["last_seq"], dailies[-1]["last_hash"])
    else:
        day, last = parse_timestamp(entries[0]["committed_at"]).date(), (0, None)
    signer = signer_for(in_force["witness_key"]["key_id"])
    while _midnight(day + timedelta(days=1)) <= now:
        last = _follow(container, workflow, day, last, by_seq)
        submit(build.daily(chain, day, last[0], last[1], signer), in_force)
        day += timedelta(days=1)
    return receipts


def _chain_level(container: Container, workflow: str) -> list[dict[str, Any]]:
    """Every chain-level entry, in order, each checked to be stored canonically with its hash."""
    entries = []
    for name in container.list(f"dossiers/{workflow}/"):
        if not (name.endswith("/") and name[-5:-1].isdigit()):
            continue
        for blob in container.list(f"{name}_chain/"):
            entry, problems = check_line(container.read(blob) or b"")
            if problems or entry["hash"] != entry_hash(entry):
                raise ChainBroken(f"{blob} does not hold its entry")
            entries.append(entry)
    entries.sort(key=lambda entry: entry["seq"])
    if entries and entries[0]["seq"] != 1:
        raise ChainBroken("the chain-level log does not start at the genesis entry")
    return entries


def _mandate(container: Container, config: Mapping[str, Any]) -> dict[str, Any]:
    sha256 = config["body"]["mandate"]
    data = container.read(paths.artefact(sha256))
    if data is None or hashlib.sha256(data).hexdigest() != sha256:
        raise ChainBroken(f"the mandate of seq {config['seq']} is not stored")
    return strict_loads(data)


def _follow(
    container: Container,
    workflow: str,
    day: date,
    last: tuple[int, str | None],
    chain_level: Mapping[int, Mapping[str, Any]],
) -> tuple[int, str | None]:
    """Follow one day's segment on from `last`, and return the last `seq` and `hash` of the day."""
    seq, digest = last
    folder = paths.chain_segment(workflow, _midnight(day))
    for record in container.list(folder):
        line = container.read(record) or b""
        try:
            item = strict_loads(line)
            canonical = segment_line(item)
        except (InvalidJSON, KeyError, TypeError) as error:
            raise ChainBroken(f"{day}: a segment record cannot be read") from error
        if canonical != line:
            raise ChainBroken(f"{day}: a segment record is not canonical")
        if item["seq"] != seq + 1:
            raise ChainBroken(f"{day}: after seq {seq} comes {item['seq']}")
        known = chain_level.get(item["seq"])
        if known is not None and known["hash"] != item["hash"]:
            raise ChainBroken(f"{day}: seq {item['seq']} differs from the chain-level log")
        seq, digest = item["seq"], item["hash"]
    if seq == 0:
        raise ChainBroken(f"{day}: the genesis day has no entries")
    return seq, digest


def _starting(response: httpx.Response) -> int | None:
    """The seconds to wait if the gateway answered that the chain is still starting, else
    None."""
    if response.status_code != 503:
        return None
    try:
        problems = response.json().get("problems") or []
        codes = {problem.get("code") for problem in problems}
    except (ValueError, AttributeError):
        return None
    if "gateway_starting" not in codes:
        return None
    after = response.headers.get("Retry-After", "")
    return min(int(after), 60) if after.isdigit() and int(after) > 0 else 5


def _midnight(day: date) -> datetime:
    return datetime.combine(day, time(0), UTC)


__all__: Sequence[str] = (
    "ChainBroken",
    "Container",
    "GatewayClient",
    "SubmissionRefused",
    "run_once",
)
