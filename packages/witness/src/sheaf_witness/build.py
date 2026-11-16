"""Building a witness (5.2): sign the chain head, then have the authorities the mandate names
stamp its imprint. Following the chain to its head, and submitting the witness with its tokens,
are the job's other steps (7.2 step 5)."""

import hashlib
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from typing import Any

from sheaf_core import paths
from sheaf_core.witness import imprint_bytes, signing_input, time_attestation
from sheaf_witness.signer import Signer
from sheaf_witness.stamp import Stamper

SPEC = "sheaf/1"


def daily(chain: str, day: date, last_seq: int, last_hash: str, signer: Signer) -> dict[str, Any]:
    """The signed daily witness for one UTC day, before its time attestation."""
    following = day + timedelta(days=1)
    interval = {"from": f"{day:%Y-%m-%d}T00:00:00Z", "to": f"{following:%Y-%m-%d}T00:00:00Z"}
    return _signed(chain, "daily", last_seq, last_hash, signer, interval)


def interim(chain: str, last_seq: int, last_hash: str, signer: Signer) -> dict[str, Any]:
    """The signed interim witness for the entry at `last_seq`, before its time attestation."""
    return _signed(chain, "interim", last_seq, last_hash, signer, None)


def _signed(chain, which, last_seq, last_hash, signer, interval) -> dict[str, Any]:
    witness: dict[str, Any] = {"spec": SPEC, "chain": chain, "witness": which}
    if interval is not None:
        witness["interval"] = interval
    witness.update({"last_seq": last_seq, "last_hash": last_hash, "key_id": signer.key_id})
    witness["signature"] = signer.sign(signing_input(witness))
    return witness


def attest(
    witness: Mapping[str, Any],
    authorities: Sequence[Mapping[str, Any]],
    roots: Mapping[str, Sequence[bytes]],
    stamper: Stamper,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Ask every authority the mandate lists to stamp the witness imprint, all at once, so one that
    is down and being retried never delays the others. Returns the witness with its time
    attestation, listing the authorities in the mandate's order, and each token obtained."""
    imprint = imprint_bytes(witness)
    with ThreadPoolExecutor(max_workers=max(len(authorities), 1)) as pool:
        stamps = list(
            pool.map(lambda a: stamper.stamp(a, roots[a["authority"]], imprint), authorities)
        )
    attested = {
        **witness,
        "time_attestation": time_attestation(witness, [s.result for s in stamps]),
    }
    tokens = {
        a["authority"]: s.response
        for a, s in zip(authorities, stamps, strict=True)
        if s.response is not None
    }
    return attested, tokens


def roots_for(
    authorities: Sequence[Mapping[str, Any]], read: Callable[[str], bytes]
) -> dict[str, list[bytes]]:
    """The certificates the mandate pins for each authority, read from `trust/tsa/`, each checked
    against the SHA-256 the mandate names it by."""
    roots = {}
    for authority in authorities:
        name, found = authority["authority"], []
        for sha256 in authority["roots"]:
            der = read(paths.tsa_certificate(name, sha256))
            if hashlib.sha256(der).hexdigest() != sha256:
                raise ValueError(f"{name}: the stored certificate is not {sha256}")
            found.append(der)
        roots[name] = found
    return roots
