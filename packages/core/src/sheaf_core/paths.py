"""Where everything is stored in the `evidence` container (section 4). Dates are UTC."""

from datetime import date, datetime

SPEC_DIR = "sheaf-1"


def artefact(sha256: str) -> str:
    return f"artefacts/sha256/{sha256[0:2]}/{sha256[2:4]}/{sha256}"


def dossier(workflow: str, opened_at: datetime, dossier_id: str) -> str:
    """The folder of a dossier's entries, filed under the UTC month its `dossier.opened` was
    committed. Each entry is its own write-once blob in it (`entry`)."""
    return f"dossiers/{workflow}/{opened_at:%Y/%m}/{dossier_id}/"


def chain_dossier(workflow: str, committed_at: datetime) -> str:
    """The year's folder of chain-level entries (`dossier` null)."""
    return f"dossiers/{workflow}/{committed_at:%Y}/_chain/"


def chain_segment(workflow: str, committed_at: datetime) -> str:
    """The day's folder of segment records, one blob per entry committed that day."""
    return f"chain/{workflow}/{committed_at:%Y/%m/%d}/"


def entry(folder: str, seq: int) -> str:
    """One entry's blob in a dossier, chain-level or segment folder. The `seq` is zero-padded to
    16 digits (2^53 has 16), so a listing comes back in `seq` order."""
    return f"{folder}{seq:016d}.json"


def witness_daily(workflow: str, day: date) -> str:
    return f"witness/{workflow}/{day:%Y/%m/%d}.json"


def daily_token(workflow: str, day: date, authority: str) -> str:
    return f"witness/{workflow}/{day:%Y/%m/%d}.{authority}.tsr"


def daily_revocation(workflow: str, day: date, authority: str) -> str:
    return f"witness/{workflow}/{day:%Y/%m/%d}.{authority}.rev"


def witness_interim(workflow: str, seq: int) -> str:
    return f"witness/{workflow}/interim/{seq}.json"


def interim_token(workflow: str, seq: int, authority: str) -> str:
    return f"witness/{workflow}/interim/{seq}.{authority}.tsr"


def interim_revocation(workflow: str, seq: int, authority: str) -> str:
    return f"witness/{workflow}/interim/{seq}.{authority}.rev"


def witness_key(key_id: str) -> str:
    return f"trust/witness-keys/{key_id}.pem"


def tsa(authority: str) -> str:
    return f"trust/tsa/{authority}/"


def tsa_certificate(authority: str, sha256: str) -> str:
    """A root or intermediate certificate the mandate pins for an authority, in DER, named by the
    SHA-256 the mandate lists in `authorities.list[].roots`."""
    return f"{tsa(authority)}{sha256}.der"


def registry(version: str) -> str:
    return f"registry/{SPEC_DIR}/{version}/"
