"""Rebuilding the chain state from the container on start (7.1), so a restart carries on from the
stored head and never reuses a `seq`.

The chain segments give every entry in order; each entry is read from its dossier blob or the
chain-level blob, and checked: stored canonically, its hash, its link to the one before, and the
segment's record of it. Anything that does not add up stops the gateway from starting.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from sheaf_core import paths
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.chain import check_line, segment_line
from sheaf_core.digest import entry_hash
from sheaf_gateway.store import Store


class ChainCorrupt(Exception):
    """The container does not hold an unbroken chain: reconcile it before the gateway starts."""


def replay(store: Store, workflow: str) -> Iterator[dict[str, Any]]:
    """Every committed entry, in order, each checked against its segment record and the entry
    before it."""
    opened: dict[str, datetime] = {}
    previous, expected = None, 1
    for day_folder in _days(store, workflow):
        day = datetime.strptime(
            day_folder.removeprefix(f"chain/{workflow}/").rstrip("/"), "%Y/%m/%d"
        ).replace(tzinfo=UTC)
        for record in store.list(day_folder):
            line = store.read(record) or b""
            try:
                item = strict_loads(line)
                canonical = segment_line(item)
            except (InvalidJSON, KeyError, TypeError) as error:
                raise ChainCorrupt(f"{record}: the segment record cannot be read") from error
            if (
                canonical != line
                or item["seq"] != expected
                or record != paths.entry(day_folder, expected)
            ):
                raise ChainCorrupt(f"{record}: expected seq {expected}")
            dossier = item["dossier"]
            if dossier is None:
                folder = paths.chain_dossier(workflow, day)
            else:
                if item["type"] == "dossier.opened":
                    opened[dossier] = day
                if dossier not in opened:
                    raise ChainCorrupt(f"seq {expected}: dossier {dossier} was never opened")
                folder = paths.dossier(workflow, opened[dossier], dossier)
            entry, problems = check_line(store.read(paths.entry(folder, expected)) or b"")
            if (
                problems
                or entry["seq"] != expected
                or entry["hash"] != item["hash"]
                or entry_hash(entry) != entry["hash"]
                or entry["prev"] != previous
            ):
                raise ChainCorrupt(f"seq {expected}: {folder} does not hold the entry recorded")
            yield entry
            previous, expected = entry["hash"], expected + 1


def _days(store: Store, workflow: str) -> list[str]:
    found = []
    for year in store.list(f"chain/{workflow}/"):
        for month in store.list(year):
            found += [day for day in store.list(month) if day.endswith("/")]
    return sorted(found)
