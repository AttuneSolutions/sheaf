"""Rebuilding the chain state from the container on start (7.1), so a restart carries on from the
stored head and never reuses a `seq`.

The chain segments give every entry in order; each entry is read from its dossier blob or the
chain-level blob, and checked: stored canonically, its hash, its link to the one before, and the
segment's record of it. Anything that does not add up stops the gateway from starting.

Blobs are read several at a time, ahead of the checks, which still take each entry in order: a
Blob read takes milliseconds, and a chain is replayed whole every time a gateway starts.
"""

from collections import deque
from collections.abc import Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from sheaf_core import paths
from sheaf_core.canonical import InvalidJSON, strict_loads
from sheaf_core.chain import check_line, segment_line
from sheaf_core.digest import entry_hash
from sheaf_gateway.store import Store

READERS = 8
"""Blobs read at once while replaying: fewer than the connections the Blob reader keeps open
(`azure.BlobReader.CONNECTIONS`)."""


class ChainCorrupt(Exception):
    """The container does not hold an unbroken chain: reconcile it before the gateway starts."""


def replay(store: Store, workflow: str, *, readers: int = READERS) -> Iterator[dict[str, Any]]:
    """Every committed entry, in order, each checked against its segment record and the entry
    before it."""
    pool = ThreadPoolExecutor(readers, thread_name_prefix="replay")
    ahead = readers * 4
    try:
        records = _read_ahead(pool, store, _records(store, workflow), ahead)
        located = _read_ahead(pool, store, _located(workflow, records), ahead)
        previous = None
        for (item, folder), raw in located:
            seq = item["seq"]
            entry, problems = check_line(raw or b"")
            if (
                problems
                or entry["seq"] != seq
                or entry["hash"] != item["hash"]
                or entry_hash(entry) != entry["hash"]
                or entry["prev"] != previous
            ):
                raise ChainCorrupt(f"seq {seq}: {folder} does not hold the entry recorded")
            yield entry
            previous = entry["hash"]
    finally:
        pool.shutdown(cancel_futures=True)


def _records(store: Store, workflow: str) -> Iterator[tuple[tuple[str, str], str]]:
    """Each segment record, in order, as its day folder and path, and the path to read."""
    for day_folder in _days(store, workflow):
        for record in store.list(day_folder):
            yield (day_folder, record), record


def _located(
    workflow: str, records: Iterable[tuple[tuple[str, str], bytes | None]]
) -> Iterator[tuple[tuple[dict[str, Any], str], str]]:
    """Check each segment record, in order, and say where its entry is: the record and the
    entry's folder, and the path to read."""
    opened: dict[str, datetime] = {}
    expected = 1
    for (day_folder, record), line in records:
        line = line or b""
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
        day = datetime.strptime(
            day_folder.removeprefix(f"chain/{workflow}/").rstrip("/"), "%Y/%m/%d"
        ).replace(tzinfo=UTC)
        dossier = item["dossier"]
        if dossier is None:
            folder = paths.chain_dossier(workflow, day)
        else:
            if item["type"] == "dossier.opened":
                opened[dossier] = day
            if dossier not in opened:
                raise ChainCorrupt(f"seq {expected}: dossier {dossier} was never opened")
            folder = paths.dossier(workflow, opened[dossier], dossier)
        yield (item, folder), paths.entry(folder, expected)
        expected += 1


def _read_ahead[K](
    pool: ThreadPoolExecutor, store: Store, items: Iterable[tuple[K, str]], ahead: int
) -> Iterator[tuple[K, bytes | None]]:
    """Each item's key with the bytes at its path, in order, reading up to `ahead` paths ahead.
    An error from `items` or from a read is raised only after the items before it, as reading
    one at a time would."""
    pending: deque[tuple[K, Future[bytes | None]]] = deque()
    source, failed, done = iter(items), None, False
    while True:
        while not done and len(pending) < ahead:
            try:
                item = next(source)
            except StopIteration:
                done = True
            except Exception as error:
                failed, done = error, True
            else:
                key, path = item
                pending.append((key, pool.submit(store.read, path)))
        if not pending:
            break
        key, read = pending.popleft()
        yield key, read.result()
    if failed is not None:
        raise failed


def _days(store: Store, workflow: str) -> list[str]:
    found = []
    for year in store.list(f"chain/{workflow}/"):
        for month in store.list(year):
            found += [day for day in store.list(month) if day.endswith("/")]
    return sorted(found)
