"""The kind registry, v1 (section 6): every kind, its media types and its size limit."""

import functools
import json
from importlib.resources import files
from typing import Any


@functools.cache
def _registry() -> dict[str, Any]:
    return json.loads((files("sheaf_core") / "registry" / "kinds.json").read_text("utf-8"))


def registry_version() -> str:
    return _registry()["version"]


def kind(name: str) -> dict[str, Any] | None:
    """A kind's entry in the registry: `media_types` and `max_bytes`; None if unregistered."""
    return _registry()["kinds"].get(name)


def kinds() -> tuple[str, ...]:
    return tuple(_registry()["kinds"])
