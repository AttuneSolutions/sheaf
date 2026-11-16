"""sheaf-core must run offline on a downloaded container: no Azure, no network (CLAUDE.md)."""

import ast
import tomllib
from importlib.resources import files
from pathlib import Path

FORBIDDEN = ("azure", "requests", "httpx", "urllib", "http", "socket", "aiohttp", "ssl")


def test_core_imports_nothing_that_reaches_a_network():
    root = Path(str(files("sheaf_core")))
    for source in root.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text("utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in FORBIDDEN, f"{source.name} imports {name}"


def test_core_depends_only_on_offline_libraries():
    # The token checks need cryptography and asn1crypto (standard 9); nothing here opens a socket.
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    deps = tomllib.loads(pyproject.read_text())["project"]["dependencies"]

    assert sorted(dep.split(">")[0].split("=")[0] for dep in deps) == [
        "asn1crypto",
        "cryptography",
        "jsonschema",
        "rfc8785",
    ]


def test_every_type_schema_agrees_with_chain_level_types():
    from sheaf_core.entry import CHAIN_LEVEL_TYPES, TYPES
    from sheaf_core.schema import schema

    for entry_type in TYPES:
        dossier = schema(f"sheaf.entry.{entry_type}/1")["properties"].get("dossier")
        assert (dossier == {"type": "null"}) == (entry_type in CHAIN_LEVEL_TYPES), entry_type
