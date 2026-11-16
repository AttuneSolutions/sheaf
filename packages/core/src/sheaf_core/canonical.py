"""RFC 8785 canonical JSON, restricted to the numbers the standard allows (section 5.2).

Entries hold integers only, within +/-(2^53 - 1). Floating point is where JSON canonicalisation
implementations in different languages most often disagree, and the verifier must be easy to
rewrite, so a fraction is written as a string instead.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any

import rfc8785

MAX_SAFE_INTEGER = 2**53 - 1


MAX_DEPTH = 64
"""The deepest nesting allowed in a value to be canonicalised. Far beyond any real entry, and
well inside what any canonicaliser's recursion can handle."""


class ValueNotAllowed(ValueError):
    """Something in a value that the standard does not allow to be canonicalised."""


class NumberNotAllowed(ValueNotAllowed):
    """A float, or an integer outside the safe range."""


class TooDeep(ValueNotAllowed):
    """Nesting deeper than MAX_DEPTH."""


class InvalidJSON(ValueError):
    """Bytes that are not one unambiguous JSON value in UTF-8."""


def check_numbers(value: Any, path: str = "$") -> None:
    """Raise ValueNotAllowed, naming the JSON path, for any number the standard does not allow,
    or for nesting deeper than MAX_DEPTH. Iterative, so hostile input cannot exhaust the stack."""
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    while stack:
        item, here, depth = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, str):
            continue
        if isinstance(item, float):
            raise NumberNotAllowed(f"{here}: non-integer number {item!r}; write it as a string")
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_INTEGER:
                raise NumberNotAllowed(f"{here}: integer {item} is outside +/-(2^53 - 1)")
            continue
        if isinstance(item, Mapping | Sequence) and depth >= MAX_DEPTH:
            raise TooDeep(f"{here}: nested deeper than {MAX_DEPTH} levels")
        if isinstance(item, Mapping):
            stack.extend((child, f"{here}.{key}", depth + 1) for key, child in item.items())
        elif isinstance(item, Sequence):
            stack.extend((child, f"{here}[{i}]", depth + 1) for i, child in enumerate(item))
        else:
            raise TypeError(f"{here}: {type(item).__name__} is not a JSON value")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON value."""
    check_numbers(value)
    return rfc8785.dumps(value)


def strict_loads(data: bytes | str) -> Any:
    """Parse UTF-8 JSON, refusing what JSON parsers disagree on.

    Refused: bytes that are not UTF-8 (or carry a byte-order mark), duplicate keys, NaN and
    Infinity, and strings holding lone surrogates. Python keeps the last of two duplicate keys
    where other parsers keep the first, and a writer and a checker that read one text as two
    different values would compute two different hashes. Numbers are left alone: artefacts may
    hold fractions, and `check_numbers` applies the stricter rule to entries.
    """
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InvalidJSON(f"not UTF-8: {error}") from error
    try:
        value = json.loads(data, object_pairs_hook=_unique_keys, parse_constant=_no_constant)
    except InvalidJSON:
        raise
    except RecursionError as error:
        raise InvalidJSON("nested too deep to parse") from error
    except ValueError as error:  # JSONDecodeError, and integers over Python's 4300-digit limit
        raise InvalidJSON(str(error)) from error
    _check_strings(value)
    return value


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJSON(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise InvalidJSON(f"{name} is not a JSON number")


def _check_strings(value: Any) -> None:
    # An explicit stack rather than recursion: artefacts can be deeply nested.
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            _encodable(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                _encodable(key)
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def _encodable(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise InvalidJSON(f"string holds a lone surrogate: {text!r}") from error
