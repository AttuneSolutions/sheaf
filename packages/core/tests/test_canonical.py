import json

import pytest

from sheaf_core.canonical import (
    MAX_DEPTH,
    InvalidJSON,
    NumberNotAllowed,
    ValueNotAllowed,
    canonicalize,
    strict_loads,
)


def test_keys_sort_by_utf16_code_units_not_code_points():
    # RFC 8785 section 3.2.3. A sort by code point would put U+1F600 after U+FB33;
    # UTF-16 puts its high surrogate (D83D) first.
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }

    keys = list(json.loads(canonicalize(value)).keys())

    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_output_is_compact_utf8_with_no_insignificant_whitespace():
    assert canonicalize({"b": [1, 2], "a": "é"}) == '{"a":"é","b":[1,2]}'.encode()


def test_nested_objects_are_sorted_too():
    assert canonicalize({"z": {"y": 1, "x": 2}}) == b'{"z":{"x":2,"y":1}}'


@pytest.mark.parametrize("bad", [1.5, 1.0, float("nan")])
def test_floats_are_refused_anywhere(bad):
    with pytest.raises(NumberNotAllowed, match=r"\$\.body\.usage\[1\]"):
        canonicalize({"body": {"usage": [1, bad]}})


@pytest.mark.parametrize("bad", [2**53, -(2**53)])
def test_integers_outside_the_safe_range_are_refused(bad):
    with pytest.raises(NumberNotAllowed, match=r"\$\.n"):
        canonicalize({"n": bad})


def test_largest_safe_integers_are_allowed():
    assert canonicalize({"n": 2**53 - 1}) == b'{"n":9007199254740991}'
    assert canonicalize({"n": -(2**53 - 1)}) == b'{"n":-9007199254740991}'


def test_booleans_and_null_are_not_mistaken_for_numbers():
    assert canonicalize({"t": True, "f": False, "n": None}) == b'{"f":false,"n":null,"t":true}'


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "a": 2}',
        '{"a": {"b": 1, "b": 1}}',
        '{"n": NaN}',
        '{"n": Infinity}',
        '{"s": "\\ud800"}',
        '{"\\udfff": 1}',
        "﻿{}",
        "{",
    ],
)
def test_strict_loads_refuses_what_json_leaves_ambiguous(text):
    with pytest.raises(InvalidJSON):
        strict_loads(text.encode("utf-8", "surrogatepass"))


def test_strict_loads_refuses_bytes_that_are_not_utf8():
    with pytest.raises(InvalidJSON):
        strict_loads(b'{"a": "\xff"}')
    with pytest.raises(InvalidJSON):
        strict_loads('{"a": 1}'.encode("utf-16"))


def test_strict_loads_parses_ordinary_json_and_leaves_numbers_alone():
    # Artefacts may hold fractions; only entries are restricted to integers.
    assert strict_loads(b'{"a": [1, 2.5, "x", null, true]}') == {"a": [1, 2.5, "x", None, True]}


@pytest.mark.parametrize("text", ["[" * 100_000 + "]" * 100_000, "1" * 5000])
def test_strict_loads_turns_every_parse_failure_into_invalid_json(text):
    # Deep nesting and huge integer literals raise RecursionError and ValueError in Python.
    with pytest.raises(InvalidJSON):
        strict_loads(text.encode())


def nested(depth):
    value = {}
    for _ in range(depth):
        value = {"x": value}
    return value


def test_values_too_deep_to_canonicalise_safely_are_refused():
    with pytest.raises(ValueNotAllowed, match="deep"):
        canonicalize(nested(MAX_DEPTH + 1))
    assert canonicalize(nested(MAX_DEPTH - 1))
