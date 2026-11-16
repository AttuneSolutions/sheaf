import json

import pytest

from sheaf_core.canonical import canonicalize
from sheaf_core.chain import check_chain, check_line, entry_line, link_entry, segment_line
from sheaf_core.digest import entry_hash


def draft(n):
    return {
        "spec": "sheaf/1",
        "tenant": "acme",
        "chain": "acme/case-review",
        "dossier": "cr-20261126-7Q2MZK",
        "type": "notice",
        "body": {"n": n},
    }


def build(count):
    entries, prev = [], None
    for i in range(1, count + 1):
        entry = link_entry(draft(i), seq=i, prev=prev, committed_at=f"2026-11-26T00:00:{i:02d}Z")
        entries.append(entry)
        prev = entry["hash"]
    return entries


def codes(problems):
    return [(p.seq, p.code) for p in problems]


def test_link_entry_sets_chain_fields_and_a_hash_that_recomputes():
    entry = link_entry(draft(1), seq=1, prev=None, committed_at="2026-11-26T00:00:01Z")

    assert entry["seq"] == 1
    assert entry["prev"] is None
    assert entry["committed_at"] == "2026-11-26T00:00:01Z"
    assert entry["hash"] == entry_hash(entry)


def test_link_entry_refuses_a_draft_that_already_carries_chain_fields():
    with pytest.raises(ValueError, match="seq"):
        link_entry({**draft(1), "seq": 7}, seq=1, prev=None, committed_at="x")


def test_link_entry_refuses_null_prev_after_the_first_entry():
    with pytest.raises(ValueError, match="prev"):
        link_entry(draft(2), seq=2, prev=None, committed_at="x")


def test_link_entry_refuses_a_prev_on_the_first_entry():
    with pytest.raises(ValueError, match="prev"):
        link_entry(draft(1), seq=1, prev="sha256:" + "0" * 64, committed_at="x")


def test_entry_line_is_the_canonical_entry_and_a_newline():
    entry = build(1)[0]
    assert entry_line(entry) == canonicalize(entry) + b"\n"


def test_a_well_formed_chain_has_no_problems():
    assert check_chain(build(5)) == []


def test_an_empty_chain_has_no_problems():
    assert check_chain([]) == []


def test_an_edited_entry_is_caught():
    entries = build(3)
    entries[1]["body"]["n"] = 99

    assert codes(check_chain(entries)) == [(2, "hash_mismatch")]


def test_a_removed_entry_is_caught_as_a_gap_and_a_broken_link():
    entries = build(4)
    del entries[1]

    assert codes(check_chain(entries)) == [(3, "seq_gap"), (3, "prev_mismatch")]


def test_swapped_entries_are_caught():
    entries = build(3)
    entries[1], entries[2] = entries[2], entries[1]

    assert (3, "seq_gap") in codes(check_chain(entries))


def test_a_rehashed_forgery_still_breaks_the_next_link():
    entries = build(3)
    entries[1]["body"]["n"] = 99
    entries[1]["hash"] = entry_hash(entries[1])

    assert codes(check_chain(entries)) == [(3, "prev_mismatch")]


def test_a_chain_must_start_at_seq_one_with_null_prev():
    entries = build(2)
    entries[0]["prev"] = "sha256:" + "0" * 64
    entries[0]["hash"] = entry_hash(entries[0])

    assert (1, "genesis_prev") in codes(check_chain(entries))


def test_a_segment_can_be_checked_from_a_known_point():
    entries = build(5)

    problems = check_chain(entries[2:], first_seq=3, first_prev=entries[1]["hash"])

    assert problems == []


def test_a_segment_with_the_wrong_starting_point_is_caught():
    entries = build(5)

    problems = check_chain(entries[2:], first_seq=3, first_prev=entries[0]["hash"])

    assert codes(problems) == [(3, "prev_mismatch")]


def test_entries_from_two_chains_are_caught():
    entries = build(2)
    entries[1]["chain"] = "acme/other"
    entries[1]["hash"] = entry_hash(entries[1])

    assert (2, "chain_mismatch") in codes(check_chain(entries))


def test_a_malformed_hash_is_reported_rather_than_raising():
    entries = build(2)
    entries[1]["hash"] = "not-a-digest"

    assert (2, "hash_format") in codes(check_chain(entries))


def test_a_chain_segment_line_holds_identifiers_and_the_hash_only():
    entry = build(1)[0]

    line = segment_line(entry)

    assert (
        line
        == canonicalize(
            {"seq": 1, "dossier": entry["dossier"], "type": "notice", "hash": entry["hash"]}
        )
        + b"\n"
    )


def test_check_chain_reports_entries_it_cannot_hash_rather_than_raising():
    entries = build(2)
    entries[1]["seq"] = 2.0

    assert (None, "hash_uncomputable") in codes(check_chain(entries))
    assert codes(check_chain([["not", "an", "object"]])) == [(None, "not_object")]


def test_a_stored_line_must_be_the_canonical_form_of_its_entry():
    entry = build(1)[0]

    assert check_line(entry_line(entry)) == (entry, [])
    spaced = json.dumps(entry).encode() + b"\n"
    assert [p.code for p in check_line(spaced)[1]] == ["line_not_canonical"]
    assert [p.code for p in check_line(b'{"seq": 1.5}\n')[1]] == ["number"]
    assert [p.code for p in check_line(b"[1]\n")[1]] == ["not_object"]
    assert [p.code for p in check_line(b'{"a": 1, "a": 2}\n')[1]] == ["invalid_json"]
