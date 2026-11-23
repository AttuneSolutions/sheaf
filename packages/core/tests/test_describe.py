import copy

from sheaf_core import testing as t
from sheaf_core.describe import describe, diff, technical
from sheaf_core.mandate import PARTS


def lines(sections, part):
    return next(s["lines"] for s in sections if s["part"] == part)


def text(sections):
    return "\n".join(line for s in sections for line in s["lines"])


def test_every_part_is_described_in_order_with_a_title():
    sections = describe(t.mandate_document())

    assert [s["part"] for s in sections] == list(PARTS)
    assert all(s["title"] and s["lines"] for s in sections)
    assert all(isinstance(line, str) for s in sections for line in s["lines"])


def test_who_may_write_is_said_in_plain_language():
    policy = lines(describe(t.mandate_document()), "policy")

    assert "acme-review-agent may open a dossier, record a source it read," in policy[0]
    assert policy[0].endswith("record a notice and seal a dossier.")
    assert any(
        line == "Anyone holding the app role reviewer may record a person's decision."
        for line in policy
    )
    assert "Whoever proposes a change to this mandate may not also approve it." in policy
    assert "Source documents are referenced by fingerprint; they are not copied." in policy
    assert "AI requests and responses may be stored, up to 20 MiB each (ai.exchange.raw)." in policy
    assert (
        "Snapshots of source records may be stored, up to 5 MiB each (record.snapshot)." in policy
    )
    assert not any(line.endswith(":") for line in policy)
    assert "Evidence about clients may be opened by the app role case-reviewer." in policy
    assert (
        "Other evidence may be opened by the app roles case-reviewer and case-review-admin."
        in policy
    )


def test_the_rest_of_the_mandate_is_said_in_plain_language():
    sections = describe(t.mandate_document())

    assert lines(sections, "retention") == [
        "regulated-record: kept for 7 years.",
        "working-file: kept for 1 year.",
    ]
    assert lines(sections, "models")[0].startswith(
        "example-model version 2026-01-01, deployment case-review, from azure-ai-foundry in "
        "example-region"
    )
    assert "temperature 0.2" in lines(sections, "models")[0]
    assert lines(sections, "personal_data")[0] == (
        "People and clients are recorded by their identifiers, in clear."
    )
    assert "Example authority tsa-a, in CH" in lines(sections, "authorities")[0]


def test_the_plain_language_follows_the_mandate():
    old = t.mandate_document()
    new = copy.deepcopy(old)
    new["models"][0]["model_version"] = "2026-06-01"
    new["policy"]["callers"][0]["types"].remove("trace.recorded")
    new["policy"]["four_eyes"] = False

    before, after = text(describe(old)), text(describe(new))

    assert "version 2026-01-01" in before and "version 2026-06-01" in after
    assert "record a trace" in before and "acme-review-agent may open a dossier" in after
    assert "record a trace" not in lines(describe(new), "policy")[0]
    assert "Whoever proposes a change to this mandate may also approve it." in after


def test_a_diff_names_each_changed_part_with_what_was_and_what_will_be():
    old = t.mandate_document()
    new = copy.deepcopy(old)
    new["version"] = "2026.11.2"
    new["retention"]["classes"][1]["period"] = "P2Y"

    changes = diff(old, new)

    assert [c["part"] for c in changes] == ["retention"]
    assert changes[0]["removed"] == ["working-file: kept for 1 year."]
    assert changes[0]["added"] == ["working-file: kept for 2 years."]
    assert changes[0]["title"] == "How long the record is kept"


def test_a_genesis_diff_adds_every_part():
    changes = diff(None, t.mandate_document())

    assert [c["part"] for c in changes] == list(PARTS)
    assert all(c["removed"] == [] and c["added"] for c in changes)


def test_text_from_the_mandate_is_kept_as_text():
    doc = t.mandate_document()
    doc["personal_data"]["basis"] = "<script>alert(1)</script>"

    assert "Basis: <script>alert(1)</script>" in lines(describe(doc), "personal_data")


def test_the_technical_summary_names_digests_in_full():
    doc = t.mandate_document()
    rows = dict(technical(doc, "f" * 64))

    assert rows["mandate"] == "f" * 64
    assert rows["witness key"].startswith(doc["witness_key"]["key_id"])
    assert rows["gateway image"] == doc["gateway"]["image"]


def test_a_change_to_pinned_roots_shows_in_plain_language():
    old = t.mandate_document()
    new = copy.deepcopy(old)
    new["authorities"]["list"][0]["roots"] = ["e" * 64]

    [change] = diff(old, new)

    assert change["part"] == "authorities"
    assert any("eeeeeeeeeeeeeeee" in line for line in change["added"])


def test_a_part_that_changes_in_no_sentence_says_so():
    old = t.mandate_document()
    new = copy.deepcopy(old)
    new["instructions"] = new["instructions"] * 2  # the same sentence, twice

    [change] = diff(old, new)

    assert change["part"] == "instructions"
    assert change["added"] == [
        "Changed in details these sentences do not show: see the technical summary."
    ]


def test_no_sentence_ends_with_an_ellipsis_and_a_full_stop():
    lines = [line for s in describe(t.mandate_document()) for line in s["lines"]]

    assert not any(line.endswith("….") for line in lines)
    assert "review-instructions (fingerprint " in lines_of(describe(t.mandate_document()))


def lines_of(sections):
    return "\n".join(line for s in sections for line in s["lines"])
