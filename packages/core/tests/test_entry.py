import copy

import pytest

from sheaf_core import testing as t
from sheaf_core.chain import link_entry
from sheaf_core.entry import check_caller, check_draft, check_entry


def codes(problems):
    return [p.code for p in problems]


def at(problems):
    return {(p.code, p.path) for p in problems}


EXAMPLES = t.examples()


@pytest.mark.parametrize("entry_type", sorted(EXAMPLES))
def test_every_example_draft_is_valid(entry_type):
    assert check_draft(EXAMPLES[entry_type]) == []


def test_a_linked_entry_is_valid_and_its_draft_is_not():
    entry = link_entry(t.notice(), seq=1, prev=None, committed_at="2026-11-26T18:04:11.204Z")

    assert check_entry(entry) == []
    assert codes(check_draft(entry)) == ["schema"]


def test_a_committed_entry_must_carry_every_chain_field():
    entry = link_entry(t.notice(), seq=2, prev="sha256:" + "a" * 64, committed_at=t.OBSERVED)
    del entry["committed_at"]

    assert ("schema", "$") in at(check_entry(entry))


def test_prev_is_null_exactly_at_seq_one():
    first = link_entry(t.notice(), seq=1, prev=None, committed_at=t.OBSERVED)
    first["prev"] = "sha256:" + "a" * 64
    second = link_entry(t.notice(), seq=2, prev="sha256:" + "a" * 64, committed_at=t.OBSERVED)
    second["prev"] = None

    assert ("schema", "$.prev") in at(check_entry(first))
    assert ("schema", "$.prev") in at(check_entry(second))


def test_an_unknown_field_is_refused():
    assert codes(check_draft({**t.notice(), "note": "hi"})) == ["schema"]


def test_a_draft_that_is_not_an_object_is_refused():
    assert codes(check_draft([])) == ["schema"]


def test_the_chain_must_belong_to_the_tenant():
    entry = {**t.notice(), "tenant": "other"}

    assert at(check_draft(entry)) == {("chain_tenant", "$.chain")}


def test_a_fraction_anywhere_is_refused_even_where_the_schema_allows_any_value():
    entry = t.ai_exchange()
    entry["body"]["parameters"]["temperature"] = 0.2

    assert "number" in codes(check_draft(entry))


def test_an_integer_written_as_a_float_is_refused():
    entry = t.ai_exchange()
    entry["body"]["usage"]["input_tokens"] = 1200.0

    assert "number" in codes(check_draft(entry))


@pytest.mark.parametrize("entry_type", ["config.changed", "witness.daily", "retention.expired"])
def test_chain_level_types_carry_no_dossier(entry_type):
    entry = copy.deepcopy(EXAMPLES[entry_type])
    entry.update(dossier=t.DOSSIER, subject=t.SUBJECT, retention=t.RETENTION)

    assert ("schema", "$.dossier") in at(check_draft(entry))


@pytest.mark.parametrize("entry_type", ["dossier.opened", "ai.exchange", "decision.recorded"])
def test_dossier_types_need_a_dossier(entry_type):
    entry = copy.deepcopy(EXAMPLES[entry_type])
    entry["dossier"] = None
    del entry["subject"], entry["retention"]

    assert ("schema", "$.dossier") in at(check_draft(entry))


def test_a_notice_may_be_in_a_dossier_or_at_chain_level():
    assert check_draft(t.notice()) == []
    assert check_draft(t.notice(dossier=None)) == []


def test_dossier_entries_carry_subject_and_retention_and_chain_entries_do_not():
    missing = t.notice()
    del missing["subject"]
    extra = {**t.notice(dossier=None), "retention": t.RETENTION}

    assert ("schema", "$") in at(check_draft(missing))
    assert ("schema", "$.retention") in at(check_draft(extra))


@pytest.mark.parametrize("bad", ["C104233#1", "", "x" * 257, "C104233\n"])
def test_subject_fields_must_be_usable_as_index_tags(bad):
    entry = t.notice(subject={**t.SUBJECT, "id": bad})

    assert ("schema", "$.subject.id") in at(check_draft(entry))


@pytest.mark.parametrize("bad", ["cr/../x", "cr 1", "cr-", "-cr", "cr-1\n"])
def test_dossier_ids_are_path_safe(bad):
    assert ("schema", "$.dossier") in at(check_draft(t.notice(dossier=bad)))


def test_a_system_actor_has_a_version_and_a_person_does_not():
    no_version = t.notice(actor={"kind": "system", "id": "acme-review-agent"})
    versioned = t.notice(actor={**t.REVIEWER, "version": "1"})

    assert ("schema", "$.actor") in at(check_draft(no_version))
    assert ("schema", "$.actor.version") in at(check_draft(versioned))


def test_an_unknown_kind_is_refused():
    entry = t.artefact_attached({**t.output_ref(), "kind": "video.mp4"})

    assert at(check_draft(entry)) == {("kind_unknown", "$.artefacts[0].kind")}


def test_a_media_type_the_kind_does_not_allow_is_refused():
    entry = t.artefact_attached({**t.output_ref(), "media_type": "text/html"})

    assert at(check_draft(entry)) == {("media_type_mismatch", "$.artefacts[0].media_type")}


def test_an_artefact_over_the_registry_size_limit_is_refused():
    entry = t.artefact_attached({**t.output_ref(), "bytes": 10 * 1024 * 1024 + 1})

    assert at(check_draft(entry)) == {("too_large", "$.artefacts[0].bytes")}


def test_a_rendition_names_its_original_and_nothing_else_may():
    pdf = t.ref(
        b"%PDF-1.7", role="rendition", kind="document.rendition", media_type="application/pdf"
    )
    named = {**t.output_ref(), "rendition_of": t.stand_in("original")}

    assert ("schema", "$.artefacts[0]") in at(check_draft(t.artefact_attached(pdf)))
    assert check_draft(t.artefact_attached({**pdf, "rendition_of": t.stand_in("x")})) == []
    assert ("schema", "$.artefacts[0].rendition_of") in at(check_draft(t.artefact_attached(named)))


def test_ai_exchange_needs_one_request_and_one_response():
    only_request = t.ai_exchange()
    only_request["artefacts"] = [t.ai_request()]
    two_requests = t.ai_exchange()
    two_requests["artefacts"] = [t.ai_request(), t.ai_request()]
    wrong_kind = t.ai_exchange()
    wrong_kind["artefacts"][1]["kind"] = "text.plain"
    wrong_kind["artefacts"][1]["media_type"] = "text/plain"

    for entry in (only_request, two_requests, wrong_kind):
        assert ("schema", "$.artefacts") in at(check_draft(entry))


def test_trace_recorded_needs_exactly_one_trace():
    entry = t.trace_recorded()
    entry["artefacts"] = []

    assert ("schema", "$.artefacts") in at(check_draft(entry))


def test_a_decision_is_made_by_a_person():
    entry = t.decision(t.stand_in("draft"), actor=t.AGENT)

    assert ("schema", "$.actor.kind") in at(check_draft(entry))


def test_only_approve_with_edits_carries_edits():
    missing = t.decision(t.stand_in("draft"), choice="approve_with_edits")
    del missing["body"]["edits"]
    stray = t.decision(t.stand_in("draft"))
    stray["body"]["edits"] = "x"

    assert ("schema", "$.body") in at(check_draft(missing))
    assert ("schema", "$.body.edits") in at(check_draft(stray))


def test_a_dossier_id_never_embeds_its_subject():
    entry = t.opened("sha256:" + "a" * 64, dossier="cr-20261126-c104233-1")

    assert at(check_draft(entry)) == {("dossier_names_subject", "$.dossier")}


def test_a_copied_source_is_the_bytes_whose_fingerprint_is_recorded():
    entry = t.source_read(copy=True)
    entry["body"]["sha256"] = t.stand_in("something else")

    assert at(check_draft(entry)) == {("fingerprint_mismatch", "$.artefacts[0].sha256")}


def test_an_attached_output_is_the_bytes_whose_fingerprint_is_recorded():
    entry = t.output_produced()
    entry["body"]["sha256"] = t.stand_in("something else")

    assert at(check_draft(entry)) == {("fingerprint_mismatch", "$.artefacts[0].sha256")}
    assert check_draft(t.output_produced(attach=False)) == []


def test_config_changed_attaches_the_mandate_it_names():
    entry = t.config_changed(t.mandate_document())
    entry["body"]["mandate"] = t.stand_in("another mandate")

    assert at(check_draft(entry)) == {("mandate_mismatch", "$.body.mandate")}


def test_config_changed_attaches_exactly_one_mandate():
    entry = t.config_changed(t.mandate_document())
    entry["artefacts"].append(entry["artefacts"][0])

    assert ("schema", "$.artefacts") in at(check_draft(entry))


def test_config_changed_is_approved_by_a_person():
    entry = t.config_changed(t.mandate_document())
    entry["body"]["approved_by"] = {"kind": "system", "id": "acme-admin-tool"}

    assert ("schema", "$.body.approved_by.kind") in at(check_draft(entry))


def test_a_witness_entry_is_for_its_own_chain():
    body = t.witness("interim", 7, "sha256:" + "a" * 64, chain="acme/other")

    entry = {**t.witness_draft(body), "chain": t.CHAIN}

    assert at(check_draft(entry)) == {("witness_chain", "$.body.chain")}


def test_a_witness_entry_type_matches_its_witness():
    entry = copy.deepcopy(EXAMPLES["witness.interim"])
    entry["type"] = "witness.daily"

    assert ("schema", "$.body.witness") in at(check_draft(entry))


def test_a_witness_entry_body_is_checked_as_a_witness():
    entry = copy.deepcopy(EXAMPLES["witness.interim"])
    entry["body"]["last_seq"] += 1

    assert codes(check_draft(entry)) == ["imprint_mismatch"]


def test_an_authority_that_did_not_answer_is_named():
    entry = t.notice(dossier=None)
    entry["body"] = {"event": "authority_unavailable", "detail": "timeout"}

    assert ("schema", "$.body") in at(check_draft(entry))
    entry["body"]["authority"] = "tsa-b"
    assert check_draft(entry) == []


def test_retention_expired_lists_something():
    assert ("schema", "$.body") in at(check_draft(t.retention_expired()))


def test_a_float_in_a_witness_body_is_reported_not_raised():
    entry = copy.deepcopy(EXAMPLES["witness.interim"])
    entry["body"]["last_seq"] = float(entry["body"]["last_seq"])

    assert codes(check_draft(entry)) == ["number"]


def test_a_body_nested_too_deep_is_reported_not_raised():
    entry = t.ai_exchange()
    deep = {}
    for _ in range(1100):
        deep = {"x": deep}
    entry["body"]["content_filter"] = deep

    assert codes(check_draft(entry)) == ["too_deep"]


def test_committed_at_has_milliseconds():
    entry = link_entry(t.notice(), seq=1, prev=None, committed_at="2026-11-26T09:00:00Z")

    assert ("schema", "$.committed_at") in at(check_entry(entry))


# -- who submits ------------------------------------------------------------------------------


def test_an_entry_is_submitted_by_its_actor():
    assert check_caller(t.notice(), t.AGENT["id"]) == []
    assert at(check_caller(t.decision(t.stand_in("x")), t.APP["id"])) == {
        ("actor_not_caller", "$.actor.id")
    }


@pytest.mark.parametrize("entry_type", ["config.changed", "retention.expired"])
@pytest.mark.parametrize("actor", [t.ADMIN, t.REVIEWER], ids=["system", "another person"])
def test_the_approver_submits_the_approval(entry_type, actor):
    entry = copy.deepcopy(EXAMPLES[entry_type])
    assert entry["actor"] == entry["body"]["approved_by"]
    entry["actor"] = dict(actor)

    assert at(check_draft(entry)) == {("approver_not_actor", "$.body.approved_by")}


def test_a_caller_names_only_a_role_it_holds():
    entry = t.decision(t.stand_in("x"))

    assert check_caller(entry, t.REVIEWER["id"], roles={"reviewer"}) == []
    assert at(check_caller(entry, t.REVIEWER["id"])) == {("role_not_held", "$.actor.role")}
    assert at(check_caller(entry, t.REVIEWER["id"], roles={"approver"})) == {
        ("role_not_held", "$.actor.role")
    }


def test_an_approver_may_approve_under_a_role():
    entry = copy.deepcopy(EXAMPLES["config.changed"])
    entry["actor"]["role"] = "approver"

    assert check_draft(entry) == []


@pytest.mark.parametrize("role", ["", "has space", "-leading", "x" * 121])
def test_a_role_is_a_plain_name(role):
    entry = copy.deepcopy(EXAMPLES["decision.recorded"])
    entry["actor"]["role"] = role

    assert codes(check_draft(entry)) == ["schema"]


def test_an_actor_is_a_person_exactly_when_the_caller_is_one():
    decision = t.decision(t.stand_in("x"))
    notice = t.notice()

    assert check_caller(decision, t.REVIEWER["id"], {"reviewer"}, person=True) == []
    assert check_caller(notice, t.AGENT["id"], person=False) == []
    assert at(check_caller(decision, t.REVIEWER["id"], {"reviewer"}, person=False)) == {
        ("actor_kind_mismatch", "$.actor.kind")
    }
    assert at(check_caller(notice, t.AGENT["id"], person=True)) == {
        ("actor_kind_mismatch", "$.actor.kind")
    }
