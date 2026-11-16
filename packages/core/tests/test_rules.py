import copy
import json
from datetime import UTC, date, datetime

import pytest

from sheaf_core import testing as t
from sheaf_core.chain import link_entry
from sheaf_core.digest import artefact_sha256


@pytest.fixture
def s():
    """A chain with its genesis mandate in force and the example artefacts uploaded."""
    scenario = t.Scenario()
    scenario.genesis()
    scenario.upload_standard()
    return scenario


@pytest.fixture
def fresh():
    return t.Scenario()


# -- genesis and the mandate in force ---------------------------------------------------------


def test_the_first_entry_of_a_chain_is_a_config_changed(fresh):
    fresh.upload_standard()

    assert fresh.codes(t.notice(dossier=None)) == ["genesis_required"]
    assert fresh.codes(t.opened("sha256:" + "a" * 64)) == ["genesis_required"]


def test_the_genesis_config_changed_has_no_previous_version(fresh):
    entry = fresh.config(previous={"version": "0", "config": "sha256:" + "a" * 64})

    assert "genesis_previous" in fresh.codes(entry)


def test_a_mandate_applies_only_after_its_interim_witness(fresh):
    config = fresh.commit(fresh.config())

    assert fresh.state.in_force is None
    assert fresh.state.pending.config == config["hash"]
    assert fresh.codes(t.opened(config["hash"])) == ["mandate_not_in_force"]

    fresh.commit(fresh.interim())

    assert fresh.state.in_force.config == config["hash"]
    assert fresh.state.pending is None


def test_a_notice_may_be_written_while_a_mandate_waits(fresh):
    fresh.commit(fresh.config())
    entry = t.notice(dossier=None)
    entry["body"] = {"event": "authority_unavailable", "detail": "timeout", "authority": "tsa-b"}

    assert fresh.problems(entry) == []


def test_an_interim_witness_follows_a_config_changed(s):
    entry = s.open()

    assert s.codes(s.interim(entry["seq"])) == ["interim_target"]


def test_an_entry_is_interim_witnessed_once(s):
    assert s.codes(s.interim(1)) == ["interim_duplicate"]


def test_interim_after_sealed_is_the_tenants_choice(fresh):
    fresh.genesis(
        t.mandate_document(witness_interval={"interval": "daily", "interim_after_sealed": True})
    )
    fresh.open()
    seal = fresh.commit(t.sealed(2, 0))

    assert fresh.problems(fresh.interim(seal["seq"])) == []


def test_a_new_mandate_names_the_one_it_replaces(s):
    old = t.mandate_document()
    new = t.mandate_document(
        version="2026.12.1", witness_interval={"interval": "daily", "interim_after_sealed": True}
    )
    genesis = s.entries[0]

    assert "previous_required" in s.codes(s.config(new, old=old))
    wrong = s.config(
        new, old=old, previous={"version": old["version"], "config": s.entries[1]["hash"]}
    )
    assert "previous_mismatch" in s.codes(wrong)

    right = s.config(new, old=old, previous={"version": old["version"], "config": genesis["hash"]})
    assert s.problems(right) == []
    config = s.commit(right)
    assert s.state.pending.config == config["hash"]
    assert s.state.in_force.config == genesis["hash"]


def test_one_mandate_change_at_a_time(s):
    old = t.mandate_document()
    previous = {"version": old["version"], "config": s.entries[0]["hash"]}
    first = t.mandate_document(version="2026.12.1", gateway={"image": "sha256:" + "1" * 64})
    s.commit(s.config(first, old=old, previous=previous))
    second = t.mandate_document(version="2026.12.2", gateway={"image": "sha256:" + "2" * 64})

    assert "mandate_pending" in s.codes(s.config(second, old=old, previous=previous))


def test_changed_lists_exactly_the_parts_that_changed(s):
    old = t.mandate_document()
    new = t.mandate_document(version="2026.12.1", gateway={"image": "sha256:" + "1" * 64})
    entry = s.config(
        new, old=old, previous={"version": old["version"], "config": s.entries[0]["hash"]}
    )
    entry["body"]["changed"] = ["gateway", "policy"]

    assert s.codes(entry) == ["changed_mismatch"]


def test_a_mandate_that_changes_nothing_is_refused(s):
    old = t.mandate_document()
    entry = s.config(
        old, old=old, previous={"version": old["version"], "config": s.entries[0]["hash"]}
    )
    entry["body"]["changed"] = ["gateway"]

    assert "changed_mismatch" in s.codes(entry)


def test_part_digests_are_recomputed_from_the_mandate(fresh):
    entry = fresh.config()
    entry["body"]["parts"]["policy"] = "sha256:" + "0" * 64

    assert fresh.codes(entry) == ["part_digest_mismatch"]


def test_the_mandate_is_attached_whole(fresh):
    entry = fresh.config()
    entry["artefacts"] = entry["artefacts"][:1]

    assert fresh.codes(entry) == ["mandate_incomplete"]


def test_the_mandate_attaches_nothing_it_does_not_name(fresh):
    extra = b"# Unused\n"
    entry = fresh.config(instructions=(t.INSTRUCTIONS, extra))

    assert fresh.codes(entry) == ["mandate_incomplete"]


def test_the_mandate_must_be_valid_and_for_this_chain(fresh):
    invalid = t.mandate_document()
    del invalid["gateway"]
    other = t.mandate_document(chain="acme/other")

    assert "mandate_invalid" in fresh.codes(fresh.config(invalid))
    assert "mandate_chain" in fresh.codes(fresh.config(other))


def test_the_version_in_the_body_is_the_mandates(fresh):
    entry = fresh.config()
    entry["body"]["version"] = "other"

    assert fresh.codes(entry) == ["mandate_version"]


def test_the_mandate_artefact_declares_the_mandate_schema(fresh):
    doc = t.mandate_document()
    doc["$schema"] = "acme.findings/1"

    assert "mandate_schema" in fresh.codes(fresh.config(doc))


# -- dossiers ---------------------------------------------------------------------------------


def test_a_dossier_opens_under_the_mandate_in_force(s):
    assert s.problems(t.opened(s.entries[0]["hash"])) == []
    assert s.codes(t.opened(s.entries[1]["hash"])) == ["mandate_not_in_force"]


def test_a_dossier_records_the_policys_source_capture(s):
    assert s.codes(t.opened(s.entries[0]["hash"], source_capture="copy")) == [
        "source_capture_mismatch"
    ]


def test_a_dossiers_retention_class_is_in_the_mandate(s):
    entry = t.opened(
        s.entries[0]["hash"], retention={"class": "forever", "min_until": "2099-01-01"}
    )

    assert s.codes(entry) == ["retention_class_unknown"]


def test_a_dossier_opens_once(s):
    s.open()

    assert s.codes(t.opened(s.entries[0]["hash"])) == ["dossier_exists"]


def test_entries_go_into_an_open_dossier(s):
    assert s.codes(t.notice()) == ["dossier_unknown"]
    s.open()
    assert s.problems(t.notice()) == []
    s.commit(t.sealed(2, 0))
    assert s.codes(t.notice()) == ["dossier_sealed"]


def test_every_entry_in_a_dossier_has_its_subject_and_retention(s):
    s.open()
    other_subject = t.notice(subject={**t.SUBJECT, "id": "C999"})
    other_retention = t.notice(retention={**t.RETENTION, "min_until": "2040-01-01"})

    assert s.codes(other_subject) == ["subject_mismatch"]
    assert s.codes(other_retention) == ["retention_mismatch"]


def test_a_dossier_is_sealed_with_its_true_counts(s):
    s.open()
    s.commit(t.ai_exchange())
    s.commit(t.finding_drafted())

    assert s.codes(t.sealed(3, 3)) == ["count_mismatch"]
    assert s.codes(t.sealed(4, 2)) == ["count_mismatch"]
    assert s.problems(t.sealed(4, 3)) == []


# -- artefacts --------------------------------------------------------------------------------


def test_an_artefact_must_have_been_uploaded(s):
    s.open()
    unknown = t.ref(b"never uploaded", role="x", kind="text.plain", media_type="text/plain")

    assert s.codes(t.artefact_attached(unknown)) == ["artefact_unknown"]


def test_an_artefact_reference_matches_its_upload(s):
    s.open()
    claimed = {**t.output_ref(), "sensitivity": "client_pii"}

    assert s.codes(t.artefact_attached(claimed)) == ["artefact_mismatch"]


def test_a_rendition_is_of_something_in_the_dossier(s):
    s.open()
    pdf = b"%PDF-1.7 rendition"
    s.upload(pdf, kind="document.rendition", media_type="application/pdf")
    rendition = t.ref(
        pdf,
        role="rendition",
        kind="document.rendition",
        media_type="application/pdf",
        rendition_of=artefact_sha256(t.OUTPUT),
    )

    assert s.codes(t.artefact_attached(rendition)) == ["rendition_unknown"]
    s.commit(t.output_produced())
    assert s.problems(t.artefact_attached(rendition)) == []


def test_source_capture_policy_decides_whether_a_source_is_copied(fresh):
    fresh.upload_standard()
    fresh.genesis(
        t.mandate_document(policy={**t.mandate_document()["policy"], "source_capture": "copy"})
    )
    fresh.open(source_capture="copy")

    assert fresh.codes(t.source_read()) == ["source_not_copied"]
    assert fresh.problems(t.source_read(copy=True)) == []


def test_under_the_reference_policy_a_source_is_not_copied(s):
    s.open()

    assert s.codes(t.source_read(copy=True)) == ["source_copied"]
    assert s.problems(t.source_read()) == []


def test_findings_declare_the_schema_the_entry_names(s):
    s.open()

    assert s.codes(t.finding_drafted(schema="acme.findings/2")) == ["findings_schema_mismatch"]


# -- decisions and corrections ----------------------------------------------------------------


def test_a_decision_names_something_in_this_dossier(s):
    s.open()
    s.commit(t.finding_drafted())
    s.commit(t.source_read())

    assert s.problems(t.decision(artefact_sha256(t.FINDINGS))) == []
    assert s.problems(t.decision(artefact_sha256(t.SOURCE))) == []
    assert s.codes(t.decision(t.stand_in("elsewhere"))) == ["decided_unknown"]


def test_a_decision_cannot_name_something_in_another_dossier(s):
    s.open()
    s.commit(t.finding_drafted())
    s.open(dossier="cr-20261126-8R3NAL")

    assert s.codes(t.decision(artefact_sha256(t.FINDINGS), dossier="cr-20261126-8R3NAL")) == [
        "decided_unknown"
    ]


def test_a_correction_names_an_entry_in_a_dossier(s):
    opened = s.open()

    assert s.problems(t.correction(opened["hash"])) == []
    assert s.codes(t.correction("sha256:" + "0" * 64)) == ["target_unknown"]
    assert s.codes(t.correction(s.entries[0]["hash"])) == ["target_chain_level"]


# -- witnesses --------------------------------------------------------------------------------


def test_a_witness_comes_from_the_witness_identity(s):
    entry = s.interim()
    entry["actor"] = t.AGENT

    assert "witness_identity" in s.codes(entry)


def test_a_witness_is_signed_with_the_mandates_key(fresh):
    fresh.commit(fresh.config())

    assert fresh.codes(fresh.interim(key_id="acme-witness/0000")) == ["witness_key_mismatch"]


def test_a_witness_lists_the_mandates_authorities(fresh):
    fresh.commit(fresh.config())
    entry = fresh.interim()
    body = t.witness(
        "interim",
        1,
        fresh.entries[0]["hash"],
        authorities=t.results(authorities=(("tsa-a", "CH"), ("tsa-c", "JP"))),
    )
    entry["body"] = body

    assert fresh.codes(entry) == ["authorities_mismatch"]


def test_a_witness_names_the_hash_at_its_seq(fresh):
    fresh.commit(fresh.config())
    wrong = t.witness_draft(t.witness("interim", 1, "sha256:" + "0" * 64))
    ahead = t.witness_draft(t.witness("interim", 2, "sha256:" + "0" * 64))

    assert fresh.codes(wrong) == ["witness_hash_mismatch"]
    assert fresh.codes(ahead) == ["witness_ahead"]


def test_daily_witnesses_cover_every_day_from_genesis(s):
    s.now = datetime(2026, 11, 28, 0, 5, tzinfo=UTC)

    assert s.codes(s.daily(date(2026, 11, 27))) == ["interval_gap"]
    assert s.problems(s.daily(date(2026, 11, 26))) == []
    s.commit(s.daily(date(2026, 11, 26)))
    assert s.codes(s.daily(date(2026, 11, 26))) == ["interval_gap"]
    assert s.problems(s.daily(date(2026, 11, 27))) == []


def test_a_day_is_witnessed_after_it_ends(s):
    assert s.codes(s.daily(date(2026, 11, 26))) == ["interval_not_ended"]


def test_a_daily_witness_ends_at_the_last_entry_of_its_day(s):
    s.now = datetime(2026, 11, 26, 23, 59, 59, tzinfo=UTC)
    s.open()
    s.now = datetime(2026, 11, 27, 0, 0, 1, tzinfo=UTC)
    s.commit(t.notice())
    entry = s.daily(date(2026, 11, 26))
    last = s.entries[-1]
    late = t.witness_draft(
        t.witness(
            "daily", last["seq"], last["hash"], interval=tuple(entry["body"]["interval"].values())
        )
    )
    early_seq = s.entries[-3]
    early = t.witness_draft(
        t.witness(
            "daily",
            early_seq["seq"],
            early_seq["hash"],
            interval=tuple(entry["body"]["interval"].values()),
        )
    )

    assert s.problems(entry) == []
    assert s.codes(late) == ["witness_boundary"]
    assert s.codes(early) == ["witness_boundary"]


# -- retention --------------------------------------------------------------------------------


def expire_scenario():
    s = t.Scenario()
    s.genesis()
    s.upload_standard()
    s.open()
    s.commit(t.finding_drafted())
    s.commit(t.sealed(3, 1))
    return s


def test_a_dossier_expires_only_after_its_retention_passes():
    s = expire_scenario()

    assert s.codes(t.retention_expired(dossiers=[t.DOSSIER])) == ["retention_not_passed"]
    s.now = datetime(2033, 11, 27, tzinfo=UTC)
    assert s.problems(t.retention_expired(dossiers=[t.DOSSIER])) == []


def test_min_until_covers_every_listed_dossier():
    s = expire_scenario()
    s.now = datetime(2034, 1, 1, tzinfo=UTC)

    entry = t.retention_expired(dossiers=[t.DOSSIER], min_until="2033-01-01")
    assert s.codes(entry) == ["retention_not_passed"]


def test_an_open_or_unknown_dossier_does_not_expire():
    s = expire_scenario()
    s.open(dossier="cr-20261126-8R3NAL")
    s.now = datetime(2034, 1, 1, tzinfo=UTC)

    assert s.codes(t.retention_expired(dossiers=["cr-20261126-8R3NAL"])) == ["dossier_open"]
    assert s.codes(t.retention_expired(dossiers=["cr-x"])) == ["dossier_unknown"]


def test_an_artefact_expires_only_when_no_live_dossier_refers_to_it():
    s = expire_scenario()
    s.open(dossier="cr-20261126-8R3NAL")
    s.commit(t.finding_drafted(dossier="cr-20261126-8R3NAL"))
    s.now = datetime(2034, 1, 1, tzinfo=UTC)
    findings = artefact_sha256(t.FINDINGS)

    assert s.codes(t.retention_expired(dossiers=[t.DOSSIER], artefacts=[findings])) == [
        "artefact_live"
    ]


def test_mandate_artefacts_never_expire():
    s = expire_scenario()
    s.now = datetime(2034, 1, 1, tzinfo=UTC)
    mandate = s.entries[0]["body"]["mandate"]

    assert s.codes(t.retention_expired(artefacts=[mandate])) == ["artefact_chain_level"]


def test_after_expiry_nothing_refers_to_what_expired():
    s = expire_scenario()
    s.now = datetime(2034, 1, 1, tzinfo=UTC)
    findings = artefact_sha256(t.FINDINGS)
    s.commit(t.retention_expired(dossiers=[t.DOSSIER], artefacts=[findings]))
    s.open(dossier="cr-20340101-9S4OBM", retention={**t.RETENTION, "min_until": "2041-01-01"})

    later = {
        "dossier": "cr-20340101-9S4OBM",
        "retention": {**t.RETENTION, "min_until": "2041-01-01"},
    }

    assert s.codes(t.finding_drafted(**later)) == ["artefact_expired"]
    assert s.codes(t.retention_expired(dossiers=[t.DOSSIER])) == ["already_expired"]
    assert s.codes(t.notice()) == ["dossier_expired"]
    assert s.codes(t.correction(s.entries[3]["hash"], **later)) == ["target_expired"]


# -- apply ------------------------------------------------------------------------------------


def test_apply_takes_entries_in_chain_order_only(fresh):
    config = fresh.config()
    out_of_order = link_entry(config, seq=2, prev="sha256:" + "0" * 64, committed_at=t.OBSERVED)

    with pytest.raises(ValueError, match="seq"):
        fresh.state.apply(out_of_order, artefacts=fresh.store)


def test_apply_refuses_an_entry_that_does_not_follow_the_head(s):
    entry = link_entry(
        t.notice(dossier=None), seq=3, prev="sha256:" + "0" * 64, committed_at=t.OBSERVED
    )

    with pytest.raises(ValueError, match="prev"):
        s.state.apply(entry, artefacts=s.store)


def test_check_does_not_change_the_state(s):
    before = copy.deepcopy(s.state.head)
    s.problems(t.opened(s.entries[0]["hash"]))

    assert s.state.head == before


def test_now_must_be_timezone_aware(s):
    with pytest.raises(ValueError, match="aware"):
        s.state.check(t.notice(dossier=None), artefacts=s.store, now=datetime(2026, 11, 26))


def test_rules_run_only_on_well_formed_drafts(s):
    entry = t.notice()
    entry["actor"] = "nobody"

    assert s.codes(entry) == ["schema"]


def test_a_draft_for_another_chain_is_refused(s):
    entry = t.notice(dossier=None)
    entry["chain"] = "acme/other"

    assert s.codes(entry) == ["chain_mismatch"]


# -- decisions of 2026-11-16 ------------------------------------------------------------------


def pending_change(s, **parts):
    old = t.mandate_document()
    new = t.mandate_document(version="2026.12.1", **parts)
    previous = {"version": old["version"], "config": s.entries[0]["hash"]}
    return s.commit(s.config(new, old=old, previous=previous))


def test_while_a_change_waits_the_previous_mandate_stays_in_force(s):
    s.open()
    pending = pending_change(s, gateway={"image": "sha256:" + "1" * 64})

    assert s.problems(t.ai_exchange()) == []
    assert s.codes(t.opened(pending["hash"], dossier="cr-20261126-8R3NAL")) == [
        "mandate_not_in_force"
    ]


def test_a_daily_witness_may_be_written_while_the_genesis_mandate_waits(fresh):
    fresh.commit(fresh.config())
    fresh.now = datetime(2026, 11, 27, 0, 5, tzinfo=UTC)

    assert fresh.problems(fresh.daily(date(2026, 11, 26))) == []


def test_during_a_change_daily_witnesses_use_the_key_in_force(s):
    new_key = {**t.mandate_document()["witness_key"], "key_id": "acme-witness/4a2d"}
    config = pending_change(s, witness_key=new_key)
    s.now = datetime(2026, 11, 27, 0, 5, tzinfo=UTC)

    assert s.problems(s.daily(date(2026, 11, 26))) == []
    assert s.codes(s.daily(date(2026, 11, 26), key_id="acme-witness/4a2d")) == [
        "witness_key_mismatch"
    ]
    assert s.problems(s.interim(config["seq"], key_id="acme-witness/4a2d")) == []
    assert s.codes(s.interim(config["seq"])) == ["witness_key_mismatch"]


def test_a_correction_elsewhere_targets_a_sealed_dossier_with_the_same_subject(s):
    first = s.open()
    second = "cr-20261126-8R3NAL"
    s.open(dossier=second)
    elsewhere = {"dossier": second}

    assert s.codes(t.correction(first["hash"], **elsewhere)) == ["target_open_elsewhere"]
    s.commit(t.sealed(2, 0))
    assert s.problems(t.correction(first["hash"], **elsewhere)) == []

    other = "cr-20261126-9S4OBM"
    other_subject = {**t.SUBJECT, "id": "C999"}
    s.open(dossier=other, subject=other_subject)
    assert s.codes(t.correction(first["hash"], dossier=other, subject=other_subject)) == [
        "target_subject"
    ]


def test_apply_changes_nothing_when_it_refuses(s):
    head = s.state.head
    stray = link_entry(
        t.notice(dossier="cr-never-opened"), seq=3, prev=head[1], committed_at=t.OBSERVED
    )

    with pytest.raises(ValueError, match="dossier"):
        s.state.apply(stray, artefacts=s.store)
    assert s.state.head == head

    doc = t.mandate_document(version="2026.12.1", gateway={"image": "sha256:" + "1" * 64})
    unuploaded = t.config_changed(
        doc,
        old=t.mandate_document(),
        previous={"version": "2026.11.1", "config": s.entries[0]["hash"]},
    )
    linked = link_entry(unuploaded, seq=3, prev=head[1], committed_at=t.OBSERVED)
    with pytest.raises(ValueError, match="mandate"):
        s.state.apply(linked, artefacts=s.store)
    assert s.state.head == head and s.state.pending is None


# -- tenant schemas ---------------------------------------------------------------------------


def test_a_mandate_attaches_every_schema_it_names(fresh):
    assert fresh.codes(fresh.config(schemas=())) == ["mandate_incomplete"]


def test_a_mandate_schema_is_the_one_its_id_names(fresh):
    other = copy.deepcopy(t.FINDINGS_SCHEMA_DOC)
    other["$id"] = "urn:sheaf:acme.findings/2"
    data = json.dumps(other).encode()
    doc = t.mandate_document()
    doc["schemas"][0]["sha256"] = artefact_sha256(data)

    assert fresh.codes(fresh.config(doc, schemas=(data,))) == ["schema_id_mismatch"]


def test_findings_name_a_schema_of_the_mandate_in_force(s):
    s.open()
    findings = b'{"$schema":"acme.findings/2","findings":[]}'
    s.upload(findings, kind="data.json", media_type="application/json")
    entry = t.draft(
        "finding.drafted",
        {"schema": "acme.findings/2"},
        artefacts=[
            t.ref(findings, role="findings", kind="data.json", media_type="application/json")
        ],
    )

    assert s.codes(entry) == ["schema_unknown"]


def test_findings_satisfy_their_schema(s):
    s.open()
    findings = b'{"$schema":"acme.findings/1","findings":[1]}'
    s.upload(findings, kind="data.json", media_type="application/json")
    entry = t.draft(
        "finding.drafted",
        {"schema": "acme.findings/1"},
        artefacts=[
            t.ref(findings, role="findings", kind="data.json", media_type="application/json")
        ],
    )

    assert s.codes(entry) == ["findings_invalid"]


# -- trust files ------------------------------------------------------------------------------


def test_a_mandate_applies_only_once_its_trust_files_are_stored(fresh):
    problems = fresh.problems(fresh.config(trust=False))

    assert {p.code for p in problems} == {"trust_missing"}
    assert len(problems) == 3  # the witness key and each authority's root


# -- pseudonymised identifiers (5.7) -----------------------------------------------------------

PSEUDO_APPROVER = {"kind": "person", "id": "ps-" + "a" * 32}
PSEUDO_SUBJECT = {**t.SUBJECT, "id": "ps-" + "b" * 32}


def pseudonymised_doc(**overrides):
    doc = t.mandate_document(
        personal_data={"identifiers": "pseudonymised", "basis": "Staff and clients pseudonymised."},
        **overrides,
    )
    doc["authorities"]["assessment"]["by"] = PSEUDO_APPROVER
    return doc


def pseudonymised_genesis(scenario, doc=None, approver=PSEUDO_APPROVER):
    entry = scenario.config(doc or pseudonymised_doc())
    entry["actor"], entry["body"]["approved_by"] = dict(approver), dict(approver)
    return entry


def test_under_pseudonyms_the_approver_is_named_by_pseudonym(fresh):
    clear = {"kind": "person", "id": "acme-approver-1"}

    assert fresh.codes(pseudonymised_genesis(fresh, approver=clear)) == [
        "identifier_not_pseudonymised"
    ]
    assert fresh.codes(pseudonymised_genesis(fresh)) == []


def test_under_pseudonyms_the_assessor_is_named_by_pseudonym(fresh):
    doc = pseudonymised_doc()
    doc["authorities"]["assessment"]["by"] = {"kind": "person", "id": "acme-approver-1"}

    assert fresh.codes(pseudonymised_genesis(fresh, doc)) == ["identifier_not_pseudonymised"]


def test_under_pseudonyms_a_subject_and_a_reviewer_are_named_by_pseudonym(fresh):
    fresh.commit(pseudonymised_genesis(fresh))
    fresh.commit(fresh.interim())
    fresh.upload_standard()
    mandate = fresh.state.in_force.config

    assert fresh.codes(t.opened(mandate)) == ["identifier_not_pseudonymised"]
    fresh.commit(t.opened(mandate, subject=PSEUDO_SUBJECT))
    fresh.commit(t.ai_exchange(subject=PSEUDO_SUBJECT))
    decided = t.artefact_sha256(t.RESPONSE)
    assert fresh.codes(t.decision(decided, subject=PSEUDO_SUBJECT)) == [
        "identifier_not_pseudonymised"
    ]
    reviewer = {"kind": "person", "id": "ps-" + "c" * 32, "role": "reviewer"}
    assert fresh.codes(t.decision(decided, subject=PSEUDO_SUBJECT, actor=reviewer)) == []
