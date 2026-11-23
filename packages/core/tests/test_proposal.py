from datetime import UTC, datetime

from sheaf_core import testing as t
from sheaf_core.entry import check_draft
from sheaf_core.mandate import changed_parts, part_digests
from sheaf_core.proposal import STAND_IN_APPROVER, approval_draft

WHEN = datetime(2026, 11, 26, 9, 30, tzinfo=UTC)


def proposal(doc=None, previous=None):
    """A proposal as the gateway keeps it, for the example mandate."""
    doc = doc or t.mandate_document()
    entry = t.config_changed(doc)
    return {
        "chain": doc["chain"],
        "mandate": entry["body"]["mandate"],
        "version": doc["version"],
        "previous": previous,
        "changed": changed_parts(None, doc),
        "parts": part_digests(doc),
        "artefacts": entry["artefacts"],
        "proposed_by": dict(t.PROPOSER),
        "proposed_at": "2026-11-26T09:00:00.000Z",
        "reason": "genesis",
        "expires_at": "2026-12-10T09:00:00.000Z",
        "status": "pending",
    }


def test_the_approval_of_a_proposal_is_its_config_changed():
    draft = approval_draft(proposal(), approver=t.APPROVER["id"], observed_at=WHEN)

    expected = {**t.config_changed(t.mandate_document()), "observed_at": "2026-11-26T09:30:00.000Z"}
    assert draft == expected
    assert check_draft(draft) == []


def test_an_approver_under_a_role_names_it_as_actor_but_not_as_approver():
    draft = approval_draft(
        proposal(), approver="acme-approver-2", role="approver", observed_at=WHEN
    )

    assert draft["actor"] == {"kind": "person", "id": "acme-approver-2", "role": "approver"}
    assert draft["body"]["approved_by"] == {"kind": "person", "id": "acme-approver-2"}
    assert check_draft(draft) == []


def test_a_change_names_the_mandate_it_replaces_without_its_fingerprint():
    previous = {"version": "2026.11.1", "config": "sha256:" + "c" * 64, "mandate": "d" * 64}

    draft = approval_draft(
        proposal(previous=previous), approver="acme-approver-1", observed_at=WHEN
    )

    assert draft["body"]["previous"] == {"version": "2026.11.1", "config": "sha256:" + "c" * 64}


def test_the_stand_in_approver_is_valid_under_either_identifier_choice():
    draft = approval_draft(proposal(), approver=STAND_IN_APPROVER, observed_at=WHEN)

    assert check_draft(draft) == []
    assert STAND_IN_APPROVER.startswith("ps-") and len(STAND_IN_APPROVER) == 35


def test_what_is_shown_is_checked_against_what_is_committed():
    from sheaf_core.proposal import shown_differs

    doc = t.mandate_document()
    assert shown_differs(proposal(doc), doc, None) == []

    other = t.mandate_document(version="2026.11.9")
    other["policy"]["four_eyes"] = False
    assert shown_differs(proposal(doc), other, None) == ["version", "parts"]
    assert shown_differs(proposal(doc), doc, t.mandate_document()) == ["changed", "previous"]
