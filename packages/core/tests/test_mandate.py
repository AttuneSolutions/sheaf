import copy

import pytest

from sheaf_core import testing as t
from sheaf_core.digest import canonical_digest
from sheaf_core.mandate import PARTS, changed_parts, check_mandate, part_digests, permits


def codes(problems):
    return [p.code for p in problems]


def test_the_example_mandate_is_valid():
    assert check_mandate(t.mandate_document()) == []


def test_each_part_digest_is_the_canonical_digest_of_that_part():
    doc = t.mandate_document()

    assert part_digests(doc) == {part: canonical_digest(doc[part]) for part in PARTS}


def test_changing_one_part_changes_only_its_digest():
    old = t.mandate_document()
    new = copy.deepcopy(old)
    new["witness_interval"]["interim_after_sealed"] = True

    before, after = part_digests(old), part_digests(new)
    assert [p for p in PARTS if before[p] != after[p]] == ["witness_interval"]
    assert changed_parts(old, new) == ["witness_interval"]


def test_a_genesis_mandate_changes_every_part():
    assert changed_parts(None, t.mandate_document()) == list(PARTS)


def test_a_mandate_missing_a_part_is_refused():
    doc = t.mandate_document()
    del doc["personal_data"]

    assert codes(check_mandate(doc)) == ["schema"]


def test_a_mandate_may_only_allow_registered_kinds_within_the_registry_limit():
    doc = t.mandate_document()
    doc["policy"]["kinds"]["video.mp4"] = {"max_bytes": 1}
    doc["policy"]["kinds"]["text.plain"] = {"max_bytes": 10 * 1024 * 1024 + 1}

    assert sorted(codes(check_mandate(doc))) == ["kind_limit", "kind_unknown"]


def test_a_mandate_names_a_registry_version_that_exists():
    doc = t.mandate_document(registry={"version": "9.0.0"})

    assert codes(check_mandate(doc)) == ["registry_unknown"]


def test_authorities_are_distinct_and_in_at_least_two_jurisdictions():
    doc = t.mandate_document()
    doc["authorities"]["list"][1]["jurisdiction"] = "CH"
    assert codes(check_mandate(doc)) == ["authorities_one_jurisdiction"]

    doc = t.mandate_document()
    doc["authorities"]["list"][1]["authority"] = "tsa-a"
    assert "authority_duplicate" in codes(check_mandate(doc))


def test_names_within_a_mandate_are_unique():
    doc = t.mandate_document()
    doc["retention"]["classes"].append({"class": "working-file", "period": "P2Y"})
    doc["instructions"].append({"name": "review-instructions", "sha256": t.stand_in("x")})
    doc["policy"]["callers"].append({"id": t.AGENT["id"], "types": ["notice"]})

    assert sorted(codes(check_mandate(doc))) == [
        "caller_duplicate",
        "instructions_duplicate",
        "retention_class_duplicate",
    ]


def test_the_witness_identity_is_not_also_a_caller():
    doc = t.mandate_document()
    doc["policy"]["callers"].append({"id": t.WITNESS["id"], "types": ["notice"]})

    assert codes(check_mandate(doc)) == ["witness_is_caller"]


def test_no_caller_may_be_granted_witness_entries():
    doc = t.mandate_document()
    doc["policy"]["callers"][0]["types"].append("witness.daily")

    assert codes(check_mandate(doc)) == ["schema"]


# -- permits ----------------------------------------------------------------------------------


def test_a_listed_caller_may_write_its_types():
    assert permits(t.mandate_document(), t.AGENT["id"], t.ai_exchange()) == []


def test_an_unlisted_caller_is_refused():
    assert codes(permits(t.mandate_document(), "someone-else", t.notice())) == ["caller_unknown"]


def test_a_caller_may_write_only_its_types():
    decision = t.decision(t.stand_in("x"), actor=t.AGENT)
    problems = permits(t.mandate_document(), t.AGENT["id"], decision)

    assert codes(problems) == ["type_not_permitted"]


def test_only_the_witness_identity_submits_witness_entries():
    doc = t.mandate_document()
    witness = t.examples()["witness.interim"]

    assert permits(doc, t.WITNESS["id"], witness) == []
    assert codes(permits(doc, t.ADMIN["id"], witness)) == ["witness_identity"]
    assert codes(permits(doc, t.WITNESS["id"], t.notice())) == ["type_not_permitted"]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"kind": "image.raster", "media_type": "image/png"}, "kind_not_permitted"),
        ({"bytes": 1024 * 1024 + 1}, "too_large"),
    ],
)
def test_artefacts_must_be_of_a_permitted_kind_and_size(change, code):
    entry = t.artefact_attached({**t.output_ref(), **change})

    assert codes(permits(t.mandate_document(), t.AGENT["id"], entry)) == [code]


def test_a_fraction_in_a_mandate_is_refused_since_its_parts_are_hashed():
    doc = t.mandate_document()
    doc["models"][0]["parameters"]["temperature"] = 0.2

    assert codes(check_mandate(doc)) == ["number"]


def test_a_mandate_too_deep_to_hash_is_reported_not_raised():
    doc = t.mandate_document()
    deep = {}
    for _ in range(1100):
        deep = {"x": deep}
    doc["models"][0]["parameters"] = deep

    assert codes(check_mandate(doc)) == ["too_deep"]


def test_a_mandate_change_is_permitted_whatever_kinds_the_policy_allows():
    # Its artefacts are the mandate itself, so the policy it replaces cannot forbid them.
    doc = t.mandate_document()
    del doc["policy"]["kinds"]["text.markdown"]
    del doc["policy"]["kinds"]["data.json"]

    assert permits(doc, t.APPROVER["id"], t.config_changed(t.mandate_document())) == []


# -- roles ------------------------------------------------------------------------------------


def unrolled(actor):
    return {k: v for k, v in actor.items() if k != "role"}


def test_a_role_grants_its_types_to_a_caller_naming_it():
    assert t.REVIEWER["role"] == "reviewer"
    assert permits(t.mandate_document(), t.REVIEWER["id"], t.decision(t.stand_in("x"))) == []


def test_a_caller_neither_listed_nor_naming_a_role_is_unknown():
    decision = t.decision(t.stand_in("x"), actor=unrolled(t.REVIEWER))

    assert codes(permits(t.mandate_document(), t.REVIEWER["id"], decision)) == ["caller_unknown"]


def test_a_role_not_in_the_policy_grants_nothing():
    decision = t.decision(t.stand_in("x"), actor={**t.REVIEWER, "role": "auditor"})
    problems = permits(t.mandate_document(), t.REVIEWER["id"], decision)

    assert {(p.code, p.path) for p in problems} == {("role_unknown", "$.actor.role")}


def test_a_role_grants_only_its_types():
    entry = t.notice(actor=t.REVIEWER)

    assert codes(permits(t.mandate_document(), t.REVIEWER["id"], entry)) == ["type_not_permitted"]


def test_a_role_is_listed_once():
    doc = t.mandate_document()
    doc["policy"]["roles"].append(copy.deepcopy(doc["policy"]["roles"][0]))

    assert "role_duplicate" in codes(check_mandate(doc))


def test_the_policy_always_says_which_roles_it_grants():
    doc = t.mandate_document()
    del doc["policy"]["roles"]

    assert codes(check_mandate(doc)) == ["schema"]


# -- tenant schemas ---------------------------------------------------------------------------


def test_the_mandate_names_its_tenant_schemas():
    assert "schemas" in PARTS
    assert check_mandate(t.mandate_document()) == []


def test_a_tenant_schema_is_named_once():
    doc = t.mandate_document()
    doc["schemas"].append(copy.deepcopy(doc["schemas"][0]))

    assert "schema_duplicate" in codes(check_mandate(doc))


def test_a_tenant_schema_id_belongs_to_the_tenant():
    doc = t.mandate_document()
    doc["schemas"][0]["id"] = "other.findings/1"

    assert codes(check_mandate(doc)) == ["schema_tenant"]


def test_sensitivity_names_app_roles_not_group_names():
    doc = t.mandate_document()
    doc["policy"]["sensitivity"]["client_pii"] = ["Case Reviewers (London)"]

    assert codes(check_mandate(doc)) == ["schema"]


def test_the_policy_says_whether_a_proposer_may_approve():
    doc = t.mandate_document()
    del doc["policy"]["four_eyes"]

    assert codes(check_mandate(doc)) == ["schema"]
