import base64
import copy
import hashlib

import pytest

from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.canonical import canonicalize
from sheaf_core.witness import (
    IMPRINT_OVER,
    AuthorityResult,
    check_witness,
    imprint,
    imprint_bytes,
    signing_input,
    summarise,
    time_attestation,
)

LAST = "sha256:" + "a" * 64
DAY = ("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z")


def daily(**kw):
    return t.witness("daily", 18342, LAST, interval=DAY, **kw)


def codes(problems):
    return [p.code for p in problems]


def obtained(name, jurisdiction):
    return AuthorityResult(
        authority=name,
        jurisdiction=jurisdiction,
        obtained=True,
        qualified=False,
        gen_time="2026-11-27T00:03:12Z",
        token_sha256=t.stand_in(name),
    )


def missed(name, jurisdiction):
    return AuthorityResult(
        authority=name,
        jurisdiction=jurisdiction,
        obtained=False,
        unavailable_reason="timeout after 6 h of retries",
    )


def test_signing_input_is_canonical_witness_without_signature_or_attestation():
    witness = daily()
    unsigned = {k: v for k, v in witness.items() if k not in ("signature", "time_attestation")}

    assert signing_input(witness) == canonicalize(unsigned)
    assert b"signature" not in signing_input(witness)


def test_signing_input_is_the_same_before_and_after_signing():
    witness = daily()
    unsigned = {k: v for k, v in witness.items() if k not in ("signature", "time_attestation")}

    assert signing_input(unsigned) == signing_input(witness)


def test_imprint_covers_the_signature_but_not_the_attestation():
    witness = daily()
    without = {k: v for k, v in witness.items() if k != "time_attestation"}

    assert imprint(witness) == "sha256:" + hashlib.sha256(canonicalize(without)).hexdigest()
    assert imprint({**witness, "signature": "b3RoZXI"}) != imprint(witness)
    assert imprint({**witness, "time_attestation": {}}) == imprint(witness)


def test_an_unsigned_witness_has_no_imprint():
    witness = daily()
    del witness["signature"]

    with pytest.raises(ValueError, match="signature"):
        imprint(witness)


def test_imprint_bytes_are_the_32_bytes_sent_to_the_authorities():
    witness = daily()

    assert imprint_bytes(witness) == bytes.fromhex(imprint(witness).removeprefix("sha256:"))
    assert len(imprint_bytes(witness)) == 32


@pytest.mark.parametrize(
    ("results", "count", "jurisdictions", "distinct"),
    [
        ([obtained("tsa-a", "CH"), obtained("tsa-b", "JP")], 2, ["CH", "JP"], True),
        ([obtained("tsa-b", "JP"), obtained("tsa-a", "CH")], 2, ["CH", "JP"], True),
        ([obtained("tsa-a", "CH"), missed("tsa-b", "JP")], 1, ["CH"], False),
        ([obtained("tsa-a", "CH"), obtained("tsa-c", "CH")], 2, ["CH"], False),
        ([missed("tsa-a", "CH"), missed("tsa-b", "JP")], 0, [], False),
    ],
)
def test_summary_is_a_fact_about_the_authorities_that_attested(
    results, count, jurisdictions, distinct
):
    assert summarise(results) == {
        "attested_count": count,
        "attested_jurisdictions": jurisdictions,
        "distinct_jurisdictions": distinct,
    }


def test_time_attestation_lists_every_authority_asked_in_order():
    witness = daily()
    block = time_attestation(witness, [obtained("tsa-a", "CH"), missed("tsa-b", "JP")])

    assert block["imprint"] == imprint(witness)
    assert block["imprint_over"] == IMPRINT_OVER
    assert block["authorities"] == [
        {
            "authority": "tsa-a",
            "jurisdiction": "CH",
            "obtained": True,
            "qualified": False,
            "gen_time": "2026-11-27T00:03:12Z",
            "token_sha256": t.stand_in("tsa-a"),
        },
        {
            "authority": "tsa-b",
            "jurisdiction": "JP",
            "obtained": False,
            "unavailable_reason": "timeout after 6 h of retries",
        },
    ]
    assert block["attested_count"] == 1


def test_an_authority_result_is_either_a_token_or_a_reason():
    with pytest.raises(ValueError):
        AuthorityResult(authority="tsa-a", jurisdiction="CH", obtained=True)
    with pytest.raises(ValueError):
        AuthorityResult(authority="tsa-a", jurisdiction="CH", obtained=False)
    with pytest.raises(ValueError):
        AuthorityResult(
            authority="tsa-a",
            jurisdiction="CH",
            obtained=False,
            qualified=False,
            unavailable_reason="x",
        )


def test_a_well_formed_witness_has_no_problems():
    assert check_witness(daily()) == []
    assert check_witness(t.witness("interim", 7, LAST)) == []
    assert check_witness(daily(authorities=[obtained("tsa-a", "CH"), missed("tsa-b", "JP")])) == []


def test_a_witness_edited_after_stamping_no_longer_matches_its_imprint():
    witness = daily()
    witness["last_seq"] = 18343

    assert codes(check_witness(witness)) == ["imprint_mismatch"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attested_count", 1),
        ("attested_jurisdictions", ["JP", "CH"]),
        ("distinct_jurisdictions", False),
    ],
)
def test_derived_fields_must_agree_with_the_authorities_listed(field, value):
    witness = daily()
    witness["time_attestation"][field] = value

    assert codes(check_witness(witness)) == ["attestation_inconsistent"]


def test_an_authority_is_listed_once():
    witness = daily(authorities=[obtained("tsa-a", "CH"), obtained("tsa-a", "CH")])

    assert "authority_duplicate" in codes(check_witness(witness))


def test_an_authority_not_obtained_claims_no_qualification_or_time():
    witness = daily(authorities=[obtained("tsa-a", "CH"), missed("tsa-b", "JP")])
    witness["time_attestation"]["authorities"][1]["qualified"] = False

    assert codes(check_witness(witness)) == ["schema"]


def test_an_obtained_authority_names_its_token():
    witness = daily()
    del witness["time_attestation"]["authorities"][0]["token_sha256"]

    assert codes(check_witness(witness)) == ["schema"]


def test_a_daily_witness_has_an_interval_and_an_interim_does_not():
    no_interval = daily()
    del no_interval["interval"]
    with_interval = copy.deepcopy(t.witness("interim", 7, LAST))
    with_interval["interval"] = {"from": DAY[0], "to": DAY[1]}

    assert codes(check_witness(no_interval)) == ["schema"]
    assert codes(check_witness(with_interval)) == ["schema"]


@pytest.mark.parametrize(
    "interval",
    [
        ("2026-11-26T00:00:00Z", "2026-11-28T00:00:00Z"),
        ("2026-11-26T01:00:00Z", "2026-11-27T01:00:00Z"),
        ("2026-11-27T00:00:00Z", "2026-11-26T00:00:00Z"),
    ],
)
def test_a_daily_interval_is_one_utc_day(interval):
    witness = t.witness("daily", 18342, LAST, interval=interval)

    assert codes(check_witness(witness)) == ["interval_invalid"]


def test_imprint_over_says_what_the_stamp_binds():
    witness = daily()
    witness["time_attestation"]["imprint_over"] = "something else"

    assert codes(check_witness(witness)) == ["schema"]


def test_daily_bounds_are_written_as_exact_midnights():
    # 900 ns past midnight truncates to midnight in Python; another verifier would refuse it.
    late = ("2026-11-26T00:00:00.0000009Z", "2026-11-27T00:00:00.0000009Z")

    assert codes(check_witness(t.witness("daily", 18342, LAST, interval=late))) == [
        "interval_invalid"
    ]


# -- the witness signature (ES256) ------------------------------------------------------------

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from sheaf_core.witness import public_key_sha256, sign_es256, verify_signature  # noqa: E402


def keypair(curve=None):
    key = ec.generate_private_key(curve or ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, pem


def signed(key):
    witness = daily()
    witness["signature"] = sign_es256(key, signing_input(witness))
    return witness


def test_a_witness_signed_with_the_mandate_key_verifies():
    key, pem = keypair()

    assert verify_signature(signed(key), pem) == []


def test_an_es256_signature_is_64_bytes_in_unpadded_base64url():
    key, _ = keypair()
    signature = signed(key)["signature"]

    assert "=" not in signature and "+" not in signature and "/" not in signature
    assert len(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))) == 64


def test_a_witness_changed_after_signing_does_not_verify():
    key, pem = keypair()
    witness = signed(key)
    witness["last_seq"] += 1

    assert codes(verify_signature(witness, pem)) == ["witness_signature"]


def test_a_signature_by_another_key_does_not_verify():
    key, _ = keypair()
    _, other = keypair()

    assert codes(verify_signature(signed(key), other)) == ["witness_signature"]


def test_the_witness_key_is_p256():
    key, _ = keypair()
    _, p384 = keypair(ec.SECP384R1())

    assert codes(verify_signature(signed(key), p384)) == ["witness_key_invalid"]


def test_the_mandate_names_the_key_by_the_sha256_of_its_pem():
    _, pem = keypair()

    assert public_key_sha256(pem) == hashlib.sha256(pem).hexdigest()


# -- the attestation against the tokens and trust/ (7.2 step 5) --------------------------------

from sheaf_core.witness import check_attestation  # noqa: E402


def attestation(witness, tokens, *, trust=None, mandate=None):
    files = t.trust_files() if trust is None else trust
    return check_attestation(
        witness, mandate or t.mandate_document(), tokens=tokens, trust=files.get
    )


def test_a_signed_witness_with_every_token_passes():
    witness, tokens = t.attested("daily", 18342, LAST, interval=DAY)

    assert attestation(witness, tokens) == []


def test_an_authority_that_did_not_attest_sends_no_token():
    witness, tokens = t.attested("interim", 7, LAST, down={"tsa-b"})

    assert attestation(witness, tokens) == []
    assert codes(attestation(witness, {**tokens, "tsa-b": tokens["tsa-a"]})) == ["token_unexpected"]


def test_every_obtained_token_is_supplied():
    witness, tokens = t.attested("interim", 7, LAST)
    del tokens["tsa-b"]

    assert codes(attestation(witness, tokens)) == ["token_missing"]


def test_a_token_is_the_one_whose_sha256_the_witness_lists():
    witness, tokens = t.attested("interim", 7, LAST)
    tokens["tsa-a"], tokens["tsa-b"] = tokens["tsa-b"], tokens["tsa-a"]

    assert codes(attestation(witness, tokens)) == ["token_mismatch", "token_mismatch"]


def test_a_token_time_is_the_one_the_witness_lists():
    witness, tokens = t.attested("interim", 7, LAST)
    witness["time_attestation"]["authorities"][0]["gen_time"] = "2026-11-27T00:03:13Z"

    assert codes(attestation(witness, tokens)) == ["token_time_mismatch"]


def test_a_witness_signed_by_another_key_is_refused():
    witness, tokens = t.attested("interim", 7, LAST)
    _, other = keypair()
    files = {**t.trust_files(), paths.witness_key(t.KEY_ID): other}
    mandate = t.mandate_document()
    mandate["witness_key"]["public_key_sha256"] = hashlib.sha256(other).hexdigest()

    assert codes(attestation(witness, tokens, trust=files, mandate=mandate)) == [
        "witness_signature"
    ]


def test_the_key_and_roots_come_from_trust_and_must_be_the_ones_pinned():
    witness, tokens = t.attested("interim", 7, LAST)

    assert codes(attestation(witness, tokens, trust={})) == [
        "trust_missing",
        "trust_missing",
        "trust_missing",
    ]
