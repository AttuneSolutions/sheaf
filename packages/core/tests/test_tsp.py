import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest
from asn1crypto import tsp

from sheaf_core.tsp import check_token, request

DATA = Path(__file__).parent / "data" / "tsa"
# Real responses from 16 Nov 2026 to one request: a random 32-byte imprint and this nonce.
IMPRINT = bytes.fromhex("7c0f5891ed916b1d77e255dd188670aa457f4b5d4070a4d1cf2efc72f57f06e0")
NONCE = 0x74C5E000196D24E9
REAL = {
    "freetsa": datetime(2026, 11, 16, 2, 50, 48, tzinfo=UTC),
    "sectigo": datetime(2026, 11, 16, 2, 55, 46, tzinfo=UTC),
    "digicert": datetime(2026, 11, 16, 2, 55, 34, tzinfo=UTC),
}


def read(name):
    return (DATA / name).read_bytes()


def codes(problems):
    return [p.code for p in problems]


def check(name, *, imprint=IMPRINT, nonce=NONCE, root=None, data=None):
    return check_token(
        data if data is not None else read(f"{name}.tsr"),
        imprint=imprint,
        roots=[read(root or f"{name}-root.der")],
        nonce=nonce,
    )


@pytest.mark.parametrize("name", sorted(REAL))
def test_a_real_token_verifies_against_its_pinned_root(name):
    token, problems = check(name)

    assert problems == []
    assert token.gen_time == REAL[name]
    assert token.qualified is False


def test_a_qualified_token_says_so():
    token, problems = check("sectigo-qualified", root="sectigo-qualified-ca.der")

    assert problems == []
    assert token.qualified is True
    assert token.policy == "0.4.0.2023.1.1"


def test_a_token_over_another_imprint_is_refused():
    _, problems = check("freetsa", imprint=bytes(32))

    assert codes(problems) == ["token_imprint"]


def test_a_token_answering_another_request_is_refused():
    _, problems = check("freetsa", nonce=NONCE + 1)

    assert codes(problems) == ["token_nonce"]


def test_a_token_is_checked_against_its_own_authority_root_only():
    _, problems = check("freetsa", root="sectigo-root.der")

    assert codes(problems) == ["token_chain"]


def test_a_token_whose_signature_was_altered_is_refused():
    response = tsp.TimeStampResp.load(read("digicert.tsr"))
    signer = response["time_stamp_token"]["content"]["signer_infos"][0]
    signature = bytearray(signer["signature"].native)
    signature[10] ^= 1
    signer["signature"] = bytes(signature)

    _, problems = check("digicert", data=response.dump(force=True))

    assert codes(problems) == ["token_signature"]


def test_a_token_whose_time_was_altered_is_refused():
    response = tsp.TimeStampResp.load(read("sectigo.tsr"))
    content = response["time_stamp_token"]["content"]["encap_content_info"]["content"]
    info = content.parsed
    info["gen_time"] = datetime(2026, 11, 15, 2, 55, 46, tzinfo=UTC)
    content.set(info.dump(force=True))

    _, problems = check("sectigo", data=response.dump(force=True))

    assert codes(problems) == ["token_digest"]


@pytest.mark.parametrize("data", [b"", b"not a token", read("freetsa.tsr") + b"\x00"])
def test_what_is_not_a_time_stamp_response_is_refused(data):
    _, problems = check("freetsa", data=data)

    assert codes(problems) == ["token_unparseable"]


def test_a_refusal_from_the_authority_is_not_a_token():
    refusal = bytes.fromhex("30053003020102")  # PKIStatusInfo { status rejection (2) }

    _, problems = check("freetsa", data=refusal)

    assert codes(problems) == ["token_status"]


def test_a_request_asks_for_a_sha256_imprint_with_a_nonce_and_the_certificates():
    req = tsp.TimeStampReq.load(request(IMPRINT, NONCE))

    assert req["version"].native == "v1"
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert req["message_imprint"]["hashed_message"].native == IMPRINT
    assert req["nonce"].native == NONCE
    assert req["cert_req"].native is True


def test_a_request_is_only_for_a_32_byte_imprint():
    with pytest.raises(ValueError):
        request(b"short", NONCE)


def test_the_test_data_is_what_it_claims():
    # The responses are byte-for-byte what the authorities sent; nothing here re-encodes them.
    assert base64.b16encode(read("freetsa.tsr")[:2]) == b"3082"


# -- the test authority -----------------------------------------------------------------------


def test_the_test_authority_issues_tokens_the_checker_accepts():
    from sheaf_core import testing as t

    authority = t.FakeAuthority("tsa-a")
    at = datetime(2026, 11, 27, 0, 3, 12, tzinfo=UTC)
    response = authority.respond(request(IMPRINT, NONCE), at=at)

    token, problems = check_token(response, imprint=IMPRINT, roots=[authority.root], nonce=NONCE)

    assert problems == []
    assert token.gen_time == at
    assert codes(check_token(response, imprint=IMPRINT, roots=[t.FakeAuthority("x").root])[1]) == [
        "token_chain"
    ]
