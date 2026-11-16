import hashlib
from datetime import UTC, date, datetime

import httpx
import pytest

from sheaf_core import testing as t
from sheaf_core.tsp import check_token
from sheaf_core.witness import check_witness, imprint_bytes, verify_signature
from sheaf_witness.build import attest, daily, interim, roots_for
from sheaf_witness.signer import LocalSigner
from sheaf_witness.stamp import Stamper

LAST = "sha256:" + "a" * 64
AT = datetime(2026, 11, 27, 0, 3, 12, tzinfo=UTC)
NAMES = (("tsa-a", "CH"), ("tsa-b", "JP"), ("tsa-c", "NZ"))


@pytest.fixture
def world():
    authorities = {name: t.FakeAuthority(name) for name, _ in NAMES}
    entries = [
        {"authority": name, "jurisdiction": j, "url": f"https://{name}.example/tsa"}
        for name, j in NAMES
    ]
    down = set()

    def handler(request):
        name = request.url.host.split(".")[0]
        if name in down:
            return httpx.Response(503)
        return httpx.Response(200, content=authorities[name].respond(request.content, at=AT))

    stamper = Stamper(
        httpx.Client(transport=httpx.MockTransport(handler)), retry_for=0, sleep=lambda s: None
    )
    roots = {name: [a.root] for name, a in authorities.items()}
    return entries, roots, stamper, down


def test_a_daily_witness_covers_one_utc_day_and_is_signed():
    signer = LocalSigner(t.KEY_ID)

    witness = daily(t.CHAIN, date(2026, 11, 26), 18342, LAST, signer)

    assert witness["interval"] == {"from": "2026-11-26T00:00:00Z", "to": "2026-11-27T00:00:00Z"}
    assert witness["key_id"] == t.KEY_ID
    assert verify_signature(witness, signer.public_key_pem()) == []


def test_an_attested_witness_is_valid_and_carries_every_token(world):
    entries, roots, stamper, _ = world
    signer = LocalSigner(t.KEY_ID)

    witness, tokens = attest(
        daily(t.CHAIN, date(2026, 11, 26), 18342, LAST, signer), entries, roots, stamper
    )

    assert check_witness(witness) == []
    assert verify_signature(witness, signer.public_key_pem()) == []
    assert list(tokens) == ["tsa-a", "tsa-b", "tsa-c"]
    for name, response in tokens.items():
        assert check_token(response, imprint=imprint_bytes(witness), roots=roots[name])[1] == []
    listed = witness["time_attestation"]["authorities"]
    assert [a["token_sha256"] for a in listed] == [
        hashlib.sha256(tokens[a["authority"]]).hexdigest() for a in listed
    ]


def test_an_authority_that_is_down_is_listed_and_the_rest_still_attest(world):
    entries, roots, stamper, down = world
    down.add("tsa-b")

    witness, tokens = attest(
        interim(t.CHAIN, 7, LAST, LocalSigner(t.KEY_ID)), entries, roots, stamper
    )

    assert check_witness(witness) == []
    assert list(tokens) == ["tsa-a", "tsa-c"]
    block = witness["time_attestation"]
    assert [a["obtained"] for a in block["authorities"]] == [True, False, True]
    assert block["attested_jurisdictions"] == ["CH", "NZ"]
    assert block["distinct_jurisdictions"] is True


def test_an_interim_witness_has_no_interval():
    assert "interval" not in interim(t.CHAIN, 7, LAST, LocalSigner(t.KEY_ID))


def test_roots_are_read_from_trust_and_must_be_the_ones_the_mandate_pins():
    authority = t.FakeAuthority("tsa-a")
    sha256 = hashlib.sha256(authority.root).hexdigest()
    entries = [{"authority": "tsa-a", "roots": [sha256]}]
    files = {f"trust/tsa/tsa-a/{sha256}.der": authority.root}

    assert roots_for(entries, files.__getitem__) == {"tsa-a": [authority.root]}
    with pytest.raises(ValueError, match="tsa-a"):
        roots_for(entries, lambda path: b"other bytes")


def test_every_authority_is_asked_at_the_same_time():
    import threading

    names = [name for name, _ in NAMES]
    arrived = {name: threading.Event() for name in names}

    def handler(request):
        name = request.url.host.split(".")[0]
        arrived[name].set()
        # Answer only once every authority has been asked: asked one after another, none would.
        if not all(event.wait(timeout=2) for event in arrived.values()):
            return httpx.Response(503)
        return httpx.Response(200, content=t.authority(name).respond(request.content, at=AT))

    stamper = Stamper(
        httpx.Client(transport=httpx.MockTransport(handler)), retry_for=0, sleep=lambda s: None
    )
    entries = [
        {"authority": name, "jurisdiction": j, "url": f"https://{name}.example/tsa"}
        for name, j in NAMES
    ]
    roots = {name: [t.authority(name).root] for name in names}

    witness, tokens = attest(
        interim(t.CHAIN, 7, LAST, LocalSigner(t.KEY_ID)), entries, roots, stamper
    )

    assert [a["obtained"] for a in witness["time_attestation"]["authorities"]] == [True] * 3
    assert [a["authority"] for a in witness["time_attestation"]["authorities"]] == names
