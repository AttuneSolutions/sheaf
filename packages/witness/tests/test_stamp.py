import hashlib
from datetime import UTC, datetime

import httpx
import pytest
from asn1crypto import tsp

from sheaf_core import testing as t
from sheaf_core.tsp import check_token
from sheaf_witness.stamp import Stamper

IMPRINT = hashlib.sha256(b"a witness").digest()
AT = datetime(2026, 11, 27, 0, 3, 12, tzinfo=UTC)
ENTRY = {"authority": "tsa-a", "jurisdiction": "CH", "url": "https://tsa-a.example/tsa"}


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def stamper(handler, clock=None, **kw):
    clock = clock or Clock()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Stamper(client, sleep=clock.sleep, clock=clock, **kw), clock


@pytest.fixture
def authority():
    return t.FakeAuthority("tsa-a")


def answering(authority, failures=0, status=503):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) <= failures:
            return httpx.Response(status)
        return httpx.Response(
            200,
            content=authority.respond(request.content, at=AT),
            headers={"Content-Type": "application/timestamp-reply"},
        )

    return handler, calls


def test_a_stamp_is_a_verified_token_and_its_exact_bytes(authority):
    handler, calls = answering(authority)
    s, _ = stamper(handler)

    stamp = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert stamp.result.as_json() == {
        "authority": "tsa-a",
        "jurisdiction": "CH",
        "obtained": True,
        "qualified": False,
        "gen_time": "2026-11-27T00:03:12Z",
        "token_sha256": hashlib.sha256(stamp.response).hexdigest(),
    }
    assert check_token(stamp.response, imprint=IMPRINT, roots=[authority.root])[1] == []
    (request,) = calls
    assert request.headers["Content-Type"] == "application/timestamp-query"
    asked = tsp.TimeStampReq.load(request.content)
    assert asked["message_imprint"]["hashed_message"].native == IMPRINT
    assert asked["nonce"].native is not None


def test_an_authority_that_fails_is_asked_again(authority):
    handler, calls = answering(authority, failures=2)
    s, clock = stamper(handler, first_delay=5, min_interval={"tsa-a": 15})

    stamp = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert stamp.result.obtained
    assert len(calls) == 3
    assert clock.slept == [15, 15]


def test_an_authority_that_never_answers_is_listed_as_not_obtained_with_the_reason(authority):
    handler, calls = answering(authority, failures=10**6)
    s, clock = stamper(handler, retry_for=3600, first_delay=60, max_delay=600)

    stamp = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert stamp.response is None
    assert stamp.result.as_json()["obtained"] is False
    assert "HTTP 503" in stamp.result.unavailable_reason
    assert clock.now <= 3600
    assert clock.slept[:4] == [60, 120, 240, 480]


def test_a_token_that_does_not_verify_is_not_obtained(authority):
    handler, _ = answering(authority)
    s, _ = stamper(handler, retry_for=0)

    stamp = s.stamp(ENTRY, [t.FakeAuthority("other").root], IMPRINT)

    assert not stamp.result.obtained
    assert "token_chain" in stamp.result.unavailable_reason


def test_a_timeout_is_a_reason_not_a_crash(authority):
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)

    s, _ = stamper(handler, retry_for=0)

    stamp = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert stamp.result.unavailable_reason.startswith("timeout")


def test_an_oversized_response_is_refused(authority):
    s, _ = stamper(lambda request: httpx.Response(200, content=b"x" * (1024 * 1024)), retry_for=0)

    stamp = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert "too large" in stamp.result.unavailable_reason


def test_an_authority_down_for_a_whole_window_is_tried_once_for_the_rest_of_the_run(authority):
    handler, calls = answering(authority, failures=10**6)
    s, clock = stamper(handler, retry_for=3600, first_delay=60, max_delay=600)
    s.stamp(ENTRY, [authority.root], IMPRINT)
    asked, slept = len(calls), len(clock.slept)

    later = s.stamp(ENTRY, [authority.root], IMPRINT)

    assert len(calls) == asked + 1
    assert len(clock.slept) == slept
    assert not later.result.obtained
    assert "down earlier in this run" in later.result.unavailable_reason


def test_an_authority_back_after_its_window_is_used_again(authority):
    down = {"now": True}

    def handler(request):
        if down["now"]:
            return httpx.Response(503)
        return httpx.Response(200, content=authority.respond(request.content, at=AT))

    s, _ = stamper(handler, retry_for=600, first_delay=60)
    s.stamp(ENTRY, [authority.root], IMPRINT)
    down["now"] = False

    assert s.stamp(ENTRY, [authority.root], IMPRINT).result.obtained
