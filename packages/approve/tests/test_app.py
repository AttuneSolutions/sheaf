"""sheaf-approve (7.6): a person approves a staged mandate change in their own browser, signed in
as themselves, and the service relays their own token to the gateway."""

import json
import logging
import re
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from sheaf_approve.app import create_app
from sheaf_core import paths
from sheaf_core import testing as t
from sheaf_core.canonical import strict_loads
from sheaf_core.mandate import PARTS
from sheaf_core.times import parse_timestamp

from .conftest import (
    APPROVER_TOKEN,
    CLIENT_ID,
    PROPOSER_TOKEN,
    PUBLISHED,
    SCOPE,
    TENANT_ID,
    World,
    auth,
    forwarding,
    token,
)

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://login.microsoftonline.com; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


def committed_entry(world, receipt):
    folder = paths.chain_dossier(t.WORKFLOW, parse_timestamp(receipt["committed_at"]))
    return strict_loads(world.store.blob(paths.entry(folder, receipt["seq"])))


# -- the page ------------------------------------------------------------------------------------


def test_the_page_and_its_script_and_style_are_served(world):
    page = world.client.get("/")
    script = world.client.get("/app.js")
    style = world.client.get("/app.css")

    assert page.status_code == script.status_code == style.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert script.headers["content-type"].startswith("text/javascript")
    assert style.headers["content-type"].startswith("text/css")


def test_the_stylesheet_is_pico_served_from_here_with_its_licence(world):
    from importlib import resources

    pico = world.client.get("/pico.css")
    html = world.client.get("/").text

    assert pico.status_code == 200 and pico.headers["content-type"].startswith("text/css")
    assert "Pico CSS ✨ v2.1.1" in pico.text[:200]
    assert re.findall(r'<link rel="stylesheet" href="([^"]+)">', html) == ["pico.css", "app.css"]
    licence = resources.files("sheaf_approve") / "static" / "vendor" / "pico-LICENSE.md"
    assert "MIT" in licence.read_text()


def test_the_page_has_no_inline_script_or_style(world):
    html = world.client.get("/").text

    assert re.findall(r"<script\b[^>]*>", html) == ['<script src="app.js" defer>']
    assert "<style" not in html
    assert not re.search(r"\sstyle\s*=", html)
    assert not re.search(r"\son[a-z]+\s*=", html)


def test_the_script_writes_text_never_markup(world):
    script = world.client.get("/app.js").text

    assert "innerHTML" not in script and "outerHTML" not in script
    assert "insertAdjacentHTML" not in script and "document.write" not in script
    assert "eval(" not in script and "new Function" not in script
    assert "localStorage" not in script
    assert 'response_mode: "fragment"' in script
    assert 'code_challenge_method: "S256"' in script


def test_the_sign_in_settings_are_the_services_own(world):
    config = world.client.get("/api/config").json()

    assert config == {
        "tenant": TENANT_ID,
        "client_id": CLIENT_ID,
        "scope": f"{SCOPE} openid profile",
        "redirect_uri": PUBLISHED,
        "authority": f"https://login.microsoftonline.com/{TENANT_ID}",
        "chains": [t.CHAIN],
    }


@pytest.mark.parametrize(
    "path", ["/", "/app.js", "/api/config", "/api/me", "/healthz", "/nowhere", "/api/proposals"]
)
def test_every_answer_carries_the_security_headers(world, path):
    response = world.client.get(path)

    assert response.headers["content-security-policy"] == CSP
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_health_says_nothing_more(world):
    response = world.client.get("/healthz")

    assert response.json() == {"status": "ok"}


def test_no_api_description_is_served(world):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert world.client.get(path).status_code == 404


# -- signed in -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/me"),
        ("GET", "/api/proposals"),
        ("GET", "/api/proposals/" + "a" * 64),
        ("POST", "/api/proposals/" + "a" * 64 + "/approve"),
    ],
)
def test_without_a_token_nothing_is_answered(world, method, path):
    response = world.client.request(method, path, json={"confirm": "x", "fingerprint": "y"})

    assert response.status_code == 401
    assert response.json()["error"] == "unauthenticated"


def test_who_is_signed_in_comes_from_the_gateway(world):
    me = world.get("/api/me", token("acme-approver-1", "approver"))

    assert me.json() == {"id": "acme-approver-1", "person": True, "roles": ["approver"]}


def test_a_token_the_gateway_refuses_is_refused(world):
    response = world.get("/api/me", "not-a-token")

    assert response.status_code == 401
    assert response.json()["error"] == "gateway_refused"


def test_when_nothing_is_pending_nothing_is_listed(world):
    response = world.get("/api/proposals")

    assert response.status_code == 200
    assert response.json() == {"proposals": [], "unavailable": []}


def test_a_chain_that_cannot_be_read_is_named_rather_than_listed_as_empty(world):
    world.stage(t.mandate_document())
    world.gateway._halt("chain_corrupt", "the stored chain does not add up")

    response = world.get("/api/proposals", PROPOSER_TOKEN)

    assert response.status_code == 200
    assert response.json() == {"proposals": [], "unavailable": [t.CHAIN]}


def test_pending_proposals_are_listed(world):
    sha256 = world.stage(t.mandate_document())

    listed = world.get("/api/proposals", PROPOSER_TOKEN).json()["proposals"]

    assert [(p["mandate"], p["status"], p["chain"]) for p in listed] == [
        (sha256, "pending", t.CHAIN)
    ]


def test_a_proposal_is_shown_in_plain_language_with_its_fingerprint(world):
    sha256 = world.stage(t.mandate_document())

    shown = world.get(f"/api/proposals/{sha256}").json()

    assert shown["fingerprint"] == sha256
    assert shown["proposal"]["mandate"] == sha256
    assert shown["genesis"] is True
    assert [s["part"] for s in shown["plain"]] == list(PARTS)
    assert [c["part"] for c in shown["diff"]] == list(PARTS)
    assert all(c["removed"] == [] for c in shown["diff"])
    assert ["mandate", sha256] in shown["technical"]
    caller = shown["caller"]
    assert (caller["id"], caller["may_approve"]) == (t.APPROVER["id"], True)
    assert caller["role"] is None and caller["refusal"] is None


def test_the_plain_language_follows_the_mandate(world):
    world.genesis()
    first = world.get(f"/api/proposals/{world.stage(world.change(), reason='new model')}").json()
    other = world.change("2026.11.3", model_version="2026-09-01")

    sentences = {line for s in first["plain"] for line in s["lines"]}

    assert first["genesis"] is False
    assert [c["part"] for c in first["diff"]] == ["models"]
    assert any("version 2026-01-01" in line for line in first["diff"][0]["removed"])
    assert any("version 2026-06-01" in line for line in first["diff"][0]["added"])
    assert any("version 2026-06-01" in line for line in sentences)
    assert not any("version 2026-09-01" in line for line in sentences)
    assert other["models"][0]["model_version"] == "2026-09-01"


def test_a_proposal_for_a_chain_not_served_here_is_not_shown():
    world = World(chains=("acme/claims-triage",))
    sha256 = world.stage(t.mandate_document())

    shown = world.get(f"/api/proposals/{sha256}")
    approved = world.approve(sha256)

    assert shown.status_code == approved.status_code == 404
    assert approved.json()["error"] == "proposal_unknown"
    assert world.head() is None


def test_a_fingerprint_is_sixty_four_hex_digits(world):
    response = world.get("/api/proposals/not-a-digest")

    assert response.status_code == 422


# -- approving -----------------------------------------------------------------------------------


def test_the_approver_approves_the_genesis(world):
    sha256 = world.stage(t.mandate_document())

    response = world.approve(sha256)

    assert response.status_code == 200, response.json()
    receipt = response.json()["approved"]
    assert receipt["seq"] == 1 and world.head() == (1, receipt["hash"])
    entry = committed_entry(world, receipt)
    assert entry["type"] == "config.changed"
    assert entry["actor"] == t.APPROVER
    assert entry["body"]["proposed_by"] == t.PROPOSER
    proposal = world.proposal(sha256)
    assert proposal["status"] == "approved"
    assert proposal["approved"]["seq"] == 1


def test_the_next_interim_witness_puts_an_approved_mandate_in_force(world):
    receipt = world.genesis()

    assert world.gateway.state.in_force.config == receipt["hash"]


def test_a_change_is_approved_under_the_role_that_grants_it(world):
    world.genesis()
    sha256 = world.stage(world.change(), reason="new model")
    approver = token("acme-approver-2", "approver")

    response = world.approve(sha256, approver)

    assert response.status_code == 200, response.json()
    entry = committed_entry(world, response.json()["approved"])
    assert entry["actor"] == {"kind": "person", "id": "acme-approver-2", "role": "approver"}
    assert entry["body"]["approved_by"] == {"kind": "person", "id": "acme-approver-2"}
    assert entry["body"]["previous"]["version"] == t.mandate_document()["version"]


def test_approving_again_after_it_was_approved_writes_nothing_more(world):
    sha256 = world.stage(t.mandate_document())
    first = world.approve(sha256).json()["approved"]

    again = world.approve(sha256)

    assert again.status_code == 200
    assert again.json()["approved"] == {k: first[k] for k in ("seq", "hash", "committed_at")}
    assert world.head() == (1, first["hash"])


def test_someone_who_may_not_approve_sees_the_proposal_but_is_refused(world):
    sha256 = world.stage(t.mandate_document())
    other = token("acme-proposer-2", "proposer")

    shown = world.get(f"/api/proposals/{sha256}", other).json()
    response = world.approve(sha256, other)

    assert shown["fingerprint"] == sha256
    assert shown["caller"]["may_approve"] is False
    assert response.status_code == 403
    assert response.json()["error"] == "not_an_approver"
    assert "bootstrap" in response.json()["detail"]
    assert world.head() is None


def test_an_application_does_not_approve(world):
    sha256 = world.stage(t.mandate_document())

    response = world.approve(sha256, token(t.APPROVER["id"], person=False))

    assert (response.status_code, response.json()["error"]) == (403, "not_a_person")
    assert world.head() is None


def test_the_chain_name_must_be_typed(world):
    sha256 = world.stage(t.mandate_document())

    response = world.approve(sha256, confirm="acme/case-reviews")

    assert (response.status_code, response.json()["error"]) == (422, "confirmation_mismatch")
    assert world.head() is None


def test_only_the_fingerprint_shown_is_approved(world):
    sha256 = world.stage(t.mandate_document())

    response = world.approve(sha256, fingerprint="b" * 64)

    assert (response.status_code, response.json()["error"]) == (409, "fingerprint_mismatch")
    assert world.head() is None


def test_there_must_be_a_proposal(world):
    response = world.approve("c" * 64)

    assert response.status_code == 404
    assert response.json()["error"] == "gateway_refused"
    assert [p["code"] for p in response.json()["problems"]] == ["proposal_unknown"]
    assert world.head() is None


def test_an_expired_proposal_is_not_approved(world):
    sha256 = world.stage(t.mandate_document())
    world.clock.now += timedelta(days=15)

    response = world.approve(sha256)

    assert (response.status_code, response.json()["error"]) == (409, "proposal_not_pending")
    assert "expired" in response.json()["detail"]
    assert world.head() is None


def test_a_withdrawn_proposal_is_not_approved(world):
    sha256 = world.stage(t.mandate_document())
    assert world.call("DELETE", f"/v1/proposals/{sha256}", PROPOSER_TOKEN).status_code == 200

    response = world.approve(sha256)

    assert (response.status_code, response.json()["error"]) == (409, "proposal_not_pending")
    assert world.head() is None


def test_under_four_eyes_whoever_proposed_does_not_approve(world):
    sha256 = world.stage(t.mandate_document(), value=APPROVER_TOKEN)

    response = world.approve(sha256)

    assert (response.status_code, response.json()["error"]) == (403, "not_an_approver")
    assert response.json()["refusal_code"] == "four_eyes"
    assert "four eyes" in response.json()["detail"]
    assert world.head() is None


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b'{"confirm": "acme/case-review"}',
        b'{"confirm": "acme/case-review", "fingerprint": "x", "extra": 1}',
        b'{"confirm": 1, "fingerprint": "x"}',
        b'{"confirm": "a", "confirm": "acme/case-review", "fingerprint": "x"}',
        b"[]",
    ],
)
def test_an_approval_is_exactly_a_confirmation_and_a_fingerprint(world, body):
    sha256 = world.stage(t.mandate_document())

    response = world.client.post(
        f"/api/proposals/{sha256}/approve",
        content=body,
        headers={**auth(APPROVER_TOKEN), "Content-Type": "application/json"},
    )

    assert (response.status_code, response.json()["error"]) == (422, "invalid_request")
    assert world.head() is None


def test_a_refusal_by_the_gateway_is_passed_on_with_its_problems(world):
    sha256 = world.stage(t.mandate_document())

    def halt_first(request):
        # The gateway halts just before the commit reaches it.
        if request.method == "POST" and request.url.path == "/v1/entries":
            world.gateway._halt("write_failed", "a write failed at seq 1; restart to finish it")
        return False

    client = TestClient(create_app(world.settings, forwarding(world, refuse=halt_first)))
    response = client.post(
        f"/api/proposals/{sha256}/approve",
        json={"confirm": t.CHAIN, "fingerprint": sha256},
        headers=auth(APPROVER_TOKEN),
    )

    assert response.status_code == 503
    body = response.json()
    assert body["error"] == "gateway_refused" and body["status"] == 503
    assert [p["code"] for p in body["problems"]] == ["gateway_halted"]


# -- the gateway out of reach --------------------------------------------------------------------


def test_an_unreachable_gateway_is_said_plainly(world):
    dead = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused", request=request))
        )
    )
    app = create_app(world.settings, dead)
    client = TestClient(app, base_url=PUBLISHED.rstrip("/"))

    me = client.get("/api/me", headers=auth(APPROVER_TOKEN))
    approved = client.post(
        "/api/proposals/" + "a" * 64 + "/approve",
        json={"confirm": t.CHAIN, "fingerprint": "a" * 64},
        headers=auth(APPROVER_TOKEN),
    )

    assert (me.status_code, me.json()["error"]) == (502, "gateway_unreachable")
    assert (approved.status_code, approved.json()["error"]) == (502, "gateway_unreachable")


def test_a_commit_that_does_not_reach_the_gateway_writes_nothing_and_says_to_reload(world):
    sha256 = world.stage(t.mandate_document())
    lost = forwarding(world, refuse=lambda r: r.method == "POST" and r.url.path == "/v1/entries")
    client = TestClient(create_app(world.settings, lost), base_url=PUBLISHED.rstrip("/"))

    response = client.post(
        f"/api/proposals/{sha256}/approve",
        json={"confirm": t.CHAIN, "fingerprint": sha256},
        headers=auth(APPROVER_TOKEN),
    )

    assert (response.status_code, response.json()["error"]) == (502, "gateway_unreachable")
    assert "reload" in response.json()["detail"].lower()
    assert world.head() is None
    assert world.proposal(sha256)["status"] == "pending"


# -- logs ----------------------------------------------------------------------------------------


def test_no_token_or_sign_in_code_is_logged(world, caplog, capsys):
    secret = "tok-" + "s3cr3t" * 6
    code = "code-" + "0AQ" * 8
    approver = token(t.APPROVER["id"], secret=secret)
    caplog.set_level(logging.DEBUG)
    sha256 = world.stage(t.mandate_document())

    world.client.get(f"/?code={code}&state=xyz")
    world.get("/api/me", approver)
    world.get("/api/proposals", approver)
    world.get(f"/api/proposals/{sha256}", approver)
    world.approve(sha256, approver, confirm="wrong")
    world.approve(sha256, approver)
    world.get("/api/me", "Bearer-" + secret)

    captured = capsys.readouterr()
    # The test's own client logs the addresses it asks for; the service never does.
    own = [
        r.getMessage()
        for r in caplog.records
        if not (r.name == "httpx" and PUBLISHED.rstrip("/") in r.getMessage())
    ]
    logged = "\n".join(own) + captured.out + captured.err
    assert secret not in logged
    assert code not in logged
    assert f"by={t.APPROVER['id']} proposal={sha256} chain={t.CHAIN} outcome=approved" in logged
    assert "outcome=confirmation_mismatch" in logged
    assert "GET / 200" in logged


def test_every_approval_attempt_is_logged_with_its_outcome(world, caplog):
    caplog.set_level(logging.INFO, logger="sheaf.approve")
    sha256 = world.stage(t.mandate_document())

    world.approve(sha256, fingerprint="d" * 64)
    world.approve(sha256, None)

    attempts = [r.getMessage() for r in caplog.records if r.name == "sheaf.approve"]
    assert any("outcome=fingerprint_mismatch" in a for a in attempts)
    assert any("by=unknown" in a and "outcome=unauthenticated" in a for a in attempts)


def test_the_service_keeps_nothing_between_requests(world):
    sha256 = world.stage(t.mandate_document())
    world.get(f"/api/proposals/{sha256}")

    state = {k: v for k, v in vars(world.app.state).items() if not k.startswith("_")}

    assert json.dumps(state, default=str).count(sha256) == 0


# -- what is shown is what is committed ----------------------------------------------------------


def proposal_answer(request):
    return request.method == "GET" and request.url.path.startswith("/v1/proposals/")


def test_a_mandate_that_is_not_its_proposals_is_neither_shown_nor_approved(world):
    sha256 = world.stage(t.mandate_document())

    def tamper(request, answer):
        if proposal_answer(request):
            answer["mandate"]["models"][0]["model_version"] = "2030-01-01"
        return answer

    client = TestClient(create_app(world.settings, forwarding(world, change=tamper)))
    shown = client.get(f"/api/proposals/{sha256}", headers=auth(APPROVER_TOKEN))
    approved = client.post(
        f"/api/proposals/{sha256}/approve",
        json={"confirm": t.CHAIN, "fingerprint": sha256},
        headers=auth(APPROVER_TOKEN),
    )

    assert (shown.status_code, shown.json()["error"]) == (502, "gateway_inconsistent")
    assert (approved.status_code, approved.json()["error"]) == (502, "gateway_inconsistent")
    assert "parts" in approved.json()["detail"]
    assert world.head() is None


def test_an_approval_whose_answer_was_lost_is_finished_by_approving_again(world):
    sha256 = world.stage(t.mandate_document())
    lost = []

    def once(request):
        if request.method == "POST" and request.url.path == "/v1/entries" and not lost:
            lost.append(request)
            return True
        return False

    client = TestClient(create_app(world.settings, forwarding(world, lose_answer=once)))
    body = {"confirm": t.CHAIN, "fingerprint": sha256}

    first = client.post(f"/api/proposals/{sha256}/approve", json=body, headers=auth(APPROVER_TOKEN))
    head = world.head()
    again = client.post(f"/api/proposals/{sha256}/approve", json=body, headers=auth(APPROVER_TOKEN))

    assert (first.status_code, first.json()["error"]) == (502, "gateway_unreachable")
    assert head is not None and head[0] == 1
    assert again.status_code == 200, again.json()
    assert again.json()["already"] is True
    assert (again.json()["approved"]["seq"], again.json()["approved"]["hash"]) == head
    assert world.head() == head


def test_an_approved_proposal_without_its_record_says_so(world):
    sha256 = world.stage(t.mandate_document())

    def approved_elsewhere(request, answer):
        if proposal_answer(request):
            answer["proposal"]["status"] = "approved"
            answer["proposal"].pop("approved", None)
        return answer

    client = TestClient(create_app(world.settings, forwarding(world, change=approved_elsewhere)))
    response = client.post(
        f"/api/proposals/{sha256}/approve",
        json={"confirm": t.CHAIN, "fingerprint": sha256},
        headers=auth(APPROVER_TOKEN),
    )

    assert (response.status_code, response.json()["error"]) == (409, "proposal_approved")
    assert "reload" in response.json()["detail"]
    assert world.head() is None


def test_a_proposal_superseded_after_it_was_shown_is_refused(world):
    world.genesis()
    first = world.stage(world.change(), reason="new model")
    second = world.stage(world.change("2026.11.3", model_version="2026-09-01"), reason="newer")
    assert world.get(f"/api/proposals/{second}").json()["proposal"]["status"] == "pending"
    assert world.approve(first).status_code == 200
    head = world.head()

    response = world.approve(second)

    assert (response.status_code, response.json()["error"]) == (409, "proposal_not_pending")
    assert "superseded" in response.json()["detail"]
    assert world.head() == head


def test_an_answer_that_is_not_a_json_object_is_said_to_be_bad(world):
    def listed(request, answer):
        return ["not", "an", "object"] if request.url.path == "/v1/me" else answer

    client = TestClient(create_app(world.settings, forwarding(world, change=listed)))

    response = client.get("/api/me", headers=auth(APPROVER_TOKEN))

    assert (response.status_code, response.json()["error"]) == (502, "gateway_bad_answer")


def test_an_approval_whose_checks_took_too_long_is_not_sent(world):
    sha256 = world.stage(t.mandate_document())
    ticks = iter(range(0, 10_000, 30))
    app = create_app(world.settings, world.gateway_http, monotonic=lambda: next(ticks))
    client = TestClient(app)

    response = client.post(
        f"/api/proposals/{sha256}/approve",
        json={"confirm": t.CHAIN, "fingerprint": sha256},
        headers=auth(APPROVER_TOKEN),
    )

    assert (response.status_code, response.json()["error"]) == (504, "gateway_slow")
    assert world.head() is None


@pytest.mark.parametrize(
    "header",
    [b"Bearer t\xc3\xb6ken", b"Bearer two words", b"Bearer a\x7fb", b"Bearer a:b", b"Basic abc"],
)
def test_a_token_holds_only_the_characters_a_bearer_token_may(world, header):
    response = world.client.get("/api/me", headers={"Authorization": header})

    assert (response.status_code, response.json()["error"]) == (401, "unauthenticated")


def test_a_sign_in_error_is_shown_as_a_fixed_sentence_and_a_code(world):
    script = world.client.get("/app.js").text

    assert "error_description" not in script
    assert "/^[a-z_]{1,64}$/" in script
