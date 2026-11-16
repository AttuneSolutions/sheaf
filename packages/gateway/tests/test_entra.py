import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from starlette.requests import Request

from sheaf_core import testing as t
from sheaf_gateway.app import create_app
from sheaf_gateway.entra import EntraAuthenticator
from sheaf_gateway.gateway import Gateway, Settings
from sheaf_gateway.hooks import Caller
from sheaf_gateway.store import MemoryStore

TENANT = "00000000-0000-4000-8000-000000000001"
AUDIENCE = "00000000-0000-4000-8000-0000000000aa"
CALLER = "00000000-0000-4000-8000-0000000000c1"
NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key, pem


KEY, KEY_PEM = keypair()
OTHER, OTHER_PEM = keypair()


def jwk(key, kid):
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**public, "kid": kid, "use": "sig", "alg": "RS256"}


class Keys:
    """The tenant's published signing keys, counting how often they are fetched."""

    def __init__(self, *keys):
        self.keys, self.fetched = list(keys), []

    def __call__(self, url):
        self.fetched.append(url)
        return json.dumps({"keys": self.keys}).encode()


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


def token(claims=None, *, pem=KEY_PEM, kid="k1", algorithm="RS256", drop=()):
    body = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": AUDIENCE,
        "tid": TENANT,
        "oid": CALLER,
        "roles": ["reviewer"],
        "iat": int(NOW.timestamp()) - 60,
        "nbf": int(NOW.timestamp()) - 60,
        "exp": int(NOW.timestamp()) + 3600,
        "ver": "2.0",
        **(claims or {}),
    }
    for name in drop:
        del body[name]
    return jwt.encode(body, pem, algorithm=algorithm, headers={"kid": kid})


def request(authorization):
    headers = [] if authorization is None else [(b"authorization", authorization.encode())]
    return Request({"type": "http", "headers": headers})


@pytest.fixture
def keys():
    return Keys(jwk(KEY, "k1"))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def authenticate(keys, clock):
    return EntraAuthenticator(TENANT, AUDIENCE, fetch=keys, clock=clock)


def test_a_valid_token_names_the_caller_by_object_id_with_its_roles(authenticate, keys):
    assert authenticate(request(f"Bearer {token()}")) == Caller(
        CALLER, frozenset({"reviewer"}), person=False
    )
    assert keys.fetched == [f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"]


def test_the_signing_keys_are_fetched_once_and_cached(authenticate, keys):
    for _ in range(3):
        assert authenticate(request(f"Bearer {token()}")) is not None

    assert len(keys.fetched) == 1


def test_keys_that_cannot_be_fetched_are_retried_after_a_pause_not_on_every_request(clock):
    attempts = []

    def unreachable(url):
        attempts.append(url)
        raise OSError("unreachable")

    authenticate = EntraAuthenticator(TENANT, AUDIENCE, fetch=unreachable, clock=clock)
    for _ in range(3):
        assert authenticate(request(f"Bearer {token()}")) is None
    assert len(attempts) == 1

    clock.now += timedelta(seconds=31)
    authenticate(request(f"Bearer {token()}"))
    assert len(attempts) == 2


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "00000000-0000-4000-8000-0000000000bb"},
        {"iss": "https://login.microsoftonline.com/other/v2.0"},
        {"iss": f"https://sts.windows.net/{TENANT}/"},
        {"tid": "00000000-0000-4000-8000-000000000002"},
        {"exp": int(NOW.timestamp()) - 120},
        {"nbf": int(NOW.timestamp()) + 120},
        {"roles": "reviewer"},
        {"oid": ""},
    ],
    ids=["audience", "issuer", "v1 issuer", "tenant", "expired", "not yet valid", "roles", "oid"],
)
def test_a_token_for_someone_else_or_another_time_is_refused(authenticate, claims):
    assert authenticate(request(f"Bearer {token(claims)}")) is None


@pytest.mark.parametrize("missing", ["oid", "tid", "exp", "aud", "iss"])
def test_a_token_lacking_a_claim_is_refused(authenticate, missing):
    assert authenticate(request(f"Bearer {token(drop=(missing,))}")) is None


def test_a_token_signed_by_another_key_is_refused(authenticate):
    assert authenticate(request(f"Bearer {token(pem=OTHER_PEM)}")) is None


def test_a_token_signed_with_a_shared_secret_is_refused(authenticate):
    # The algorithm-confusion attack: HMAC "signed" with what the verifier holds. Only RS256 counts.
    forged = jwt.api_jws.PyJWS().encode(
        json.dumps({"oid": CALLER}).encode(), b"k" * 32, algorithm="HS256", headers={"kid": "k1"}
    )

    assert authenticate(request(f"Bearer {forged}")) is None


def test_an_unsigned_token_is_refused(authenticate):
    unsigned = jwt.encode({"oid": CALLER}, None, algorithm="none", headers={"kid": "k1"})

    assert authenticate(request(f"Bearer {unsigned}")) is None


@pytest.mark.parametrize(
    "header", [None, "", "Basic abc", "Bearer", "Bearer a.b", "bearer " + "x" * 20000]
)
def test_anything_but_a_bearer_token_is_no_caller(authenticate, header):
    assert authenticate(request(header)) is None


def test_a_new_signing_key_is_fetched_but_not_on_every_unknown_key_id(keys, clock):
    authenticate = EntraAuthenticator(TENANT, AUDIENCE, fetch=keys, clock=clock)
    assert authenticate(request(f"Bearer {token()}")) is not None
    keys.keys.append(jwk(OTHER, "k2"))

    rotated = authenticate(request(f"Bearer {token(pem=OTHER_PEM, kid='k2')}"))
    junk = [authenticate(request(f"Bearer {token(kid=f'junk-{n}')}")) for n in range(5)]

    assert rotated is not None
    assert junk == [None] * 5
    assert len(keys.fetched) == 2


def test_the_gateway_answers_401_to_a_bad_token_and_serves_a_good_one(keys, clock):
    gateway = Gateway(Settings(chain=t.CHAIN, bootstrap_caller=CALLER), MemoryStore())
    app = create_app(
        gateway, authenticate=EntraAuthenticator(TENANT, AUDIENCE, fetch=keys, clock=clock)
    )
    client = TestClient(app)
    body = t.mandate_bytes(t.notice(dossier=None))

    refused = client.post("/v1/entries", content=body, headers={"Authorization": "Bearer junk"})
    served = client.post(
        "/v1/entries", content=body, headers={"Authorization": f"Bearer {token()}"}
    )

    assert refused.status_code == 401
    assert served.status_code != 401


def test_a_delegated_token_is_a_person_and_an_app_token_a_system(authenticate):
    person = authenticate(request(f"Bearer {token({'scp': 'Entries.Write'})}"))
    system = authenticate(request(f"Bearer {token()}"))

    assert person.person is True
    assert system.person is False
