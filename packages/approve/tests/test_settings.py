import pytest

from sheaf_approve.settings import Settings, listen_from

ENV = {
    "SHEAF_GATEWAY_URL": "https://acme-sheaf-gateway.internal.example",
    "SHEAF_ENTRA_TENANT": "00000000-0000-4000-8000-00000000aaaa",
    "SHEAF_APPROVE_CLIENT_ID": "00000000-0000-4000-8000-00000000bbbb",
    "SHEAF_GATEWAY_SCOPE": "api://00000000-0000-4000-8000-00000000cccc/user_impersonation",
    "SHEAF_APPROVE_URL": "https://approve.acme.example/",
    "SHEAF_CHAINS": "acme/case-review, acme/claims-triage",
}


def test_the_service_is_configured_from_the_environment():
    settings = Settings.from_env(ENV)

    assert settings.gateway_url == "https://acme-sheaf-gateway.internal.example"
    assert settings.tenant == ENV["SHEAF_ENTRA_TENANT"]
    assert settings.client_id == ENV["SHEAF_APPROVE_CLIENT_ID"]
    assert settings.scope == ENV["SHEAF_GATEWAY_SCOPE"]
    assert settings.redirect_uri == "https://approve.acme.example/"
    assert settings.chains == ("acme/case-review", "acme/claims-triage")


@pytest.mark.parametrize("name", sorted(ENV))
def test_it_will_not_start_without_each_setting(name):
    env = {k: v for k, v in ENV.items() if k != name}

    with pytest.raises(RuntimeError, match=name):
        Settings.from_env(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SHEAF_GATEWAY_URL", "http://acme-sheaf-gateway.internal.example"),
        ("SHEAF_APPROVE_URL", "http://approve.acme.example/"),
        ("SHEAF_CHAINS", "case-review"),
        ("SHEAF_CHAINS", "acme/case-review,other/case-review"),
        ("SHEAF_ENTRA_TENANT", "acme tenant"),
        ("SHEAF_ENTRA_TENANT", "common"),
        ("SHEAF_ENTRA_TENANT", "organizations"),
        ("SHEAF_ENTRA_TENANT", "consumers"),
        ("SHEAF_ENTRA_TENANT", "acme"),
        ("SHEAF_GATEWAY_SCOPE", "user_impersonation"),
        ("SHEAF_GATEWAY_SCOPE", "api://0000/user_impersonation openid"),
        ("SHEAF_GATEWAY_SCOPE", "api://0000"),
        ("SHEAF_GATEWAY_URL", "https://"),
        ("SHEAF_GATEWAY_URL", "https://user:secret@gateway.acme.example"),
        ("SHEAF_GATEWAY_URL", "https://gateway.acme.example/v1?x=1"),
        ("SHEAF_APPROVE_URL", "https://approve.acme.example"),
        ("SHEAF_APPROVE_URL", "https://approve.acme.example/approve/"),
        ("SHEAF_APPROVE_URL", "https://approve.acme.example/?x=1"),
        ("SHEAF_APPROVE_URL", "https://approve.acme.example/#x"),
        ("SHEAF_APPROVE_URL", "https://someone@approve.acme.example/"),
    ],
)
def test_it_will_not_start_with_a_setting_it_cannot_use(name, value):
    with pytest.raises(RuntimeError, match=name):
        Settings.from_env({**ENV, name: value})


def test_a_local_address_may_be_plain_http_for_trying_it_out():
    settings = Settings.from_env({**ENV, "SHEAF_APPROVE_URL": "http://localhost:8080/"})

    assert settings.redirect_uri == "http://localhost:8080/"


@pytest.mark.parametrize(
    "tenant", ["00000000-0000-4000-8000-00000000aaaa", "acme.onmicrosoft.com", "acme.example"]
)
def test_a_tenant_is_its_directory_id_or_one_of_its_domains(tenant):
    assert Settings.from_env({**ENV, "SHEAF_ENTRA_TENANT": tenant}).tenant == tenant


def test_a_scope_may_name_an_identifier_uri_with_a_path():
    scope = "api://acme.example/sheaf-gateway/user_impersonation"

    assert Settings.from_env({**ENV, "SHEAF_GATEWAY_SCOPE": scope}).scope == scope


def test_where_it_listens_defaults_to_every_address_on_8080():
    assert listen_from({}) == ("0.0.0.0", 8080)
    assert listen_from({"SHEAF_APPROVE_HOST": "127.0.0.1", "SHEAF_APPROVE_PORT": "8090"}) == (
        "127.0.0.1",
        8090,
    )


@pytest.mark.parametrize("port", ["eighty", "0", "65536", "-1", "80.5"])
def test_a_port_it_cannot_use_is_refused(port):
    with pytest.raises(RuntimeError, match="SHEAF_APPROVE_PORT"):
        listen_from({"SHEAF_APPROVE_PORT": port})


def test_the_service_exits_with_two_when_it_cannot_start(monkeypatch, capsys):
    from sheaf_approve import __main__ as cli

    for name in ENV:
        monkeypatch.setenv(name, ENV[name])
    monkeypatch.setenv("SHEAF_APPROVE_PORT", "eighty")

    assert cli.main() == 2
    assert "SHEAF_APPROVE_PORT" in capsys.readouterr().err
