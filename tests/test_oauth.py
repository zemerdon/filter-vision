import json
import pytest

from filter_vision import oauth
from filter_vision.app import create_app
from filter_vision.oauth import OAuthError, TokenVault


def test_vault_encrypts_tokens_and_never_writes_plaintext(tmp_path):
    vault = TokenVault(tmp_path)
    body = {"access_token": "A" * 120, "refresh_token": "R" * 120, "expires_in": 3600}
    vault.save(3, body)
    raw = (tmp_path / "oauth" / "3.token").read_bytes()
    assert b"A" * 24 not in raw
    assert b"R" * 24 not in raw
    assert vault.connected(3)
    loaded = vault.load(3)
    assert loaded["access_token"] == body["access_token"]
    assert loaded["refresh_token"] == body["refresh_token"]
    assert (tmp_path / "oauth" / "fernet.key").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "oauth" / "3.token").stat().st_mode & 0o777 == 0o600


def test_vault_rejects_malformed_tokens(tmp_path):
    vault = TokenVault(tmp_path)
    with pytest.raises(OAuthError):
        vault.save(1, {"access_token": "tiny", "refresh_token": "R" * 120,
                       "expires_in": 3600})
    with pytest.raises(OAuthError):
        vault.load(1)


def test_microsoft_oauth_device_flow_and_account_remains_inactive(
    signed_in, app, monkeypatch, tmp_path
):
    client, csrf = signed_in
    config = tmp_path / "oauth-clients.json"
    config.write_text(json.dumps({
        "sample@hotmail.com": {
            "client_id": "12345678-1234-1234-1234-123456789000",
            "permission_url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
            "oauth2_scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        }
    }))
    monkeypatch.setenv("FV_OAUTH_CLIENTS_PATH", str(config))
    assert client.post("/accounts", data={
        "csrf": csrf, "label": "My Hotmail", "provider": "outlook",
        "host": "outlook.office365.com", "port": 993,
        "username": "sample@hotmail.com", "folder": "Junk", "interval": 30,
    }, follow_redirects=False).status_code == 303

    def fake_start(url, fields, timeout=18):
        assert url.startswith("https://login.microsoftonline.com/")
        return {"device_code": "D" * 60, "user_code": "ABCD-EFGH",
                "verification_uri": "https://www.microsoft.com/link",
                "expires_in": 900, "interval": 5}
    monkeypatch.setattr(oauth, "_json_post", fake_start)
    assert client.post("/accounts/1/oauth/start", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    page = client.get("/accounts/1/oauth").text
    assert "ABCD-EFGH" in page
    assert "D" * 40 not in page
    assert "Microsoft" in page

    def fake_pending(url, fields, timeout=18):
        return {"_error": "authorization_pending"}
    monkeypatch.setattr(oauth, "_json_post", fake_pending)
    response = client.post("/accounts/1/oauth/poll", data={"csrf": csrf})
    assert response.status_code == 200
    assert "Waiting for Microsoft approval" in response.text

    with app.state.oauth_lock:
        app.state.oauth_flows[1]["last_poll_at"] = 0

    def fake_authorized(url, fields, timeout=18):
        return {"access_token": "a" * 120, "refresh_token": "r" * 120,
                "expires_in": 3600}
    monkeypatch.setattr(oauth, "_json_post", fake_authorized)
    import filter_vision.app as module
    validated = []
    monkeypatch.setattr(module, "verify_imap_auth",
                        lambda email, token: validated.append(email))
    assert client.post("/accounts/1/oauth/poll", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert validated == ["sample@hotmail.com"]
    assert app.state.token_vault.connected(1)
    assert "Authorized" in client.get("/accounts").text
    with app.state.store.db() as con:
        assert con.execute("SELECT enabled FROM accounts WHERE id=1").fetchone()[0] == 0
    assert "a" * 50 not in client.get("/accounts").text


def test_device_start_requires_csrf(signed_in):
    client, csrf = signed_in
    assert client.post("/accounts/999/oauth/start", data={"csrf": csrf + "x"}).status_code == 403
    assert client.get("/accounts/999/oauth").status_code == 404


def test_fail_safe_on_unsupported_oauth_client(tmp_path, monkeypatch):
    config = tmp_path / "oauth-clients.json"
    config.write_text(json.dumps({"sample@hotmail.com": {
        "client_id": "public-client-id",
        "permission_url": "https://not-microsoft.example.com/auth",
        "token_url": "https://not-microsoft.example.com/token",
        "oauth2_scope": "offline_access"
    }}))
    monkeypatch.setenv("FV_OAUTH_CLIENTS_PATH", str(config))
    with pytest.raises(OAuthError):
        oauth.client_settings("sample@hotmail.com")


@pytest.mark.parametrize(
    ("verification_uri", "expected_success"),
    [
        ("https://login.microsoft.com/devicelogin", True),
        ("https://www.microsoft.com/devicelogin", True),
        ("https://microsoft.com/devicelogin", True),
        ("http://login.microsoft.com/devicelogin", False),
        ("https://login.microsoft.com.attacker.invalid/devicelogin", False),
        ("https://evil.example.invalid/devicelogin", False),
    ],
)
def test_real_microsoft_device_verification_hostname(verification_uri, expected_success,
                                                      monkeypatch):
    """The live Microsoft response uses login.microsoft.com, not microsoftonline.com."""
    monkeypatch.setattr(oauth, "client_settings", lambda _: {
        "client_id": "12345678-1234-1234-1234-123456789000",
        "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        "device_url": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    })
    monkeypatch.setattr(oauth, "_json_post", lambda *args, **kwargs: {
        "device_code": "D" * 1045,
        "user_code": "A1B2-C3D4",
        "verification_uri": verification_uri,
        "expires_in": 900,
        "interval": 5,
    })
    if expected_success:
        flow = oauth.start_device_auth("sample@hotmail.com")
        assert flow["verification_uri"] == verification_uri
        assert flow["user_code"] == "A1B2-C3D4"
        assert len(flow["device_code"]) == 1045
    else:
        with pytest.raises(OAuthError, match="Unexpected Microsoft"):
            oauth.start_device_auth("sample@hotmail.com")
