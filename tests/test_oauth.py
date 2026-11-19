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


def test_imap_xoauth2_uses_real_sasl_control_separators(monkeypatch):
    import imaplib
    captured = {}

    class FakeIMAP:
        def authenticate(self, mechanism, callback):
            captured["mechanism"] = mechanism
            captured["bytes"] = callback(b"")
            return "OK", [b"Authenticated"]

        def logout(self):
            captured["logged_out"] = True

    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **kw: FakeIMAP())
    oauth.verify_imap_auth("sample@hotmail.com", "A" * 80)
    assert captured["mechanism"] == "XOAUTH2"
    assert captured["bytes"] == (
        b"user=sample@hotmail.com\x01auth=Bearer " + b"A" * 80 + b"\x01\x01"
    )
    assert b"\\x01" not in captured["bytes"]
    assert captured["logged_out"] is True


def test_imap_xoauth2_authentication_failure_is_safe(monkeypatch):
    import imaplib

    class RejectingIMAP:
        def authenticate(self, mechanism, callback):
            assert b"\x01auth=Bearer " in callback(b"")
            raise imaplib.IMAP4.error("authentication refused")

        def logout(self):
            pass

    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **kw: RejectingIMAP())
    with pytest.raises(OAuthError, match="authentication failed"):
        oauth.verify_imap_auth("sample@hotmail.com", "A" * 80)


def test_device_code_page_links_to_official_portal_not_localhost(signed_in, app, monkeypatch):
    import importlib

    client, csrf = signed_in
    webui = importlib.import_module("filter_vision.app")
    with app.state.store.db() as con:
        con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,interval_minutes,"
            "enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("Microsoft", "outlook", "outlook.office365.com", 993,
             "sample@hotmail.com", "Junk", 30, 0, 1),
        )

    def mock_start(email):
        assert email == "sample@hotmail.com"
        return {
            "user_code": "ABCD-EFGH", "device_code": "D" * 100,
            "verification_uri": "https://login.microsoft.com/device",
            "expires_at": 2999999999,
            "interval": 5,
            "last_poll_at": 0,
            "settings": {"token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token"},
        }
    monkeypatch.setattr(webui, "start_device_auth", mock_start)
    response = client.post("/accounts/1/oauth/start", data={"csrf": csrf},
                           follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/accounts/1/oauth")
    assert page.status_code == 200
    assert "https://microsoft.com/devicelogin" in page.text
    assert "https://login.microsoft.com/device" not in page.text
    assert "ABCD-EFGH" in page.text
    assert "http://127.0.0.1" not in page.text
    assert "device-code sign-in" in page.text
    assert "D" * 60 not in page.text


def _legacy_browser_test_config(tmp_path, monkeypatch):
    from pathlib import Path
    path = Path(tmp_path) / "oauth-clients.json"
    path.write_text(json.dumps({"sample@hotmail.com": {
        "client_id": "12345678-1234-1234-1234-123456789000",
        "permission_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "oauth2_scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        "redirect_uri": "https://localhost",
    }}))
    monkeypatch.setenv("FV_OAUTH_CLIENTS_PATH", str(path))
    return path


def test_browser_auth_pkce_authorize_url_contains_required_fields(tmp_path, monkeypatch):
    import urllib.parse
    _legacy_browser_test_config(tmp_path, monkeypatch)
    flow = oauth.start_browser_auth("sample@hotmail.com")
    parsed = urllib.parse.urlsplit(flow["authorization_url"])
    assert parsed.scheme == "https"
    assert parsed.hostname == "login.microsoftonline.com"
    assert parsed.path.endswith("/authorize")
    q = urllib.parse.parse_qs(parsed.query)
    assert q["response_type"] == ["code"]
    assert q["response_mode"] == ["query"]
    assert q["redirect_uri"] == ["https://localhost"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["scope"] == [
        "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    ]
    assert q["prompt"] == ["select_account"]
    assert q["state"] == [flow["state"]]
    import base64
    import hashlib
    actual_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(flow["verifier"].encode()).digest()
    ).decode().rstrip("=")
    assert q["code_challenge"] == [actual_challenge]
    assert flow["verifier"] not in flow["authorization_url"]


def test_browser_auth_code_state_check_and_token_redemption(tmp_path, monkeypatch):
    import urllib.parse
    _legacy_browser_test_config(tmp_path, monkeypatch)
    flow = oauth.start_browser_auth("sample@hotmail.com")
    calls = []
    def fake_post(url, fields, timeout=18):
        calls.append((url, fields))
        return {"access_token": "A" * 120, "refresh_token": "R" * 120,
                "expires_in": 3600}
    monkeypatch.setattr(oauth, "_json_post", fake_post)
    good_callback = "https://localhost?"+urllib.parse.urlencode({
        "code": "C" * 110, "state": flow["state"],
        "session_state": "not-used",
    })
    for bad_url in [
        good_callback.replace("https://localhost?", "http://localhost?"),
        good_callback.replace("https://localhost?", "https://attacker.invalid?"),
        good_callback.replace("state="+flow["state"], "state=bad"),
        "https://localhost?error=invalid_request&error_description=missing_response_type",
        "https://localhost?code="+"C"*110+"&state=wrong&state="+flow["state"],
    ]:
        with pytest.raises(OAuthError):
            oauth.redeem_browser_auth(flow, bad_url)
    assert calls == []
    result = oauth.redeem_browser_auth(flow, good_callback)
    assert result["refresh_token"] == "R" * 120
    assert len(calls) == 1
    token_url, fields = calls[0]
    assert token_url.endswith("/token")
    assert fields["grant_type"] == "authorization_code"
    assert fields["code"] == "C" * 110
    assert fields["redirect_uri"] == "https://localhost"
    assert fields["code_verifier"] == flow["verifier"]
    assert "client_secret" not in fields


def test_browser_auth_rejects_unknown_remote_redirect(tmp_path, monkeypatch):
    config = _legacy_browser_test_config(tmp_path, monkeypatch)
    payload = json.loads(config.read_text())
    payload["sample@hotmail.com"]["redirect_uri"] = "https://evil.invalid/redirect"
    config.write_text(json.dumps(payload))
    with pytest.raises(OAuthError, match="not a local callback"):
        oauth.start_browser_auth("sample@hotmail.com")


def test_browser_auth_webui_flow_and_one_time_consumption(signed_in, app, tmp_path,
                                                         monkeypatch):
    import importlib
    import urllib.parse
    _legacy_browser_test_config(tmp_path, monkeypatch)
    client, csrf = signed_in
    webui = importlib.import_module("filter_vision.app")
    with app.state.store.db() as con:
        con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,interval_minutes,"
            "enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("Imported", "outlook", "outlook.office365.com", 993,
             "sample@hotmail.com", "Junk", 30, 0, 1),
        )
    assert client.post("/accounts/1/oauth/browser/start", data={"csrf": "wrong"}).status_code == 403
    response = client.post("/accounts/1/oauth/browser/start", data={"csrf": csrf},
                           follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/accounts/1/oauth")
    assert "Open Microsoft Browser Sign-In" in page.text
    assert "response_type=code" in page.text
    assert "Paste the complete localhost callback URL" in page.text
    flow = app.state.oauth_code_flows[1]
    callback = "https://localhost?" + urllib.parse.urlencode({
        "code": "C" * 120, "state": flow["state"],
    })
    validated = []
    monkeypatch.setattr(webui, "verify_imap_auth",
                        lambda email, token: validated.append((email, token)))
    monkeypatch.setattr(webui, "redeem_browser_auth",
                        lambda flow, callback_url: {
                            "access_token": "A" * 120,
                            "refresh_token": "R" * 120, "expires_in": 3600,
                        })
    response = client.post("/accounts/1/oauth/browser/finish", data={
        "csrf": csrf, "callback_url": callback,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert validated == [("sample@hotmail.com", "A" * 120)]
    assert app.state.token_vault.connected(1)
    assert 1 not in app.state.oauth_code_flows
    with app.state.store.db() as con:
        assert con.execute("SELECT enabled FROM accounts WHERE id=1").fetchone()[0] == 0
    replay = client.post("/accounts/1/oauth/browser/finish", data={
        "csrf": csrf, "callback_url": callback,
    })
    assert replay.status_code == 200
    assert "No active browser authorization was found" in replay.text
    assert 'id="browser-result"' in replay.text
    assert "Connection not completed" in replay.text


@pytest.mark.parametrize(
    ("oauth_error", "stage", "public_detail"),
    [
        ("Callback address does not match the registered Microsoft redirect",
         "callback", "Callback address does not match"),
        ("Authorization state mismatch: do not reuse this callback",
         "callback", "Authorization state mismatch"),
        ("Microsoft denied browser authorization: invalid_request",
         "microsoft_error", "invalid_request"),
        ("Microsoft could not redeem the browser authorization: invalid_grant",
         "token_exchange", "invalid_grant"),
    ],
)
def test_failed_browser_callback_visible_inline_and_safe(
    signed_in, app, monkeypatch, oauth_error, stage, public_detail
):
    import importlib
    webui = importlib.import_module("filter_vision.app")
    client, csrf = signed_in
    with app.state.store.db() as con:
        con.execute("INSERT INTO accounts(label,provider,host,port,username,folder,"
                    "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("Imported", "outlook", "outlook.office365.com", 993,
                     "sample@hotmail.com", "Junk", 30, 0, 1))
    secret_url = "https://localhost?code=" + "SECRETCODE" * 12 + "&state=" + "STATE" * 12
    app.state.oauth_code_flows[1] = {
        "owner_csrf": csrf, "expires_at": 2999999999,
        "state": "STATE" * 12, "verifier": "PRIVATEVERIFIER" * 6,
        "redirect_uri": "https://localhost",
    }
    monkeypatch.setattr(webui, "redeem_browser_auth",
                        lambda flow, url: (_ for _ in ()).throw(OAuthError(oauth_error)))
    result = client.post("/accounts/1/oauth/browser/finish", data={
        "csrf": csrf, "callback_url": secret_url,
    }, follow_redirects=False)
    assert result.status_code == 303
    assert result.headers["location"] == "/accounts/1/oauth#browser-result"
    response = client.get("/accounts/1/oauth")
    assert response.status_code == 200
    assert 'id="browser-result"' in response.text
    assert 'role="alert"' in response.text
    assert public_detail in response.text
    assert "Connection not completed" in response.text
    assert "Start Microsoft Browser Sign-In" in response.text
    assert "SECRETCODE" not in response.text
    assert "PRIVATEVERIFIER" not in response.text
    assert "STATE" * 12 not in response.text
    assert "No account was enabled" in response.text
    # One-time notice is not replayed on future page visits.
    assert "Connection not completed" not in client.get("/accounts/1/oauth").text
    with app.state.store.db() as db:
        audit = db.execute("SELECT detail FROM audit_events WHERE event='microsoft_browser_auth_failed'").fetchone()
        assert audit["detail"] == "stage=" + stage
        assert "SECRET" not in audit["detail"]


def test_browser_callback_error_after_imap_validation(signed_in, app, monkeypatch):
    import importlib
    webui = importlib.import_module("filter_vision.app")
    client, csrf = signed_in
    with app.state.store.db() as db:
        db.execute("INSERT INTO accounts(label,provider,host,port,username,folder,"
                   "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   ("Imported", "outlook", "outlook.office365.com", 993,
                    "sample@hotmail.com", "Junk", 30, 0, 1))
    app.state.oauth_code_flows[1] = {
        "owner_csrf": csrf, "expires_at": 2999999999,
        "state": "S" * 50, "verifier": "V" * 65,
        "redirect_uri": "https://localhost",
    }
    monkeypatch.setattr(webui, "redeem_browser_auth",
                        lambda flow, callback_url: {
                            "access_token": "A" * 120,
                            "refresh_token": "R" * 120, "expires_in": 3600,
                        })
    monkeypatch.setattr(webui, "verify_imap_auth",
                        lambda email, token: (_ for _ in ()).throw(
                            OAuthError("Microsoft IMAP authentication failed for this account")))
    r=client.post("/accounts/1/oauth/browser/finish",data={
        "csrf":csrf,"callback_url":"https://localhost?code="+"C"*120+"&state="+"S"*50
    },follow_redirects=False)
    assert r.status_code==303
    assert r.headers["location"].endswith("#browser-result")
    page=client.get("/accounts/1/oauth").text
    assert "Outlook IMAP rejected" in page
    assert "No account was connected" in page
    assert not app.state.token_vault.connected(1)
    with app.state.store.db() as db:
        event=db.execute("SELECT detail FROM audit_events WHERE event='microsoft_browser_auth_failed'").fetchone()
        assert event["detail"]=="stage=imap_validation"
