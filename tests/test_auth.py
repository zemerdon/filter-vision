from fastapi.testclient import TestClient
from filter_vision.app import create_app


def test_passwordless_navigation_without_setup(client, app):
    assert not (app.state.store.directory / "setup-token").exists()
    for path in ["/", "/accounts", "/analyze", "/rules", "/activity", "/updates", "/settings"]:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 200, path
        assert "Sign out" not in response.text
        assert "Passwordless" in response.text or "passwordless" in response.text
    assert client.get("/setup", follow_redirects=False).headers["location"] == "/"
    assert client.get("/login", follow_redirects=False).headers["location"] == "/"
    for path in ["/setup", "/login"]:
        assert client.post(path, data={"password":"foo"}).status_code == 405
    assert client.post("/logout").status_code == 404


def test_no_setup_token_and_signed_cookie(client, app):
    response = client.get("/accounts")
    assert response.status_code == 200
    assert "fv_browser" in client.cookies
    cookie = response.headers.get("set-cookie", "").lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert not (app.state.store.directory / "setup-token").exists()


def test_csrf_still_required_for_all_writes(signed_in):
    client, csrf = signed_in
    payload = {"label":"Draft", "provider":"outlook", "host":"outlook.office365.com",
               "port":993, "username":"draft@example.com", "folder":"Junk", "interval":30}
    assert client.post("/accounts", data=payload).status_code == 403
    assert client.post("/accounts", data={**payload,"csrf":csrf[:-1]+"X"}).status_code == 403
    assert client.post("/accounts", data={**payload,"csrf":csrf},
                       headers={"Origin":"https://attacker.invalid"}).status_code == 403
    assert client.post("/accounts", data={**payload,"csrf":csrf},
                       follow_redirects=False).status_code == 303


def test_untrusted_source_does_not_get_webui(app):
    with TestClient(app, base_url="https://filter-vision",
                    client=("8.8.8.8", 50000)) as external:
        for path in ["/", "/accounts", "/rules", "/healthz", "/static/style.css"]:
            assert external.get(path).status_code == 403, path
        assert external.post("/rules", data={"csrf":"anything"}).status_code == 403


def test_host_rebinding_rejected(app):
    with TestClient(app, base_url="https://attacker.example",
                    client=("192.168.1.69", 50000)) as browser:
        assert browser.get("/").status_code == 400


def test_bad_cookie_cannot_authorize_csrf(signed_in):
    client, good_csrf = signed_in
    client.cookies.clear()
    client.cookies.set("fv_browser", "tampered.bad", path="/")
    response = client.get("/accounts")
    assert response.status_code == 200
    assert "fv_browser=" in response.headers.get("set-cookie","")
    data = {"csrf":good_csrf,"label":"Draft","provider":"outlook","host":"imap.example.com",
            "port":993,"username":"user@example.com","folder":"Junk","interval":30}
    assert client.post("/accounts",data=data).status_code == 403


def test_trusted_network_override_narrowed(tmp_path, monkeypatch):
    monkeypatch.setenv("FV_TRUSTED_CIDRS","127.0.0.1/32")
    app=create_app(tmp_path / "narrow")
    with TestClient(app, base_url="https://filter-vision",
                    client=("192.168.1.69",50000)) as blocked:
        assert blocked.get("/").status_code == 403
    with TestClient(app, base_url="https://filter-vision",
                    client=("127.0.0.1",50000)) as allowed:
        assert allowed.get("/").status_code == 200


def test_secure_headers(client):
    resp = client.get("/healthz")
    assert resp.json() == {"status":"ok","service":"filter-vision"}
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_browser_origin_port_variations_and_forgery_rejection(app):
    """POSTs must work from the same HTTPS host even with omitted Origin port."""
    import re
    from fastapi.testclient import TestClient
    with TestClient(app, base_url="https://filter-vision:9494",
                    client=("192.168.1.69", 50000)) as browser:
        page = browser.get("/accounts")
        assert page.status_code == 200
        csrf = re.search(r'name="csrf" value="([0-9a-f]{64})"', page.text).group(1)
        payload = {"csrf": csrf, "label": "Browser draft", "provider": "outlook",
                   "host": "outlook.office365.com", "port": 993,
                   "username": "sample@example.com", "folder": "Junk", "interval": 30}
        for origin in ["https://filter-vision:9494", "https://filter-vision", "null"]:
            response = browser.post("/accounts", data=payload,
                                    headers={"Origin": origin},
                                    follow_redirects=False)
            assert response.status_code == 303, (origin, response.text)
        for origin in ["http://filter-vision:9494", "https://filter-vision:9999",
                       "https://evil.example:9494", "https://filter-vision:badport",
                       "https://filter-vision:9494/malicious"]:
            response = browser.post("/accounts", data=payload,
                                    headers={"Origin": origin})
            assert response.status_code == 403, origin
        assert browser.post("/accounts", data=payload,
                            headers={"Origin": "null",
                                     "Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert browser.post("/accounts", data={**payload, "csrf": ""},
                            headers={"Origin": "null"}).status_code == 403


def test_oauth_and_update_forms_accept_implicit_https_origin_port(app, monkeypatch):
    """Regression covering both buttons reported broken by the browser."""
    import importlib
    import io
    import json
    import re
    from fastapi.testclient import TestClient
    webui = importlib.import_module("filter_vision.app")
    with app.state.store.db() as con:
        con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,interval_minutes,"
            "enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("Microsoft", "outlook", "outlook.office365.com", 993,
             "sample@hotmail.com", "Junk", 30, 0, 1),
        )
    def fake_start(email):
        assert email == "sample@hotmail.com"
        return {"device_code": "D" * 60, "user_code": "F4G7-Q8K9",
                "verification_uri": "https://www.microsoft.com/link",
                "expires_at": 2999999999, "interval": 5, "last_poll_at": 0,
                "settings": {"client_id": "fixture"}}
    monkeypatch.setattr(webui, "start_device_auth", fake_start)
    metadata = {"tag_name": "v0.1.6", "target_commitish": "stable",
                "draft": False, "prerelease": False,
                "html_url": "https://github.com/zemerdon/filter-vision/releases/tag/v0.1.6"}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *args, **kwargs: io.BytesIO(json.dumps(metadata).encode()))
    with TestClient(app, base_url="https://filter-vision:9494",
                    client=("192.168.1.69", 50000)) as browser:
        response = browser.get("/updates")
        csrf = re.search(r'name="csrf" value="([0-9a-f]{64})"', response.text).group(1)
        headers = {"Origin": "https://filter-vision"}
        assert browser.post("/updates/check", data={"csrf": csrf}, headers=headers,
                            follow_redirects=False).status_code == 303
        assert "v0.1.6" in browser.get("/updates").text
        assert browser.post("/accounts/1/oauth/start", data={"csrf": csrf},
                            headers=headers, follow_redirects=False).status_code == 303
        page = browser.get("/accounts/1/oauth")
        assert page.status_code == 200
        assert "F4G7-Q8K9" in page.text
        assert "D" * 40 not in page.text
