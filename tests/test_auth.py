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
