from filter_vision.app import password_hash, password_ok


def test_password_roundtrip():
    digest = password_hash("A good password 1234!")
    assert "A good password" not in digest
    assert password_ok("A good password 1234!", digest)
    assert not password_ok("bad password", digest)
    assert not password_ok("bad", "not-a-valid-hash")


def test_setup_requires_random_code(client, app):
    assert client.get("/").url.path == "/setup"
    assert client.post("/setup", data={"setup_code": "wrong", "password": "secure-strong-password",
                                       "password_confirm": "secure-strong-password"}).status_code == 400
    assert not app.state.store.has_admin()
    assert len(app.state.store.setup_path.read_text().strip()) >= 40


def test_setup_login_logout(signed_in):
    client, csrf = signed_in
    assert "Dashboard" in client.get("/").text
    assert client.get("/accounts").status_code == 200
    assert client.get("/analyze").status_code == 200
    assert client.get("/updates").status_code == 200
    assert client.post("/logout", data={"csrf": csrf+"x"}, follow_redirects=False).status_code == 403
    assert client.post("/logout", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert client.get("/").url.path == "/login"


def test_login_rate_limit(client, app):
    code = app.state.store.setup_path.read_text().strip()
    client.post("/setup", data={"setup_code": code, "password": "strong-password-123!",
                                "password_confirm": "strong-password-123!"})
    for i in range(8):
        assert client.post("/login", data={"password": "wrong"}).status_code == 401
    assert client.post("/login", data={"password": "wrong"}).status_code == 429


def test_sensitive_endpoints_reject_unauthenticated(client):
    for path in ["/", "/accounts", "/analyze", "/rules", "/activity", "/updates", "/settings"]:
        assert client.get(path, follow_redirects=False).status_code == 303
    assert client.post("/rules", data={"kind": "sender_exact",
            "field": "From", "value": "foo@example.com"}, follow_redirects=False).status_code == 303


def test_secure_headers(client):
    resp = client.get("/healthz")
    assert resp.json() == {"status": "ok", "service": "filter-vision"}
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"
