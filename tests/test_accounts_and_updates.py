import io
import json

def test_disabled_account_draft(signed_in, app):
    client, csrf = signed_in
    response = client.post("/accounts", data={
        "csrf": csrf, "label": "My Hotmail", "provider": "outlook",
        "host": "outlook.office365.com", "port": 993,
        "username": "user@example.com", "folder": "Junk", "interval": 30,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert "My Hotmail" in client.get("/accounts").text
    with app.state.store.db() as con:
        row = con.execute("SELECT enabled FROM accounts").fetchone()
    assert row["enabled"] == 0
    assert client.post("/accounts", data={"csrf": csrf, "label": "X",
        "provider": "outlook", "host": "http://evil", "port": 993,
        "username": "user@example.com", "folder": "Junk", "interval": 30}).status_code == 400


def test_stable_updates_queues_fixed_action(signed_in, app, monkeypatch):
    client, csrf = signed_in
    payload = {"tag_name": "v0.2.1", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.0",
               "target_commitish": "stable", "prerelease": False, "draft": False}
    def fake_open(*args, **kwargs):
        return io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    page = client.get("/updates").text
    assert "v0.2.1" in page
    assert "Apply v0.2.1 stable update" in page
    assert "no develop update channel" in page.lower()
    assert client.post("/updates/apply", data={"csrf": csrf+"x"}).status_code == 403
    assert client.post("/updates/apply", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    request = app.state.store.directory / "update-request"
    assert request.read_bytes() == b"latest-stable" + bytes([10])
    assert request.stat().st_mode & 0o777 == 0o600
    assert client.post("/updates/apply", data={"csrf": csrf}).status_code == 409


def test_stable_updates_invalid_api_payload(signed_in, monkeypatch):
    client, csrf = signed_in
    def fake_open(*args, **kwargs):
        return io.BytesIO(json.dumps({"tag_name": "v0.2.0-beta", "html_url":
            "https://attacker.invalid"}).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()


def test_stable_updates_rejects_wrong_branch(signed_in, monkeypatch):
    client, csrf = signed_in
    payload = {"tag_name": "v0.2.1", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.0",
               "target_commitish": "main", "prerelease": False, "draft": False}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a,**kw: io.BytesIO(json.dumps(payload).encode()))
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()
    assert client.post("/updates/apply", data={"csrf": csrf}).status_code == 409


def test_stable_updates_rejects_prerelease(signed_in, monkeypatch):
    client, csrf = signed_in
    payload = {"tag_name": "v0.2.1", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.0",
               "target_commitish": "stable", "prerelease": True, "draft": False}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a,**kw: io.BytesIO(json.dumps(payload).encode()))
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()
