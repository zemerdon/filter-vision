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


def test_stable_updates_no_apply_endpoint(signed_in, monkeypatch):
    client, csrf = signed_in
    payload = {"tag_name": "v0.2.0", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.0"}
    def fake_open(*args, **kwargs):
        return io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    page = client.get("/updates").text
    assert "v0.2.0" in page
    assert "Apply update — unavailable" in page
    assert "no develop update channel" in page.lower()
    assert client.post("/updates/apply", data={"csrf": csrf}).status_code == 404


def test_stable_updates_invalid_api_payload(signed_in, monkeypatch):
    client, csrf = signed_in
    def fake_open(*args, **kwargs):
        return io.BytesIO(json.dumps({"tag_name": "v0.2.0-beta", "html_url":
            "https://attacker.invalid"}).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()
