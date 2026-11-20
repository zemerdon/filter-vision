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
    payload = {"tag_name": "v0.2.6", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.6",
                "target_commitish": "stable", "prerelease": False, "draft": False,
               "body": "- Added activity statistics\n- Fixed update version display"}
    def fake_open(*args, **kwargs):
        return io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    page = client.get("/updates").text
    assert "v0.2.6" in page
    assert "Apply v0.2.6 stable update" in page
    assert "no develop update channel" in page.lower()
    assert "<li>Added activity statistics</li>" in page
    assert "<li>Fixed update version display</li>" in page
    assert "View v0.2.6 release notes on GitHub" not in page
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
    payload = {"tag_name": "v0.2.6", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.6",
               "target_commitish": "main", "prerelease": False, "draft": False}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a,**kw: io.BytesIO(json.dumps(payload).encode()))
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()
    assert client.post("/updates/apply", data={"csrf": csrf}).status_code == 409


def test_stable_updates_rejects_prerelease(signed_in, monkeypatch):
    client, csrf = signed_in
    payload = {"tag_name": "v0.2.6", "html_url":
               "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.6",
               "target_commitish": "stable", "prerelease": True, "draft": False}
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a,**kw: io.BytesIO(json.dumps(payload).encode()))
    assert client.post("/updates/check", data={"csrf": csrf},
                       follow_redirects=False).status_code == 303
    assert "stable release check unavailable" in client.get("/updates").text.lower()


def test_updates_running_version_not_stale_after_a_completed_upgrade(
        client, app, monkeypatch):
    import importlib
    web=importlib.import_module("filter_vision.app")
    assert web.__version__ == "0.2.5"
    app.state.latest={
        "tag":"v0.2.5",
        "url":"https://github.com/zemerdon/filter-vision/releases/tag/v0.2.5",
        "is_newer":True, "notes":["An old cached release"], "error":"",
    }
    monkeypatch.setattr(web,"update_status",lambda: {
        "state":"success", "version":"v0.2.3", "detail":"Earlier success"})
    page=client.get("/updates").text
    assert "v0.2.5" in page
    assert "No newer version reported" in page
    assert "Apply v0.2.5 stable update" not in page
    assert "while it restarts" not in page
    app.state.latest={
        "tag":"v0.2.6",
        "url":"https://github.com/zemerdon/filter-vision/releases/tag/v0.2.6",
        "is_newer":True,"notes":["Privacy-friendly scan history"],"error":"",
    }
    monkeypatch.setattr(web,"update_status",lambda: {
        "state":"success", "version":"v0.2.6", "detail":"Install completed"})
    page=client.get("/updates").text
    assert "The WebUI is still reporting v0.2.5 while it restarts" in page
    assert 'http-equiv="refresh"' in page
    assert "Apply v0.2.6 stable update" not in page


def test_release_notes_html_is_escaped(client, app, monkeypatch):
    app.state.latest={
        "tag":"v0.2.6",
        "url":"https://github.com/zemerdon/filter-vision/releases/tag/v0.2.6",
        "is_newer":True,"notes":["<script>alert('XSS')</script>"],"error":"",
    }
    html=client.get("/updates").text
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
