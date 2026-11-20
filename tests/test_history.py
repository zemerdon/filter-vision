"""Activity list settings, historical totals, private email preview and security."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sqlite3
import re

import pytest

from filter_vision.history import safe_email_preview, report, MAX_CAPTURE_BYTES
from filter_vision.storage import Store
from filter_vision.recovery import create_key, backup, verify, restore_staging, BackupError
from filter_vision.release_notes import changelog_items


def _create_account(store):
    with store.db() as db:
        db.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,"
            "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("Example", "outlook", "outlook.office365.com", 993,
             "archive@example.invalid", "Junk", 30, 0, 1))
        for id in (1, 2):
            db.execute(
                "INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at)"
                " VALUES(?,?,?,?,?,0,'draft',?)",
                (id, f"Rule #{id}", "legacy_raw_header", "raw", f"Test-{id}", 1))


def test_default_limits_and_persistent_activity_preferences(tmp_path):
    store = Store(tmp_path/"data")
    assert store.activity_limit() == 50
    for limit in (25, 50, 100, 250, 500):
        store.set_activity_limit(limit)
        assert Store(tmp_path/"data").activity_limit() == limit
    for invalid in (0, 1, 20, 1000, "50", True, None):
        with pytest.raises(ValueError):
            store.set_activity_limit(invalid)
    assert Store(tmp_path/"data").activity_limit() == 500
    assert (tmp_path/"data/activity.key").stat().st_mode & 0o777 == 0o600


def test_encrypted_mail_history_stats_and_rule_counts(tmp_path):
    store = Store(tmp_path/"data")
    _create_account(store)
    with store.db() as db:
        for i in range(4):
            db.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                       (i+10,"live_scan",
                        f"account_id=1 inspected=4 matched={int(i<2)} deleted={int(i<2)}"))
        db.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                   (20, "live_scan_failed", "account_id=1 stage=TestFailure"))
    preview = {"from": "tester@example.invalid", "to": "recipient@example.invalid",
               "subject": "Archive this email", "date": "20 Nov 2026", "body": "Text preview"}
    item = store.record_pending_action(1, 47, [1, 2], preview)
    with store.db() as db:
        row=db.execute("SELECT preview_ciphertext,state FROM message_actions WHERE id=?",(item,)).fetchone()
    assert b"tester@example.invalid" not in row["preview_ciphertext"]
    assert b"Text preview" not in row["preview_ciphertext"]
    assert row["state"] == "pending"
    assert report(store)["uncertain"] == 1
    store.mark_action_deleted(item)
    results = report(store)
    assert results["totals"] == {"scans":4,"examined":16,"matched":2,"deleted":2,"failures":1}
    assert results["confirmed_logged"] == 1
    assert [r["count"] for r in results["per_rule"]] == [1, 1]
    assert [r["id"] for r in results["per_rule"]] == [1, 2]
    action = next(e for e in results["entries"] if e["kind"] == "message")
    assert action["action"]["preview"]["subject"] == "Archive this email"
    assert len(action["action"]["rules"]) == 2
    with pytest.raises(RuntimeError,match="unknown pending"):
        store.mark_action_deleted(item)


def test_activity_history_limit_affects_only_visible_entries(tmp_path):
    store = Store(tmp_path/"db")
    with store.db() as db:
        for id in range(85):
            db.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                       (id+1, "example", "No private details"))
    assert len(report(store)["entries"]) == 50
    store.set_activity_limit(25)
    result=report(store)
    assert len(result["entries"]) == 25
    store.set_activity_limit(100)
    assert len(report(store)["entries"]) == 85
    assert "1970" in result["entries"][0]["when"]


def test_preview_no_raw_html_or_attachments():
    header=b"From: sender@example.invalid\r\nTo: owner@example.invalid\r\nSubject: Hello world\r\nDate: Thu, 20 Nov 2026 15:10:00 +1000\r\n\r\n"
    content=header + b'Content not parsed as MIME'
    # The preview must not expose HTML tags or unsafe attachment content.
    plain=header.split(b"\r\n\r\n")[0] + (
        b"\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<h1>Hello</h1><script>alert('XSS')</script><p>OK</p>")
    result=safe_email_preview(header,plain)
    assert result["subject"]=="Hello world"
    assert "Hello" in result["body"] and "OK" in result["body"]
    assert "<h1>" not in result["body"] and "alert(" not in result["body"]
    with pytest.raises(ValueError,match="exceeded"):
        safe_email_preview(header,b"X"*(MAX_CAPTURE_BYTES+1))
    message=(header.split(b"\r\n\r\n")[0]+
             b"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
             b"Example email body.")
    assert "Example email body." in safe_email_preview(header,message)["body"]


def test_private_preview_backup_and_restoration(tmp_path):
    store=Store(tmp_path/"data")
    _create_account(store)
    store.record_pending_action(1, 123, [1], {
        "from":"secret@example.invalid","to":"me@example.invalid",
        "subject":"Secret mail","date":"Friday","body":"Confidential body"})
    cfg=tmp_path/"config";cfg.mkdir()
    key=tmp_path/"backup.key";create_key(key)
    archive=tmp_path/"history.fvb"
    backup(store.directory,cfg,archive,key)
    files=verify(archive,key)
    assert "data/activity.key" in files
    assert b"Confidential body" not in archive.read_bytes()
    restore_staging(archive,key,tmp_path/"restored",tmp_path/"restored-config")
    restored=Store(tmp_path/"restored")
    with restored.db() as db:
        row=db.execute("SELECT preview_ciphertext FROM message_actions").fetchone()
    assert restored.decrypt_message_preview(row[0])["body"] == "Confidential body"


def test_existing_mail_history_without_key_fails_closed(tmp_path):
    store=Store(tmp_path/"data")
    _create_account(store)
    store.record_pending_action(1,44,[1],{"body":"Original confidential content"})
    store.activity_key_path.unlink()
    with pytest.raises(RuntimeError,match="encryption key missing"):
        Store(store.directory)


def test_changelog_bullets_and_prose_are_safe_and_bounded():
    assert changelog_items("- One new feature\n- Better status") == ["One new feature","Better status"]
    assert changelog_items("Not a list but a long paragraph. "+ "A second useful sentence. "*20)
    assert len(changelog_items("- Nice\n"*100)) == 12
    assert changelog_items(43) == []


def test_activity_page_escapes_private_previews(client, app):
    store=app.state.store
    _create_account(store)
    store.record_pending_action(1, 4, [1], {
        "from":"sender@example.invalid","to":"me@example.invalid",
        "subject":"<img src=x onerror=alert(1)>",
        "date":"Friday",
        "body":"<script>alert('XSS')</script> <a href='https://attacker.invalid'>hello</a>"})
    page=client.get("/activity")
    assert page.status_code==200
    assert "EMAILS FILTERED" in page.text
    assert "Filtering by rule" in page.text
    assert "Show captured email" in page.text
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text
    assert "Server time" in page.text
    assert "Unix time" not in page.text


def test_activity_settings_guard_and_persist(signed_in, app):
    client, csrf = signed_in
    assert client.post("/settings/activity",data={"activity_limit":"100"}).status_code==403
    assert client.post("/settings/activity",data={"csrf":csrf+"x","activity_limit":"100"}).status_code==403
    for invalid in ("0","51","700","<script>","50;delete"):
        result=client.post("/settings/activity",data={"csrf":csrf,"activity_limit":invalid})
        assert result.status_code==400
    update=client.post("/settings/activity",data={"csrf":csrf,"activity_limit":"250"},follow_redirects=False)
    assert update.status_code==303
    assert update.headers["location"] == "/settings#activity-settings"
    assert app.state.store.activity_limit()==250
    assert "250 entries" in client.get("/settings").text
    assert "Last 250 entries" in client.get("/activity").text


def test_backup_fails_closed_without_encryption_key_for_existing_mail(tmp_path):
    store=Store(tmp_path/"data")
    _create_account(store)
    store.record_pending_action(1,21,[1],{"body":"Sensitive history"})
    store.activity_key_path.unlink()
    cfg=tmp_path/"config";cfg.mkdir()
    key=tmp_path/"backup.key";create_key(key)
    archive=tmp_path/"should-not-be-written.fvb"
    with pytest.raises(BackupError,match="encryption key"):
        backup(store.directory,cfg,archive,key)
    assert not archive.exists()


def test_private_action_requires_history_write_before_mail_delete():
    from filter_vision.live import _scan_live, LiveSafetyError
    from test_live import LiveIMAP, SAMPLE_RULES
    class FailingStore:
        def record_pending_action(self, *args):
            raise OSError("Simulated encrypted store full")
        def mark_action_deleted(self, *args):
            pytest.fail("No confirmed deletion should be possible")
    connection=LiveIMAP()
    with pytest.raises(LiveSafetyError,match="securely record"):
        _scan_live(connection,1,SAMPLE_RULES,journal=FailingStore())
    assert "STORE" not in connection.commands
    assert "EXPUNGE" not in connection.commands


def test_reject_mail_preview_failure_before_mutation():
    from filter_vision.live import _scan_live, LiveSafetyError
    from test_live import LiveIMAP, SAMPLE_RULES
    class NoPreview(LiveIMAP):
        def uid(self, command, *args):
            if command == "FETCH" and args[1] == "(BODY.PEEK[]<0.32768>)":
                self.commands.append("FETCH")
                return "NO", [b"rejected"]
            return super().uid(command,*args)
    connection=NoPreview()
    with pytest.raises(LiveSafetyError,match="Bounded message preview"):
        _scan_live(connection,1,SAMPLE_RULES,journal=object())
    assert "STORE" not in connection.commands
    assert "EXPUNGE" not in connection.commands
