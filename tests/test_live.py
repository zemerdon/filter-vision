"""No live external email operations; all mutation mocks are strict and auditable."""
import json

import pytest

from filter_vision.live import (
    _scan_live, rules_digest, load_policy, run_live_account,
    LEGACY_SOURCE_SHA, LiveSafetyError,
)
from filter_vision.oauth import TokenVault
from filter_vision.storage import Store

SAMPLE_RULES = [
    {"id": 1, "kind": "legacy_raw_header", "pattern": "X-Campaign: Unique-77"},
    {"id": 2, "kind": "legacy_raw_header", "pattern": "special@sender.invalid"},
]


class LiveIMAP:
    capabilities = (b"IMAP4REV1", b"UIDPLUS", b"AUTH=XOAUTH2")

    def __init__(self, missing_uidplus=False, change_headers=False,
                 change_uidvalidity=False, store_fail=False):
        self.commands = []
        self.logged_out = False
        self.readonly = None
        self.change_headers = change_headers
        self.change_uidvalidity = change_uidvalidity
        self.store_fail = store_fail
        if missing_uidplus:
            self.capabilities = (b"IMAP4REV1",)

    def authenticate(self, mechanism, cb):
        assert mechanism == "XOAUTH2"
        assert b"\x01auth=Bearer " in cb(b"")
        return "OK", [b"authenticated"]

    def select(self, folder, readonly=False):
        assert folder == "Junk"
        self.readonly = readonly
        return "OK", [b"2"]

    def response(self, code):
        assert code == "UIDVALIDITY"
        return "UIDVALIDITY", [None] if self.change_uidvalidity else [b"1"]

    def uid(self, command, *args):
        self.commands.append(command)
        if command == "SEARCH":
            return "OK", [b"3 4"]
        if command == "FETCH":
            assert args[0] in (b"3", b"4")
            if args[1] == "(BODY.PEEK[]<0.32768>)":
                return "OK", [(b"BODY", b"From: archive@sender.invalid\r\n"
                               b"Subject: Test archived message\r\n"
                               b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                               b"Safe text body from mock mailbox")]
            assert args[1] == "(BODY.PEEK[HEADER])"
            if args[0] == b"3":
                return "OK", [(b"HEADER", b"From: harmless@example.invalid\r\n"
                                b"X-MS-Exchange-Organization-SCL: 9\r\n")]
            hits = self.commands.count("FETCH")
            if self.change_headers and hits >= 3:
                return "OK", [(b"HEADER", b"From: harmless@example.invalid\r\n")]
            return "OK", [(b"HEADER", b"X-Campaign: Unique-77\r\n")]
        if command == "STORE":
            assert args == (b"4", "+FLAGS.SILENT", r"(\Deleted)")
            return ("NO", [b"could not set"]) if self.store_fail else ("OK", [])
        if command == "EXPUNGE":
            assert args == (b"4",)
            return "OK", [b"done"]
        raise AssertionError("Unsafe IMAP operation")

    def logout(self):
        self.logged_out = True


def test_only_matching_uid_expunge_and_scl9_not_enough():
    c = LiveIMAP()
    result = _scan_live(c, 1, SAMPLE_RULES)
    assert result == {"account_id": 1, "examined": 2, "matched": 1,
                      "deleted": 1, "total": 2}
    assert c.readonly is False
    assert c.commands == ["SEARCH", "FETCH", "FETCH", "FETCH", "STORE", "EXPUNGE"]
    assert "EXPUNGE" in c.commands
    assert all(cmd != "CLOSE" for cmd in c.commands)


@pytest.mark.parametrize("opts, reason", [
    ({"missing_uidplus": True}, "UIDPLUS"),
    ({"change_headers": True}, "headers changed"),
    ({"change_uidvalidity": True}, "UIDVALIDITY"),
    ({"store_fail": True}, "Deleted flag"),
])
def test_safety_failure_does_not_expunge(opts, reason):
    c = LiveIMAP(**opts)
    with pytest.raises(LiveSafetyError, match=reason):
        _scan_live(c, 1, SAMPLE_RULES)
    assert "EXPUNGE" not in c.commands


def test_policy_only_with_offline_marker(tmp_path):
    p = tmp_path / "policy.json"
    m = tmp_path / "offline"
    value = {"schema": 1, "enabled": True, "legacy_sha256": LEGACY_SOURCE_SHA,
             "rules_sha256": rules_digest(SAMPLE_RULES), "accounts": [1, 2]}
    p.write_text(json.dumps(value))
    with pytest.raises(LiveSafetyError):
        load_policy(p, m, require_root=False)
    m.write_text("LEGACY_STOPPED_VERIFIED\n")
    assert load_policy(p, m, require_root=False)["accounts"] == [1, 2]
    value["enabled"] = False
    p.write_text(json.dumps(value))
    with pytest.raises(LiveSafetyError, match="not approved"):
        load_policy(p, m, require_root=False)


def test_live_account_requires_exact_import_approved_digest_and_scopes(tmp_path, monkeypatch):
    import filter_vision.live as lv
    store=Store(tmp_path/"db")
    with store.db() as c:
        for n in range(2):
            c.execute("INSERT INTO accounts(label,provider,host,port,username,folder,"
                      "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      ("Legacy","outlook","outlook.office365.com",993,
                       f"sample{n}@hotmail.com","Junk",30,0,1))
        for i in range(1,23):
            c.execute("INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at) "
                      "VALUES(?,?,?, ?,?,0,'draft',?)",
                      (i,"Legacy","legacy_raw_header","raw",f"X-Campaign: Unique-{i}",1))
            for a in (1,2):
                c.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",(i,a))
        c.execute("INSERT INTO legacy_imports(source_sha256,account_count,rule_count,imported_at)"
                  " VALUES(?,?,?,?)",(LEGACY_SOURCE_SHA,2,22,1))
    with store.db() as c:
        all_rules=[dict(r) for r in c.execute("SELECT id,pattern FROM rules")]
    policy=tmp_path/"p"
    policy.write_text(json.dumps({
        "schema":1,"enabled":True, "legacy_sha256":LEGACY_SOURCE_SHA,
        "rules_sha256":rules_digest(all_rules),"accounts":[1,2]}))
    marker=tmp_path/"offline"
    marker.write_text("LEGACY_STOPPED_VERIFIED\n")
    v=TokenVault(store.directory)
    v.save(1,{"access_token":"A"*90,"refresh_token":"R"*90,"expires_in":3600})
    monkeypatch.setattr(lv,"access_token_for",lambda *args:"A"*90)
    live=LiveIMAP()
    result=run_live_account(store,1,connector=lambda:live,
                            policy_path=policy,marker=marker,require_root=False)
    assert result["deleted"]==1  # Unique-7 matches Unique-77: exact legacy substring parity
    assert live.logged_out
    # New safe drafts may be saved by Analyze Email and must not suspend
    # the same 22 root-approved legacy signatures.
    with store.db() as c:
        c.execute("INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at) "
                  "VALUES(23,'Safe new draft','sender_domain','from',"
                  "'unapproved.example.invalid',0,'draft',2)")
    repeat=run_live_account(store,1,connector=LiveIMAP,
                            policy_path=policy,marker=marker,require_root=False)
    assert repeat["deleted"] == 1
    # The extra draft must NOT be allowed into the protected scope.
    with store.db() as c:
        c.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(23,1)")
    with pytest.raises(LiveSafetyError, match="scope count"):
        run_live_account(store,1,connector=LiveIMAP,
                         policy_path=policy,marker=marker,require_root=False)
    with store.db() as c:
        c.execute("DELETE FROM rule_scopes WHERE rule_id=23")
        log = c.execute("SELECT rule_ids,state,preview_ciphertext FROM message_actions").fetchone()
        assert log and log["state"] == "deleted" and log["rule_ids"] == "[7]"
        assert b"Safe text body" not in log["preview_ciphertext"]
        assert store.decrypt_message_preview(log["preview_ciphertext"])["body"] == "Safe text body from mock mailbox"
        c.execute("UPDATE rules SET pattern='X-Some-New-Rule' WHERE id=1")
    with pytest.raises(LiveSafetyError, match="changed since approval"):
        run_live_account(store,1,connector=LiveIMAP,policy_path=policy,
                         marker=marker,require_root=False)
