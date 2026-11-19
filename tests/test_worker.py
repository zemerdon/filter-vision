import importlib
import sqlite3

import pytest

from filter_vision.worker import DryRunError, preview_connection, run_account_dry_run
from filter_vision.oauth import TokenVault


RULES = [
    {"id": 1, "kind": "legacy_raw_header", "pattern": "X-Campaign: Unique-77"},
    {"id": 2, "kind": "legacy_raw_header", "pattern": "special@sender.invalid"},
]


class ReadOnlyIMAP:
    def __init__(self, malformed=False, duplicate=False, no_validity=False, count=3):
        self.commands = []
        self.readonly = None
        self.logged_out = False
        self.malformed = malformed
        self.duplicate = duplicate
        self.no_validity = no_validity
        self.count = count

    def authenticate(self, method, callback):
        assert method == "XOAUTH2"
        payload = callback(b"")
        assert b"\x01auth=Bearer " in payload
        assert payload.endswith(b"\x01\x01")
        return "OK", [b"accepted"]

    def select(self, folder, readonly=False):
        assert folder == "Junk"
        self.readonly = readonly
        return "OK", [b"3"]

    def response(self, name):
        assert name == "UIDVALIDITY"
        if self.no_validity:
            return "UIDVALIDITY", [None]
        return "UIDVALIDITY", [b"78712"]

    def uid(self, command, *args):
        self.commands.append(command)
        if command == "SEARCH":
            if self.duplicate:
                return "OK", [b"1 2 2"]
            return "OK", [b" ".join(str(i).encode() for i in range(1, self.count+1))]
        if command != "FETCH":
            raise AssertionError("A destructive IMAP command was attempted")
        assert args[1] == "(BODY.PEEK[HEADER])"
        if self.malformed:
            return "OK", [(b"header", b"x" * (256 * 1024 + 1))]
        uid = int(args[0])
        if uid == 1:
            headers = b"From: benign@example.invalid\r\nX-MS-Exchange-Organization-SCL: 9\r\n"
        elif uid == 2:
            headers = b"From: special@sender.invalid\r\nX-Campaign: Unique-77\r\n"
        else:
            headers = b"From: benign@example.invalid\r\nX-Campaign: unrelated\r\n"
        return "OK", [(b"header", headers)]

    def logout(self):
        self.logged_out = True


def test_worker_read_only_exact_matches_and_no_scl_only():
    fake = ReadOnlyIMAP()
    report = preview_connection(fake, 7, "Junk", RULES)
    assert report == {
        "account_id": 7, "folder": "Junk", "uidvalidity_present": True,
        "total": 3, "examined": 3, "matched": 1,
        "truncated": False, "per_rule_hits": {1: 1, 2: 1},
        "action": "read_only",
    }
    assert fake.readonly is True
    assert fake.commands == ["SEARCH", "FETCH", "FETCH", "FETCH"]


@pytest.mark.parametrize("options,error", [
    ({"no_validity": True}, "UIDVALIDITY"),
    ({"duplicate": True}, "strictly increasing"),
    ({"malformed": True}, "oversized"),
])
def test_worker_fails_closed_on_bad_imap_server(options, error):
    with pytest.raises(DryRunError, match=error):
        preview_connection(ReadOnlyIMAP(**options), 7, "Junk", RULES)


@pytest.mark.parametrize("rules,folder", [
    ([], "Junk"),
    (RULES, "Inbox"),
    ([{"id": 1, "kind": "sender_domain", "pattern": "example.com"}], "Junk"),
    (RULES + [RULES[0]], "Junk"),
])
def test_worker_refuses_unsafe_scope(rules, folder):
    with pytest.raises(DryRunError):
        preview_connection(ReadOnlyIMAP(), 1, folder, rules)


def test_worker_bounds_and_full_scan_report():
    fake = ReadOnlyIMAP(count=7)
    report = preview_connection(fake, 1, "Junk", RULES, max_uids=3)
    assert report["total"] == 7 and report["examined"] == 3
    assert report["truncated"] is True
    assert len(fake.commands) == 4
    with pytest.raises(DryRunError):
        preview_connection(ReadOnlyIMAP(), 1, "Junk", RULES, max_uids=1001)


def test_worker_isolates_scoped_account_and_records_aggregate_only(tmp_path, monkeypatch):
    from filter_vision.storage import Store
    w = importlib.import_module("filter_vision.worker")
    store = Store(tmp_path/"state")
    with store.db() as db:
        for name in ("sample@hotmail.com","another@live.com"):
            db.execute(
                "INSERT INTO accounts(label,provider,host,port,username,folder,"
                "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("Microsoft","outlook","outlook.office365.com",993,name,"Junk",30,0,1),
            )
        for r in RULES:
            db.execute(
                "INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at)"
                " VALUES(?,?,?,?,?,0,'draft',?)",
                (r["id"],"Imported",r["kind"],"All raw headers",r["pattern"],1),
            )
        db.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(1,1)")
        db.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(2,2)")
    vault = TokenVault(store.directory)
    for id in (1,2):
        vault.save(id,{"access_token":"A"*120,"refresh_token":"R"*120,"expires_in":3600})
    monkeypatch.setattr(w, "access_token_for", lambda id,email,vault: "A"*120)
    connection = ReadOnlyIMAP()
    report = run_account_dry_run(store,1,connector=lambda: connection)
    assert report["per_rule_hits"] == {1: 1}
    assert report["matched"] == 1
    assert connection.logged_out and connection.readonly
    with store.db() as db:
        audit=db.execute("SELECT event,detail FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        assert audit["event"]=="safe_dry_run"
        assert "account_id=1" in audit["detail"]
        assert "sample@" not in audit["detail"]
        assert db.execute("SELECT COUNT(*) FROM accounts WHERE enabled=1").fetchone()[0]==0
        assert db.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0]==0
    assert sorted(p.name for p in (tmp_path/"state"/"scan-locks").glob("*"))==["account-1.lock"]


def test_worker_refuses_unconnected_mailbox_and_missing_account(tmp_path):
    from filter_vision.storage import Store
    store=Store(tmp_path/"state")
    with pytest.raises(DryRunError,match="missing"):
        run_account_dry_run(store,77)
