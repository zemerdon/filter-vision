import hashlib

import pytest

from filter_vision.import_legacy import import_payload, legacy_matches
from filter_vision.storage import Store


def sample():
    return {
        "schema": 1,
        "source_sha256": hashlib.sha256(b"legacy-fixture").hexdigest(),
        "accounts": ["sample@hotmail.com", "sample@live.com"],
        "rules": ["X-Relaying-Domain: domain.invalid", "7404:422441:posti",
                  "sales@fmaparts.invalid"],
        "folder": "Junk",
        "scan_interval_minutes": 30,
        "legacy_action": "permanent_delete",
    }


def test_import_scoped_disabled_and_idempotent(tmp_path):
    store = Store(tmp_path / "state")
    assert import_payload(store, sample()) == {"accounts": 2, "rules": 3,
                                                "already_imported": False}
    assert import_payload(store, sample()) == {"accounts": 0, "rules": 0,
                                                "already_imported": True}
    with store.db() as con:
        accounts = con.execute(
            "SELECT username,enabled,folder,interval_minutes,host FROM accounts ORDER BY id"
        ).fetchall()
        assert len(accounts) == 2
        assert all(x["enabled"] == 0 and x["folder"] == "Junk" and
                   x["interval_minutes"] == 30 and x["host"] == "outlook.office365.com"
                   for x in accounts)
        rules = con.execute("SELECT kind,pattern,enabled,action FROM rules").fetchall()
        assert len(rules) == 3
        assert all(x["kind"] == "legacy_raw_header" and not x["enabled"]
                   and x["action"] == "draft" for x in rules)
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 6


def test_failed_import_atomic_no_partial_mutation(tmp_path):
    store = Store(tmp_path / "state")
    with store.db() as con:
        con.execute("INSERT INTO accounts(label,provider,host,port,username,folder,"
                    "interval_minutes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    ("Collision", "outlook", "outlook.office365.com", 993,
                     "sample@live.com", "Junk", 30, 1))
    with pytest.raises(RuntimeError, match="reconciliation"):
        import_payload(store, sample())
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM legacy_imports").fetchone()[0] == 0


@pytest.mark.parametrize("change", [
    lambda x: x.update(folder="Inbox"),
    lambda x: x.update(legacy_action="auto-delete"),
    lambda x: x.update(scan_interval_minutes=5),
    lambda x: x.update(accounts=["badaddress"]),
    lambda x: x.update(rules=["scl 9", "SCL 9"]),
    lambda x: x.update(rules=["x\nanything"]),
    lambda x: x.update(source_sha256="nothash"),
])
def test_reject_mismatched_legacy_export(tmp_path, change):
    payload = sample()
    change(payload)
    store = Store(tmp_path / "state")
    with pytest.raises(ValueError):
        import_payload(store, payload)
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_legacy_raw_header_exact_casefold():
    headers = b"From: Example <friendly@example.invalid>\r\nX-Relaying-Domain: domain.invalid\r\n\r\n"
    assert legacy_matches(headers, "x-relaying-domain: DOMAIN.INVALID")
    assert not legacy_matches(headers, "X-Relaying-Domain: other.invalid")
    assert not legacy_matches(b"X-MS-Exchange-Organization-SCL: 9\r\n\r\n",
                              "X-Relaying-Domain: domain.invalid")


def test_schema_v1_migration_retains_rows(tmp_path):
    from filter_vision.storage import DDL
    import sqlite3
    path = tmp_path / "db"
    path.mkdir()
    con = sqlite3.connect(path / "filter-vision.sqlite3")
    con.executescript(DDL)
    con.execute("INSERT INTO accounts(label,provider,host,port,username,folder,"
                "interval_minutes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                ("Existing", "outlook", "outlook.office365.com", 993, "sample@example.com", "Junk", 30, 1))
    con.commit()
    con.close()
    store = Store(path)
    with store.db() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert db.execute("SELECT activity_limit FROM app_preferences").fetchone()[0] == 50
        assert db.execute("SELECT COUNT(*) FROM message_actions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0
