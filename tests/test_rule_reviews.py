"""All saved rules expose controls; pending reviews never alter live mail deletion."""
from __future__ import annotations

import json
import sqlite3

from filter_vision.rule_reviews import load_review, RuleManagementError


def add_account(store):
    with store.db() as con:
        cur = con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,interval_minutes,"
            "enabled,created_at) VALUES('Test Outlook','outlook','outlook.office365.com',993,"
            "'synthetic@example.invalid','Junk',30,0,1)")
        return cur.lastrowid


def add_draft(store):
    with store.db() as con:
        cur = con.execute(
            "INSERT INTO rules(label,kind,field,pattern,enabled,action,created_at)"
            "VALUES('Test source','sender_domain','From','sub.example.invalid',0,'draft',1)")
        return cur.lastrowid


def add_legacy(store, account_id):
    with store.db() as con:
        cur = con.execute(
            "INSERT INTO rules(label,kind,field,pattern,enabled,action,created_at)"
            "VALUES('Protected','legacy_raw_header','raw','X-Test-Header: synthetic-id-123',0,'draft',1)")
        rule_id = cur.lastrowid
        con.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",
                    (rule_id, account_id))
        return rule_id


def rows(store):
    with store.db() as con:
        rules = [dict(x) for x in con.execute("SELECT * FROM rules ORDER BY id")]
        scopes = [tuple(x) for x in con.execute("SELECT rule_id,account_id FROM rule_scopes")]
        requests = [dict(x) for x in con.execute(
            "SELECT * FROM rule_review_requests ORDER BY id")]
    return rules, scopes, requests


def test_draft_enable_stages_only_valid_account_scope(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    rule_id = add_draft(store)
    account_id = add_account(store)
    before = rows(store)
    url = f"/rules/{rule_id}/request"
    for payload in (
        {"operation": "enable", "confirm": "request_review"},
        {"operation": "enable", "confirm": "request_review", "account_ids": "99999"},
        {"operation": "enable", "confirm": "not_review", "account_ids": str(account_id)},
        {"operation": "disabled", "confirm": "request_review", "account_ids": str(account_id)},
    ):
        response = client.post(url, data={"csrf": csrf, **payload},
                               follow_redirects=False)
        assert response.status_code == 400
        assert rows(store) == before
    response = client.post(url, data={
        "csrf": csrf, "operation": "enable", "confirm": "request_review",
        "account_ids": str(account_id)}, follow_redirects=False)
    assert response.status_code == 303
    after = rows(store)
    assert after[0] == before[0] and after[1] == before[1]
    assert len(after[2]) == 1
    review = after[2][0]
    assert review["operation"] == "enable"
    assert review["status"] == "pending_review"
    assert json.loads(review["account_ids"]) == [account_id]
    assert review["kind"] == "sender_domain"
    assert review["pattern"] == "sub.example.invalid"
    assert "Pending proposals" in client.get("/rules").text
    assert "Pending proposals" in client.get("/rules").text


def test_legacy_disable_keeps_all_signatures_and_scopes(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    account_id = add_account(store)
    rule_id = add_legacy(store, account_id)
    before = rows(store)
    response = client.post(f"/rules/{rule_id}/request",data={
        "csrf": csrf,"operation":"disable","confirm":"request_review"},
        follow_redirects=False)
    assert response.status_code == 303
    after = rows(store)
    assert before[0] == after[0]
    assert before[1] == after[1]
    assert len(after[2]) == 1
    assert json.loads(after[2][0]["account_ids"]) == [account_id]
    assert after[2][0]["operation"] == "disable"
    assert client.post(f"/rules/{rule_id}/delete",data={
        "csrf": csrf,"confirm":"delete"}).status_code == 409


def test_legacy_duplicate_is_direct_disabled_copy_not_a_review(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    aid = add_account(store)
    rid = add_legacy(store, aid)
    before = rows(store)
    duplicated = client.post(f"/rules/{rid}/duplicate",
                             data={"csrf":csrf},follow_redirects=False)
    assert duplicated.status_code == 303
    assert duplicated.headers["location"].startswith("/rules/")
    copied_id = int(duplicated.headers["location"].split("/")[2])
    with store.db() as con:
        copied = dict(con.execute("SELECT * FROM rules WHERE id=?",
                                  (copied_id,)).fetchone())
        current = dict(con.execute("SELECT * FROM rules WHERE id=?",
                                   (rid,)).fetchone())
        scopes = [tuple(x) for x in con.execute("SELECT * FROM rule_scopes")]
        reviews = con.execute("SELECT COUNT(*) FROM rule_review_requests").fetchone()[0]
    assert copied["kind"] == "custom_raw_header"
    assert copied["enabled"] == 0 and copied["action"] == "draft"
    assert current == before[0][0] and scopes == before[1]
    assert reviews == 0
    # Editing the duplicate is a normal draft save, without root-only
    # original signature mutation or a second confirmation page.
    changed = client.post(f"/rules/{copied_id}/edit", data={
        "csrf":csrf, "definition":"sender_domain:From",
        "value":"other.example.invalid", "label":"Independent copy"},
        follow_redirects=False)
    assert changed.status_code == 303
    with store.db() as con:
        copied_new = dict(con.execute("SELECT * FROM rules WHERE id=?",
                                     (copied_id,)).fetchone())
        original = dict(con.execute("SELECT * FROM rules WHERE id=?",(rid,)).fetchone())
    assert copied_new["pattern"] == "other.example.invalid"
    assert original == current


def test_root_original_drift_does_not_rewrite_independent_copy(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    aid = add_account(store)
    rid = add_legacy(store, aid)
    duplicated = client.post(f"/rules/{rid}/duplicate",
                             data={"csrf":csrf},follow_redirects=False)
    assert duplicated.status_code == 303
    with store.db() as con:
        con.execute("UPDATE rules SET label='Changed underneath original root policy' "
                    "WHERE id=?", (rid,))
    # The disabled copied draft is independent of imported original's
    # subsequent label and is editable without inheriting any approval.
    editor = client.get(duplicated.headers["location"])
    assert editor.status_code == 200
    copied_id = int(duplicated.headers["location"].split("/")[2])
    with store.db() as con:
        copied = dict(con.execute("SELECT * FROM rules WHERE id=?",
                                  (copied_id,)).fetchone())
    assert copied["enabled"] == 0 and copied["action"] == "draft"


def test_csrf_origin_and_replay_fails_closed(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    rid = add_draft(store)
    aid = add_account(store)
    url = f"/rules/{rid}/request"
    payload = {"operation": "enable","confirm":"request_review","account_ids":str(aid)}
    for data, headers in (
        (payload, {}),
        ({"csrf":"bad",**payload}, {}),
        ({"csrf":csrf,**payload}, {"Origin":"https://other.invalid"}),
    ):
        assert client.post(url, data=data, headers=headers).status_code == 403
    assert rows(store)[2] == []
    ok = client.post(url, data={"csrf":csrf,**payload},follow_redirects=False)
    assert ok.status_code == 303
    request_id = rows(store)[2][0]["id"]
    for url,payload in (
        (f"/rule-reviews/{request_id}/cancel",{"confirm":"cancel"}),
        (f"/rule-reviews/{request_id}/edit",{
            "definition":"sender_domain:From","value":"aaa.example.invalid",
            "label":"changed"}),
    ):
        assert client.post(url, data={"csrf":"bad", **payload}).status_code == 403
    assert rows(store)[2][0]["status"] == "pending_review"


def test_schema_migrated_review_is_inert(tmp_path):
    from filter_vision.storage import Store, SCHEMA_VERSION
    store = Store(tmp_path / "state")
    with store.db() as con:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        row = con.execute(
            "SELECT COUNT(*) FROM rule_review_requests").fetchone()[0]
    assert version == SCHEMA_VERSION == 4
    assert row == 0

def test_schema_v3_upgrade_preserves_22_legacy_signatures_and_44_scopes(tmp_path):
    from filter_vision.storage import Store, DDL, SCHEMA_V2, SCHEMA_V3
    target = tmp_path / "v3existing"
    target.mkdir()
    con = sqlite3.connect(target / "filter-vision.sqlite3")
    con.executescript(DDL)
    con.executescript(SCHEMA_V2)
    con.executescript(SCHEMA_V3)
    for n in (1, 2):
        con.execute(
            "INSERT INTO accounts(id,label,provider,host,port,username,folder,"
            "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,0,1)",
            (n,"Account", "outlook", "outlook.office365.com",993,
             f"test{n}@example.invalid","Junk",30))
    for idx in range(1, 23):
        con.execute(
            "INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at)"
            "VALUES(?,?,'legacy_raw_header','raw',?,0,'draft',1)",
            (idx,f"Legacy {idx}",f"X-Synthetic-ID: {idx:03d}"))
        for account in (1, 2):
            con.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",
                        (idx, account))
    con.commit()
    old = [tuple(x) for x in con.execute("SELECT * FROM rules ORDER BY id")]
    scopes = [tuple(x) for x in con.execute(
        "SELECT rule_id,account_id FROM rule_scopes ORDER BY rule_id,account_id")]
    assert len(old) == 22 and len(scopes) == 44
    assert con.execute("PRAGMA user_version").fetchone()[0] == 3
    con.close()
    store = Store(target)
    with store.db() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert [tuple(x) for x in db.execute(
            "SELECT * FROM rules ORDER BY id")] == old
        assert [tuple(x) for x in db.execute(
            "SELECT rule_id,account_id FROM rule_scopes ORDER BY rule_id,account_id")] == scopes
        assert db.execute("SELECT COUNT(*) FROM rule_review_requests").fetchone()[0] == 0
