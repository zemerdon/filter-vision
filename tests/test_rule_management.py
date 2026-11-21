"""Rule UI controls must never mutate root-approved live deletion rules."""
from __future__ import annotations

import sqlite3
import json

import pytest

from filter_vision.rule_management import RuleManagementError, update_draft

DRAFT = {
    "kind": "sender_domain",
    "field": "From",
    "value": "advertising.example.invalid",
}
EDIT = {
    "definition": "header_contains:Feedback-ID",
    "value": "unique-campaign-123",
    "label": "Known campaign source",
}


def created_draft(client, csrf, **values):
    result = client.post("/rules", data={"csrf": csrf, **{**DRAFT, **values}},
                         follow_redirects=False)
    assert result.status_code == 303
    return result


def get_rule(store, *, pattern: str = DRAFT["value"]):
    with store.db() as con:
        row = con.execute("SELECT * FROM rules WHERE pattern=?", (pattern,)).fetchone()
    assert row is not None
    return dict(row)


def test_edit_draft_form_and_safe_update(signed_in, app):
    client, csrf = signed_in
    created_draft(client, csrf)
    row = get_rule(app.state.store)
    page = client.get("/rules")
    assert page.status_code == 200
    assert "Manage" in page.text and "Edit" in page.text
    assert "Duplicate" in page.text and '>Delete</button>' in page.text
    assert 'name="confirm"' not in page.text
    assert f'href="/rules/{row["id"]}/edit"' in page.text
    editor = client.get(f'/rules/{row["id"]}/edit')
    assert editor.status_code == 200
    assert "Edit rule" in editor.text
    assert DRAFT["value"] in editor.text
    assert 'name="definition"' in editor.text
    response = client.post(f'/rules/{row["id"]}/edit',
                           data={"csrf": csrf, **EDIT}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/rules"
    with app.state.store.db() as con:
        updated = con.execute("SELECT * FROM rules WHERE id=?", (row["id"],)).fetchone()
        changes = con.execute("SELECT event,detail FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    assert updated["id"] == row["id"] and updated["kind"] == "header_contains"
    assert updated["field"] == "Feedback-ID"
    assert updated["pattern"] == EDIT["value"]
    assert updated["label"] == EDIT["label"]
    assert updated["action"] == "draft" and updated["enabled"] == 0
    assert changes["event"] == "rule_draft_edited"
    assert changes["detail"] == f"rule_id={row['id']}"
    assert EDIT["value"] not in changes["detail"]


def test_duplicate_is_always_disabled_unscoped(signed_in, app):
    client, csrf = signed_in
    created_draft(client, csrf)
    original = get_rule(app.state.store)
    copied = client.post(f'/rules/{original["id"]}/duplicate',
                         data={"csrf": csrf}, follow_redirects=False)
    assert copied.status_code == 303
    new_id = int(copied.headers["location"].split("/")[-2])
    with app.state.store.db() as con:
        row = con.execute("SELECT * FROM rules WHERE id=?", (new_id,)).fetchone()
        scopes = con.execute("SELECT COUNT(*) FROM rule_scopes WHERE rule_id=?",
                             (new_id,)).fetchone()[0]
    assert new_id != original["id"]
    assert row["label"].startswith("Copy of ")
    assert row["pattern"] == original["pattern"]
    assert row["kind"] == original["kind"]
    assert row["enabled"] == 0 and row["action"] == "draft"
    assert scopes == 0


def test_delete_only_confirmed_unscoped_draft(signed_in, app):
    client, csrf = signed_in
    created_draft(client, csrf)
    original = get_rule(app.state.store)
    endpoint = f'/rules/{original["id"]}/delete'
    assert client.post(endpoint, data={"csrf":"invalid"}).status_code == 403
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules WHERE id=?",
                           (original["id"],)).fetchone()[0] == 1
    result = client.post(endpoint, data={"csrf":csrf},
                         follow_redirects=False)
    assert result.status_code == 303
    with app.state.store.db() as con:
        assert not con.execute("SELECT 1 FROM rules WHERE id=?",
                               (original["id"],)).fetchone()
        event = con.execute(
            "SELECT event,detail FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    assert event["event"] == "rule_draft_deleted"
    assert event["detail"] == f"rule_id={original['id']}"
    assert client.post(endpoint, data={"csrf":csrf,"confirm":"delete"}).status_code == 404


@pytest.mark.parametrize("definition,value", [
    ("legacy_raw_header:raw", "trusted@example.invalid"),
    ("sender_exact:From", "broad-domain"),
    ("sender_domain:From", "ab"),
    ("header_contains:Feedback-ID", "short"),
    ("header_exact:X-Forged-Identity", "anything"),
    ("subject_exact:Subject", ""),
    ("sender_exact:From", "a@example.invalid\nInjected: value"),
])
def test_invalid_rule_edits_are_rejected(signed_in, app, definition, value):
    client, csrf = signed_in
    created_draft(client, csrf)
    original = get_rule(app.state.store)
    response = client.post(f'/rules/{original["id"]}/edit', data={
        "csrf":csrf, "definition":definition,"value":value,"label":"Updated"})
    assert response.status_code == 400
    current=get_rule(app.state.store)
    assert current == original


def test_label_validation_and_escaped_output(signed_in, app):
    client, csrf = signed_in
    created_draft(client, csrf)
    rule = get_rule(app.state.store)
    endpoint = f'/rules/{rule["id"]}/edit'
    for bad in ("X\nY", "T"*201):
        assert client.post(endpoint,data={
            "csrf":csrf,**EDIT,"label":bad}).status_code == 400
    result = client.post(endpoint,data={
        "csrf":csrf,**EDIT,"label":"<script>alert('bad')</script>"},
        follow_redirects=False)
    assert result.status_code == 303
    page=client.get("/rules").text
    assert "&lt;script&gt;" in page
    assert "<script>alert" not in page


def test_csrf_origin_and_host_enforced_for_all_rule_mutations(signed_in, app):
    client, csrf=signed_in
    created_draft(client,csrf)
    original=get_rule(app.state.store)
    for action,payload in (
        ("edit",EDIT),("duplicate",{}),("delete",{"confirm":"delete"})):
        url=f'/rules/{original["id"]}/{action}'
        assert client.post(url,data=payload).status_code == 403
        assert client.post(url,data={"csrf":"bad",**payload}).status_code == 403
        assert client.post(url,data={"csrf":csrf,**payload},
                           headers={"Origin":"https://attacker.invalid"}).status_code == 403
    assert get_rule(app.state.store) == original


def test_original_root_rule_copy_is_disabled_and_source_unchanged(signed_in, app):
    """One-click duplicates are independent drafts, not old review tickets."""
    client, csrf = signed_in
    store = app.state.store
    with store.db() as con:
        con.execute(
            "INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at) "
            "VALUES(7,'Protected signature','legacy_raw_header','raw',"
            "'X-Safe-Pattern: Unique-1234',0,'draft',1)")
        con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,"
            "interval_minutes,enabled,created_at) VALUES("
            "'Mock','outlook','outlook.office365.com',993,"
            "'safe@example.invalid','Junk',30,0,1)")
        aid = con.execute("SELECT id FROM accounts").fetchone()[0]
        con.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(7,?)",(aid,))
        before = dict(con.execute("SELECT * FROM rules WHERE id=7").fetchone())
    page = client.get("/rules")
    assert f'href="/rules/7/edit"' in page.text
    assert 'action="/rules/7/duplicate"' in page.text
    assert 'action="/rules/7/toggle"' in page.text
    assert 'name="confirm"' not in page.text
    editor = client.get("/rules/7/edit")
    assert editor.status_code == 200 and "Edit rule" in editor.text
    assert "Original raw-header substring" in editor.text
    duplicated = client.post("/rules/7/duplicate",
                             data={"csrf":csrf},follow_redirects=False)
    assert duplicated.status_code == 303
    new_id = int(duplicated.headers["location"].split("/")[2])
    with store.db() as con:
        original = dict(con.execute("SELECT * FROM rules WHERE id=7").fetchone())
        copied = dict(con.execute("SELECT * FROM rules WHERE id=?", (new_id,)).fetchone())
        scopes = list(con.execute("SELECT * FROM rule_scopes"))
    assert original == before and len(scopes) == 1
    assert copied["kind"] == "custom_raw_header"
    assert copied["enabled"] == 0 and copied["action"] == "draft"
    assert copied["pattern"] == before["pattern"]
    # This isolated legacy fixture is not fully root-approved: activation
    # correctly refuses rather than bypassing the 22-signature policy.
    assert client.post("/rules/7/toggle",
        data={"csrf":csrf,"action":"disable"}).status_code == 409


def test_unapproved_scoped_draft_cannot_change_live_policy(signed_in, app):
    client, csrf = signed_in
    store = app.state.store
    created_draft(client, csrf)
    original = get_rule(store)
    with store.db() as con:
        con.execute("INSERT INTO accounts(label,provider,host,port,username,"
                    "folder,interval_minutes,enabled,created_at) VALUES("
                    "'Mock','outlook','outlook.office365.com',993,"
                    "'safe@example.invalid','Junk',30,0,1)")
        aid = con.execute("SELECT id FROM accounts").fetchone()[0]
        con.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",
                    (original["id"],aid))
    assert client.post(f'/rules/{original["id"]}/edit',
        data={"csrf":csrf,**EDIT}).status_code == 409
    assert client.post(f'/rules/{original["id"]}/delete',
        data={"csrf":csrf}).status_code == 409
    copied = client.post(f'/rules/{original["id"]}/duplicate',
        data={"csrf":csrf},follow_redirects=False)
    assert copied.status_code == 303
    with store.db() as con:
        scopes = con.execute("SELECT COUNT(*) FROM rule_scopes WHERE rule_id=?",
                             (original["id"],)).fetchone()[0]
        current = dict(con.execute("SELECT * FROM rules WHERE id=?",
                                   (original["id"],)).fetchone())
        total_scopes = con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]
    assert scopes == total_scopes == 1
    assert current == original


def test_live_approval_source_stays_constant_after_draft_changes(signed_in, app):
    """Draft editing can neither make a legacy match nor add a live account scope."""
    client,csrf=signed_in
    store=app.state.store
    created_draft(client,csrf)
    row=get_rule(store)
    client.post(f'/rules/{row["id"]}/edit',data={"csrf":csrf,**EDIT})
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]==0
        assert con.execute("SELECT COUNT(*) FROM rules WHERE kind='legacy_raw_header'").fetchone()[0]==0
        assert con.execute("SELECT COUNT(*) FROM rules WHERE enabled<>0 OR action<>'draft'").fetchone()[0]==0


def test_old_draft_with_lowercase_header_field_is_editable(signed_in, app):
    client,csrf=signed_in
    created_draft(client,csrf)
    rule=get_rule(app.state.store)
    with app.state.store.db() as con:
        con.execute("UPDATE rules SET field='from' WHERE id=?", (rule["id"],))
    html=client.get(f'/rules/{rule["id"]}/edit').text
    import re
    assert re.search(r'value="sender_domain:From"\s+selected', html)
    saved=client.post(f'/rules/{rule["id"]}/edit',data={
        "csrf":csrf,"definition":"sender_domain:From",
        "label":"Fixed old field capitalization",
        "value":"repaired.example.invalid"},follow_redirects=False)
    assert saved.status_code==303
    with app.state.store.db() as con:
        row=con.execute("SELECT field FROM rules WHERE id=?",(rule["id"],)).fetchone()
        assert row["field"]=="From"
