"""One-click rule control, root approval boundaries and complete MIME safety.

Synthetic mail only; never connects to external services or runs real deletion.
"""
from __future__ import annotations
import json
import os
import stat
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from filter_vision import control, rule_activation
from filter_vision.live import (_active_rules, _scan_live, LEGACY_SOURCE_SHA,
                                rules_digest, LiveSafetyError)
from filter_vision.live_matching import matches, bounded_full_message, MatchError
from filter_vision.storage import Store
from filter_vision.rule_management import draft_guard, RuleManagementError


@pytest.fixture
def approved_fixture(tmp_path, monkeypatch):
    store = Store(tmp_path / "data")
    with store.db() as db:
        for aid in (1, 2):
            db.execute("INSERT INTO accounts(id,label,provider,host,port,username,"
                       "folder,interval_minutes,enabled,created_at)"
                       " VALUES(?,?,'outlook','outlook.office365.com',993,?,"
                       "'Junk',30,0,1)",
                       (aid, f"Account {aid}", f"account{aid}@example.invalid"))
        for rid in range(1, 23):
            db.execute("INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at) "
                       "VALUES(?, 'Protected', 'legacy_raw_header', 'raw', ?,0,'draft',1)",
                       (rid, f"X-Test-Original-{rid}: unique-value-{rid}"))
            for aid in (1, 2):
                db.execute("INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",
                           (rid,aid))
        db.execute("INSERT INTO legacy_imports(source_sha256,account_count,rule_count,imported_at)"
                   " VALUES(?,2,22,1)", (LEGACY_SOURCE_SHA,))
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at)"
                   " VALUES(24,'Campaign','click_destination','HTML click destination',"
                   "'promo.example.com',0,'draft',1)")
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,enabled,action,created_at)"
                   " VALUES(25,'Header candidate','raw_header_contains','All raw headers',"
                   "'unique-campaign-2026-xyz',0,'draft',1)")
        baseline = [dict(row) for row in db.execute(
            "SELECT id,pattern FROM rules WHERE kind='legacy_raw_header'")]
    policy = {"schema":1,"enabled":True,"legacy_sha256":LEGACY_SOURCE_SHA,
              "rules_sha256":rules_digest(baseline), "accounts":[1,2]}
    root_dir = tmp_path / "root-only"
    root_dir.mkdir(mode=0o700)
    file = root_dir / "extra-rule-approvals.json"
    import grp
    monkeypatch.setattr(grp, "getgrnam",
                        lambda name: grp.getgrgid(os.getgid()))
    return store, policy, file


def test_root_extra_policy_one_click_enable_disable_preserves_frozen_legacy(approved_fixture):
    store, policy, path = approved_fixture
    with store.db() as db:
        draft = dict(db.execute("SELECT * FROM rules WHERE id=24").fetchone())
    digest = rule_activation.source_digest(draft)
    result = rule_activation.apply_approval(
        store, "enable-rule", 24, [1,2], digest, path=path,
        policy_loader=lambda:policy)
    assert "enabled" in result
    assert path.stat().st_uid == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert rule_activation.read_approvals(path) == [{
        "id": 24, "sha256": digest, "accounts": [1,2]}]
    assert [r["id"] for r in rule_activation.active_rules(store,1,path=path)] == [24]
    assert [r["id"] for r in rule_activation.active_rules(store,2,path=path)] == [24]
    account, rules = _active_rules(store,1,policy,extra_policy_path=path)
    assert account["id"] == 1
    assert len(rules) == 23 and rules[-1]["id"] == 24
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 44
        assert db.execute("SELECT COUNT(*) FROM rules WHERE enabled!=0").fetchone()[0] == 0
    assert "disabled" in rule_activation.apply_approval(
        store, "disable-rule", 24, [1,2], digest, path=path,
        policy_loader=lambda:policy)
    assert rule_activation.read_approvals(path) == []
    assert len(_active_rules(store,1,policy,extra_policy_path=path)[1]) == 22


def test_approved_draft_changes_fail_closed_even_after_edit_or_delete(approved_fixture):
    store, policy, path = approved_fixture
    with store.db() as db:
        item=dict(db.execute("SELECT * FROM rules WHERE id=25").fetchone())
    digest=rule_activation.source_digest(item)
    rule_activation.apply_approval(store,"enable-rule",25,[1],digest,
                                   path=path,policy_loader=lambda:policy)
    with store.db() as db:
        db.execute("UPDATE rules SET pattern='changed-2026-rule' WHERE id=25")
    with pytest.raises(rule_activation.ActivationError,match="changed since"):
        rule_activation.active_rules(store,1,path=path)
    with pytest.raises(LiveSafetyError,match="Managed rule approval invalid"):
        _active_rules(store,1,policy,extra_policy_path=path)
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.apply_approval(store,"enable-rule",25,[1],digest,
                                       path=path,policy_loader=lambda:policy)
    # Existing exact 22 imported rule scopes remain unchanged after rejection.
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 44


def test_rejects_forged_accounts_and_mismatched_draft(approved_fixture):
    store,policy,path=approved_fixture
    with store.db() as db:
        item=dict(db.execute("SELECT * FROM rules WHERE id=24").fetchone())
    digest=rule_activation.source_digest(item)
    for accounts in ([3],[],[1,1],[True],[1,"2"]):
        with pytest.raises(rule_activation.ActivationError):
            rule_activation.apply_approval(store, "enable-rule",24,accounts,digest,
                                            path=path,policy_loader=lambda:policy)
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.apply_approval(store,"enable-rule",1,[1],digest,
                                       path=path,policy_loader=lambda:policy)
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.apply_approval(store,"enable-rule",24,[1],"0"*64,
                                       path=path,policy_loader=lambda:policy)
    assert not path.exists()


def test_read_approvals_rejects_malformed_or_non_root_file(approved_fixture):
    _,_,path=approved_fixture
    path.write_text('{"schema":1,"rules":[]}')  # missing legacy digest
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.read_approvals(path)
    path.chmod(0o666)
    with pytest.raises(rule_activation.ActivationError,match="Insecure"):
        rule_activation.read_approvals(path)


def test_one_click_web_enable_requires_no_checkbox_and_waits_for_real_status(
        signed_in, app, monkeypatch):
    import filter_vision.app as web
    client,csrf=signed_in
    store=app.state.store
    with store.db() as db:
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at) "
                   "VALUES(1,'Protected','legacy_raw_header','raw','Original-legacy-01',1)")
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at) "
                   "VALUES(24,'Campaign','click_destination','HTML click destination',"
                   "'promo.example.com',1)")
        rule=dict(db.execute("SELECT * FROM rules WHERE id=24").fetchone())
    monkeypatch.setattr(web,"load_policy",lambda:{"accounts":[1,2]})
    from filter_vision.oauth import TokenVault
    monkeypatch.setattr(TokenVault,"connected",lambda self,i: True)
    calls=[]
    monkeypatch.setattr(web,"preview_rule",
        lambda store,rule,accounts,vault:calls.append((rule["id"],accounts)) or
        [{"account_id":i,"examined":6,"matched":6} for i in accounts])
    page=client.get("/rules").text
    assert '>Enable</button>' in page
    assert 'name="confirm"' not in page
    assert 'name="account_ids"' not in page
    assert 'Confirm enable' not in page
    denied=client.post("/rules/24/toggle",data={
        "csrf":"invalid","action":"enable"},follow_redirects=False)
    assert denied.status_code==403 and calls==[]
    accepted=client.post("/rules/24/toggle",data={
        "csrf":csrf,"action":"enable"},follow_redirects=False)
    assert accepted.status_code==303
    assert calls==[(24,[1,2])]
    data=json.loads((store.directory / control.REQUEST).read_text())
    assert data=={"schema":2,"action":"enable-rule","rule_id":24,
                  "accounts":[1,2],"source_sha256":rule_activation.source_digest(rule)}
    waiting=client.get(accepted.headers["location"]).text
    assert "Applying rule change" in waiting
    assert "Activated rule #24" not in waiting
    # Only after the protected policy reflects the change is success shown.
    (store.directory / control.REQUEST).unlink()
    entry={"id":24,"sha256":rule_activation.source_digest(rule),"accounts":[1,2]}
    monkeypatch.setattr(web,"read_approvals",lambda:[entry])
    confirmed=client.get(accepted.headers["location"]).text
    assert "Activated rule #24" in confirmed
    assert "Activated · 2 account(s)" in confirmed
    assert 'value="disable"' in confirmed
    assert 'name="confirm"' not in confirmed
    stopped=client.post("/rules/24/toggle",data={
        "csrf":csrf,"action":"disable"},follow_redirects=False)
    assert stopped.status_code==303
    pending=json.loads((store.directory / control.REQUEST).read_text())
    assert pending["action"]=="disable-rule"
    (store.directory / control.REQUEST).unlink()
    monkeypatch.setattr(web,"read_approvals",lambda:[])
    response=client.get(stopped.headers["location"])
    assert "Disabled rule #24" in response.text


class BodyIMAP:
    capabilities = (b"IMAP4REV1",b"UIDPLUS")
    def __init__(self, *, body_changed=False, oversize=False):
        self.calls=[]
        self.body_changed=body_changed
        self.oversize=oversize
        self.readonly=None
        self.fetch_count=0
        self.body=(b"From: source@example.invalid\r\n"
                   b"Subject: Example\r\nContent-Type: text/html\r\n\r\n"
                   b'<a href="https://promo.example.com/path">Offer</a>')
        self.other=(b"From: source@example.invalid\r\n"
                    b"Subject: Different\r\nContent-Type: text/html\r\n\r\n"
                    b'<a href="https://legitimate.example.invalid/path">Safe</a>')
    def select(self, folder, readonly=False):
        assert folder=="Junk"
        self.readonly=readonly
        return "OK",[b"2"]
    def response(self, key):
        return "UIDVALIDITY",[b"7"]
    def uid(self,cmd,*args):
        self.calls.append((cmd,args))
        if cmd=="SEARCH":return "OK",[b"11 12"]
        uid=args[0]
        blob=self.body if uid==b"11" else self.other
        if cmd=="FETCH":
            if args[1]=="(BODY.PEEK[HEADER])":
                return "OK",[(b"HEADER",blob.split(b"\r\n\r\n")[0]+b"\r\n")]
            if args[1]=="(RFC822.SIZE)":
                size=3*1024*1024 if self.oversize else len(blob)
                return "OK",[(b"12 (RFC822.SIZE "+str(size).encode()+b")",b"")]
            assert args[1]==f"(BODY.PEEK[]<0.{len(blob)+1}>)"
            self.fetch_count+=1
            if self.body_changed and self.fetch_count>=2:
                return "OK",[(b"BODY",blob.replace(b"promo.example.com",b"fraudcasino4u.com"))]
            return "OK",[(b"BODY",blob)]
        if cmd=="STORE":
            assert uid==b"11" and args[1:]==("+FLAGS.SILENT",r"(\Deleted)")
            return "OK",[]
        if cmd=="EXPUNGE":
            assert uid==b"11"
            return "OK",[]
        raise AssertionError("Unsafe command")
    def logout(self): pass


def test_live_body_matcher_only_expunge_matching_uid():
    rule={"id":24,"kind":"click_destination","field":"HTML click destination",
          "pattern":"promo.example.com"}
    imap=BodyIMAP()
    report=_scan_live(imap,1,[rule])
    assert report["examined"]==2 and report["deleted"]==1
    assert imap.readonly is False
    writes=[(kind,args[0]) for kind,args in imap.calls if kind in ("STORE","EXPUNGE")]
    assert writes==[("STORE",b"11"),("EXPUNGE",b"11")]
    assert imap.fetch_count==3 # two matched-message fetches and one nonmatch


def test_outlook_size_estimate_larger_than_complete_mime_is_accepted():
    rule={"id":24,"kind":"click_destination",
          "field":"HTML click destination","pattern":"promo.example.com"}

    class OutlookReportedSize(BodyIMAP):
        def uid(self,cmd,*args):
            if cmd=="FETCH" and args[1]=="(RFC822.SIZE)":
                self.calls.append((cmd,args))
                blob=self.body if args[0]==b"11" else self.other
                return "OK",[(b"11 (RFC822.SIZE "+str(len(blob)+339071).encode()+b")",b"")]
            if cmd=="FETCH" and args[1].startswith("(BODY.PEEK[]<0."):
                self.calls.append((cmd,args))
                blob=self.body if args[0]==b"11" else self.other
                self.fetch_count+=1
                return "OK",[(b"BODY",blob)]
            return super().uid(cmd,*args)

    imap=OutlookReportedSize()
    report=_scan_live(imap,1,[rule])
    assert report["deleted"]==1
    assert imap.fetch_count==3
    assert [kind for kind,_ in imap.calls if kind=="EXPUNGE"]==["EXPUNGE"]


def test_changed_body_prevents_any_delete():
    rule={"id":24,"kind":"click_destination","field":"HTML click destination",
          "pattern":"promo.example.com"}
    imap=BodyIMAP(body_changed=True)
    with pytest.raises(LiveSafetyError,match="Cannot recheck HTML body|Message body changed"):
        _scan_live(imap,1,[rule])
    assert not any(kind in ("STORE","EXPUNGE") for kind,_ in imap.calls)


def test_oversized_body_cannot_match_or_delete():
    rule={"id":24,"kind":"click_destination","field":"HTML click destination",
          "pattern":"promo.example.com"}
    imap=BodyIMAP(oversize=True)
    report=_scan_live(imap,1,[rule])
    assert report["deleted"]==0 and report["matched"]==0
    assert not any(kind in ("STORE","EXPUNGE") for kind,_ in imap.calls)


def test_no_uidplus_body_rule_cannot_delete():
    rule={"id":24,"kind":"click_destination","field":"HTML click destination",
          "pattern":"promo.example.com"}
    imap=BodyIMAP()
    imap.capabilities=(b"IMAP4REV1",)
    with pytest.raises(LiveSafetyError,match="UIDPLUS"):
        _scan_live(imap,1,[rule])
    assert not imap.calls


def test_save_and_enable_from_editor_updates_source_then_queues_one_click(
        signed_in, app, monkeypatch):
    import filter_vision.app as web
    from filter_vision.oauth import TokenVault
    client, csrf = signed_in
    with app.state.store.db() as db:
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                   " VALUES(1,'Protected','legacy_raw_header','raw','original',1)")
        db.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                   " VALUES(24,'Campaign','click_destination','HTML click destination',"
                   "'old.example.invalid',1)")
    monkeypatch.setattr(web, "load_policy", lambda: {"accounts":[1,2]})
    monkeypatch.setattr(TokenVault,"connected",lambda self,i:True)
    observed=[]
    monkeypatch.setattr(web,"preview_rule",
        lambda store,rule,accounts,vault:observed.append((rule["pattern"],accounts)) or
        [{"examined":0,"matched":0} for i in accounts])
    editor=client.get("/rules/24/edit")
    assert editor.status_code==200
    assert 'name="enable_after_save" value="yes"' in editor.text
    assert 'name="confirm"' not in editor.text
    response=client.post("/rules/24/edit",data={
        "csrf":csrf,"definition":"click_destination:HTML click destination",
        "value":"promo.example.com","label":"Approved spam destination",
        "enable_after_save":"yes"},follow_redirects=False)
    assert response.status_code==303
    assert "action=enable" in response.headers["location"]
    assert observed==[("promo.example.com",[1,2])]
    queue=json.loads((app.state.store.directory/control.REQUEST).read_text())
    with app.state.store.db() as db:
        rule=dict(db.execute("SELECT * FROM rules WHERE id=24").fetchone())
    assert rule["pattern"]=="promo.example.com"
    assert rule["enabled"]==0 and rule["action"]=="draft"
    assert queue["source_sha256"]==rule_activation.source_digest(rule)


def test_control_helper_consumes_one_click_schema_and_records_specific_rule(tmp_path,monkeypatch):
    queue = tmp_path/"control"
    queue.mkdir()
    fingerprint="a"*64
    assert control.request_rule_control(queue,"enable-rule",24,[1,2],fingerprint)
    called=[]
    monkeypatch.setattr(control,"_apply_rule_request",
        lambda directory,action,rid,accounts,sha:
          called.append((action,rid,accounts,sha)) or "Rule #24 enabled")
    import grp
    monkeypatch.setattr(grp,"getgrnam",lambda _:grp.getgrgid(os.getgid()))
    control.consume_request(queue,uid=os.getuid(),status_dir=tmp_path/"status")
    assert called==[("enable-rule",24,[1,2],fingerprint)]
    assert not (queue/control.REQUEST).exists()
    status=control._bounded_status(tmp_path/"status"/"status.json")
    assert status["state"]=="success"
    assert status["action"]=="enable-rule" and status["rule_id"]==24
    assert "enabled" in status["detail"]


def test_control_helper_rejects_forged_rule_schema(tmp_path):
    path=tmp_path/control.REQUEST
    payload={"schema":2,"action":"enable-rule","rule_id":24,
             "accounts":[1,2],"source_sha256":"a"*64}
    for change in (
        {"rule_id":True},{"accounts":[1,1]},{"accounts":[3]},
        {"source_sha256":"nothex"},{"action":"delete-mail"},
        {"extra_key":"cmd"}):
        row={**payload,**change}
        path.write_text(json.dumps(row))
        path.chmod(0o600)
        with pytest.raises(control.ControlError):
            control.consume_request(tmp_path,uid=os.getuid(),status_dir=tmp_path/"status")
        assert not path.exists()


def test_previously_approved_rule_is_not_editable_without_disabling(
        approved_fixture,monkeypatch):
    store, policy, path=approved_fixture
    with store.db() as db:
        rule=dict(db.execute("SELECT * FROM rules WHERE id=24").fetchone())
    fingerprint=rule_activation.source_digest(rule)
    rule_activation.apply_approval(store,"enable-rule",24,[1,2],fingerprint,
                                   path=path,policy_loader=lambda:policy)
    # draft_guard resolves read_approvals through its guarded module.
    monkeypatch.setattr(rule_activation,"read_approvals",
                        lambda *args,**kwargs:[{
                           "id":24,"sha256":fingerprint,"accounts":[1,2]}])
    with store.db() as db:
        with pytest.raises(RuleManagementError,match="managed by the protected control"):
            draft_guard(db,24)


def test_recovery_encrypted_backup_includes_new_root_approvals(tmp_path):
    from filter_vision.recovery import backup,create_key,verify,restore_staging
    from filter_vision.storage import Store
    data=tmp_path/"data"
    Store(data)
    config=tmp_path/"config"
    config.mkdir()
    content=(b'{"schema":1,"legacy_sha256":"'+
             LEGACY_SOURCE_SHA.encode()+b'","rules":[]}')
    path=config/"extra-rule-approvals.json"
    path.write_bytes(content)
    key=tmp_path/"key"
    create_key(key)
    archive=tmp_path/"backup.fvb"
    backup(data,config,archive,key)
    assert b"extra-rule-approvals" not in archive.read_bytes()
    files=verify(archive,key)
    assert files["config/extra-rule-approvals.json"]==content
    restore_staging(archive,key,tmp_path/"restore-data",tmp_path/"restore-config")
    assert (tmp_path/"restore-config/extra-rule-approvals.json").read_bytes()==content


@pytest.mark.parametrize("kind,field,value,header,want",[
    ("sender_exact","From","owner@example.invalid",
     b"From: Owner <owner@example.invalid>\r\n",True),
    ("sender_domain","From","example.invalid",
     b"From: Owner <owner@example.invalid>\r\n",True),
    ("sender_domain","From","example.invalid",
     b"From: Owner <owner@safe.example.invalid>\r\n",False),
    ("header_exact","X-VMTA-Source","campaign-2026-id",
     b"X-VMTA-Source: campaign-2026-id\r\n",True),
    ("header_contains","Feedback-ID","unique-campaign-2026",
     b"Feedback-ID: block:unique-campaign-2026:77\r\n",True),
    ("subject_exact","Subject","Testing campaign",
     b"Subject: Testing campaign\r\n",True),
    ("raw_header_contains","All raw headers","unique-campaign-2026",
     b"X-Campaign-ID: unique-campaign-2026\r\n",True),
])
def test_supported_live_matchers(kind,field,value,header,want):
    rule={"kind":kind,"field":field,"pattern":value}
    assert matches(rule,header) is want


def test_root_owned_original_disable_edit_enable_preserves_archival_baseline(
        approved_fixture, monkeypatch):
    import filter_vision.managed_rules as managed
    store, policy, existing_path = approved_fixture
    path = existing_path.parent / "managed-rules.json"
    monkeypatch.setattr(managed, "MANAGED_PATH", path)
    with store.db() as con:
        base = dict(con.execute("SELECT * FROM rules WHERE id=1").fetchone())
    digest = rule_activation.source_digest(base)
    assert len(_active_rules(store, 1, policy)[1]) == 22
    assert "disabled" in managed.apply_managed(
        store, "legacy-disable", 1, digest, path=path,
        policy_loader=lambda: policy)
    assert len(_active_rules(store, 1, policy)[1]) == 21
    assert len(_active_rules(store, 2, policy)[1]) == 21
    assert managed.read_managed()["legacy"][0]["enabled"] is False
    assert "activated" in managed.apply_managed(
        store, "legacy-enable", 1, digest, path=path,
        policy_loader=lambda: policy)
    assert len(_active_rules(store, 1, policy)[1]) == 22
    override = managed.normalize("click_destination", "HTML click destination",
                                 "promo.example.com", "Edited original rule")
    assert "updated" in managed.apply_managed(
        store, "legacy-edit", 1, digest, override=override, path=path,
        policy_loader=lambda: policy)
    effective = _active_rules(store, 1, policy)[1]
    assert effective[0]["id"] == 1
    assert effective[0]["kind"] == "click_destination"
    assert effective[0]["pattern"] == "promo.example.com"
    assert len(effective) == 22
    with store.db() as con:
        still_original = dict(con.execute("SELECT * FROM rules WHERE id=1").fetchone())
        count = con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]
        others = con.execute(
            "SELECT COUNT(*) FROM rules WHERE kind='legacy_raw_header'").fetchone()[0]
    assert still_original == base and count == 44 and others == 22
    # Disabling the edited original does not rewrite or lose that edit.
    managed.apply_managed(store, "legacy-disable", 1, digest,
                          path=path, policy_loader=lambda: policy)
    assert all(x["id"] != 1 for x in _active_rules(store, 1, policy)[1])
    assert managed.read_managed()["legacy"][0]["override"] == override
    # Re-enabling restores the approved edit, not a stale different signature.
    managed.apply_managed(store, "legacy-enable", 1, digest,
                          path=path, policy_loader=lambda: policy)
    assert _active_rules(store, 1, policy)[1][0]["pattern"] == "promo.example.com"


def test_managed_legacy_rejects_wrong_source_malformed_overrides_and_missing_scope(
        approved_fixture, monkeypatch):
    import filter_vision.managed_rules as managed
    store, policy, existing_path = approved_fixture
    path = existing_path.parent / "managed.json"
    monkeypatch.setattr(managed, "MANAGED_PATH", path)
    with store.db() as con:
        row = dict(con.execute("SELECT * FROM rules WHERE id=2").fetchone())
    digest = rule_activation.source_digest(row)
    with pytest.raises(managed.ManagedError):
        managed.apply_managed(store, "legacy-disable", 2, "1"*64,
                              path=path, policy_loader=lambda:policy)
    for kind, field, pattern in [
        ("sender_domain", "From", "com"),
        ("click_destination", "HTML click destination", "*.example.invalid"),
        ("legacy_raw_header", "raw", "Invalid\nHeader"),
    ]:
        with pytest.raises(managed.ManagedError):
            managed.normalize(kind,field,pattern,"Unsafe")
    assert not path.exists()
    managed.apply_managed(store,"legacy-disable",2,digest,
                          path=path,policy_loader=lambda:policy)
    with store.db() as con:
        con.execute("DELETE FROM rule_scopes WHERE rule_id=2 AND account_id=1")
    with pytest.raises(LiveSafetyError,match="scope count"):
        _active_rules(store,1,policy)


def test_one_click_root_owned_controls_and_direct_duplicate_no_confirmation(
        approved_fixture, monkeypatch):
    """UI buttons available on all original rules, no confirmation checkboxes."""
    from filter_vision.app import create_app
    import filter_vision.app as web
    import filter_vision.managed_rules as managed
    import re
    from fastapi.testclient import TestClient
    store, policy, config_path = approved_fixture
    path = config_path.parent / "managed.json"
    monkeypatch.setattr(managed, "MANAGED_PATH", path)
    monkeypatch.setattr(web, "load_policy", lambda: policy)
    from filter_vision.oauth import TokenVault
    monkeypatch.setattr(TokenVault, "connected", lambda self,aid: True)
    checked=[]
    monkeypatch.setattr(web,"preview_rule",lambda store,rule,accounts,vault:
                        checked.append((rule["kind"],rule["pattern"])) or
                        [{"account_id":a,"examined":1,"matched":1} for a in accounts])
    app = create_app(store.directory)
    with TestClient(app, base_url="https://filter-vision",
                    client=("192.168.1.69",50000)) as client:
        page=client.get("/rules").text
        csrf=re.search(r'name="csrf" value="([a-f0-9]{64})"',page).group(1)
        for i in range(1,23):
            assert f'href="/rules/{i}/edit"' in page
            assert f'action="/rules/{i}/duplicate"' in page
            assert f'action="/rules/{i}/toggle"' in page
        assert 'name="confirm"' not in page
        assert "Submit for review" not in page
        copied=client.post("/rules/1/duplicate",data={"csrf":csrf},
                           follow_redirects=False)
        assert copied.status_code==303
        with store.db() as con:
            new_id=con.execute("SELECT MAX(id) FROM rules").fetchone()[0]
            row=dict(con.execute("SELECT * FROM rules WHERE id=?",(new_id,)).fetchone())
            assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 44
        assert row["kind"]=="custom_raw_header" and row["enabled"]==0
        assert copied.headers["location"]==f"/rules/{new_id}/edit"
        disabled=client.post("/rules/1/toggle",data={
            "csrf":csrf,"action":"disable"},follow_redirects=False)
        assert disabled.status_code==303
        req=json.loads((store.directory/control.REQUEST).read_text())
        assert req["schema"]==3 and req["action"]=="legacy-disable"
        assert checked == []
        (store.directory/control.REQUEST).unlink()
        managed.apply_managed(store,"legacy-disable",1,req["source_sha256"],
                              path=path,policy_loader=lambda:policy)
        page=client.get("/rules").text
        assert "Disabled" in page and 'value="enable"' in page
        restored=client.post("/rules/1/toggle",data={
            "csrf":csrf,"action":"enable"},follow_redirects=False)
        assert restored.status_code==303
        assert checked and checked[-1][0]=="legacy_raw_header"
        req=json.loads((store.directory/control.REQUEST).read_text())
        assert req["action"]=="legacy-enable"
        (store.directory/control.REQUEST).unlink()
        managed.apply_managed(store,"legacy-enable",1,req["source_sha256"],
                              path=path,policy_loader=lambda:policy)
        page=client.get("/rules").text
        assert "Activated" in page
        editor=client.get("/rules/1/edit")
        assert editor.status_code==200 and 'Save &amp; Enable' not in editor.text
        changed=client.post("/rules/1/edit",data={
            "csrf":csrf,"definition":"click_destination:HTML click destination",
            "value":"promo.example.com","label":"Changed original"},
            follow_redirects=False)
        assert changed.status_code==303
        assert checked[-1][0]=="click_destination"
        request=json.loads((store.directory/control.REQUEST).read_text())
        assert request["action"]=="legacy-edit"
        assert request["override"]["pattern"]=="promo.example.com"
        (store.directory/control.REQUEST).unlink()
        managed.apply_managed(store,"legacy-edit",1,request["source_sha256"],
                              request["override"],path=path,
                              policy_loader=lambda:policy)
        final=client.get("/rules").text
        assert "Changed original" in final
        assert "promo.example.com" in final
        assert "Edit" in final and "Duplicate" in final and "Disable" in final
        with store.db() as con:
            original=con.execute("SELECT pattern FROM rules WHERE id=1").fetchone()[0]
        assert original.startswith("X-Test-Original-1")


def test_active_custom_edit_duplicate_and_disable_are_independent_of_sqlite(
        approved_fixture, monkeypatch):
    """Active new rules edit through root override, never through direct SQLite."""
    import filter_vision.managed_rules as managed
    store, policy, approvals_path = approved_fixture
    managed_path = approvals_path.parent / "managed.json"
    monkeypatch.setattr(rule_activation, "EXTRA_POLICY", approvals_path)
    monkeypatch.setattr(managed, "MANAGED_PATH", managed_path)
    with store.db() as con:
        original = dict(con.execute("SELECT * FROM rules WHERE id=24").fetchone())
    digest = rule_activation.source_digest(original)
    rule_activation.apply_approval(store,"enable-rule",24,[1,2],digest,
                                   path=approvals_path,policy_loader=lambda:policy)
    before = _active_rules(store,1,policy)[1]
    assert len(before)==23
    assert before[-1]["pattern"]=="promo.example.com"
    override = managed.normalize("sender_exact","From",
                                 "trusted-campaign@example.invalid",
                                 "Adjusted custom rule")
    managed.apply_managed(store,"custom-edit",24,digest,override=override,
                          path=managed_path,policy_loader=lambda:policy)
    after=_active_rules(store,1,policy)[1]
    assert len(after)==23
    assert after[-1]["kind"]=="sender_exact"
    assert after[-1]["pattern"]=="trusted-campaign@example.invalid"
    with store.db() as con:
        still_original=dict(con.execute("SELECT * FROM rules WHERE id=24").fetchone())
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]==44
    assert still_original==original
    # Disabling an edited new rule retains its effective matcher as a managed
    # override but does not permit deletion until re-enabled.
    rule_activation.apply_approval(store,"disable-rule",24,[1,2],digest,
                                   path=approvals_path,policy_loader=lambda:policy)
    assert len(_active_rules(store,1,policy)[1])==22
    assert managed.read_managed()["custom"][0]["override"]==override
    rule_activation.apply_approval(store,"enable-rule",24,[1,2],digest,
                                   path=approvals_path,policy_loader=lambda:policy)
    assert _active_rules(store,1,policy)[1][-1]["pattern"]=="trusted-campaign@example.invalid"


def test_custom_save_and_enable_is_one_managed_root_action(approved_fixture, monkeypatch):
    import filter_vision.managed_rules as managed
    store,policy,approvals_path=approved_fixture
    managed_path=approvals_path.parent/"managed.json"
    monkeypatch.setattr(rule_activation,"EXTRA_POLICY",approvals_path)
    monkeypatch.setattr(managed,"MANAGED_PATH",managed_path)
    with store.db() as con:
        baseline=dict(con.execute("SELECT * FROM rules WHERE id=24").fetchone())
    override=managed.normalize("click_destination","HTML click destination",
                               "newhost.example.com", "Updated and active")
    digest=rule_activation.source_digest(baseline)
    managed.apply_managed(store,"custom-edit",24,digest,override=override,
                          activate=True,path=managed_path,policy_loader=lambda:policy)
    assert rule_activation.read_approvals()==[
        {"id":24,"sha256":digest,"accounts":[1,2]}]
    assert _active_rules(store,2,policy)[1][-1]["pattern"]=="newhost.example.com"


def test_managed_schema3_is_queued_and_consumed_once(tmp_path,monkeypatch):
    request_dir=tmp_path/"queue"
    request_dir.mkdir()
    change={"kind":"click_destination","field":"HTML click destination",
            "pattern":"campaign.example.com","label":"Edited original"}
    fingerprint="b"*64
    assert control.request_managed_control(
        request_dir,"legacy-edit",1,fingerprint,override=change)
    payload=json.loads((request_dir/control.REQUEST).read_text())
    assert payload["schema"]==3 and payload["action"]=="legacy-edit"
    assert payload["override"]==change and payload["activate"] is False
    events=[]
    monkeypatch.setattr(control,"_apply_managed_request",
                        lambda path,data:events.append(data) or "Rule #1 updated")
    import grp
    monkeypatch.setattr(grp,"getgrnam",
                        lambda name:grp.getgrgid(os.getgid()))
    control.consume_request(request_dir,uid=os.getuid(),
                            status_dir=tmp_path/"status")
    assert events==[payload]
    assert not (request_dir/control.REQUEST).exists()
    state=control._bounded_status(tmp_path/"status"/"status.json")
    assert state["state"]=="success" and state["rule_id"]==1
    assert state["action"]=="legacy-edit"
    for invalid in (
        {"action":"reboot"},
        {"rule_id":True},
        {"source_sha256":"invalid"},
        {"override":{"kind":"click_destination","field":"HTML click destination",
                     "pattern":"*.invalid","label":"bad"}},
        {"extra":"malicious"},
    ):
        invalid_payload={**payload,**invalid}
        path=request_dir/control.REQUEST
        path.write_text(json.dumps(invalid_payload))
        path.chmod(0o600)
        with pytest.raises(control.ControlError):
            control.consume_request(request_dir,uid=os.getuid(),
                                    status_dir=tmp_path/"status")
        assert not path.exists()


def test_encrypted_backup_preserves_managed_root_rule_overrides(tmp_path):
    """Snapshot includes root managed policy as config; never user-visible."""
    from filter_vision.recovery import _allowed, _collect
    from filter_vision.storage import Store
    from filter_vision.managed_rules import LEGACY_SOURCE_SHA
    assert _allowed("config/managed-rules.json")
    store=Store(tmp_path/"data")
    config=tmp_path/"config"
    config.mkdir()
    payload={"schema":1,"legacy_sha256":LEGACY_SOURCE_SHA,
             "legacy":[{"id":1,"sha256":"0"*64,"enabled":False,
                        "override":None}],"custom":[]}
    (config/"managed-rules.json").write_text(json.dumps(payload))
    snapshot=_collect(store.directory,config)
    assert json.loads(snapshot["config/managed-rules.json"])==payload


def test_atomic_root_batch_approvals_preserve_original_policy(approved_fixture):
    store, policy, path = approved_fixture
    with store.db() as con:
        selected = [dict(con.execute(
            "SELECT * FROM rules WHERE id=?", (rid,)).fetchone()) for rid in (24,25)]
    entries = [{"id": row["id"], "sha256": rule_activation.source_digest(row)}
               for row in selected]
    result = rule_activation.apply_batch_approvals(
        store, entries, [1, 2], path=path, policy_loader=lambda:policy)
    assert "2 rules enabled" in result
    loaded = rule_activation.read_approvals(path)
    assert {a["id"] for a in loaded} == {24,25}
    assert all(a["accounts"] == [1,2] for a in loaded)
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 44
        assert con.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0] == 0
    assert len(_active_rules(store,1,policy,extra_policy_path=path)[1]) == 24


def test_root_batch_rejects_stale_or_invalid_member_without_partial_write(approved_fixture):
    store,policy,path=approved_fixture
    with store.db() as con:
        rows = [dict(con.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone())
                for rid in (24,25)]
    entries = [{"id":x["id"],"sha256":rule_activation.source_digest(x)}
               for x in rows]
    bad = [entries[0],{**entries[1],"sha256":"0"*64}]
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.apply_batch_approvals(
            store,bad,[1,2],path=path,policy_loader=lambda:policy)
    assert not path.exists()
    for request in ([entries[0],entries[0]], [entries[0],{**entries[1],"id":1}]):
        with pytest.raises(rule_activation.ActivationError):
            rule_activation.apply_batch_approvals(
                store,request,[1,2],path=path,policy_loader=lambda:policy)
    assert not path.exists()
    with pytest.raises(rule_activation.ActivationError):
        rule_activation.apply_batch_approvals(
            store,entries,[3],path=path,policy_loader=lambda:policy)
    assert not path.exists()


def test_control_schema4_batch_request_contract_root_consumer(tmp_path,monkeypatch):
    items=[{"id":24,"sha256":"a"*64},{"id":25,"sha256":"b"*64}]
    path=tmp_path/"queue"
    path.mkdir()
    batch_id="a"*24
    assert control.request_batch_enable(path,items,[1,2],batch_id)
    request=json.loads((path/control.REQUEST).read_text())
    assert request["schema"]==4 and request["action"]=="enable-batch"
    assert request["entries"]==items
    assert not control.request_batch_enable(path,items,[1,2],batch_id)
    import grp
    monkeypatch.setattr(grp,"getgrnam",lambda name:grp.getgrgid(os.getgid()))
    calls=[]
    monkeypatch.setattr(control,"_apply_batch_request",lambda d,r:
                        calls.append(r) or "2 rules enabled on 2 account(s)")
    control.consume_request(path,uid=os.getuid(),status_dir=tmp_path/"status")
    assert len(calls)==1
    status=json.loads((tmp_path/"status/status.json").read_text())
    assert status["batch_id"]==batch_id and status["state"]=="success"
    assert not (path/control.REQUEST).exists()
    with pytest.raises(control.ControlError):
        control.request_batch_enable(path,items+[items[0]],[1,2],"b"*24)


def test_control_schema4_rejects_forged_and_oversize_batch(tmp_path,monkeypatch):
    path=tmp_path/"queue";path.mkdir()
    import grp
    monkeypatch.setattr(grp,"getgrnam",lambda name:grp.getgrgid(os.getgid()))
    called=[]
    monkeypatch.setattr(control,"_apply_batch_request",lambda *a:called.append(1))
    payload={"schema":4,"action":"enable-batch","batch_id":"a"*24,
             "accounts":[1,2],"entries":[{"id":24,"sha256":"b"*64}]}
    for malformed in (
        {**payload,"accounts":[1,1]},
        {**payload,"entries":[{"id":24,"sha256":"b"*64}]*2},
        {**payload,"entries":[{"id":True,"sha256":"b"*64}]},
        {**payload,"entries":[{"id":24,"sha256":"evil"}]},
        {**payload,"action":"disable-batch"},
    ):
        file=path/control.REQUEST
        file.write_text(json.dumps(malformed))
        file.chmod(0o600)
        with pytest.raises(control.ControlError):
            control.consume_request(path,uid=os.getuid(),status_dir=tmp_path/"status")
        assert not file.exists()
    assert not called
