"""Rules-page bulk operations and disclosure layouts; synthetic test records."""
from __future__ import annotations

import json
import re
from pathlib import Path
import pytest

from filter_vision.bulk_rule_management import (duplicate_rules, delete_rules,
                                                apply_root_bulk_rule_state)
from filter_vision.rule_management import RuleManagementError
from filter_vision.rule_activation import source_digest
from test_rule_activation import approved_fixture


def test_activity_panels_initial_expansion_and_indicators(client):
    page = client.get("/activity")
    assert page.status_code == 200
    assert '<details class="panel activity-section">' in page.text
    assert '<summary>Filtering by rule</summary>' in page.text
    assert '<details class="panel activity-section" open>' in page.text
    assert '<summary>Recent events</summary>' in page.text


def test_analyze_default_collapses_and_orders_plans(signed_in,app):
    from test_batch_rule_drafts import analyzed
    client, csrf = signed_in
    result=analyzed(client,csrf)
    assert '<details class="panel manual-evaluation"  id="manual-evaluate">' in result.text
    assert '<details class="panel shared-evidence">' in result.text
    assert 'Shared campaign evidence <span class="pill">' in result.text
    kinds = [result.text.find("Exact sender-domain combination"),
             result.text.find("Fewest header conditions found")]
    assert all(i >= 0 for i in kinds) and kinds[0] < kinds[1]
    assert "Enable selected" in result.text


def test_rules_page_checkboxes_and_aligned_action_slots(signed_in,app):
    client,csrf=signed_in
    with app.state.store.db() as con:
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(24,'Rule','sender_domain','From','bulk.example.com',1)")
    html=client.get("/rules").text
    assert 'id="rules-bulk-form"' in html
    assert 'name="select_all" value="yes"' in html
    assert 'name="selected" value="24"' in html
    assert 'action="/rules/bulk"' in html
    for word in ("Delete selected","Enable selected","Disable selected",
                 "Duplicate selected"):
        assert word in html
    for slot in ("rule-toggle","rule-edit","rule-duplicate","rule-delete"):
        assert slot in html
    assert 'src="/static/rule-select.js"' in html


def test_bulk_duplicate_and_delete_are_atomic_on_ineligible_rules(app):
    store=app.state.store
    with store.db() as con:
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(1,'Legacy','legacy_raw_header','raw','X-Unique: sample-domain',1)")
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(24,'Draft','sender_domain','From','bulk.example.com',1)")
    assert duplicate_rules(store,[1,24])==2
    with store.db() as con:
        clones = [dict(r) for r in con.execute("SELECT * FROM rules WHERE id NOT IN (1,24)")]
        assert len(clones)==2 and all(x["enabled"]==0 for x in clones)
        assert any(x["kind"]=="custom_raw_header" for x in clones)
    with pytest.raises(RuleManagementError):
        delete_rules(store,[24,1])
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==4
    assert delete_rules(store,[24,clones[-1]["id"]])==2
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==2


def test_rules_bulk_route_fails_csrf_invalid_and_protected_deletion(signed_in,app):
    client,csrf=signed_in
    with app.state.store.db() as con:
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(1,'Legacy','legacy_raw_header','raw','X-Unique: sample-domain',1)")
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(24,'Draft','sender_domain','From','bulk.example.com',1)")
    assert client.post("/rules/bulk",data={
        "csrf":csrf+"bad","selected":["24"],"operation":"delete"}).status_code==403
    assert client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24","24"],"operation":"delete"}).status_code==400
    assert client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24","1"],"operation":"delete"}).status_code==409
    assert client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24"],"operation":"rm -rf /"}).status_code==400
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==2
    response=client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24"],"operation":"duplicate"},
        follow_redirects=False)
    assert response.status_code==303
    assert "bulk_done=duplicated" in response.headers["location"]
    assert client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24"],"operation":"delete"},
        follow_redirects=False).status_code==303
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules WHERE id=1").fetchone()[0]==1


def test_rules_bulk_root_queue_and_confirmation(signed_in,app,monkeypatch):
    import importlib
    web=importlib.import_module("filter_vision.app")
    client,csrf=signed_in
    with app.state.store.db() as con:
        con.execute("INSERT INTO rules(id,label,kind,field,pattern,created_at)"
                    "VALUES(24,'Draft','sender_domain','From','bulk.example.com',1)")
        for aid in (1,2):
            con.execute("INSERT INTO accounts(id,label,provider,host,port,username,"
                        "folder,interval_minutes,created_at) "
                        "VALUES(?,?, 'outlook','outlook.office365.com',993,?,'Junk',30,1)",
                        (aid, f"Account {aid}",f"user{aid}@example.invalid"))
    monkeypatch.setattr(web,"load_policy",lambda:{"accounts":[1,2]})
    monkeypatch.setattr(web,"read_approvals",lambda:[])
    monkeypatch.setattr(web,"read_managed",lambda:{"legacy":[],"custom":[]})
    monkeypatch.setattr(web,"control_view",lambda *_:{
        "control_installed":True,"request_pending":False,"last_action":{}})
    monkeypatch.setattr(app.state.token_vault,"connected",lambda aid:True)
    calls=[]
    monkeypatch.setattr(web,"preview_rules",lambda store,rules,accounts,vault:
                        calls.append(("preview",len(rules),accounts)) or [])
    request=client.post("/rules/bulk",data={
        "csrf":csrf,"selected":["24"],"operation":"enable"},
        follow_redirects=False)
    assert request.status_code==303,request.text[:400]
    assert "bulk=" in request.headers["location"]
    assert calls == [("preview",1,[1,2])]
    queued=json.loads((app.state.store.directory/"cleaner-control-request").read_text())
    assert queued["schema"]==5 and queued["action"]=="rules-enable"
    assert len(queued["entries"])==1 and queued["entries"][0]["id"]==24
    with app.state.store.db() as con:
        assert con.execute("SELECT enabled FROM rules WHERE id=24").fetchone()[0]==0
    # A queued request alone must not display activation.
    waiting=client.get(request.headers["location"]).text
    assert "Bulk enable verified" not in waiting
    monkeypatch.setattr(web,"control_view",lambda *_:{
        "control_installed":True,"request_pending":False,
        "last_action":{"batch_id":queued["batch_id"],"state":"success",
                       "action":"rules-enable"}})
    still=client.get(request.headers["location"]).text
    assert "could not be confirmed" in still
    monkeypatch.setattr(web,"read_approvals",lambda:[
        {**queued["entries"][0],"accounts":[1,2]}])
    verified=client.get(request.headers["location"]).text
    assert "Bulk enable verified" in verified


def test_root_bulk_mixed_original_and_custom_with_rollback(approved_fixture,monkeypatch):
    from filter_vision import rule_activation
    import filter_vision.managed_rules as managed
    store,policy,approvals_path=approved_fixture
    managed_path=approvals_path.parent/"managed.json"
    with store.db() as con:
        rows=[dict(con.execute("SELECT * FROM rules WHERE id=?",(i,)).fetchone())
              for i in (1,24)]
    entries=[{"id":r["id"],"sha256":source_digest(r)} for r in rows]
    # First disable the original; unapproved custom stays inactive.
    assert "disabled" in apply_root_bulk_rule_state(
        store,entries,[1,2],False,managed_path=managed_path,
        approvals_path=approvals_path,policy_loader=lambda:policy)
    assert managed.read_managed(managed_path)["legacy"][0]["enabled"] is False
    before=managed.read_managed(managed_path)
    original_write=rule_activation._write_root_policy
    def fail(*args):
        raise rule_activation.ActivationError("Synthetic root policy write failure")
    monkeypatch.setattr(rule_activation,"_write_root_policy",fail)
    with pytest.raises(RuleManagementError):
        apply_root_bulk_rule_state(
            store,entries,[1,2],True,managed_path=managed_path,
            approvals_path=approvals_path,policy_loader=lambda:policy)
    assert managed.read_managed(managed_path)==before
    assert not approvals_path.exists()
    monkeypatch.setattr(rule_activation,"_write_root_policy",original_write)
    assert "enabled" in apply_root_bulk_rule_state(
        store,entries,[1,2],True,managed_path=managed_path,
        approvals_path=approvals_path,policy_loader=lambda:policy)
    assert managed.read_managed(managed_path)["legacy"]==[]
    assert {x["id"] for x in rule_activation.read_approvals(approvals_path)}=={24}
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]==44


def test_rules_bulk_root_schema_rejects_forged(tmp_path,monkeypatch):
    from filter_vision import control
    import grp,os
    monkeypatch.setattr(grp,"getgrnam",lambda name:grp.getgrgid(os.getgid()))
    folder=tmp_path/"control";folder.mkdir()
    items=[{"id":24,"sha256":"a"*64}]
    assert control.request_rules_bulk(folder,items,[1,2],"rules-disable","f"*24)
    called=[]
    monkeypatch.setattr(control,"_apply_rules_bulk_request",
                        lambda d,row:called.append(row) or "1 rule disabled")
    control.consume_request(folder,uid=os.getuid(),status_dir=tmp_path/"status")
    assert len(called)==1
    with pytest.raises(control.ControlError):
        control.request_rules_bulk(folder,items*2,[1,2],"rules-enable","f"*24)
    data={"schema":5,"action":"rules-enable","batch_id":"f"*24,
          "accounts":[1,2],"entries":items}
    for changed in (
        {**data,"accounts":[1,1]},
        {**data,"entries":items*2},
        {**data,"entries":[{"id":True,"sha256":"a"*64}]},
        {**data,"action":"wipe-mail"},
    ):
        path=folder/control.REQUEST
        path.write_text(json.dumps(changed))
        path.chmod(0o600)
        with pytest.raises(control.ControlError):
            control.consume_request(folder,uid=os.getuid(),status_dir=tmp_path/"status")
    assert len(called)==1



def test_real_rules_list_javascript_toggle_and_mixed_selection():
    import shutil,subprocess
    if not shutil.which("node"):
        pytest.skip("Node not installed")
    root=Path(__file__).resolve().parents[1]
    js=(root/"src/filter_vision/static/rule-select.js").read_text()
    code=r"""
const vm=require('vm'),assert=require('assert');
const control=(name)=>({
  name,checked:false,indeterminate:false,callbacks:{},
  addEventListener(n,fn){this.callbacks[n]=fn},
  fire(n){this.callbacks[n]?.()}
});
const master=control('select_all');
const boxes=Array.from({length:3},()=>control('selected'));
const form={id:'rules-bulk-form',elements:[master,...boxes],callbacks:{},
  addEventListener(n,fn){this.callbacks[n]=fn}};
const status={textContent:''};
const document={
  addEventListener(n,fn){assert.strictEqual(n,'DOMContentLoaded');fn();},
  querySelectorAll(s){
    if(s==='form[data-coverage-plan]')return [];
    if(s==='form[data-rule-list]')return [form];
    throw Error(s);
  },
  querySelector(s){
    assert.strictEqual(s,'[data-rule-count="rules-bulk-form"]');
    return status;
  }
};
vm.runInNewContext(process.argv[1],{document});
assert(status.textContent==='0 of 3 rules selected');
master.checked=true;master.fire('change');
assert(boxes.every(b=>b.checked)&&status.textContent==='3 of 3 rules selected');
boxes[1].checked=false;boxes[1].fire('change');
assert(master.indeterminate&&!master.checked);
form.callbacks.submit();
assert(!master.checked&&boxes.filter(b=>b.checked).length===2);
boxes[1].checked=true;boxes[1].fire('change');
assert(master.checked&&!master.indeterminate);
master.checked=false;master.fire('change');
assert(boxes.every(b=>!b.checked));
console.log('Rules bulk selection PASS');
"""
    result=subprocess.run(["node","-e",code,js],check=True,capture_output=True,text=True)
    assert "Rules bulk selection PASS" in result.stdout
