"""Synthetic Analyze selection and duplicate exclusion; no live mail actions."""
import re

from filter_vision.analysis import (candidate_signature, candidate_token,
                                    coverage_options, inspect_eml, suggestions)
from filter_vision.draft_saving import MAX_BATCH_DRAFTS, save_disabled_drafts, saved_signatures


def sample_data():
    emails = [
        ("one@alpha.example.com", "First offer"),
        ("two@alpha.example.com", "Second offer"),
        ("three@beta.example.com", "Third offer"),
    ]
    return [(
        f"item{i}.eml",
        (f"From: Sample <{sender}>\r\nSubject: {subject}\r\n"
         f"X-VMTA-Source: unique-{i}.campaign\r\n\r\nbody").encode(),
        "message/rfc822",
    ) for i, (sender, subject) in enumerate(emails)]


def analyzed(client, csrf):
    result = client.post("/analyze", data={"csrf": csrf},
                         files=[("files", file) for file in sample_data()])
    assert result.status_code == 200, result.text[:500]
    return result


def plan_for(app, csrf, kind):
    samples = app.state.analysis_memory.read(csrf)["samples"]
    return next(plan for plan in coverage_options(samples) if plan["kind"] == kind)


def rules(app):
    with app.state.store.db() as con:
        return [dict(row) for row in con.execute("SELECT * FROM rules ORDER BY id")]


def test_select_all_adds_one_plan_at_once_and_hides_saved_across_views(signed_in, app):
    client, csrf = signed_in
    response = analyzed(client, csrf)
    assert 'action="/analyze/drafts"' in response.text
    assert 'src="/static/rule-select.js"' in response.text
    assert 'Save selected drafts' in response.text
    assert 'name="select_all" value="yes"' in response.text
    plan = plan_for(app, csrf, "sender_domain")
    assert len(plan["items"]) == 2
    result = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_domain", "select_all": "yes",
    }, follow_redirects=False)
    assert result.status_code == 303 and result.headers["location"] == "/analyze?saved=2"
    stored = rules(app)
    assert len(stored) == 2 and {r["kind"] for r in stored} == {"sender_domain"}
    assert all(r["enabled"] == 0 and r["action"] == "draft" for r in stored)
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0
        audit = con.execute(
            "SELECT detail FROM audit_events WHERE event='rule_drafts_saved' "
            "ORDER BY id DESC LIMIT 1").fetchone()[0]
        assert audit == "added=2 requested=2"
        assert "alpha.example" not in audit
    after = client.get("/analyze")
    assert "2/3 covered by new candidates" not in after.text
    assert "Exact sender-domain combination" not in after.text
    assert "Exact sender-address combination" in after.text
    assert "sender_domain" not in after.text  # saved shared suggestion removed too
    assert "Select all" in after.text
    assert client.get("/analyze?saved=2").status_code == 200
    assert "2 new disabled drafts saved." in client.get("/analyze?saved=2").text


def test_manual_selection_then_select_all_skips_existing_case_insensitive(signed_in, app):
    client, csrf = signed_in
    analyzed(client, csrf)
    original = plan_for(app, csrf, "sender_exact")
    assert len(original["items"]) == 3
    token = candidate_token(original["items"][0])
    response = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_exact", "selected": [token],
    }, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/analyze?saved=1"
    # Re-saving the same candidate under mixed case must not produce a duplicate.
    value = original["items"][0]["value"].upper()
    repeat = client.post("/rules", data={
        "csrf": csrf, "kind": "sender_exact", "field": "From", "value": value,
    }, follow_redirects=False)
    assert repeat.status_code == 303
    assert len(rules(app)) == 1
    panel = client.get("/analyze")
    assert value.lower() not in panel.text.split('class="panel coverage-strategies"')[1].split('Shared campaign evidence')[0]
    result = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_exact", "select_all": "yes",
    }, follow_redirects=False)
    assert result.status_code == 303
    assert result.headers["location"] == "/analyze?saved=2"
    assert len(rules(app)) == 3
    # A repeated/stale all-selection must not save any duplicates.
    blocked = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_exact", "select_all": "yes",
    })
    assert blocked.status_code == 409
    assert len(rules(app)) == 3


def test_bulk_rejects_forged_stale_invalid_empty_and_expired_without_changes(signed_in, app):
    client, csrf = signed_in
    analyzed(client, csrf)
    good = candidate_token(plan_for(app, csrf, "sender_domain")["items"][0])
    cases = [
        ({"csrf": csrf + "x", "plan": "sender_domain", "selected": [good]}, 403),
        ({"csrf": csrf, "plan": "sender_domain", "selected": ["f" * 64]}, 400),
        ({"csrf": csrf, "plan": "sender_domain", "selected": []}, 400),
        ({"csrf": csrf, "plan": "sender_domain", "select_all": "maybe"}, 400),
        ({"csrf": csrf, "plan": "nonexistent", "selected": [good]}, 409),
        ({"csrf": csrf, "plan": "sender_domain", "selected": [good, good]}, 400),
        ({"csrf": csrf, "plan": "sender_domain", "selected": [good, "f" * 64]}, 400),
        ({"csrf": csrf, "plan": "sender_domain", "selected": [good] * 65}, 400),
    ]
    for payload, status in cases:
        result = client.post("/analyze/drafts", data=payload)
        assert result.status_code == status, (payload, result.text[:300])
    assert rules(app) == []
    app.state.analysis_memory.write(csrf, samples=[])
    expired = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_domain", "selected": [good]})
    assert expired.status_code == 410
    assert rules(app) == []


def test_legacy_raw_signatures_and_added_drafts_excluded_from_coverage(signed_in, app):
    client, csrf = signed_in
    analyzed(client, csrf)
    with app.state.store.db() as con:
        con.execute("INSERT INTO rules(label,kind,field,pattern,created_at) "
                    "VALUES(?,?,?,?,?)",
                    ("existing legacy", "legacy_raw_header", "Raw header",
                     "unique-0.campaign", 1))
        assert candidate_signature("legacy_raw_header", "Raw header", "CAMPAIGN") == (
            candidate_signature("raw_header_contains", "All raw headers", "campaign"))
        existing = saved_signatures(con)
    samples = app.state.analysis_memory.read(csrf)["samples"]
    originals = coverage_options(samples)
    remaining = coverage_options(samples, existing)
    # The existing rule identity is not offered as a new raw-header condition.
    assert all(candidate_signature(i["kind"], i["field"], i["value"]) not in existing
               for plan in remaining for i in plan["items"])
    assert all(0 <= p["count"] <= p["total"] and p["missed"] == p["total"] - p["count"]
               for p in remaining)
    assert originals and remaining
    assert client.get("/analyze").status_code == 200


def test_atomic_validation_bounded_duplicate_and_no_approval(signed_in, app):
    _, csrf = signed_in
    store = app.state.store
    good = ("sender_domain", "From", "alpha.example.com")
    invalid = ("sender_domain", "From", "com")
    import pytest
    with pytest.raises(ValueError):
        save_disabled_drafts(store, [good, invalid])
    assert rules(app) == []
    with pytest.raises(ValueError):
        save_disabled_drafts(store, [good] * (MAX_BATCH_DRAFTS + 1))
    assert rules(app) == []
    assert save_disabled_drafts(store, [good, good, good]) == 1
    assert save_disabled_drafts(store, [good]) == 0
    assert len(rules(app)) == 1
    with store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0


def test_batch_selection_script_served_and_no_inline_code(signed_in):
    client, csrf = signed_in
    html = analyzed(client, csrf).text
    assert "'unsafe-inline'" not in client.get("/analyze").headers["Content-Security-Policy"]
    js = client.get("/static/rule-select.js")
    assert js.status_code == 200
    assert "form.elements" in js.text
    assert "DOMContentLoaded" in js.text
    assert "<script src=\"/static/rule-select.js\" defer></script>" in html


def test_actual_node_selection_behaviour_without_browser_dependency():
    """Exercise emitted JavaScript against form-associated checkbox semantics."""
    import shutil
    import subprocess
    import pytest
    from pathlib import Path
    if not shutil.which("node"):
        pytest.skip("Node not installed")
    js=(Path(__file__).resolve().parents[1]/
        "src/filter_vision/static/rule-select.js").read_text()
    harness=r"""
const vm=require('vm'), assert=require('assert');
const check=()=>({
  name:'selected', checked:false,indeterminate:false,callbacks:{},
  addEventListener(n,fn){this.callbacks[n]=fn;},
  fire(n){this.callbacks[n]?.();}
});
const master=check();master.name='select_all';
const boxes=Array.from({length:4},check);
const form={
  id:'coverage-form-1',elements:[master,...boxes],callbacks:{},
  addEventListener(n,fn){this.callbacks[n]=fn;}
};
const status={textContent:''};
const document={
  addEventListener(n,fn){assert.strictEqual(n,'DOMContentLoaded');fn();},
  querySelectorAll(s){
    if(s==='form[data-coverage-plan]')return [form];
    if(s==='form[data-rule-list]')return [];
    throw Error('unexpected selector '+s);
  },
  querySelector(s){
    assert.strictEqual(s,'[data-coverage-count="coverage-form-1"]');
    return status;
  }
};
vm.runInNewContext(process.argv[1],{document});
assert(status.textContent.startsWith('0 selected'));
master.checked=true;master.fire('change');
assert(boxes.every(b=>b.checked) && master.checked);
assert(status.textContent.startsWith('4 selected'));
boxes[1].checked=false;boxes[1].fire('change');
assert(master.indeterminate && !master.checked);
form.callbacks.submit();
assert(!master.checked && boxes.filter(b=>b.checked).length===3);
boxes[1].checked=true;boxes[1].fire('change');
assert(master.checked && !master.indeterminate);
master.checked=false;master.fire('change');
assert(boxes.every(b=>!b.checked));
console.log('Form-associated selection, all, partial and submit PASS');
"""
    result=subprocess.run(["node","-e",harness,js],check=True,
                          capture_output=True,text=True)
    assert "PASS" in result.stdout


def test_shared_candidate_single_save_stays_on_analyze_and_disappears(signed_in, app):
    client, csrf = signed_in
    page = analyzed(client, csrf)
    samples = app.state.analysis_memory.read(csrf)["samples"]
    candidate = next(c for c in suggestions(samples)
                     if c["kind"] == "sender_domain" and c["count"] >= 2)
    token = candidate_token(candidate)
    assert 'action="/analyze/candidate"' in page.text
    assert 'name="token" value="' + token + '"' in page.text
    saved = client.post("/analyze/candidate", data={
        "csrf": csrf, "token": token}, follow_redirects=False)
    assert saved.status_code == 303
    assert saved.headers["location"] == "/analyze?saved=1"
    follow = client.get(saved.headers["location"])
    assert follow.status_code == 200
    assert "1 new disabled draft saved" in follow.text
    assert 'name="token" value="' + token + '"' not in follow.text
    assert len(rules(app)) == 1
    again = client.post("/analyze/candidate", data={
        "csrf": csrf, "token": token})
    assert again.status_code == 409
    assert len(rules(app)) == 1


def test_single_candidate_rejects_forged_cross_browser_or_expired(signed_in, app):
    client, csrf = signed_in
    analyzed(client, csrf)
    samples = app.state.analysis_memory.read(csrf)["samples"]
    token = candidate_token(next(c for c in suggestions(samples)
                                 if c.get("can_save")))
    assert client.post("/analyze/candidate", data={
        "csrf": csrf+"x", "token": token}).status_code == 403
    assert client.post("/analyze/candidate", data={
        "csrf": csrf, "token": "0"*64}).status_code == 409
    from fastapi.testclient import TestClient
    with TestClient(app, base_url="https://filter-vision",
                    client=("192.168.1.70",50200)) as other:
        second = other.get("/analyze")
        other_csrf = re.search(r'name="csrf" value="([0-9a-f]{64})"',
                               second.text).group(1)
        assert other.post("/analyze/candidate", data={
            "csrf": other_csrf, "token": token}).status_code == 410
    app.state.analysis_memory.write(csrf, samples=[])
    assert client.post("/analyze/candidate", data={
        "csrf": csrf, "token": token}).status_code == 410
    assert not rules(app)


def test_bulk_enable_previews_every_rule_then_queues_only_root_action(signed_in, app, monkeypatch):
    import importlib
    web = importlib.import_module("filter_vision.app")
    client, csrf = signed_in
    page = analyzed(client, csrf)
    assert "Enable selected" in page.text
    assert "Save selected drafts" in page.text
    from filter_vision import control
    plan = plan_for(app, csrf, "sender_domain")
    assert len(plan["items"]) == 2
    events = []
    fake_policy = {"accounts": [1, 2]}
    monkeypatch.setattr(web, "load_policy", lambda: fake_policy)
    monkeypatch.setattr(web, "read_approvals", lambda: [])
    monkeypatch.setattr(app.state.token_vault, "connected", lambda aid: True)
    monkeypatch.setattr(web, "control_view", lambda *_: {
        "control_installed": True, "request_pending": False, "last_action": {},
    })
    monkeypatch.setattr(web, "preview_rules", lambda store, rules, accounts, vault:
        events.append(("preview",tuple(rule["kind"] for rule in rules),tuple(accounts))) or
        [{"account_id":1, "examined":0, "matched_by_rule":[0,0]},
         {"account_id":2, "examined":0, "matched_by_rule":[0,0]}])
    queued = {}
    def enqueue(path, entries, accounts, batch_id):
        queued.update({"entries": entries, "accounts": accounts, "batch_id": batch_id})
        events.append(("queued",len(entries)))
        return True
    monkeypatch.setattr(web, "request_batch_enable", enqueue)
    result = client.post("/analyze/drafts", data={
        "csrf": csrf, "plan": "sender_domain", "select_all": "yes",
        "intent": "enable"}, follow_redirects=False)
    assert result.status_code == 303 and result.headers["location"] == "/analyze"
    assert events == [("preview",("sender_domain","sender_domain"),(1,2)),
                      ("queued",2)]
    assert queued["accounts"] == [1,2] and len(queued["entries"]) == 2
    assert len(queued["batch_id"]) == 24
    assert all(r["enabled"] == 0 and r["action"] == "draft" for r in rules(app))
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0
    waiting = client.get("/analyze").text
    assert "rules enabled on 2 account(s)" not in waiting
    # The policy, not just queue success, confirms actual activation.
    monkeypatch.setattr(web, "control_view", lambda *_: {
        "control_installed": True, "request_pending": False,
        "last_action": {"batch_id": queued["batch_id"], "state": "success"}})
    still_unconfirmed = client.get("/analyze").text
    assert "protected approval could not be verified" in still_unconfirmed
    monkeypatch.setattr(web,"read_approvals", lambda: [
        {**entry, "accounts": [1,2]} for entry in queued["entries"]])
    confirmed = client.get("/analyze").text
    assert "2 rules enabled on 2 account(s)" in confirmed


def test_bulk_enable_missing_root_control_or_preview_failure_fails_closed(
        signed_in, app, monkeypatch):
    import importlib
    web=importlib.import_module("filter_vision.app")
    client,csrf=signed_in
    analyzed(client,csrf)
    plan=plan_for(app,csrf,"sender_domain")
    token=plan["items"][0]["token"]
    monkeypatch.setattr(web,"control_view",lambda *_:{
        "control_installed":False,"request_pending":False,"last_action":{}})
    no_helper=client.post("/analyze/drafts",data={
        "csrf":csrf,"plan":"sender_domain","selected":[token],"intent":"enable"})
    assert no_helper.status_code==409 and not rules(app)
    monkeypatch.setattr(web,"control_view",lambda *_:{
        "control_installed":True,"request_pending":False,"last_action":{}})
    monkeypatch.setattr(web,"load_policy",lambda:{"accounts":[1,2]})
    monkeypatch.setattr(web,"read_approvals",lambda:[])
    monkeypatch.setattr(app.state.token_vault,"connected",lambda _:True)
    from filter_vision.activation_preview import ApprovalPreviewError
    monkeypatch.setattr(web,"preview_rules",lambda *a:(
        (_ for _ in ()).throw(ApprovalPreviewError("mock preview failed"))))
    forbidden=client.post("/analyze/drafts",data={
        "csrf":csrf,"plan":"sender_domain","select_all":"yes","intent":"enable"})
    assert forbidden.status_code==409 and not rules(app)
    assert app.state.analysis_memory.read(csrf)["batch"] is None
    unknown=client.post("/analyze/drafts",data={
        "csrf":csrf,"plan":"sender_domain","selected":[token],"intent":"activate"})
    assert unknown.status_code==400 and not rules(app)


def test_batch_enable_staging_race_or_invalid_is_fully_rolled_back(signed_in, app):
    from filter_vision.draft_saving import save_enable_candidates
    store=app.state.store
    with __import__("pytest").raises(ValueError):
        save_enable_candidates(store,[("sender_domain","From","good.example.com"),
                                      ("sender_domain","From","com")])
    assert rules(app)==[]
    saved=save_enable_candidates(store,[("sender_domain","From","good.example.com")])
    assert len(saved)==1
    with __import__("pytest").raises(ValueError):
        save_enable_candidates(store,[("sender_domain","From","good.example.com"),
                                      ("sender_domain","From","new.example.com")])
    assert len(rules(app))==1


def test_queued_batch_with_helper_failure_never_claims_enabled(signed_in,app,monkeypatch):
    import importlib
    web=importlib.import_module("filter_vision.app")
    client,csrf=signed_in
    analyzed(client,csrf)
    monkeypatch.setattr(web,"control_view",lambda *_:{
        "control_installed":True,"request_pending":False,"last_action":{}})
    monkeypatch.setattr(web,"load_policy",lambda:{"accounts":[1,2]})
    monkeypatch.setattr(web,"read_approvals",lambda:[])
    monkeypatch.setattr(app.state.token_vault,"connected",lambda aid:True)
    monkeypatch.setattr(web,"preview_rules",lambda *args: [])
    monkeypatch.setattr(web,"request_batch_enable",lambda *args:False)
    result=client.post("/analyze/drafts",data={
        "csrf":csrf,"plan":"sender_domain","select_all":"yes","intent":"enable"})
    assert result.status_code==409
    assert len(rules(app))==2  # Safe inert drafts, no root approval
    assert all(x["enabled"]==0 for x in rules(app))



def test_bulk_preview_reuses_one_read_only_connection_per_account(app,monkeypatch):
    import importlib
    mod=importlib.import_module("filter_vision.activation_preview")
    with app.state.store.db() as con:
        for aid in (1,2):
            con.execute("INSERT INTO accounts(id,label,provider,host,port,username,folder,"
                        "interval_minutes,created_at) VALUES(?,?,?, ?,?,?, ?,?,?)",
                        (aid,f"Account {aid}","outlook","outlook.office365.com",993,
                         f"account{aid}@example.invalid","Junk",30,1))
    connections=[]
    headers=[]
    class MockIMAP:
        def uid(self,command,*args):
            assert command=="SEARCH" and args==(None,"ALL")
            return ("OK",[b"11 12"])
        def logout(self):
            pass
    def fake_connect(username,token,connector=None):
        assert token=="synthetic-token"
        obj=MockIMAP()
        connections.append(obj)
        return obj,42
    def fake_headers(uid,connection):
        headers.append((uid,id(connection)))
        return b"From: Sales <seller@safe.example.com>\r\nX-VMTA-Source: Example\r\n\r\n"
    monkeypatch.setattr(mod,"access_token_for",lambda *args:"synthetic-token")
    monkeypatch.setattr(mod,"_connect",fake_connect)
    monkeypatch.setattr(mod,"_headers",fake_headers)
    monkeypatch.setattr(mod,"matches",lambda rule,header,body:
                        rule["kind"] == "sender_domain")
    candidates=[
        {"kind":"sender_domain","field":"From","pattern":"safe.example.com"},
        {"kind":"sender_exact","field":"From","pattern":"seller@safe.example.com"},
    ]
    reports=mod.preview_rules(app.state.store,candidates,[1,2],app.state.token_vault)
    assert len(connections)==2
    assert len(headers)==4
    assert reports[0]["matched_by_rule"] == [2,0]
    assert reports[1]["matched_by_rule"] == [2,0]
    assert all(rep["examined"]==2 and rep["oversized"]==0 for rep in reports)


def test_bulk_preview_fails_closed_when_second_account_unavailable(app,monkeypatch):
    import importlib
    mod=importlib.import_module("filter_vision.activation_preview")
    from filter_vision.junk_browse import BrowseError
    with app.state.store.db() as con:
        for aid in (1,2):
            con.execute("INSERT INTO accounts(id,label,provider,host,port,username,folder,"
                        "interval_minutes,created_at) VALUES(?,?,?, ?,?,?, ?,?,?)",
                        (aid,f"Account {aid}","outlook","outlook.office365.com",993,
                         f"account{aid}@example.invalid","Junk",30,1))
    attempts=[]
    class MockIMAP:
        def uid(self,cmd,*args):
            return "OK",[b"11"]
        def logout(self):
            pass
    def fake_connect(username,token,connector=None):
        attempts.append(username)
        if username.startswith("account2"):
            raise BrowseError("synthetic second account unavailable")
        return MockIMAP(),17
    monkeypatch.setattr(mod,"access_token_for",lambda *args:"synthetic-token")
    monkeypatch.setattr(mod,"_connect",fake_connect)
    monkeypatch.setattr(mod,"_headers",lambda *args:b"From: test@example.com\r\n\r\n")
    monkeypatch.setattr(mod,"matches",lambda *args:True)
    import pytest
    with pytest.raises(mod.ApprovalPreviewError,match="batch Junk preview failed"):
        mod.preview_rules(app.state.store,[
            {"kind":"sender_domain","field":"From","pattern":"example.com"}],
            [1,2],app.state.token_vault)
    assert len(attempts)==2
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==0
    with pytest.raises(mod.ApprovalPreviewError):
        mod.preview_rules(app.state.store,[
            {"kind":"sender_domain","field":"From","pattern":"example.com"}]*2,
            [1,2],app.state.token_vault)
