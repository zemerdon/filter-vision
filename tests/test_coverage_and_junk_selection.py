"""Synthetic nonprivate campaign samples; no live mailbox or policy mutation."""
from filter_vision.analysis import coverage_options, inspect_eml, suggestions


def six_samples():
    domains = ["mail.alpha.example.com", "news.beta.example.com",
               "mail.alpha.example.com", "offer.gamma.example.com",
               "news.beta.example.com", "deals.delta.example.com"]
    out = []
    for i, dom in enumerate(domains):
        raw = (f"From: Test <sender{i}@{dom}>\r\n"
               f"Subject: Sample {i}\r\n"
               f"Content-Type: text/html\r\n\r\n"
               f'<a href="https://promo.example.com/{i}">Visit</a>').encode()
        out.append(inspect_eml(f"{i}.eml",raw))
    return out


def test_six_message_four_domain_strategy_and_one_shared_link():
    samples=six_samples()
    shared=suggestions(samples)
    top=next(s for s in shared if s["kind"]=="click_destination")
    assert top["count"] == 6 and top["can_save"] is False
    domains, addresses=coverage_options(samples)
    assert domains["kind"]=="sender_domain"
    assert (domains["count"],domains["total"],domains["missed"])==(6,6,0)
    assert len(domains["items"])==4
    assert sorted(x["count"] for x in domains["items"])==[1,1,2,2]
    assert addresses["kind"]=="sender_exact" and len(addresses["items"])==6
    assert (addresses["count"],addresses["total"])==(6,6)
    assert all(x["kind"] in ("sender_domain","sender_exact") for p in (domains,addresses)
               for x in p["items"])
    assert not any(x["kind"] in ("sender_suffix_evidence","click_destination")
                   for p in (domains,addresses) for x in p["items"])


def test_no_or_invalid_sender_not_assumed_covered():
    samples=six_samples()
    samples[0]["sender"]=""
    samples[1]["sender"]="not-an-address"
    plan=coverage_options(samples)
    assert plan[0]["count"]==4 and plan[0]["missed"]==2
    assert plan[1]["count"]==4 and plan[1]["missed"]==2
    assert coverage_options([])==[]


def test_new_comparison_rendered_but_no_rule_auto_created(signed_in,app):
    client,csrf=signed_in
    data=[("files",(f"s{i}.eml",
                     (f"From: Tester <p{i}@campaign.example.com>\r\n"
                      f"Subject: Sample {i}\r\n\r\nbody").encode(),"message/rfc822"))
          for i in range(3)]
    resp=client.post("/analyze",data={"csrf":csrf},files=data)
    assert resp.status_code==200
    assert "Header-only coverage options" in resp.text
    assert "Exact sender-domain combination" in resp.text
    assert "Exact sender-address combination" in resp.text
    assert "3/3 covered" in resp.text
    assert "1 separate conditions" in resp.text
    with app.state.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==0


def test_master_select_all_markup_script_and_server_fallback(signed_in,app,monkeypatch):
    from test_analyze_connected_routes import seed
    client,csrf=signed_in
    seed(app,monkeypatch)
    scan=client.post("/analyze/junk/scan",data={"csrf":csrf})
    assert scan.status_code==200
    assert 'id="junk-select-all"' in scan.text
    assert 'name="select_all" value="yes"' in scan.text
    assert 'src="/static/junk-select.js"' in scan.text
    js=client.get("/static/junk-select.js")
    assert js.status_code==200
    assert "boxes.forEach" in js.text
    assert js.headers.get("Content-Type","").startswith("text/javascript")
    csp=scan.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    result=client.post("/analyze/junk/select",
                       data={"csrf":csrf,"select_all":"yes"})
    assert result.status_code==200
    assert "Manual evaluation" in result.text
    assert len(app.state.analysis_memory.read(csrf)["samples"])==4
    with app.state.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==0


def test_select_all_bound_to_first_twenty_and_invalid_inputs_fail(signed_in,app,monkeypatch):
    from test_analyze_connected_routes import seed,WEB,mail
    client,csrf=signed_in
    seed(app,monkeypatch)
    def many(account,token):
        if account["id"]==2:return []
        return [{"ref":f"index-{i}","account_id":1,"account_label":"Sample",
                 "uid":i+10,"uidvalidity":8,"header_sha256":"0"*64,
                 "sender":"test@example.invalid","subject":"synthetic","date":"Friday"}
                for i in range(25)]
    fetched=[]
    def fetch(account,items,token,remaining_budget):
        fetched.extend(items)
        return [{**mail(i%4),"_analysis_size":150} for i in range(len(items))]
    monkeypatch.setattr(WEB,"list_junk",many)
    monkeypatch.setattr(WEB,"fetch_selected",fetch)
    assert client.post("/analyze/junk/scan",data={"csrf":csrf}).status_code==200
    denied=client.post("/analyze/junk/select",
                       data={"csrf":"invalid","select_all":"yes"})
    assert denied.status_code==403 and not fetched
    denied=client.post("/analyze/junk/select",
                       data={"csrf":csrf,"select_all":"forged"})
    assert denied.status_code==400 and not fetched
    result=client.post("/analyze/junk/select",
                       data={"csrf":csrf,"select_all":"yes"})
    assert result.status_code==200
    assert len(fetched)==20
    assert [x["ref"] for x in fetched]==[f"index-{i}" for i in range(20)]
    assert len(app.state.analysis_memory.read(csrf)["samples"])==20



def test_packaged_install_includes_same_origin_script():
    from pathlib import Path
    import tarfile
    from filter_vision import __version__
    root=Path(__file__).resolve().parents[1]
    manifest=(root/"pyproject.toml").read_text()
    assert '"static/*.js"' in manifest
    archive=root/"dist"/f"filter-vision-v{__version__}.tar.gz"
    if not archive.exists():
        import pytest
        pytest.skip("Release archive not built yet")
    with tarfile.open(archive,"r:gz") as bundle:
        f=bundle.extractfile("filter-vision/src/filter_vision/static/junk-select.js")
        assert f and b"DOMContentLoaded" in f.read()


def test_real_javascript_select_all_and_limit_if_node_installed():
    import shutil,subprocess
    from pathlib import Path
    import pytest
    if not shutil.which("node"):
        pytest.skip("Node runtime not installed")
    js=(Path(__file__).resolve().parents[1]/
        "src/filter_vision/static/junk-select.js").read_text()
    harness = r"""
const vm = require('vm'), assert=require('assert');
const makeBox=()=>({
 checked:false, indeterminate:false, callbacks:{},
 addEventListener(name,fn){this.callbacks[name]=fn;},
 fire(name){this.callbacks[name]?.();}
});
const boxes=Array.from({length:25},makeBox);
const master=makeBox();
const status={textContent:""};
const form={callbacks:{},
 querySelectorAll(s){assert.strictEqual(s,'input[name="selected"]');return boxes;},
 addEventListener(name,fn){this.callbacks[name]=fn;}};
master.closest=()=>form;
const document={
 addEventListener(name,fn){assert.strictEqual(name,"DOMContentLoaded");fn();},
 getElementById(id){return id==="junk-select-all"?master:
                               id==="junk-selection-count"?status:null;}
};
vm.runInNewContext(process.argv[1], {document});
assert(status.textContent.includes("0 selected"));
master.checked=true;master.fire("change");
assert.strictEqual(boxes.filter(b=>b.checked).length,20);
assert.strictEqual(master.checked,true);
assert(boxes.slice(20).every(b=>!b.checked));
boxes[2].checked=false;boxes[2].fire("change");
assert.strictEqual(master.indeterminate,true);
boxes[21].checked=true;boxes[21].fire("change");
assert.strictEqual(boxes.filter(b=>b.checked).length,20);
assert.strictEqual(master.checked,false);
form.callbacks.submit();
assert.strictEqual(master.checked,false);
console.log("Actual DOM select all, 20 limit, partial selection and submit PASS");
"""
    result=subprocess.run(["node","-e",harness,js],
                          check=True,text=True,capture_output=True)
    assert "PASS" in result.stdout
