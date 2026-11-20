"""Passwordless-LAN Analyse flow: connected account scan -> select -> evaluate."""
import importlib

from filter_vision.analysis import inspect_eml

WEB=importlib.import_module("filter_vision.app")


def mail(i):
    domain = ("novahockey.com","office.example.com",
              "comethockey.com","ordinary.example.org")[i]
    return inspect_eml(
        f"selected{i}.eml",
        (f"From: Campaign <offer@{domain}>\r\n"
         f"Subject: Item {i}\r\n"
         f"X-Tracking-Group: Sample-{i%2}\r\n\r\nbody").encode())


def seed(app, monkeypatch):
    with app.state.store.db() as con:
        for i in (1,2):
            con.execute(
                "INSERT INTO accounts(id,label,provider,host,port,username,folder,"
                "interval_minutes,created_at) VALUES(?,?,?, ?,?,?, ?,?,?)",
                (i,f"Account {i}","outlook","outlook.office365.com",993,
                 f"account{i}@example.invalid","Junk",30,1))
    monkeypatch.setattr(app.state.token_vault,"connected",lambda account_id:True)
    monkeypatch.setattr(WEB,"access_token_for",lambda *args:"test-token")
    def browse(account,token):
        return [{
            "ref":f"ref-{account['id']}-{j}",
            "account_id":account["id"],
            "account_label":account["label"],
            "uid":j+10,
            "uidvalidity":42,
            "header_sha256":"test" * 16,
            "sender":f"offer@example.invalid",
            "subject":f"Item {(account['id']-1)*2+j}",
            "date":"Friday",
        } for j in range(2)]
    def selected(account,items,token,remaining_budget):
        return [{**mail((account["id"]-1)*2+j),
                 "account_label":account["label"],
                 "_analysis_size":150}
                for j in range(len(items))]
    monkeypatch.setattr(WEB,"list_junk",browse)
    monkeypatch.setattr(WEB,"fetch_selected",selected)


def test_connected_scan_then_manual_evaluate(signed_in,app,monkeypatch):
    client,csrf=signed_in
    seed(app,monkeypatch)
    page=client.get("/analyze")
    assert "Scan Junk folders" in page.text
    assert "Account 1" in page.text and "Account 2" in page.text
    browse=client.post("/analyze/junk/scan",data={"csrf":csrf})
    assert browse.status_code==200
    assert "Messages found" in browse.text
    rows=app.state.analysis_memory.read(csrf)["catalog"]
    assert len(rows)==4
    selected=client.post("/analyze/junk/select",
                         data={"csrf":csrf,"selected":[r["ref"] for r in rows]})
    assert selected.status_code==200
    assert "Manual evaluation" in selected.text
    evaluation=client.post("/analyze/manual",data={
        "csrf":csrf, "field":"from_domain", "operator":"wildcard",
        "value":"*hockey.com"})
    assert evaluation.status_code==200
    assert "2/4 matched" in evaluation.text
    assert "Missed (2)" in evaluation.text
    assert "Item 0" in evaluation.text and "Item 3" in evaluation.text
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0]==0
        assert con.execute("SELECT COUNT(*) FROM message_actions").fetchone()[0]==0


def test_bad_selection_and_csrf_do_not_trigger_fetch(signed_in,app,monkeypatch):
    client,csrf=signed_in
    seed(app,monkeypatch)
    assert client.post("/analyze/junk/scan").status_code==403
    assert client.post("/analyze/manual",data={
        "field":"subject","operator":"contains","value":"Item"}).status_code==403
    assert client.post("/analyze/junk/select",data={
        "csrf":csrf,"selected":["not-issued"]}).status_code==410
    assert client.post("/analyze/manual",data={
        "csrf":csrf,"field":"subject","operator":"contains","value":"Item"}).status_code==400
    client.post("/analyze/junk/scan",data={"csrf":csrf})
    assert client.post("/analyze/junk/select",data={
        "csrf":csrf,"selected":["ref-1-0"]*2}).status_code==400
    assert client.post("/analyze/junk/select",data={
        "csrf":csrf,"selected":["ref-1-0","forged"]}).status_code==410
    assert client.post("/analyze/junk/scan",data={
        "csrf":csrf},headers={"Origin":"https://forged.invalid"}).status_code==403


def test_empty_junk_scan_is_explicit(signed_in,app,monkeypatch):
    client,csrf=signed_in
    seed(app,monkeypatch)
    monkeypatch.setattr(WEB,"list_junk",lambda *args: [])
    result=client.post("/analyze/junk/scan",data={"csrf":csrf})
    assert result.status_code==200
    assert "No emails found in the connected Junk folders" in result.text
    assert not app.state.analysis_memory.read(csrf)["samples"]


def test_second_browser_cannot_reuse_first_browser_selection(signed_in,app,monkeypatch):
    from fastapi.testclient import TestClient
    client,csrf=signed_in
    seed(app,monkeypatch)
    client.post("/analyze/junk/scan",data={"csrf":csrf})
    assert app.state.analysis_memory.read(csrf)["catalog"]
    with TestClient(app,base_url="https://filter-vision",
                    client=("192.168.1.70",50100)) as other:
        page=other.get("/analyze")
        assert page.status_code==200
        assert "Messages found" not in page.text
        import re
        match=re.search(r'name="csrf" value="([a-f0-9]{64})"',page.text)
        assert match
        assert match.group(1)!=csrf
        response=other.post("/analyze/manual",data={
            "csrf":match.group(1),"field":"from_domain",
            "operator":"wildcard","value":"*hockey.com"})
        assert response.status_code==400
