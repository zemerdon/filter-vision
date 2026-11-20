"""Manual evaluation is offline, read-only and has explicit match/miss reports."""
import pytest

from filter_vision.analysis import inspect_eml
from filter_vision.manual_eval import evaluate


def sample(sender, subject, marker):
    return inspect_eml(
        "sample.eml",
        (f"From: {sender}\r\nSubject: {subject}\r\n"
         f"X-Relaying-Domain: {marker}\r\n"
         f"Content-Type: text/html\r\n\r\n"
         f'<a href="https://offer.example.com/promo">offer</a>').encode())


def four_samples():
    return [
        sample("offer@novahockey.com","First promo","sport"),
        sample("offer@ads.example.com","Second promo","other"),
        sample("offer@comethockey.com","Third promo","sport"),
        sample("offer@mailer.example.org","Fourth promo","other"),
    ]


def test_manual_wildcard_coverage():
    result=evaluate(four_samples(),"from_domain","wildcard","*hockey.com")
    assert (result["count"],result["total"])==(2,4)
    assert [row["subject"] for row in result["matched"]]==["First promo","Third promo"]
    assert [row["subject"] for row in result["missed"]]==["Second promo","Fourth promo"]


def test_named_header_and_click_destination_manual_only():
    data=four_samples()
    result=evaluate(data,"named_header","contains","sport","X-Relaying-Domain")
    assert result["count"]==2
    result=evaluate(data,"click_host","exact","offer.example.com")
    assert result["count"]==4
    assert "not a supported live rule" in result["warning"]
    assert evaluate(data,"subject","contains","promo")["count"]==4


@pytest.mark.parametrize("field,operation,value,header", [
    ("unsupported","exact","valid",""),
    ("from_domain","regex","valid",""),
    ("from_domain","wildcard","*",""),
    ("from_domain","wildcard","**",""),
    ("named_header","contains","valid","Authorization"),
    ("named_header","contains","valid","Invalid Header"),
    ("subject","exact","bad\nvalue",""),
])
def test_manual_validation(field,operation,value,header):
    with pytest.raises(ValueError):
        evaluate(four_samples(),field,operation,value,header)


def test_custom_header_labels_and_escaping(signed_in):
    client,csrf=signed_in
    one=sample("a@novahockey.com","<script>alert(1)</script>","sport")
    two=sample("b@business.example.com","Legitimate","other")
    page=client.post("/analyze",data={"csrf":csrf},files=[
        ("files",("a.eml", b"From: a@novahockey.com\r\n"
                      b"Subject: <script>alert(1)</script>\r\n"
                      b"X-Relaying-Domain: sport\r\n\r\nbody","message/rfc822")),
        ("files",("b.eml", b"From: b@business.example.com\r\n"
                      b"Subject: Legitimate\r\n"
                      b"X-Relaying-Domain: other\r\n\r\nbody","message/rfc822")),
    ])
    assert page.status_code==200
    response=client.post("/analyze/manual",data={
        "csrf":csrf,"field":"from_domain","operator":"wildcard",
        "value":"*hockey.com"})
    assert response.status_code==200
    assert "1/2 matched" in response.text
    assert "Missed (1)" in response.text
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text
    assert client.get("/analyze").status_code==200
    assert "Manual evaluation" in client.get("/analyze").text
    assert client.post("/analyze/manual",data={
        "field":"subject","operator":"exact","value":"Legitimate"}).status_code==403


def test_memory_expiry_and_caps(monkeypatch):
    from filter_vision import analysis_session
    now=[1200.]
    monkeypatch.setattr(analysis_session.time,"monotonic",lambda:now[0])
    cache=analysis_session.AnalysisMemory()
    cache.write("one",samples=[{"subject":"transient"}])
    assert len(cache.read("one")["samples"])==1
    now[0]+=analysis_session.TTL_SECONDS+1
    assert cache.read("one")["samples"]==[]
    for i in range(analysis_session.MAX_SESSIONS+3):
        now[0]+=1
        cache.write(str(i),samples=[{"id":i}])
    assert len(cache._sessions)<=analysis_session.MAX_SESSIONS
    # Reading at exactly the cache capacity must not evict another browser.
    first = next(iter(cache._sessions))
    assert cache.read(first)["samples"]
    assert len(cache._sessions) == analysis_session.MAX_SESSIONS
