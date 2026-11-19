from filter_vision.analysis import inspect_eml, suggestions, validate_rule

ONE = b"""From: Best prize <offers@new1.example>
Reply-To: reply@new1.example
Feedback-ID: ABC:7404:422441:posti
X-VMTA-Source: mail.campaign.invalid
Subject: Free Spins Tonight
Content-Type: text/html

<html><script>danger()</script></html>
"""
TWO = b"""From: Second offer <offers@new2.example>
Feedback-ID: DEF:7404:422441:posti
Subject: Free Spins Tonight

Not important
"""
BENIGN = b"""From: Link <notifications@email.link.com>
Subject: Service changes
Feedback-ID: legit:sender:234:AmazonSES

Hello
"""


def test_shared_fingerprint_across_domains():
    parsed = [inspect_eml("one.eml", ONE), inspect_eml("two.eml", TWO),
              inspect_eml("legit.eml", BENIGN)]
    candidates = suggestions(parsed)
    match = next(x for x in candidates if x["kind"] == "header_contains"
                 and x["value"] == "7404:422441:posti")
    assert match["count"] == 2 and match["total"] == 3
    assert match["field"] == "Feedback-ID"
    assert not any(x["value"] == "Link" for x in candidates)


def test_analyze_upload_and_disabled_rule(signed_in, app):
    client, csrf = signed_in
    resp = client.post("/analyze", data={"csrf": csrf}, files=[
        ("files", ("one.eml", ONE, "message/rfc822")),
        ("files", ("two.eml", TWO, "message/rfc822")),
    ])
    assert resp.status_code == 200
    assert "7404:422441:posti" in resp.text
    assert "2/2" in resp.text
    assert "<script>danger" not in resp.text
    assert client.post("/rules", data={"csrf": csrf, "kind": "header_contains",
            "field": "Feedback-ID", "value": "7404:422441:posti"},
            follow_redirects=False).status_code == 303
    with app.state.store.db() as con:
        row = con.execute("SELECT enabled,action FROM rules").fetchone()
        assert row["enabled"] == 0 and row["action"] == "draft"
    assert "Disabled draft" in client.get("/rules").text


def test_xss_is_escaped(signed_in):
    client, csrf = signed_in
    data = b'From: Evil <bad@evil.invalid>\r\nSubject: <script>alert(1)</script>\r\n\r\nbody'
    response = client.post("/analyze", data={"csrf": csrf},
                           files={"files": ("x.eml", data, "message/rfc822")})
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text


def test_invalid_upload_and_csrf(signed_in):
    client, csrf = signed_in
    response = client.post("/analyze", data={"csrf": csrf+"invalid"},
                           files={"files": ("sample.eml", ONE, "message/rfc822")})
    assert response.status_code == 403
    response = client.post("/analyze", data={"csrf": csrf},
                           files={"files": ("bad.txt", ONE, "text/plain")})
    assert response.status_code == 400
    response = client.post("/analyze", data={"csrf": csrf},
                           files={"files": ("too-big.eml", b"A"*(2*1024*1024+1), "message/rfc822")})
    assert response.status_code == 400


def test_reject_broad_rule_and_invalid_scope(signed_in):
    client, csrf = signed_in
    assert client.post("/rules", data={"csrf": csrf, "kind": "header_contains",
        "field": "X-MS-Exchange-Organization-SCL", "value": "9"}).status_code == 400
    assert client.post("/rules", data={"csrf": csrf, "kind": "sender_domain",
        "field": "From", "value": "com"}).status_code == 400
    assert client.post("/rules", data={"csrf": csrf, "kind": "sender_exact",
        "field": "From", "value": "x@a.b"}, follow_redirects=False).status_code == 303
    assert client.post("/rules", data={"csrf": csrf+"invalid", "kind": "sender_exact",
        "field": "From", "value": "x@a.b"}).status_code == 403


def test_header_only_and_validation():
    sample = inspect_eml("sample.eml", ONE)
    assert sample["sender"] == "offers@new1.example"
    assert "danger()" not in repr(sample)
    try:
        validate_rule("sender_domain", "From", "com")
    except ValueError:
        pass
    else:
        raise AssertionError("Bare TLD accepted")
