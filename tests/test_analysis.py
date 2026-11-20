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


def _campaign_mail(sender, subject, *, click_host="promo.example.com", extra_html=""):
    """Nonprivate synthetic fixture shaped like the four owner-supplied emails."""
    return (f"From: Offer <{sender}>\r\n"
            f"Subject: {subject}\r\n"
            f"X-MS-Exchange-Organization-SCL: 9\r\n"
            f"Authentication-Results: mx.example; spf=pass; dkim=pass\r\n"
            f"Received: from gmailapi.google.com with HTTPREST\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n\r\n"
            f'<html><a href="https://{click_host}/promo?private=secret">See offer</a>'
            f'<a href="https://{click_host}/another">Another</a>'
            f'<img src="https://i.imgur.com/logo.png">'
            f'{extra_html}</html>').encode()


def _four_campaign_samples():
    return [
        _campaign_mail("offers1@mailer.copper-branch.com", "Promo code winner"),
        _campaign_mail("offers2@mailer.copper-branch.com", "No deposit required"),
        _campaign_mail("feedback1@news.novahockey.com", "Retail survey"),
        _campaign_mail("offers3@info.comethockey.com", "Free spins"),
    ]


def test_shared_click_destination_outweighs_rotating_senders():
    parsed = [inspect_eml(f"{i}.eml", x) for i, x in enumerate(_four_campaign_samples())]
    found = suggestions(parsed)
    assert found[0]["kind"] == "click_destination"
    assert found[0]["field"] == "HTML click destination"
    assert found[0]["value"] == "promo.example.com"
    assert found[0]["count"] == 4
    assert found[0]["sample_ids"] == [0, 1, 2, 3]
    assert not found[0]["can_save"]  # Not a supported LIVE header rule.
    assert found[1]["kind"] == "sender_domain"
    assert found[1]["value"] == "mailer.copper-branch.com"
    assert found[1]["count"] == 2 and found[1]["can_save"]
    assert found[1]["sample_ids"] == [0, 1]
    wildcard = found[2]
    assert wildcard["kind"] == "sender_suffix_evidence"
    assert wildcard["field"] == "From domain ending"
    assert wildcard["value"] == "*hockey.com"
    assert wildcard["count"] == 2 and wildcard["sample_ids"] == [2, 3]
    assert not wildcard["can_save"]
    assert all(not x["shared"] for x in found[3:])
    assert not any("google.com" in x["value"] for x in found)
    assert not any("SCL" in x["field"] for x in found)
    assert not any("imgur" in x["value"] for x in found)
    assert all("private=secret" not in repr(sample) for sample in parsed)


def test_ui_shared_evidence_and_no_unsupported_body_rule_saved(signed_in, app):
    client, csrf = signed_in
    parsed = _four_campaign_samples()
    response = client.post(
        "/analyze", data={"csrf": csrf},
        files=[("files", (f"sample-{i}.eml", sample, "message/rfc822"))
               for i, sample in enumerate(parsed)])
    assert response.status_code == 200
    assert response.text.index("Shared campaign evidence") < response.text.index("Individual-message alternatives")
    assert "promo.example.com" in response.text
    assert "4/4" in response.text and "2/4" in response.text
    assert "BODY EVIDENCE" in response.text
    assert "*hockey.com" in response.text
    assert "DOMAIN-ENDING HYPOTHESIS" in response.text
    assert "Broad wildcard" in response.text
    assert "Analysis only" in response.text
    assert "View matching messages" in response.text
    assert "inactive, unscoped draft" in response.text
    # Exact target URL never surfaces in HTML, only the hostname does.
    assert "private=secret" not in response.text
    assert "i.imgur.com" not in response.text
    assert "gmailapi.google.com" not in response.text
    assert "No deposit required" in response.text
    # Submitting an analysis-only kind directly is refused as well.
    assert client.post("/rules", data={
        "csrf": csrf, "kind": "click_destination",
        "field": "HTML click destination", "value": "promo.example.com",
    }).status_code == 400
    assert client.post("/rules", data={
        "csrf": csrf, "kind": "sender_suffix_evidence",
        "field": "From domain ending", "value": "*hockey.com",
    }).status_code == 400
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0


def test_offline_parser_never_fetches_or_executes_html(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Network access forbidden during offline analysis")
    monkeypatch.setattr("socket.create_connection", blocked)
    mailbox = _campaign_mail(
        "sender@spoof.example", "Important security notification",
        extra_html=('<script>window.location="https://evil.example/attack"</script>'
                    '<img src="https://evil.example/image.gif">'
                    '<a href="javascript:alert(1)">Ignore</a>'
                    '<a href="http://127.0.0.1/private">Ignore</a>'
                    '<a href="https://user:pass@another.example/secret">Ignore</a>'))
    sample = inspect_eml("safe.eml", mailbox)
    assert sample["click_hosts"] == ["promo.example.com"]
    assert "window.location" not in repr(sample)
    assert "evil.example" not in repr(sample)
    assert "pass@" not in repr(sample)


def test_bounded_html_and_header_fallback():
    massive = _campaign_mail(
        "sender@same.example", "Summer deals",
        extra_html='<a href="https://not-a-match.example/">' + "X"*(512*1024) + "</a>")
    sample = inspect_eml("big.eml", massive)
    assert sample["click_hosts"] == []
    assert sample["sender"] == "sender@same.example"
    assert suggestions([sample])[0]["kind"] != "click_destination"


def test_html_markup_or_subject_cannot_inject_active_content(signed_in):
    client, csrf = signed_in
    data = _campaign_mail(
        "sender@spoof.example", "<img src=x onerror=alert(1)>",
        extra_html='<a href="https://common.example/"><svg onload=alert(1)></svg></a>')
    another = _campaign_mail(
        "another@another.example", "Routine offer",
        click_host="common.example")
    response = client.post("/analyze", data={"csrf": csrf}, files=[
        ("files", ("a.eml", data, "message/rfc822")),
        ("files", ("b.eml", another, "message/rfc822")),
    ])
    assert response.status_code == 200
    assert "common.example" in response.text
    assert "<svg" not in response.text
    assert "<img src=x" not in response.text
    assert "&lt;img src=x" in response.text


def test_unsupported_body_kinds_rejected_by_edit_validator():
    from filter_vision.rule_management import RuleManagementError, parse_edit
    import pytest
    with pytest.raises(RuleManagementError):
        parse_edit("click_destination:HTML click destination", "promo.example.com", "Candidate")
    with pytest.raises(ValueError):
        validate_rule("click_destination", "HTML click destination", "promo.example.com")



def test_suffix_family_needs_distinct_domains_not_just_two_senders():
    mails = [
        _campaign_mail("a@x.runehockey.com", "Sample A"),
        _campaign_mail("b@y.runehockey.com", "Sample B"),
        _campaign_mail("c@z.runehockey.com", "Sample C"),
    ]
    found=suggestions([inspect_eml(f"{i}.eml",mail) for i,mail in enumerate(mails)])
    assert not any(c["kind"] == "sender_suffix_evidence" for c in found)


def test_unsafe_wildcard_not_a_draftable_type():
    from filter_vision.rule_management import parse_edit, RuleManagementError
    import pytest
    with pytest.raises(RuleManagementError):
        parse_edit("sender_suffix_evidence:From domain ending",
                   "*hockey.com","Potential campaign")
    with pytest.raises(ValueError):
        validate_rule("sender_suffix_evidence","From domain ending","*hockey.com")
    with pytest.raises(ValueError):
        validate_rule("sender_domain","From","*hockey.com")


def test_only_public_tld_or_short_suffix_is_never_suggested():
    emails=[
        _campaign_mail("a@new1.com", "Sample one"),
        _campaign_mail("a@new2.com", "Sample two"),
        _campaign_mail("a@mall.com", "Sample three"),
    ]
    found=suggestions([inspect_eml(f"{i}.eml",mail) for i,mail in enumerate(emails)])
    assert not any(c["kind"]=="sender_suffix_evidence" for c in found)
