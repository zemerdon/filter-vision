"""Synthetic-only validation of legacy raw header discovery + compact cover.

No private mailbox fixtures, no live cleanup calls, no active policy change.
"""
from __future__ import annotations

from filter_vision.analysis import (inspect_eml, suggestions, coverage_options,
                                    compact_header_plan, validate_rule)
from filter_vision.import_legacy import legacy_matches
from filter_vision.legacy_fingerprints import (raw_evidence, fingerprint_candidates,
                                               MAX_EVIDENCE_CHARS)
from filter_vision.rule_management import RuleManagementError
import pytest


def mail(index, *, sender_domain="mail.example.invalid", feedback=None,
         campaign=None, extras="", body="body"):
    base = (f"From: Sender {index} <sender{index}@{sender_domain}>\r\n"
            f"Subject: Private synthetic sample {index}\r\n"
            f"X-MS-Exchange-Organization-SCL: 9\r\n"
            f"Authentication-Results: mail.microsoft.example; spf=pass; dkim=pass\r\n"
            f"Received: from gmailapi.google.com by outlook.office365.com\r\n"
            + (f"Feedback-ID: {feedback}\r\n" if feedback else "")
            + (f"X-Campaign-ID: {campaign}\r\n" if campaign else "")
            + extras + "\r\n" + body)
    return inspect_eml(f"s{index}.eml", base.encode())


def test_exact_old_cleaner_parity_for_rotating_raw_feedback_ids():
    selected = [mail(i, sender_domain=f"rotating-{i}.example.invalid",
                     feedback=f"{i:05d}:7418:888112:posti",
                     campaign=f"wave-{i}:prime-2026-test")
                for i in range(6)]
    found = [x for x in suggestions(selected) if x["kind"] == "raw_header_contains"]
    assert any(x["value"] == "7418:888112:posti" and x["count"] == 6 for x in found)
    assert any(x["value"] == "prime-2026-test" and x["count"] == 6 for x in found)
    assert all(x["can_save"] and x["shared"] for x in found)
    for item in found:
        matches = [i for i, row in enumerate(selected)
                   if legacy_matches(row["raw_header_evidence"], item["value"])]
        assert matches == item["sample_ids"]
    compact = coverage_options(selected)[0]
    assert (compact["count"], compact["missed"], len(compact["items"])) == (6, 0, 1)
    assert compact["exact"] is True
    assert compact["items"][0]["kind"] in ("header_contains", "raw_header_contains")
    # Multiple valid independent fingerprints remain visible as choices.
    assert len({x["value"] for x in found if x["count"] == 6}) >= 2


def test_legacy_matching_handles_utf8_replacement_case_and_fold_boundaries():
    raw = (b"Feedback-ID: pREFIX:RotAted-2026-Promo\r\n"
           b"X-Campaign-ID: alpha-\r\n  beta-2026-test\r\n")
    assert legacy_matches(raw, "rotated-2026-promo")
    assert not legacy_matches(raw, "alpha-beta-2026-test")
    indexed = raw_evidence(raw)
    assert legacy_matches(indexed, "rotated-2026-promo")
    assert not legacy_matches(indexed, "alpha-beta-2026-test")
    assert not fingerprint_candidates([])


def test_no_generic_microsoft_or_auth_header_candidates():
    samples = [mail(i, sender_domain=f"s{i}.example.invalid",
                    extras=("X-Forefront-Antispam-Report: shared-trace-2026\r\n"
                            "X-Spam-Score: spam-bulk-2026\r\n"
                            "DKIM-Signature: v=1; trace=shared-key-2026\r\n"
                            "X-Auth-Token: synthetic-secret-999999\r\n"))
               for i in range(4)]
    assert all(not x for x in fingerprint_candidates(samples))
    assert not any(x["kind"] == "raw_header_contains"
                   for x in suggestions(samples))
    assert all("shared-trace" not in repr(row["raw_header_evidence"])
               and "synthetic-secret" not in repr(row["raw_header_evidence"])
               for row in samples)


def test_raw_header_not_body_fingerprint_and_memory_bounded():
    body = "<a href='https://promo.example.com'>" + "safety-check-token-2026" * 30 + "</a>"
    sample = mail(1, feedback="campaign-2026-test", body=body)
    assert b"safety-check-token-2026" not in sample["raw_header_evidence"]
    assert b"<a" not in sample["raw_header_evidence"]
    assert b"Subject:" not in sample["raw_header_evidence"]
    assert b"Received:" not in sample["raw_header_evidence"]
    assert b"Authentication-Results:" not in sample["raw_header_evidence"]
    assert len(sample["raw_header_evidence"]) < MAX_EVIDENCE_CHARS
    huge = b"X-Campaign-ID: " + b"A" * 16000 + b"\r\nFrom: a@b.example\r\n"
    assert len(raw_evidence(huge)) <= MAX_EVIDENCE_CHARS
    assert b"A" * 1000 not in raw_evidence(huge)


def test_raw_any_header_evidence_uses_same_legacy_literal_matcher():
    samples = [
        mail(1, feedback="prefix:7418:888112:posti"),
        mail(2, campaign="prefix:7418:888112:posti"),
        mail(3, campaign="nonmatching-campaign-2026"),
    ]
    found = [x for x in fingerprint_candidates(samples)
             if "7418:888112:posti" in x["value"]]
    assert len(found) == 1
    assert found[0]["sample_ids"] == [0, 1]
    assert set(found[0]["source_fields"]) == {"feedback-id", "x-campaign-id"}


def test_minimum_rule_cover_computed_over_candidate_masks():
    samples = [{"subject": f"Sample {i}"} for i in range(6)]
    def candidate(kind, value, matched):
        return {"kind": kind, "field": "All raw headers",
                "value": value, "sample_ids": matched,
                "count": len(matched), "can_save": True}
    options = [
        candidate("raw_header_contains", "alpha-promo-2026-xx", [0, 1, 2, 3]),
        candidate("raw_header_contains", "beta-promo-2026-xx", [0, 1]),
        candidate("raw_header_contains", "gamma-promo-2026-xx", [2, 3, 4]),
        candidate("raw_header_contains", "delta-promo-2026-xx", [4, 5]),
    ]
    compact = compact_header_plan(samples, options)
    assert compact["exact"] is True
    assert compact["count"] == 6 and compact["missed"] == 0
    assert len(compact["items"]) == 2
    assert {x["value"] for x in compact["items"]} == {
        "alpha-promo-2026-xx", "delta-promo-2026-xx"}


def test_minimum_plan_partial_coverage_is_not_hidden():
    samples = [mail(i, sender_domain=f"unique{i}.example.invalid")
               for i in range(4)]
    candidates = [{
        "kind": "raw_header_contains", "field": "All raw headers",
        "value": "synthetic-marker-2026-xx",
        "sample_ids": [0, 1, 2], "count": 3, "can_save": True,
    }]
    plan = compact_header_plan(samples, candidates)
    assert plan["count"] == 3
    assert plan["missed"] == 1
    assert plan["exact"] is True


def test_raw_draft_save_is_inert_and_enable_request_rejected(signed_in, app):
    client, csrf = signed_in
    account = None
    with app.state.store.db() as con:
        result = con.execute(
            "INSERT INTO accounts(label,provider,host,port,username,folder,"
            "interval_minutes,enabled,created_at) "
            "VALUES('Synthetic','outlook','outlook.office365.com',993,"
            "'dry@example.invalid','Junk',30,0,1)")
        account = result.lastrowid
    response = client.post("/rules", data={
        "csrf": csrf, "kind": "raw_header_contains", "field": "All raw headers",
        "value": "7418:888112:posti",
    }, follow_redirects=False)
    assert response.status_code == 303
    with app.state.store.db() as con:
        row = con.execute("SELECT * FROM rules").fetchone()
        assert row["kind"] == "raw_header_contains"
        assert row["enabled"] == 0 and row["action"] == "draft"
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0
    rid = row["id"]
    page = client.get("/rules")
    assert "Disabled" in page.text
    assert "Raw Header Contains" in page.text
    assert "Enable…" not in page.text
    before = client.post(f"/rules/{rid}/request", data={
        "csrf": csrf, "operation": "enable", "confirm": "request_review",
        "account_ids": str(account),
    }, follow_redirects=False)
    assert before.status_code == 409
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rule_review_requests").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0] == 0
    assert client.post("/rules", data={
        "csrf": csrf, "kind": "raw_header_contains",
        "field": "All raw headers", "value": "spf=pass",
    }).status_code == 400


def test_updates_page_only_three_controls_and_closed_changelog(client, app):
    app.state.latest = {"tag": "v0.2.12", "url": "https://github.com/zemerdon/filter-vision/releases/tag/v0.2.12",
                        "is_newer": True, "error": "", "notes": ["Synthetic release note"]}
    page = client.get("/updates").text
    assert page.count("Check for updates</button>") == 1
    assert page.count(">Update</button>") == 1
    assert page.count(">Changelog</summary>") == 1
    assert '<details class="updates-changelog">' in page
    assert "Stable release check</h2>" not in page
    assert "Synthetic release note" in page


def test_twenty_sample_bounded_coverage():
    samples = [mail(i, sender_domain=f"unique{i}.example.invalid",
                    feedback=f"rotate{i}:7418:888112:posti")
               for i in range(20)]
    plan = coverage_options(samples)[0]
    assert plan["count"] == 20 and plan["missed"] == 0
    assert len(plan["items"]) == 1
    assert len(suggestions(samples)) <= 160


def test_bounded_optimization_with_twenty_unrelated_messages():
    """Large singleton-only candidate space must not explode exponentially."""
    import time
    samples = [mail(i, sender_domain=f"independent{i}.example.invalid")
               for i in range(20)]
    begin = time.monotonic()
    plan = coverage_options(samples)[0]
    elapsed = time.monotonic() - begin
    assert (plan["count"], plan["missed"]) == (20, 0)
    assert len(plan["items"]) == 20
    assert elapsed < 8, f"analysis took {elapsed:.2f}s"
    assert plan["kind"] == "compact"


def test_fragment_candidates_are_escaped_and_not_stored_as_active_rules(signed_in, app):
    client, csrf = signed_in
    messages = []
    for i in range(3):
        payload = (f"From: {i}@distinct{i}.example.invalid\r\n"
                   f"X-Campaign-ID: rotate{i}:same-2026-<review>\r\n"
                   f"Subject: Synthetic {i}\r\n\r\nbody").encode()
        messages.append(("files", (f"test-{i}.eml", payload, "message/rfc822")))
    response = client.post("/analyze", data={"csrf": csrf}, files=messages)
    assert response.status_code == 200
    # Jinja autoescape must prevent any active markup from a header marker.
    assert "<review>" not in response.text
    with app.state.store.db() as con:
        assert con.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM rule_review_requests").fetchone()[0] == 0
