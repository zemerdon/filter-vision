"""Privacy-conscious Activity reporting and bounded, encrypted email previews.

Only metadata plus a capped *text-only* representation of a matched email is
retained. Never store raw HTML, attachments, auth headers, passwords or tokens.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import json
import re

MAX_CAPTURE_BYTES = 32 * 1024
MAX_BODY_CHARS = 4096
MAX_META_CHARS = 300
SCAN_DETAIL = re.compile(r"account_id=(\d+) inspected=(\d+) matched=(\d+) deleted=(\d+)")
ACTIVITY_FIELDS = ("from", "to", "subject", "date", "body")


class _PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skipped = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self.skipped += 1
        if tag in ("br", "p", "div", "li", "tr") and not self.skipped:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg") and self.skipped:
            self.skipped -= 1
        if tag in ("p", "div", "li", "tr") and not self.skipped:
            self.parts.append("\n")

    def handle_data(self, value):
        if not self.skipped and sum(map(len, self.parts)) < MAX_BODY_CHARS * 2:
            self.parts.append(value)


def _clean(text: str, limit: int) -> str:
    text = "".join(ch if ch == "\n" or ch == "\t" or ch.isprintable() else " "
                   for ch in str(text))
    return text.strip()[:limit]


def safe_email_preview(header: bytes, source: bytes) -> dict[str, str]:
    """Read only a 32KiB prefix; never include attachments or raw HTML."""
    if not isinstance(header, bytes) or not isinstance(source, bytes):
        raise ValueError("Invalid message preview")
    if len(source) > MAX_CAPTURE_BYTES:
        raise ValueError("Mail preview exceeded fetch limit")
    try:
        header_message = BytesParser(policy=policy.default).parsebytes(
            header[:256 * 1024], headersonly=True)
        message = BytesParser(policy=policy.default).parsebytes(source)
    except (ValueError, TypeError, LookupError):
        raise ValueError("Cannot parse bounded email preview") from None

    record = {key: _clean(str(header_message.get(key.title(), "")), MAX_META_CHARS)
              for key in ("from", "to", "subject", "date")}
    record["body"] = "(Text preview unavailable; attachments and HTML are not retained)"
    parts = message.walk() if message.is_multipart() else [message]
    fallback_html = None
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            raw_text = part.get_content()
            if not isinstance(raw_text, str):
                continue
        except (UnicodeError, ValueError, LookupError, TypeError):
            continue
        if content_type == "text/plain":
            record["body"] = _clean(raw_text, MAX_BODY_CHARS) or "(Empty text message)"
            break
        if fallback_html is None:
            renderer = _PlainHTML()
            renderer.feed(raw_text[:MAX_CAPTURE_BYTES])
            fallback_html = _clean("".join(renderer.parts), MAX_BODY_CHARS)
    else:
        if fallback_html:
            record["body"] = fallback_html
    return record


def server_timestamp(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().strftime(
        "%d %b %Y, %I:%M:%S %p %Z")


def report(store) -> dict:
    """Summarize ALL historical aggregates; only detail entries from new logging."""
    limit = store.activity_limit()
    with store.db() as con:
        raw = [dict(row) for row in con.execute(
            "SELECT id,created_at,event,detail FROM audit_events "
            "ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))]
        matched = [dict(row) for row in con.execute(
            "SELECT m.id,m.created_at,m.account_id,m.imap_uid,m.rule_ids,"
            "m.state,m.preview_ciphertext,a.label AS account_label "
            "FROM message_actions m LEFT JOIN accounts a ON m.account_id=a.id "
            "ORDER BY m.created_at DESC,m.id DESC LIMIT ?", (limit,))]
        counts = [str(row["detail"]) for row in con.execute(
            "SELECT detail FROM audit_events WHERE event='live_scan'")]
        failures = con.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event='live_scan_failed'").fetchone()[0]
        rule_labels = {r["id"]: {"label": r["label"], "pattern": r["pattern"][:180]}
                       for r in con.execute("SELECT id,label,pattern FROM rules")}
        confirmed = [dict(row) for row in con.execute(
            "SELECT rule_ids FROM message_actions WHERE state='deleted'")]
        pending_count = con.execute(
            "SELECT COUNT(*) FROM message_actions WHERE state='pending'").fetchone()[0]

    totals = dict(scans=0, examined=0, matched=0, deleted=0, failures=failures)
    for detail in counts:
        found = SCAN_DETAIL.fullmatch(detail)
        if not found:
            continue
        totals["scans"] += 1
        totals["examined"] += int(found[2])
        totals["matched"] += int(found[3])
        totals["deleted"] += int(found[4])

    per_rule = Counter()
    for row in confirmed:
        try:
            ids = json.loads(row["rule_ids"])
            per_rule.update(set(int(i) for i in ids))
        except (ValueError, TypeError):
            continue

    events = []
    for row in raw:
        events.append({
            "kind": "audit", "id": row["id"], "timestamp": row["created_at"],
            "when": server_timestamp(row["created_at"]),
            "label": row["event"].replace("_", " ").capitalize(),
            "detail": row["detail"], "action": None,
        })
    for row in matched:
        try:
            rule_ids = json.loads(row["rule_ids"])
        except (ValueError, TypeError):
            rule_ids = []
        ids = [int(i) for i in rule_ids if str(i).isdigit()]
        preview = store.decrypt_message_preview(row["preview_ciphertext"])
        events.append({
            "kind": "message", "id": row["id"], "timestamp": row["created_at"],
            "when": server_timestamp(row["created_at"]),
            "label": "Junk message deleted" if row["state"] == "deleted"
                     else "Deletion outcome unconfirmed",
            "detail": f"Account {row['account_label'] or row['account_id']} · "
                      f"UID {row['imap_uid']} · "
                      f"{'Deleted' if row['state']=='deleted' else 'Pending or incomplete'}",
            "action": {"preview": preview, "account": row["account_label"] or row["account_id"],
                       "uid": row["imap_uid"],
                       "rules": [{"id": i, **rule_labels.get(i, {"label": "Legacy rule",
                                                                "pattern": "Unavailable"})}
                                 for i in ids],
                       "state": row["state"]},
        })

    events.sort(key=lambda e: (e["timestamp"], 1 if e["kind"] == "message" else 0,
                                e["id"]), reverse=True)
    return {
        "entries": events[:limit], "limit": limit, "totals": totals,
        "confirmed_logged": len(confirmed), "uncertain": pending_count,
        "per_rule": [{"id": rid, **rule_labels.get(rid, {"label": "Legacy rule",
                                                        "pattern": "Unavailable"}),
                      "count": count} for rid, count in per_rule.most_common()],
        "timezone": datetime.now().astimezone().strftime("%Z (%z)"),
    }
