"""Bounded offline email evidence analysis; never render or fetch remote content.

Headers produce draftable matching candidates. HTML links are parsed locally
ONLY as explanatory campaign evidence; the live header-only cleaner cannot
delete using them. Message bodies are never retained.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from email import policy
from email.parser import BytesHeaderParser, BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit
from .manual_eval import normalized_headers

MAX_FILES = 20
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_HEADER_BYTES = 256 * 1024
MAX_HTML_BYTES = 512 * 1024
MAX_MIME_PARTS = 32
MAX_CLICK_LINKS = 128


def _destination_host(value: str) -> str | None:
    """Normalize a literal HTTP(S) destination to a bounded DNS hostname.

    Ignore mailto, javascript, local/private IPs, malformed URL inputs and
    one-label names. This makes hosts evidence, not privileged URL actions.
    """
    if not value or len(value) > 4096:
        return None
    try:
        parts = urlsplit(value.strip())
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        if parts.username or parts.password:
            return None
        hostname = parts.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        if len(hostname) > 253 or "." not in hostname:
            return None
        try:
            ipaddress.ip_address(hostname)
            return None
        except ValueError:
            pass
        labels = hostname.split(".")
        if any(not (1 <= len(label) <= 63) or not
               re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label)
               for label in labels):
            return None
        if hostname.endswith((".local", ".localhost", ".internal", ".test", ".invalid")):
            return None
        return hostname
    except (ValueError, UnicodeError, AttributeError):
        return None


class _LinkReader(HTMLParser):
    """Extract only anchor href hostnames; never include images or load URLs."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hosts: set[str] = set()
        self.link_count = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a" or self.link_count >= MAX_CLICK_LINKS:
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.link_count += 1
                host = _destination_host(value)
                if host:
                    self.hosts.add(host)
                break


def _click_destinations(data: bytes) -> list[str]:
    """Inspect bounded MIME HTML parts read-only; never store HTML/body/URLs.

    A malformed MIME tree or huge part simply yields no links rather than
    blocking a header-based draft analysis.
    """
    try:
        mail = BytesParser(policy=policy.default).parsebytes(data)
        reader = _LinkReader()
        parts_seen = 0
        for part in mail.walk():
            parts_seen += 1
            if parts_seen > MAX_MIME_PARTS:
                break
            if part.get_content_type() != "text/html":
                continue
            body = part.get_payload(decode=True)
            if body is None or len(body) > MAX_HTML_BYTES:
                continue
            charset = part.get_content_charset() or "utf-8"
            reader.feed(body.decode(charset, errors="replace"))
            if reader.link_count >= MAX_CLICK_LINKS:
                break
        return sorted(reader.hosts)[:32]
    except (ValueError, UnicodeError, LookupError, TypeError,
            RecursionError, AttributeError):
        return []


def inspect_eml(filename: str, data: bytes) -> dict:
    if not filename.lower().endswith(".eml"):
        raise ValueError("Only .eml files are accepted")
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError("Empty or oversized .eml (maximum 2 MiB)")
    # Only parse the headers: neither body HTML nor attachments are rendered/executed.
    match = re.search(br"\r?\n\r?\n", data)
    header = data[:match.start()] if match else data
    if len(header) > MAX_HEADER_BYTES:
        raise ValueError("Email headers exceed 256 KiB")
    message = BytesHeaderParser(policy=policy.default).parsebytes(header + b"\r\n\r\n")
    if len(message.defects) > 10:
        raise ValueError("Malformed email headers")
    headers = {}
    for name, value in message.raw_items():
        # Preserve all occurrences, but not full raw message bodies.
        headers.setdefault(name.lower(), []).append(str(value))
    def one(name):
        return str(message.get(name, "")).strip()
    def addr(name):
        return parseaddr(one(name))[1].strip().lower()
    sender = addr("From")
    reply = addr("Reply-To")
    bounce = addr("Return-Path")
    return {
        "filename": filename[:160],
        "from_display": one("From")[:200],
        "subject": one("Subject")[:200],
        "sender": sender,
        "reply_to": reply,
        "return_path": bounce,
        "feedback_ids": [x.strip() for x in headers.get("feedback-id", [])],
        "vmta": [x.strip() for x in headers.get("x-vmta-source", [])],
        "relaying": [x.strip() for x in headers.get("x-relaying-domain", [])],
        "click_hosts": _click_destinations(data),
        "manual_headers": normalized_headers(message),
    }


def suggestions(samples: list[dict]) -> list[dict]:
    """Rank shared evidence ahead of one-message guesses.

    The return object intentionally distinguishes header candidates that can
    become inert drafts from body-link campaign evidence that cannot. Neither
    category enables a destructive action.
    """
    grouped: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    for index, sample in enumerate(samples):
        sender = sample["sender"]
        if sender:
            grouped[("sender_exact", "From", sender)].add(index)
            if "@" in sender:
                domain = sender.rsplit("@", 1)[-1]
                if "." in domain:
                    grouped[("sender_domain", "From", domain)].add(index)
        for attr, header in [("vmta", "X-VMTA-Source"),
                             ("relaying", "X-Relaying-Domain")]:
            for val in sample[attr]:
                if 3 <= len(val) <= 255:
                    grouped[("header_exact", header, val)].add(index)
        for val in sample["feedback_ids"]:
            fields = [f.strip() for f in val.split(":")]
            if len(fields) >= 4:
                marker = ":".join(fields[-3:])
                if len(marker) >= 8:
                    grouped[("header_contains", "Feedback-ID", marker)].add(index)
        sub = sample["subject"]
        if 10 <= len(sub) <= 160:
            grouped[("subject_exact", "Subject", sub)].add(index)
        for host in sample.get("click_hosts", []):
            grouped[("click_destination", "HTML click destination", host)].add(index)

    # Find a distinctive shared text ending in DIFFERENT sender domains.
    # This is a speculative wildcard FAMILY clue, not an RFC/DNS ownership
    # relationship and not an executable rule. For example, runeHOCKEY.com
    # and ultimat-HOCKEY.com can suggest "*hockey.com", which also matches
    # unrelated legitimate domains. Never infer such a pattern from two
    # senders on the same domain, from just a public TLD, or from co.uk.
    by_tld: dict[str, set[str]] = defaultdict(set)
    sender_domains: list[str] = []
    for sample in samples:
        sender = sample["sender"]
        domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
        sender_domains.append(domain)
        labels = domain.split(".")
        if len(labels) >= 2 and len(labels[-2]) >= 5 and labels[-1] in {
            "com", "net", "org", "info", "biz", "io"
        }:
            by_tld[labels[-1]].add(labels[-2])
    for tld, labels in by_tld.items():
        roots = sorted(labels)
        if len(roots) < 2:
            continue
        patterns: set[str] = set()
        for a, first in enumerate(roots):
            for second in roots[a + 1:]:
                suffix = first[-min(len(first), len(second)):]
                while suffix and not second.endswith(suffix):
                    suffix = suffix[1:]
                if len(suffix) >= 6 and suffix[0].isalnum() and suffix[-1].isalnum():
                    patterns.add("*" + suffix + "." + tld)
        for pattern in patterns:
            ending = pattern[1:]
            matched = {i for i, domain in enumerate(sender_domains)
                       if domain.endswith(ending)}
            # Two samples using one and the same registered sender domain do
            # not establish a rotating-domain suffix family.
            domain_roots = {
                sender_domains[i].split(".")[-2]
                for i in matched if len(sender_domains[i].split(".")) >= 2
            }
            if len(matched) >= 2 and len(domain_roots) >= 2:
                grouped[("sender_suffix_evidence", "From domain ending", pattern)] = matched

    review = {
        "sender_suffix_evidence": ("Broad wildcard · review carefully", False,
                                   "Distinct sender domains share this text ending. "
                                   "This is NOT a common owned parent domain. A wildcard "
                                   "also matches unrelated legitimate domains; "
                                   "analysis-only, not a deletion rule."),
        "click_destination": ("Shared campaign link", False,
                              "Offline HTML link evidence only. The live cleaner "
                              "does not match message bodies; not a deletion rule."),
        "header_contains": ("Review campaign marker", True,
                            "Check whether this precise header marker also occurs in legitimate mail."),
        "header_exact": ("Review sending header", True,
                         "Check the sender-specific header and potential legitimate reuse."),
        "sender_domain": ("Review whole-domain scope", True,
                          "This matches all senders on the exact domain, not only these samples."),
        "sender_exact": ("One sender only", True,
                         "Matches only this exact sender; the identity may rotate."),
        "subject_exact": ("Fragile subject", True,
                          "Subjects are easy to change and may repeat in legitimate mail."),
    }
    rank = {"click_destination": 0, "header_contains": 1, "header_exact": 2,
            "sender_domain": 3, "sender_suffix_evidence": 4,
            "sender_exact": 5, "subject_exact": 6}
    result = []
    for (kind, field, value), indices in grouped.items():
        if kind == "click_destination" and len(indices) < 2:
            # A one-off link is a weaker clue than a shared campaign destination.
            continue
        label, can_save, explanation = review[kind]
        result.append({
            "kind": kind, "field": field, "value": value,
            "count": len(indices), "total": len(samples),
            "risk": label, "explanation": explanation,
            "can_save": can_save, "shared": len(indices) >= 2,
            "sample_ids": sorted(indices),
        })
    return sorted(result, key=lambda x: (-x["count"],
                                         rank[x["kind"]], x["value"]))[:100]


def validate_rule(kind: str, field: str, value: str) -> str:
    allowed = {
        "sender_exact": {"From"}, "sender_domain": {"From"},
        "header_exact": {"X-VMTA-Source", "X-Relaying-Domain"},
        "header_contains": {"Feedback-ID"}, "subject_exact": {"Subject"},
    }
    value = value.strip()
    if field not in allowed.get(kind, set()):
        raise ValueError("Unsupported rule type/field")
    if not 3 <= len(value) <= 255 or any(c in value for c in "\r\n\x00"):
        raise ValueError("Invalid rule value")
    if kind == "sender_exact" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("Invalid sender address")
    if kind == "sender_domain" and not re.fullmatch(r"[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+", value):
        raise ValueError("Invalid domain")
    if kind == "header_contains" and len(value) < 8:
        raise ValueError("Campaign marker too short")
    return value
