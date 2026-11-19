"""Read-only RFC 5322 header analysis. Never interpret or fetch the message body."""
from __future__ import annotations

import re
from collections import defaultdict
from email import policy
from email.parser import BytesHeaderParser
from email.utils import parseaddr

MAX_FILES = 20
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_HEADER_BYTES = 256 * 1024


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
    }


def suggestions(samples: list[dict]) -> list[dict]:
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
        # A subject fragment is a deliberately higher-risk alternative.
        sub = sample["subject"]
        if 10 <= len(sub) <= 160:
            grouped[("subject_exact", "Subject", sub)].add(index)
    risk = {"sender_exact": "Specific", "sender_domain": "Review scope",
            "header_exact": "Specific", "header_contains": "Review collisions",
            "subject_exact": "Review subject reuse"}
    result = []
    for (kind, field, value), indices in grouped.items():
        result.append({"kind": kind, "field": field, "value": value,
                       "count": len(indices), "total": len(samples),
                       "risk": risk[kind], "sample_ids": sorted(indices)})
    return sorted(result, key=lambda x: (-x["count"], x["kind"], x["value"]))[:100]


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
