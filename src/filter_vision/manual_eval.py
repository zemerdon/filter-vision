"""Explicit, read-only manual match evaluation against bounded analysis samples.

Semantics describe candidate evidence only; this module is NOT used by the
root-approved deletion worker and does not create or activate filtering rules.
"""
from __future__ import annotations

import re

FIELD_OPTIONS = (
    ("from_address", "From address"),
    ("from_domain", "From domain"),
    ("subject", "Subject"),
    ("reply_to", "Reply-To address"),
    ("return_path", "Return-Path address"),
    ("named_header", "Specific header (enter name below)"),
    ("all_headers", "Any email header (broad; review carefully)"),
    ("click_host", "Clickable link destination (analysis only)"),
)
OPERATORS = (
    ("exact", "Exactly equals"),
    ("contains", "Contains"),
    ("starts", "Starts with"),
    ("ends", "Ends with"),
    ("wildcard", "Wildcard (*)"),
)
HEADER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}\Z")
SENSITIVE_HEADERS = frozenset((
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token",
))


def normalized_headers(message) -> dict[str, list[str]]:
    """Only minimal bounded header values, never raw MIME or message bodies."""
    headers: dict[str, list[str]] = {}
    total = 0
    for key, value in message.raw_items():
        name = key.lower()
        if (not HEADER_NAME.fullmatch(name) or name in SENSITIVE_HEADERS
                or len(headers) >= 64 and name not in headers
                or len(headers.get(name, ())) >= 4):
            continue
        clean = " ".join(str(value).split())[:1024]
        if total + len(clean) > 32768:
            break
        total += len(clean)
        headers.setdefault(name, []).append(clean)
    return headers


def evaluate(samples: list[dict], field: str, operator: str, value: str,
             header_name: str = "") -> dict:
    if not samples or len(samples) > 20:
        raise ValueError("Select between 1 and 20 messages first")
    if field not in dict(FIELD_OPTIONS):
        raise ValueError("Unsupported manual field")
    if operator not in dict(OPERATORS):
        raise ValueError("Unsupported comparison")
    if (not 2 <= len(value.strip()) <= 255
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Enter a valid comparison value (2–255 characters)")
    value = value.strip()
    header = header_name.strip().lower()
    if field == "named_header" and (
            not HEADER_NAME.fullmatch(header) or header in SENSITIVE_HEADERS):
        raise ValueError("Enter a valid non-sensitive email header name")
    if operator == "wildcard" and (
            value.strip("*") == "" or len(value.replace("*", "")) < 2):
        raise ValueError("Wildcard must contain at least two literal characters")
    # Linear-time anchored '*' glob; never compile user-entered regex.
    def wildcard_match(text: str, pattern: str) -> bool:
        i = j = 0
        star = -1
        restart = 0
        while i < len(text):
            if j < len(pattern) and pattern[j] == text[i]:
                i += 1
                j += 1
            elif j < len(pattern) and pattern[j] == "*":
                star = j
                j += 1
                restart = i
            elif star >= 0:
                restart += 1
                i = restart
                j = star + 1
            else:
                return False
        return all(ch == "*" for ch in pattern[j:])

    def matches(candidate: str) -> bool:
        candidate = candidate.casefold()
        target = value.casefold()
        if operator == "exact":
            return candidate == target
        if operator == "contains":
            return target in candidate
        if operator == "starts":
            return candidate.startswith(target)
        if operator == "ends":
            return candidate.endswith(target)
        return wildcard_match(candidate, target)

    matched, missed = [], []
    for sample in samples:
        header_values = sample.get("manual_headers", {})
        sender = sample.get("sender", "")
        if field == "from_address":
            possibilities = [sender]
        elif field == "from_domain":
            possibilities = [sender.rsplit("@", 1)[-1] if "@" in sender else ""]
        elif field == "subject":
            possibilities = [sample.get("subject", "")]
        elif field == "reply_to":
            possibilities = [sample.get("reply_to", "")]
        elif field == "return_path":
            possibilities = [sample.get("return_path", "")]
        elif field == "named_header":
            possibilities = header_values.get(header, [])
        elif field == "all_headers":
            possibilities = [v for name, values in header_values.items()
                             if name not in SENSITIVE_HEADERS for v in values]
        else:
            possibilities = sample.get("click_hosts", [])
        item = {
            "subject": sample.get("subject", "") or "(No subject)",
            "sender": sender or "(Unknown sender)",
            "filename": sample.get("filename", ""),
            "account_label": sample.get("account_label", ""),
        }
        (matched if any(matches(v) for v in possibilities if isinstance(v, str) and v)
         else missed).append(item)
    return {
        "field": field, "field_label": dict(FIELD_OPTIONS)[field],
        "operator": operator, "operator_label": dict(OPERATORS)[operator],
        "value": value, "header_name": header_name.strip() if field == "named_header" else "",
        "count": len(matched), "total": len(samples),
        "matched": matched, "missed": missed,
        "warning": ("Read-only evaluation of email-body links, not a supported live rule."
                    if field == "click_host" else
                    "Broad matching can include legitimate mail; this is not live deletion approval."),
    }
