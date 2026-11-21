"""Conservative, bounded legacy raw-header *evidence* extraction.

The original cleaner's matcher, import_legacy.legacy_matches, is reused
unchanged for candidate coverage: literal, case-insensitive substring search
on raw UTF-8-replaced header text. This module does not modify the live worker.

Never retain or propose every raw header: Microsoft transit/auth metadata,
authentication secrets, recipient headers, DKIM blobs, and arbitrary body
content are excluded. Only a small, short-lived RAM excerpt of uncommon
campaign/sender header fields is used to derive candidate fragments.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .import_legacy import legacy_matches

MAX_EVIDENCE_CHARS = 12000
MAX_SIGNALS_PER_SAMPLE = 160
MAX_CANDIDATES = 90
FIELD_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]{0,79}):[ \t]*(.*)$")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._@:/+-]{7,119}", re.I)
COLON_RE = re.compile(r"[a-z0-9-]{3,32}(?::[a-z0-9-]{3,32}){1,5}", re.I)
DOMAIN_RE = re.compile(r"[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63}){1,4}", re.I)
WORDS_RE = re.compile(r"[a-z0-9][a-z0-9+-]{2,39}", re.I)

ELIGIBLE_NAMES = frozenset((
    "reply-to", "return-path", "feedback-id", "list-id",
    "x-relaying-domain", "x-vmta-source", "x-campaign-id",
))
# Broad infrastructure / authentication / anti-spam classifications cannot
# become candidate deletion markers just because a biased set shares them.
NOISY_PREFIXES = (
    "x-ms-", "x-microsoft-", "x-forefront-", "x-spam-", "x-proofpoint-",
    "x-barracuda-", "x-google-", "x-gm-", "x-originating-", "x-anti-",
)
NOISY_FIELDS = frozenset((
    "received", "authentication-results", "arc-authentication-results",
    "arc-message-signature", "arc-seal", "dkim-signature", "date",
    "message-id", "subject", "mime-version", "content-type",
    "content-transfer-encoding", "to", "cc", "bcc", "delivered-to",
    "x-mailer", "x-priority", "x-sender-ip", "x-spam-score",
    "list-unsubscribe", "list-unsubscribe-post",
))
GENERIC = frozenset((
    "microsoft", "outlook", "google", "gmail", "hotmail", "mail", "smtp",
    "mailchimp", "sendgrid", "amazonses", "mime", "unknown", "pass", "fail",
    "bulk", "newsletter", "marketing", "originating", "authentication",
    "internet", "gateway", "sender", "reply-to", "received", "priority",
    "outlook.com", "hotmail.com", "gmail.com", "google.com",
    "microsoft.com", "office365.com", "googlemail.com",
))
BAD_WORDS = (
    "spf=pass", "dkim=pass", "dmarc=pass", "spf=fail", "dkim=fail",
    "scl:", "gmailapi.google.com", "outlook.office365.com", "localhost",
)


def _field_is_eligible(name: str) -> bool:
    if name in NOISY_FIELDS or name.startswith(NOISY_PREFIXES):
        return False
    return name in ELIGIBLE_NAMES or (
        name.startswith("x-") and any(word in name for word in (
            "campaign", "feedback", "batch", "source", "relay", "tracking",
            "mailing", "job", "mailer-id", "sender-id",
        ))
    )


def raw_evidence(raw_header: bytes) -> bytes:
    """Keep only short original raw header lines (in RAM, no body/headers dump).

    Preserve the source line bytes so legacy_matches has EXACT old-cleaner
    substring semantics on the retained fields, including folding boundaries.
    """
    text = raw_header.decode("utf-8", errors="replace")
    out, size = [], 0
    current = []
    current_name = ""

    def finish():
        nonlocal size
        if not current or not _field_is_eligible(current_name):
            return
        value = "\n".join(current)
        if len(value) > 900 or size + len(value) > MAX_EVIDENCE_CHARS:
            return
        out.append(value)
        size += len(value)

    for line in text.splitlines()[:500]:
        # Header continuation can only belong to an already parsed field.
        if line.startswith((" ", "\t")) and current:
            if len(current) < 5:
                current.append(line)
            continue
        finish()
        current = []
        found = FIELD_RE.match(line)
        if found:
            current_name = found.group(1).lower()
            current = [line]
    finish()
    return ("\r\n".join(out)).encode("utf-8", errors="replace")


def _meaningful(token: str) -> bool:
    token = token.strip("._:+-/ ").lower()
    if not 10 <= len(token) <= 150 or token in GENERIC:
        return False
    if any(bad in token for bad in BAD_WORDS) or token.startswith(("http:", "https:")):
        return False
    if not re.search(r"[a-z]", token):
        return False
    # Require a punctuation-bearing or alphanumeric campaign identifier,
    # or a long multiword literal. Exclude ordinary broad single words.
    return bool(re.search(r"\d", token) or re.search(r"[.@:_+-]", token)
                or len(token.split()) >= 2 and len(token) >= 19)


def _tokens(value: str) -> set[str]:
    """Short, distinctive literal runs, including stable suffixes of IDs.

    Campaigns often rotate the first segment of a Feedback-ID or an
    X-Campaign-ID while keeping the later colon/hyphen components. Extract
    bounded overlapping subruns; final coverage is checked using the exact
    ORIGINAL raw-header substring matcher, never approximate token overlap.
    """
    value = value.lower().strip()
    result = set()
    if 10 <= len(value) <= 140:
        result.add(value)
    for regex in (TOKEN_RE, COLON_RE, DOMAIN_RE):
        for match in regex.finditer(value):
            token = match.group(0).strip("._:+-/ ")
            result.add(token)
            if ":" in token:
                parts = token.split(":")[:8]
                for start in range(len(parts)):
                    for end in range(start + 1, len(parts) + 1):
                        result.add(":".join(parts[start:end]))
            # Distinctive common fragments can sit before or after rotating
            # hyphen-separated IDs. Avoid 1-character and low-information runs.
            if "-" in token:
                parts = token.split("-")[:12]
                for size in (1, 2, 3, 4):
                    for i in range(len(parts) - size + 1):
                        result.add("-".join(parts[i:i + size]))
    words = WORDS_RE.findall(value)[:20]
    for n in (2, 3):
        for i in range(len(words) - n + 1):
            result.add(" ".join(words[i:i + n]))
    return {token for token in result if _meaningful(token)}


def fingerprint_candidates(samples: list[dict]) -> list[dict]:
    """Find confirmed shared legacy-style raw substrings from safe excerpts.

    Header fields from disallowed infrastructure/sensitive categories are
    never considered. The original byte matcher confirms EVERY coverage bit.
    Multiple independent header clues may cover the same sample set; retain
    up to three distinct alternatives instead of hiding all but one.
    """
    if not samples or len(samples) > 20:
        return []
    evidence = [s.get("raw_header_evidence", b"") for s in samples]
    support: dict[str, set[int]] = defaultdict(set)
    origins: dict[str, set[str]] = defaultdict(set)
    for index, raw in enumerate(evidence):
        if not isinstance(raw, bytes) or len(raw) > MAX_EVIDENCE_CHARS * 4:
            continue
        tokens_here = {}
        for line in raw.decode("utf-8", "replace").splitlines():
            found = FIELD_RE.match(line)
            if not found:
                continue
            field = found.group(1).lower()
            if not _field_is_eligible(field):
                continue
            for token in _tokens(found.group(2)):
                tokens_here.setdefault(token, set()).add(field)
        for token in sorted(tokens_here, key=lambda t: (-len(t), t))[:MAX_SIGNALS_PER_SAMPLE]:
            support[token].add(index)
            origins[token].update(tokens_here[token])
    candidates = sorted((token for token, indices in support.items()
                         if len(indices) >= 2),
                        key=lambda t: (-len(support[t]), -len(t), t))[:500]
    result = []
    for pattern in candidates:
        matched = {i for i, raw in enumerate(evidence)
                   if isinstance(raw, bytes) and legacy_matches(raw, pattern)}
        if len(matched) < 2:
            continue
        result.append({
            "kind": "raw_header_contains", "field": "All raw headers",
            "value": pattern, "count": len(matched), "total": len(samples),
            "sample_ids": sorted(matched), "shared": True,
            "source_fields": sorted(origins[pattern])[:4],
            "can_save": True,
            "risk": "Legacy raw-header fragment · review only",
            "explanation": ("Original cleaner parity: literal case-insensitive "
                            "substring of raw headers. A match can occur in ANY "
                            "header, including legitimate mail. Save only as an "
                            "inactive draft, never automatic deletion."),
        })
    by_coverage: dict[tuple[int, ...], list[dict]] = defaultdict(list)
    for item in sorted(result, key=lambda x: (
            -len(x["value"]), -len(x["source_fields"]), x["value"])):
        coverage = tuple(item["sample_ids"])
        kept = by_coverage[coverage]
        # Prefer independently derived clues over a trivial shorter substring
        # of the same header/signature. Preserve at most 3 per coverage set.
        if len(kept) >= 3:
            continue
        if any(item["value"] in previous["value"] and
               set(item["source_fields"]) <= set(previous["source_fields"])
               for previous in kept):
            continue
        kept.append(item)
    return sorted((v for group in by_coverage.values() for v in group),
                  key=lambda x: (-x["count"], -len(x["value"]), x["value"]))[:MAX_CANDIDATES]
