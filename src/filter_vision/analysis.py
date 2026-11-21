"""Bounded offline email evidence analysis; never render or fetch remote content.

Headers produce draftable matching candidates. HTML links are parsed locally,
and their hostnames can be saved as disabled review-only drafts. The live
header-only cleaner cannot delete using HTML link destinations. Message bodies are never retained.
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
from .legacy_fingerprints import raw_evidence, fingerprint_candidates

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
        # Up to 12 KiB of uncommon original raw-header lines only, held
        # in the existing 15-minute bounded RAM cache; no MIME/body retained.
        "raw_header_evidence": raw_evidence(header),
    }


def suggestions(samples: list[dict]) -> list[dict]:
    """Rank shared evidence ahead of one-message guesses.

    Header and link-host candidates can be saved only as inactive drafts.
    Body-link drafts cannot even request enablement. Neither category
    authorizes a destructive action.
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
        "raw_header_contains": ("Legacy raw-header substring · review carefully", True,
                                "Uses the original cleaner's case-insensitive literal "
                                "substring test anywhere in the retained headers. "
                                "A match can include legitimate messages; disabled draft "
                                "only, not deletion approval."),
        "sender_suffix_evidence": ("Broad wildcard · review carefully", False,
                                   "Distinct sender domains share this text ending. "
                                   "This is NOT a common owned parent domain. A wildcard "
                                   "also matches unrelated legitimate domains; "
                                   "analysis-only, not a deletion rule."),
        "click_destination": ("Shared campaign link · review only", True,
                              "HTML body hostname evidence only. The live cleaner "
                              "cannot match or delete using body links."),
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
    rank = {"raw_header_contains": 0, "click_destination": 1,
            "header_contains": 2, "header_exact": 3, "sender_domain": 4,
            "sender_suffix_evidence": 5, "sender_exact": 6, "subject_exact": 7}
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
    result.extend(fingerprint_candidates(samples))
    return sorted(result, key=lambda x: (-x["count"],
                                         rank[x["kind"]], x["value"]))[:160]


def compact_header_plan(samples: list[dict], candidates: list[dict]) -> dict | None:
    """Bounded set-cover optimizer: fewest observed-sample conditions first.

    Coverage is measured against selected *spam samples only*. It is NOT a
    sensitivity/precision estimate, does not imply safety and never changes
    approved live deletion. Exact DP has a memory ceiling; fallback is clearly
    labelled heuristic, not a claim of global optimum.
    """
    if not 1 <= len(samples) <= 20:
        return None
    total = len(samples)
    permitted = {"raw_header_contains", "header_contains", "header_exact",
                 "sender_domain", "sender_exact", "subject_exact"}
    preference = {"header_exact": 1, "header_contains": 2,
                  "sender_exact": 3, "raw_header_contains": 4,
                  "sender_domain": 5, "subject_exact": 7}
    # A candidate set is valid only when the offline detector itself found
    # it in the selected sample, and it passes the ordinary disabled-draft
    # validator. No linked-body or speculative wildcard candidate enters.
    by_mask = {}
    for cand in candidates:
        if cand["kind"] not in permitted or not cand.get("can_save"):
            continue
        try:
            validate_rule(cand["kind"], cand["field"], cand["value"])
        except ValueError:
            continue
        indices = cand.get("sample_ids", [])
        if not all(isinstance(i, int) and 0 <= i < total for i in indices):
            continue
        mask = sum(1 << i for i in set(indices))
        if not mask:
            continue
        score = (preference[cand["kind"]], -len(cand["value"]), cand["value"])
        if mask not in by_mask or score < by_mask[mask][0]:
            by_mask[mask] = (score, cand)
    if not by_mask:
        return None
    all_masks = sorted(((mask, item) for mask, (_, item) in by_mask.items()),
                       key=lambda x: (-x[0].bit_count(), preference[x[1]["kind"]],
                                      -len(x[1]["value"]), x[1]["value"]))
    max_covered = 0
    for mask, _ in all_masks:
        max_covered |= mask

    # Prefer an optimal number of rules if we can explore all reachable
    # coverage masks under a bounded 16K-state limit.
    frontier = {0: (0, 0, ())}
    complete = True
    for i, (mask, cand) in enumerate(all_masks):
        snapshot = list(frontier.items())
        if len(snapshot) > 16000:
            complete = False
            break
        for previous, (count, risk, path) in snapshot:
            next_mask = previous | mask
            if next_mask == previous:
                continue
            option = (count + 1, risk + preference[cand["kind"]], path + (i,))
            if next_mask not in frontier or option[:2] < frontier[next_mask][:2]:
                frontier[next_mask] = option
    if complete and max_covered in frontier:
        path = frontier[max_covered][2]
    else:
        # Deterministic bounded greedy fallback; no unsupported optimality claim.
        uncovered = max_covered
        path = []
        while uncovered:
            options = [(int((mask & uncovered).bit_count()), -preference[cand["kind"]],
                        len(cand["value"]), -i, i)
                       for i, (mask, cand) in enumerate(all_masks)
                       if mask & uncovered]
            if not options:
                break
            index = max(options)[-1]
            path.append(index)
            uncovered &= ~all_masks[index][0]
        complete = False
    selected = [all_masks[i][1] for i in path]
    covered = 0
    for i in path:
        covered |= all_masks[i][0]
    return {
        "name": "Fewest header conditions found",
        "kind": "compact",
        "items": [{
            "kind": c["kind"], "field": c["field"], "value": c["value"],
            "count": c["count"], "sample_ids": c["sample_ids"],
        } for c in selected],
        "total": total, "count": covered.bit_count(),
        "missed": total - covered.bit_count(),
        "sample_ids": [i for i in range(total) if covered & (1 << i)],
        "exact": complete,
        "warning": (
            "Exact minimum among the generated valid candidates for these selected "
            "messages; not a false-positive safety assessment. Each rule is an "
            "independent, disabled, unscoped draft. Legacy raw-header fragments "
            "can match in ANY email header, including unrelated mail."
            if complete else
            "Bounded coverage heuristic: a compact combination, not a proven "
            "minimum. Test against legitimate mail before considering any "
            "future separately approved live rule."),
    }


def coverage_options(samples: list[dict]) -> list[dict]:
    """Show alternative header-only *draft* strategies, not spam verdicts.

    The small selected sample is not a legitimate-mail control set. Covering
    every selected email is not evidence the resulting rule set is safe.
    We deliberately make no changes to the protected live matcher.
    """
    if not samples:
        return []
    total = len(samples)
    options = []
    optimized = compact_header_plan(samples, suggestions(samples))
    if optimized:
        options.append(optimized)
    for kind, name, warning in (
        ("sender_domain", "Exact sender-domain combination",
         "Covers every sender on each listed exact domain, including potentially "
         "legitimate mail. Review scope and benign examples before approval."),
        ("sender_exact", "Exact sender-address combination",
         "Narrower than entire domains, but rotating addresses may evade the "
         "conditions. These are inactive drafts, not active filters."),
    ):
        groups: dict[str, set[int]] = defaultdict(set)
        for i, sample in enumerate(samples):
            sender = sample.get("sender", "").lower()
            value = sender.rsplit("@", 1)[-1] if kind == "sender_domain" and "@" in sender else sender
            try:
                validate_rule(kind, "From", value)
            except ValueError:
                continue
            groups[value].add(i)
        if not groups:
            continue
        items = [{
            "kind": kind, "field": "From", "value": value,
            "count": len(indices), "sample_ids": sorted(indices),
        } for value, indices in sorted(groups.items(),
                                        key=lambda pair: (-len(pair[1]), pair[0]))]
        matched = set().union(*groups.values())
        options.append({
            "name": name, "kind": kind, "items": items,
            "total": total, "count": len(matched), "missed": total - len(matched),
            "warning": warning, "sample_ids": sorted(matched),
        })
    return options


def validate_rule(kind: str, field: str, value: str) -> str:
    allowed = {
        "raw_header_contains": {"All raw headers"},
        "sender_exact": {"From"}, "sender_domain": {"From"},
        "header_exact": {"X-VMTA-Source", "X-Relaying-Domain"},
        "header_contains": {"Feedback-ID"}, "subject_exact": {"Subject"},
    }
    value = value.strip()
    if kind == "custom_raw_header":
        if (field != "All raw headers" or not 8 <= len(value) <= 255
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ValueError("Invalid legacy-compatible raw-header signature")
        return value
    if kind == "click_destination":
        if field != "HTML click destination":
            raise ValueError("Unsupported rule type/field")
        if (not 4 <= len(value) <= 253
                or any(ord(char) < 33 or ord(char) > 126 for char in value)
                or "*" in value or "/" in value or ":" in value
                or _destination_host("https://" + value) != value.lower()):
            raise ValueError("Invalid HTML click hostname for review-only draft")
        return value.lower()
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
    if kind == "raw_header_contains":
        from .legacy_fingerprints import _meaningful
        if len(value) > 150 or not _meaningful(value):
            raise ValueError("Raw-header fragment too broad for a review-only draft")
    return value
