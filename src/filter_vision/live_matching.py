"""Bounded live matching for explicitly root-approved nonlegacy Junk rules.

Never renders or follows message links. Body-host matches require a complete
MIME message no larger than 2 MiB, and are only considered in Junk. The raw
legacy signature matching is still handled exactly as before in live.py.
"""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesHeaderParser
from email.utils import parseaddr

from .analysis import _click_destinations, MAX_FILE_BYTES
from .import_legacy import legacy_matches



class MatchError(RuntimeError):
    pass


def matches(rule: dict, header: bytes, full_message: bytes | None = None) -> bool:
    kind = rule["kind"]
    value = str(rule["pattern"]).casefold()
    if kind in ("legacy_raw_header", "raw_header_contains", "custom_raw_header"):
        return legacy_matches(header, rule["pattern"])
    if kind == "click_destination":
        return bool(full_message and value in _click_destinations(full_message))
    try:
        msg = BytesHeaderParser(policy=policy.default).parsebytes(header+b"\r\n\r\n")
        if len(msg.defects) > 10:
            raise MatchError("Malformed mail headers")
        if kind in ("sender_exact", "sender_domain"):
            sender = parseaddr(str(msg.get("From", "")))[1].lower()
            if kind == "sender_exact":
                return sender.casefold() == value
            return "@" in sender and sender.rsplit("@", 1)[-1].casefold() == value
        if kind == "subject_exact":
            return str(msg.get("Subject", "")).strip().casefold() == value
        if kind in ("header_exact", "header_contains"):
            contents = msg.get_all(rule["field"], [])
            if kind == "header_exact":
                return any(str(h).strip().casefold() == value for h in contents)
            return any(value in str(h).casefold() for h in contents)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise MatchError("Cannot safely evaluate approved header matcher") from None
    raise MatchError("Unsupported live rule kind")


def bounded_full_message(conn, uid: bytes) -> bytes | None:
    """Read a COMPLETE message with BODY.PEEK, limited to 2 MiB.

    Oversized messages are nonmatches for body rules (not deletion candidates).
    A malformed/partial IMAP response instead halts the scan, never deletes.
    """
    kind, result = conn.uid("FETCH", uid, "(RFC822.SIZE)")
    if kind != "OK" or not result:
        raise MatchError("Cannot verify candidate email size")
    metadata = b" ".join(
        item if isinstance(item, bytes) else item[0]
        for item in result
        if isinstance(item, bytes) or
        (isinstance(item, tuple) and item and isinstance(item[0], bytes))
    )
    sizes = re.findall(rb"RFC822\.SIZE\s+([0-9]+)", metadata, re.I)
    if len(sizes) != 1:
        raise MatchError("Ambiguous candidate email size")
    size = int(sizes[0])
    if size <= 0:
        raise MatchError("Empty candidate message")
    if size > MAX_FILE_BYTES:
        return None
    kind, response = conn.uid("FETCH", uid, f"(BODY.PEEK[]<0.{size + 1}>)")
    if kind != "OK":
        raise MatchError("Bounded candidate email fetch failed")
    # Full MIME payloads may be as large as 2 MiB; the *header-only*
    # helper has a 256 KiB cap and must not be used for body bytes.
    if not isinstance(response, (tuple, list)):
        raise MatchError("Invalid complete MIME response")
    fragments = [entry[1] for entry in response
                 if isinstance(entry, tuple) and len(entry) >= 2
                 and isinstance(entry[1], bytes)]
    if len(fragments) != 1 or len(fragments[0]) > MAX_FILE_BYTES:
        raise MatchError("Ambiguous or oversized complete MIME response")
    payload = fragments[0]
    # RFC822.SIZE is not always an exact count of the bytes Outlook returns
    # for BODY.PEEK[] (we observed this on an actual connected Junk message).
    # IMAP partial-fetch semantics say that a response shorter than the
    # requested size has reached EOF; request one byte PAST the declared
    # length, then independently re-fetch/hash the same payload before any
    # UID STORE/EXPUNGE. Never accept a full-width capped response, which
    # could instead be a truncated MIME part.
    if not payload or len(payload) > MAX_FILE_BYTES or len(payload) >= size + 1:
        raise MatchError("Unverifiable bounded MIME response")
    return payload
