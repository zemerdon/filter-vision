"""Read-only IMAP preview using exact legacy header match semantics."""
from __future__ import annotations

import imaplib
import ssl

from .import_legacy import legacy_matches

MAX_MESSAGES = 1000


class PreviewError(RuntimeError):
    pass


def _raw_headers(data):
    for item in data or ():
        if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes):
            return item[1]
    return None


def scan_junk_preview(email: str, folder: str, signatures: list[dict],
                      access_token: str, connector=None) -> dict:
    if folder != "Junk":
        raise PreviewError("Only the verified legacy Junk folder may be previewed")
    if not signatures:
        raise PreviewError("No scoped legacy signatures available")
    if any(r.get("kind") != "legacy_raw_header" for r in signatures):
        raise PreviewError("Unsupported rule type in the legacy preview")
    if connector is None:
        connection = imaplib.IMAP4_SSL(
            "outlook.office365.com", 993,
            ssl_context=ssl.create_default_context(), timeout=20,
        )
    else:
        connection = connector()
    inspected = matched = 0
    by_rule = {int(r["id"]): 0 for r in signatures}
    try:
        auth = f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode()
        kind, _ = connection.authenticate("XOAUTH2", lambda _: auth)
        if kind != "OK":
            raise PreviewError("IMAP authentication rejected")
        kind, _ = connection.select(folder, readonly=True)
        if kind != "OK":
            raise PreviewError("Could not open Junk read-only")
        kind, response = connection.uid("SEARCH", None, "ALL")
        if kind != "OK":
            raise PreviewError("Could not list Junk UIDs")
        uids = response[0].split() if response and response[0] else []
        truncated = len(uids) > MAX_MESSAGES
        # Most recent IMAP UIDs are checked first in bounded previews.
        for uid in uids[-MAX_MESSAGES:]:
            if not isinstance(uid, bytes) or not uid.isdigit():
                raise PreviewError("Unexpected UID returned by IMAP server")
            kind, data = connection.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
            if kind != "OK":
                raise PreviewError("Header fetch failed during read-only preview")
            raw = _raw_headers(data)
            if not raw:
                continue
            inspected += 1
            this_message = False
            for rule in signatures:
                if legacy_matches(raw, rule["pattern"]):
                    by_rule[int(rule["id"])] += 1
                    this_message = True
            if this_message:
                matched += 1
        return {
            "total_junk_uids": len(uids),
            "examined": inspected,
            "matched": matched,
            "truncated": truncated,
            "per_rule_matches": by_rule,
        }
    except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
        raise PreviewError("Read-only IMAP preview failed") from None
    finally:
        try:
            connection.logout()
        except Exception:
            pass
