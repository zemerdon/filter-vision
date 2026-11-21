"""Automatic bounded read-only Junk preview preceding a one-click rule enable.

Only aggregate counts are returned; no email content or UID is stored.
The preview has no side effects on the mailbox.
"""
from __future__ import annotations

import imaplib
import re

from .junk_browse import _connect, _close, _headers, BrowseError
from .live_matching import bounded_full_message, matches, MatchError
from .oauth import access_token_for, OAuthError
from .rule_activation import SUPPORTED
from .analysis import validate_rule
from .managed_rules import normalize, ManagedError

MAX_PREVIEW_PER_ACCOUNT = 20


class ApprovalPreviewError(RuntimeError):
    pass


def preview_rule(store, rule: dict, account_ids: list[int], vault,
                 *, connector=None) -> list[dict]:
    if rule["kind"] not in SUPPORTED and rule["kind"] != "legacy_raw_header":
        raise ApprovalPreviewError("Unsupported rule")
    try:
        if rule["kind"] in ("legacy_raw_header", "custom_raw_header"):
            normalize(rule["kind"], rule["field"], rule["pattern"],
                      rule.get("label", "Raw header match"))
        else:
            validate_rule(rule["kind"], rule["field"], rule["pattern"])
    except (ValueError, ManagedError):
        raise ApprovalPreviewError("Invalid rule matcher") from None
    if (not account_ids or len(account_ids) > 2
            or len(set(account_ids)) != len(account_ids)
            or any(type(i) is not int or i not in (1, 2) for i in account_ids)):
        raise ApprovalPreviewError("Invalid account selection")
    with store.db() as con:
        accounts = {
            row["id"]: dict(row) for row in con.execute(
                "SELECT id,label,provider,host,port,username,folder FROM accounts "
                "WHERE id IN (" + ",".join("?" for _ in account_ids) + ")", account_ids)}
    if set(accounts) != set(account_ids):
        raise ApprovalPreviewError("Selected account no longer exists")
    outcome = []
    for account_id in account_ids:
        acc = accounts[account_id]
        if (acc["provider"], acc["host"], acc["port"], acc["folder"]) != (
                "outlook", "outlook.office365.com", 993, "Junk"):
            raise ApprovalPreviewError("Only Outlook Junk is supported")
        connection = None
        try:
            token = access_token_for(account_id, acc["username"], vault)
            connection, _ = _connect(acc["username"], token, connector)
            kind, result = connection.uid("SEARCH", None, "ALL")
            if kind != "OK" or not result or not isinstance(result[0], bytes):
                raise ApprovalPreviewError("Read-only Junk preview unavailable")
            uids = result[0].split()
            if any(not re.fullmatch(rb"[1-9][0-9]{0,18}", uid) for uid in uids):
                raise ApprovalPreviewError("Invalid Junk UID")
            subset = uids[-MAX_PREVIEW_PER_ACCOUNT:]
            matches_count = oversized = 0
            for uid in subset:
                header = _headers(uid, connection)
                body = None
                if rule["kind"] == "click_destination":
                    body = bounded_full_message(connection, uid)
                    if body is None:
                        oversized += 1
                if matches(rule, header, body):
                    matches_count += 1
            outcome.append({
                "account_id": account_id,
                "examined": len(subset), "matched": matches_count,
                "truncated": len(uids) > len(subset),
                "oversized": oversized,
            })
        except (OAuthError, BrowseError, MatchError, ApprovalPreviewError,
                imaplib.IMAP4.error, OSError, TimeoutError, ValueError, TypeError):
            raise ApprovalPreviewError("Automatic Junk preview failed; rule unchanged") from None
        finally:
            if connection is not None:
                _close(connection)
    return outcome
