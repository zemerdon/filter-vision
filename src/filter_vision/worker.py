"""Account-isolated, strictly read-only legacy-rule dry-run.

No mailbox mutation APIs, enabled-account transitions, or background timer.
A future live worker must be separately reviewed and authorized.
"""
from __future__ import annotations

import argparse
import fcntl
import imaplib
import json
import os
import re
import ssl
from pathlib import Path

from .import_legacy import legacy_matches
from .oauth import OAuthError, TokenVault, access_token_for
from .storage import Store

MAX_SCAN_UIDS = 1000
MAX_HEADER_BYTES = 256 * 1024


class DryRunError(RuntimeError):
    pass


def _uid_validity(connection) -> int:
    kind, raw = connection.response("UIDVALIDITY")
    if kind != "UIDVALIDITY" or not raw:
        raise DryRunError("Server omitted UIDVALIDITY; scan halted")
    value = raw[0]
    if isinstance(value, bytes):
        value = value.decode("ascii", "strict")
    if not str(value).isdigit() or int(value) <= 0:
        raise DryRunError("Server returned invalid UIDVALIDITY")
    return int(value)


def _header_bytes(raw) -> bytes:
    if not isinstance(raw, (tuple, list)):
        raise DryRunError("Invalid IMAP FETCH response")
    headers = [entry[1] for entry in raw if isinstance(entry, tuple)
               and len(entry) > 1 and isinstance(entry[1], bytes)]
    if len(headers) != 1 or len(headers[0]) > MAX_HEADER_BYTES:
        raise DryRunError("Ambiguous or oversized header response")
    return headers[0]


def preview_connection(connection, account_id: int, folder: str,
                       rules: list[dict], max_uids: int = MAX_SCAN_UIDS) -> dict:
    """Called *after* authenticated connection. Only readonly and BODY.PEEK used."""
    if folder != "Junk":
        raise DryRunError("Imported dry-run scope is Junk only")
    if not 1 <= max_uids <= MAX_SCAN_UIDS:
        raise DryRunError("Invalid bounded scan limit")
    if not rules or any(r["kind"] != "legacy_raw_header" for r in rules):
        raise DryRunError("No supported exact-match legacy rules")
    if len({int(r["id"]) for r in rules}) != len(rules):
        raise DryRunError("Duplicate rule identifiers")
    if any(not isinstance(r["pattern"], str) or not r["pattern"]
           for r in rules):
        raise DryRunError("Invalid legacy rule pattern")
    kind, _ = connection.select(folder, readonly=True)
    if kind != "OK":
        raise DryRunError("IMAP refused read-only Junk selection")
    validity = _uid_validity(connection)
    kind, result = connection.uid("SEARCH", None, "ALL")
    if kind != "OK" or not result or not isinstance(result[0], bytes):
        raise DryRunError("IMAP UID search failed")
    uids = result[0].split()
    if any(not uid.isdigit() or int(uid) <= 0 for uid in uids):
        raise DryRunError("IMAP returned invalid UID")
    if uids != sorted(set(uids), key=lambda uid: int(uid)):
        raise DryRunError("IMAP UID search was not strictly increasing")
    total = len(uids)
    selected = uids[-max_uids:]
    hits = {int(r["id"]): 0 for r in rules}
    matched = 0
    examined = 0
    for uid in selected:
        kind, raw = connection.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
        if kind != "OK":
            raise DryRunError("IMAP header fetch failed")
        raw_header = _header_bytes(raw)
        examined += 1
        any_hit = False
        for rule in rules:
            if legacy_matches(raw_header, rule["pattern"]):
                hits[int(rule["id"])] += 1
                any_hit = True
        matched += int(any_hit)
    return {
        "account_id": account_id,
        "folder": folder,
        "uidvalidity_present": validity > 0,
        "total": total,
        "examined": examined,
        "matched": matched,
        "truncated": total > max_uids,
        "per_rule_hits": hits,
        "action": "read_only",
    }


def run_account_dry_run(store: Store, account_id: int, connector=None,
                        max_uids: int = MAX_SCAN_UIDS) -> dict:
    if not isinstance(account_id, int) or account_id <= 0:
        raise DryRunError("Invalid account")
    with store.db() as db:
        row = db.execute(
            "SELECT id,username,provider,folder,enabled FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
        rules = [dict(r) for r in db.execute(
            "SELECT r.id,r.kind,r.pattern FROM rules r "
            "JOIN rule_scopes s ON s.rule_id=r.id WHERE s.account_id=? "
            "AND r.kind='legacy_raw_header' ORDER BY r.id", (account_id,),
        )]
    if not row or row["provider"] != "outlook" or row["folder"] != "Junk":
        raise DryRunError("Unsupported or missing imported Microsoft account")
    if row["enabled"] != 0:
        raise DryRunError("Dry-run requires account scanning to remain disabled")
    vault = TokenVault(store.directory)
    if not vault.connected(account_id):
        raise DryRunError("Account has not completed Microsoft authorization")
    lock_dir = store.directory / "scan-locks"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(lock_dir, 0o700)
    fd = os.open(lock_dir / f"account-{account_id}.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DryRunError("A scan is already running for this account") from None
        token = access_token_for(account_id, row["username"], vault)
        if connector is None:
            connection = imaplib.IMAP4_SSL(
                "outlook.office365.com", 993,
                ssl_context=ssl.create_default_context(), timeout=20,
            )
        else:
            connection = connector()
        try:
            payload = f"user={row['username']}\x01auth=Bearer {token}\x01\x01".encode()
            kind, _ = connection.authenticate("XOAUTH2", lambda _: payload)
            if kind != "OK":
                raise DryRunError("Microsoft IMAP authentication was rejected")
            report = preview_connection(connection, account_id, row["folder"], rules, max_uids)
        except (imaplib.IMAP4.error, TimeoutError, OSError):
            raise DryRunError("Outlook IMAP dry-run authentication or network failure") from None
        finally:
            try:
                connection.logout()
            except Exception:
                pass
        store.audit("safe_dry_run",
                    f"account_id={account_id} total={report['total']} "
                    f"examined={report['examined']} matched={report['matched']} "
                    f"partial={int(report['truncated'])}")
        return report
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Read-only Microsoft Junk dry-run")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--account-id", type=int, required=True)
    parser.add_argument("--max-uids", type=int, default=MAX_SCAN_UIDS)
    args = parser.parse_args()
    result = run_account_dry_run(Store(args.data_dir), args.account_id, max_uids=args.max_uids)
    # Only aggregate counts and rule IDs. Never messages/headers/tokens.
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
