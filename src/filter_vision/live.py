"""Explicitly gated, legacy-parity, UID-specific Microsoft Junk cleaner.

Never blanket-expunge. The original 22 legacy signatures remain immutable.
Only separate, explicit root-owned per-account approvals may add custom matchers.
A verified old-cleaner-offline marker remains mandatory.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import imaplib
import json
import os
import ssl
import stat
from pathlib import Path

from .import_legacy import legacy_matches
from .live_matching import matches as match_custom, bounded_full_message, MatchError
from .history import MAX_CAPTURE_BYTES, safe_email_preview
from .oauth import TokenVault, access_token_for
from .storage import Store
from .worker import DryRunError, _uid_validity, _header_bytes

DEFAULT_POLICY = Path("/etc/filter-vision/cleaner-policy.json")
DEFAULT_OFFLINE_MARKER = Path("/etc/filter-vision/legacy-offline")
LEGACY_SOURCE_SHA = "947fc4437a737b5ae217bd26e6e4a3df096edce8aa0bc7911705158d890c38e7"
MAX_LIVE_MESSAGES = 1000


class LiveSafetyError(RuntimeError):
    pass


def rules_digest(rules: list[dict]) -> str:
    fields = sorted((int(r["id"]), str(r["pattern"])) for r in rules)
    return hashlib.sha256(json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _root_only(path: Path, required: bool) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise LiveSafetyError("Required cutover approval or policy is missing")
    state = path.stat()
    if required and (state.st_uid != 0 or state.st_mode & 0o022):
        raise LiveSafetyError("Cutover approval must be managed by root")
    if state.st_size > 4096:
        raise LiveSafetyError("Invalid oversized cutover policy")
    return path.read_bytes()


def load_policy(policy_path=DEFAULT_POLICY, marker=DEFAULT_OFFLINE_MARKER,
                require_root=True) -> dict:
    p = json.loads(_root_only(Path(policy_path), require_root))
    if (not isinstance(p, dict) or set(p) !=
            {"schema", "enabled", "legacy_sha256", "rules_sha256", "accounts"}):
        raise LiveSafetyError("Invalid live filtering policy")
    if p["schema"] != 1 or p["enabled"] is not True:
        raise LiveSafetyError("Live filtering not approved")
    if p["legacy_sha256"] != LEGACY_SOURCE_SHA:
        raise LiveSafetyError("Legacy source verification mismatch")
    if (not isinstance(p["rules_sha256"], str) or len(p["rules_sha256"]) != 64
            or not all(c in "0123456789abcdef" for c in p["rules_sha256"])):
        raise LiveSafetyError("Invalid rule approval digest")
    if (not isinstance(p["accounts"], list) or not p["accounts"]
            or len(p["accounts"]) > 2 or len(set(p["accounts"])) != len(p["accounts"])
            or any(not isinstance(i, int) or i not in (1, 2) for i in p["accounts"])):
        raise LiveSafetyError("Account allowlist is invalid")
    if _root_only(Path(marker), require_root).strip() != b"LEGACY_STOPPED_VERIFIED":
        raise LiveSafetyError("Old cleaner stop has not been verified")
    return p


def _active_rules(store: Store, account_id: int, policy: dict,
                  *, include_extra: bool = True, extra_policy_path=None,
                  extra_require_root: bool = True):
    with store.db() as c:
        row = c.execute("SELECT id,username,provider,host,port,folder,interval_minutes,enabled "
                        "FROM accounts WHERE id=?", (account_id,)).fetchone()
        all_rules = [dict(x) for x in c.execute(
            "SELECT id,kind,pattern,enabled,action FROM rules ORDER BY id")]
        scoped = [dict(x) for x in c.execute(
            "SELECT r.id,r.kind,r.pattern FROM rules r JOIN rule_scopes s ON r.id=s.rule_id "
            "WHERE s.account_id=? ORDER BY r.id", (account_id,))]
        refs = c.execute("SELECT COUNT(*) FROM rule_scopes").fetchone()[0]
        imported = c.execute("SELECT source_sha256, account_count, rule_count "
                             "FROM legacy_imports").fetchall()
        accounts = c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    # Only the 22 original imported raw-header signatures are root-approved.
    # New disabled, unscoped analysis drafts must neither join that digest
    # nor suspend the already-approved cleaner merely by existing in SQLite.
    approved = [r for r in all_rules if r["kind"] == "legacy_raw_header"]
    if not row or account_id not in policy["accounts"]:
        raise LiveSafetyError("Account not approved for live filtering")
    if (row["provider"], row["host"], row["port"], row["folder"],
            row["interval_minutes"], row["enabled"]) != (
                "outlook", "outlook.office365.com", 993, "Junk", 30, 0):
        raise LiveSafetyError("Imported account settings have changed")
    if accounts != 2 or refs != 44 or len(approved) != 22 or len(scoped) != 22:
        raise LiveSafetyError("Legacy account/rule scope count changed")
    if (len(imported) != 1 or imported[0]["source_sha256"] != LEGACY_SOURCE_SHA
            or imported[0]["account_count"] != 2 or imported[0]["rule_count"] != 22):
        raise LiveSafetyError("Legacy import identity changed")
    if any(r["enabled"] != 0 or r["action"] != "draft" for r in all_rules):
        raise LiveSafetyError("Unexpected active or unsupported rule")
    if any(not r["pattern"] for r in approved):
        raise LiveSafetyError("Empty approved legacy signature")
    if rules_digest(approved) != policy["rules_sha256"]:
        raise LiveSafetyError("Rule signatures changed since approval")
    # Scopes still must match EXACTLY the frozen 22 approved signatures;
    # additional drafts are not allowed to join either account's live rules.
    if set(r["id"] for r in scoped) != set(r["id"] for r in approved):
        raise LiveSafetyError("Account scope mismatches approved legacy rules")
    if include_extra:
        # Validate immutable imported originals and 44 scopes ABOVE before
        # using root-owned, recoverable per-rule overrides for effective
        # enable/disable/edit operations. Neither file is writable by WebUI.
        from .rule_activation import active_rules, ActivationError, EXTRA_POLICY
        from .managed_rules import effective_legacy, ManagedError
        try:
            effective_originals = effective_legacy(
                scoped, store, account_id, require_root=extra_require_root)
            extra = active_rules(
                store, account_id,
                path=EXTRA_POLICY if extra_policy_path is None else extra_policy_path,
                require_root=extra_require_root)
        except (ActivationError, ManagedError):
            raise LiveSafetyError("Managed rule approval invalid; refusing live scan") from None
        return dict(row), effective_originals + extra
    return dict(row), scoped


def _scan_live(conn, account_id: int, rules: list[dict], journal=None) -> dict:
    caps = {v.decode("ascii", "ignore").upper() if isinstance(v, bytes) else str(v).upper()
            for v in conn.capabilities}
    if "UIDPLUS" not in caps:
        raise LiveSafetyError("Server does not advertise UIDPLUS; refusing delete")
    kind, _ = conn.select("Junk", readonly=False)
    if kind != "OK":
        raise LiveSafetyError("Cannot select Junk for legacy cleaning")
    try:
        _uid_validity(conn)
    except DryRunError:
        raise LiveSafetyError("UIDVALIDITY unavailable; refusing delete") from None
    kind, response = conn.uid("SEARCH", None, "ALL")
    if kind != "OK" or not response or not isinstance(response[0], bytes):
        raise LiveSafetyError("IMAP UID search failed")
    uids = response[0].split()
    if any(not uid.isdigit() or int(uid) <= 0 for uid in uids):
        raise LiveSafetyError("Unexpected IMAP UID")
    if uids != sorted(set(uids), key=lambda x: int(x)):
        raise LiveSafetyError("Nonmonotonic or duplicate IMAP UID sequence")
    if len(uids) > MAX_LIVE_MESSAGES:
        raise LiveSafetyError("Too many messages for complete bounded live scan")
    result = {"account_id": account_id, "examined": 0, "matched": 0,
              "deleted": 0, "total": len(uids)}
    for uid in uids:
        kind, raw = conn.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
        if kind != "OK":
            raise LiveSafetyError("Could not fetch message header; scan halted")
        header = _header_bytes(raw)
        matched = []
        need_body = any(r["kind"] == "click_destination" for r in rules)
        for rule in rules:
            if rule["kind"] == "click_destination":
                continue
            try:
                if match_custom(rule, header):
                    matched.append(rule["id"])
            except MatchError:
                raise LiveSafetyError("Approved header matcher failed closed") from None
        complete_body = None
        if need_body and not matched:
            try:
                complete_body = bounded_full_message(conn, uid)
                if complete_body is not None:
                    for rule in rules:
                        if rule["kind"] == "click_destination" and match_custom(
                                rule, header, complete_body):
                            matched.append(rule["id"])
            except MatchError:
                raise LiveSafetyError("Approved HTML destination check failed closed") from None
        result["examined"] += 1
        if not matched:
            continue
        result["matched"] += 1
        # UIDVALIDITY is established on SELECT. IMAP4.response() consumes
        # the cached untagged response, so it must not be read a second
        # time. We never reselect/close this mailbox during the scan.
        # Revalidate exact UID content immediately before any mutation.
        kind, verify = conn.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
        if kind != "OK" or _header_bytes(verify) != header:
            raise LiveSafetyError("Message headers changed; refusing delete")
        if complete_body is not None:
            # Body-based deletion requires a second *complete*, unchanged
            # bounded MIME fetch immediately before the UID mutation.
            try:
                second = bounded_full_message(conn, uid)
            except MatchError:
                raise LiveSafetyError("Cannot recheck HTML body; refusing delete") from None
            if second is None or hashlib.sha256(second).digest() != hashlib.sha256(
                    complete_body).digest():
                raise LiveSafetyError("Message body changed; refusing deletion")
        # Capture a small, non-executable text preview for expandable Activity.
        # Persist an encrypted pending record BEFORE any deletion, so a failed
        # persistence/preview request cannot result in unlogged destruction.
        action_id = None
        if journal is not None:
            kind, source = conn.uid("FETCH", uid, f"(BODY.PEEK[]<0.{MAX_CAPTURE_BYTES}>)")
            if kind != "OK":
                raise LiveSafetyError("Bounded message preview failed; refusing delete")
            try:
                preview = safe_email_preview(header, _header_bytes(source))
                action_id = journal.record_pending_action(
                    account_id, int(uid), matched, preview)
            except (ValueError, TypeError, OSError):
                raise LiveSafetyError("Cannot securely record matched message; refusing delete") from None
        kind, _ = conn.uid("STORE", uid, "+FLAGS.SILENT", r"(\Deleted)")
        if kind != "OK":
            raise LiveSafetyError("UID-specific Deleted flag failed")
        kind, _ = conn.uid("EXPUNGE", uid)
        if kind != "OK":
            raise LiveSafetyError("UID-specific EXPUNGE failed")
        if action_id is not None:
            journal.mark_action_deleted(action_id)
        result["deleted"] += 1
    return result


def run_live_account(store: Store, account_id: int, connector=None,
                     policy_path=DEFAULT_POLICY, marker=DEFAULT_OFFLINE_MARKER,
                     require_root=True) -> dict:
    # Two files must be *owned by root* for runtime deletion approval.
    policy = load_policy(policy_path, marker, require_root)
    account, rules = _active_rules(store, account_id, policy)
    vault = TokenVault(store.directory)
    if not vault.connected(account_id):
        raise LiveSafetyError("Microsoft account is not authorized")
    locks = store.directory / "scan-locks"
    locks.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(locks / f"account-{account_id}.lock",
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LiveSafetyError("Account scanner already running") from None
        token = access_token_for(account_id, account["username"], vault)
        conn = (connector() if connector else
                imaplib.IMAP4_SSL("outlook.office365.com", 993,
                                  ssl_context=ssl.create_default_context(), timeout=20))
        try:
            payload = f"user={account['username']}\x01auth=Bearer {token}\x01\x01".encode()
            kind, _ = conn.authenticate("XOAUTH2", lambda _: payload)
            if kind != "OK":
                raise LiveSafetyError("Microsoft IMAP authentication rejected")
            result = _scan_live(conn, account_id, rules, journal=store)
        finally:
            # IMAP CLOSE would expunge flagged messages; never use it.
            try: conn.logout()
            except Exception: pass
        store.audit("live_scan", "account_id=%d inspected=%d matched=%d deleted=%d" %
                    (account_id, result["examined"], result["matched"], result["deleted"]))
        return result
    except Exception as e:
        store.audit("live_scan_failed", "account_id=%d stage=%s" % (account_id, type(e).__name__))
        raise
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Approved legacy-compatible Junk cleaner")
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--account", type=int, choices=(1, 2), help="One approved account")
    args = parser.parse_args()
    store = Store(args.data_dir)
    if args.account:
        ids = [args.account]
    else:
        ids = load_policy()["accounts"]
    failures = []
    for account_id in ids:
        try:
            report = run_live_account(store, account_id)
            # Aggregate counts only, no message subjects or token values.
            print(json.dumps(report, sort_keys=True))
        except Exception as exc:
            failures.append(account_id)
            print(json.dumps({"account_id": account_id, "result": "failed",
                              "class": type(exc).__name__}))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
