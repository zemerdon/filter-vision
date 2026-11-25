"""Root-gated per-account custom rule approvals, separate from frozen legacy policy.

Browser processes cannot write the root-owned approval file. The systemd
control helper takes a fully validated fixed-schema request, re-reads the
source draft and its SHA256, and atomically updates a separate root approval
file. The original 22-rule legacy policy and 44 scopes never change.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from pathlib import Path

from .analysis import validate_rule
from .live import LEGACY_SOURCE_SHA, LiveSafetyError, load_policy

EXTRA_POLICY = Path("/etc/filter-vision/extra-rule-approvals.json")
SUPPORTED = frozenset((
    "click_destination", "raw_header_contains", "sender_exact",
    "sender_domain", "header_exact", "header_contains", "subject_exact",
    "custom_raw_header",
))
MAX_APPROVALS = 64
MAX_FILE_BYTES = 16384
HEX = re.compile(r"^[a-f0-9]{64}$")


class ActivationError(RuntimeError):
    pass


def source_digest(rule: dict) -> str:
    keys = ("id", "kind", "field", "pattern")
    if any(key not in rule for key in keys):
        raise ActivationError("Incomplete rule")
    data = json.dumps([rule[k] for k in keys], ensure_ascii=False,
                      separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def _draft_rule(con: sqlite3.Connection, rule_id: int) -> dict:
    if type(rule_id) is not int or not 1 <= rule_id < 2**63:
        raise ActivationError("Invalid rule ID")
    row = con.execute(
        "SELECT id,kind,field,pattern,enabled,action FROM rules WHERE id=?",
        (rule_id,)).fetchone()
    if not row:
        raise ActivationError("Rule no longer exists")
    rule = dict(row)
    if (rule["kind"] not in SUPPORTED or rule["enabled"] != 0
            or rule["action"] != "draft"):
        raise ActivationError("This rule cannot be activated")
    if con.execute("SELECT COUNT(*) FROM rule_scopes WHERE rule_id=?",
                   (rule_id,)).fetchone()[0]:
        raise ActivationError("Rule already has a protected scope")
    try:
        if rule["kind"] == "custom_raw_header":
            from .managed_rules import normalize
            normalize(rule["kind"], rule["field"], rule["pattern"], "Approved custom raw header")
        elif validate_rule(rule["kind"], rule["field"], rule["pattern"]) != rule["pattern"]:
            raise ActivationError("Rule needs review before activation")
    except ValueError:
        raise ActivationError("Rule has an invalid matching pattern") from None
    except Exception as error:
        if isinstance(error, ActivationError):
            raise
        raise ActivationError("Rule has an invalid matching pattern") from None
    return rule


def read_approvals(path: Path | None = None, *, require_root: bool = True) -> list[dict]:
    path = Path(EXTRA_POLICY if path is None else path)
    try:
        state = path.lstat()
    except FileNotFoundError:
        return []
    if (not stat.S_ISREG(state.st_mode) or state.st_size > MAX_FILE_BYTES
            or (require_root and (state.st_uid != 0 or state.st_mode & 0o022))):
        raise ActivationError("Insecure custom rule approval file")
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ActivationError("Malformed custom rule approval file") from None
    if (not isinstance(payload, dict) or set(payload) != {"schema", "legacy_sha256", "rules"}
            or payload["schema"] != 1
            or payload["legacy_sha256"] != LEGACY_SOURCE_SHA
            or type(payload["rules"]) is not list
            or len(payload["rules"]) > MAX_APPROVALS):
        raise ActivationError("Invalid custom rule approval schema")
    results, ids = [], set()
    for item in payload["rules"]:
        if (not isinstance(item, dict)
                or set(item) != {"id", "sha256", "accounts"}
                or type(item["id"]) is not int or not 1 <= item["id"] < 2**63
                or item["id"] in ids
                or type(item["sha256"]) is not str or not HEX.fullmatch(item["sha256"])
                or type(item["accounts"]) is not list
                or not item["accounts"]
                or len(set(item["accounts"])) != len(item["accounts"])
                or any(type(i) is not int or i not in (1, 2) for i in item["accounts"])):
            raise ActivationError("Invalid custom rule approval entry")
        results.append(dict(item))
        ids.add(item["id"])
    return results


def active_rules(store, account_id: int, *, path: Path | None = None,
                 require_root: bool = True) -> list[dict]:
    approvals = read_approvals(path, require_root=require_root)
    if not approvals:
        return []
    ids = [r["id"] for r in approvals]
    with store.db() as con:
        found = {row["id"]: dict(row) for row in con.execute(
            f"SELECT id,kind,field,pattern,enabled,action FROM rules "
            f"WHERE id IN ({','.join('?' for _ in ids)})", ids)}
        scopes = {int(row[0]) for row in con.execute(
            f"SELECT DISTINCT rule_id FROM rule_scopes "
            f"WHERE rule_id IN ({','.join('?' for _ in ids)})", ids)}
    result = []
    for approved in approvals:
        rule = found.get(approved["id"])
        if not rule or rule["id"] in scopes:
            raise ActivationError("Approved custom rule missing or scoped unexpectedly")
        if source_digest(rule) != approved["sha256"]:
            raise ActivationError("Approved custom rule changed since authorization")
        # Root-controlled policy cannot make an unsupported kind executable.
        if rule["kind"] not in SUPPORTED or rule["enabled"] != 0 or rule["action"] != "draft":
            raise ActivationError("Unexpected active custom rule state")
        try:
            if rule["kind"] != "custom_raw_header":
                if validate_rule(rule["kind"], rule["field"], rule["pattern"]) != rule["pattern"]:
                    raise ValueError()
            else:
                from .managed_rules import normalize
                normalize(rule["kind"], rule["field"], rule["pattern"], "Approved custom raw header")
            from .managed_rules import effective_custom, ManagedError
            rule = effective_custom(rule, require_root=require_root)
        except (ValueError, ManagedError):
            raise ActivationError("Approved custom rule invalid") from None
        if account_id in approved["accounts"]:
            result.append(rule)
    return result


def _write_root_policy(path: Path, approvals: list[dict]) -> None:
    path = Path(path)
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ActivationError("Unsafe approval configuration directory")
    mode = parent.stat()
    if mode.st_uid != 0 or mode.st_mode & 0o022:
        raise ActivationError("Approval directory must be root managed")
    if path.exists() and path.is_symlink():
        raise ActivationError("Refusing symlink approval file")
    payload = json.dumps({
        "schema": 1, "legacy_sha256": LEGACY_SOURCE_SHA,
        "rules": sorted(approvals, key=lambda r: r["id"]),
    }, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_FILE_BYTES:
        raise ActivationError("Too many approved rules")
    fd, temporary = tempfile.mkstemp(prefix=".extra-rules.", dir=parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        import grp
        os.chown(temporary, 0, grp.getgrnam("filtervision").gr_gid)
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_approval(store, action: str, rule_id: int,
                   account_ids: list[int], fingerprint: str,
                   *, path: Path | None = None,
                   policy_loader=load_policy) -> str:
    """Root control helper only. Existing legacy approval must be valid."""
    path = Path(EXTRA_POLICY if path is None else path)
    if os.geteuid() != 0:
        raise ActivationError("Root approval helper required")
    if action not in ("enable-rule", "disable-rule"):
        raise ActivationError("Unsupported rule control action")
    if (type(rule_id) is not int or rule_id <= 0
            or type(fingerprint) is not str or not HEX.fullmatch(fingerprint)
            or type(account_ids) is not list or not account_ids
            or len(set(account_ids)) != len(account_ids)
            or any(type(i) is not int for i in account_ids)):
        raise ActivationError("Invalid rule activation request")
    try:
        legacy = policy_loader()
    except (LiveSafetyError, ValueError, OSError, KeyError, TypeError):
        raise ActivationError("Existing protected cleaner approval is invalid") from None
    if not set(account_ids).issubset(legacy["accounts"]):
        raise ActivationError("Selected account is not root-approved")
    from .live import _active_rules
    # Validate the original 22-rule legacy policy for EVERY account before
    # extending it. No extra policy member can relax these checks.
    for account in legacy["accounts"]:
        _active_rules(store, account, legacy, include_extra=False)
    with store.db() as con:
        rule = _draft_rule(con, rule_id)
    if source_digest(rule) != fingerprint:
        raise ActivationError("Rule changed after its preview")
    existing = read_approvals(path)
    approved = next((r for r in existing if r["id"] == rule_id), None)
    if approved is not None and approved["sha256"] != fingerprint:
        raise ActivationError("An existing approval no longer matches this draft")
    if action == "enable-rule":
        if approved is None:
            if len(existing) >= MAX_APPROVALS:
                raise ActivationError("Maximum number of custom approvals reached")
            existing.append({"id": rule_id, "sha256": fingerprint,
                             "accounts": sorted(account_ids)})
        else:
            approved["accounts"] = sorted(set(approved["accounts"]) | set(account_ids))
    else:
        if approved is None or not set(account_ids).issubset(approved["accounts"]):
            raise ActivationError("Rule is not enabled for the selected account")
        approved["accounts"] = sorted(set(approved["accounts"]) - set(account_ids))
        if not approved["accounts"]:
            existing.remove(approved)
    _write_root_policy(path, existing)
    return ("Rule #%d %s on %d account(s)" %
            (rule_id, "enabled" if action == "enable-rule" else "disabled",
             len(account_ids)))


def apply_batch_approvals(store, entries: list[dict], account_ids: list[int],
                          *, path: Path | None = None,
                          policy_loader=load_policy) -> str:
    """Root-only all-or-nothing activation of already saved disabled drafts.

    Preview is required in the unprivileged WebUI before queuing; this root
    handler independently verifies every current source and frozen policy.
    Only one final atomic extra-policy replace can activate the whole batch.
    """
    path = Path(EXTRA_POLICY if path is None else path)
    if os.geteuid() != 0:
        raise ActivationError("Root approval helper required")
    if (type(entries) is not list or not 1 <= len(entries) <= 32
            or type(account_ids) is not list or not account_ids
            or len(account_ids) > 2 or len(set(account_ids)) != len(account_ids)
            or any(type(i) is not int or i not in (1, 2) for i in account_ids)):
        raise ActivationError("Invalid batch approval scope")
    seen = set()
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {"id", "sha256"}
                or type(entry["id"]) is not int or not 1 <= entry["id"] < 2**63
                or type(entry["sha256"]) is not str or not HEX.fullmatch(entry["sha256"])
                or entry["id"] in seen):
            raise ActivationError("Invalid batch approval source")
        seen.add(entry["id"])
    try:
        legacy = policy_loader()
    except (LiveSafetyError, ValueError, OSError, KeyError, TypeError):
        raise ActivationError("Existing protected cleaner approval is invalid") from None
    if not set(account_ids).issubset(legacy["accounts"]):
        raise ActivationError("Batch account scope not root-approved")
    from .live import _active_rules
    for account in legacy["accounts"]:
        _active_rules(store, account, legacy, include_extra=False)
    existing = read_approvals(path)
    existing_ids = {entry["id"] for entry in existing}
    if existing_ids.intersection(seen):
        raise ActivationError("Selected rule already has a protected approval")
    if len(existing) + len(entries) > MAX_APPROVALS:
        raise ActivationError("Too many approved custom rules")
    with store.db() as con:
        for entry in entries:
            rule = _draft_rule(con, entry["id"])
            if source_digest(rule) != entry["sha256"]:
                raise ActivationError("Batch rule changed after its preview")
    updated = existing + [
        {"id": entry["id"], "sha256": entry["sha256"],
         "accounts": sorted(account_ids)} for entry in entries
    ]
    # The ONLY activating write. A rejected member produces no approvals.
    _write_root_policy(path, updated)
    return "%d rules enabled on %d account(s)" % (len(entries), len(account_ids))
