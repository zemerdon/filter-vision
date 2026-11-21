"""Root-owned editable policy overlays for original and approved custom rules.

The 22 original SQLite signatures and original 44 account scopes stay intact
as a recoverable, checksum-verified baseline. Only a fixed-schema root-owned
overlay can replace/disable their effective matchers. Active custom drafts may
also be edited through an independently root-controlled overlay, so direct
SQLite writes cannot silently expand a destructive rule.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path

from .analysis import validate_rule
from .live import LEGACY_SOURCE_SHA, LiveSafetyError, load_policy
from .rule_activation import source_digest

MANAGED_PATH = Path("/etc/filter-vision/managed-rules.json")
MAX_FILE_BYTES = 16384
MAX_ITEMS = 86
HEX = re.compile(r"^[a-f0-9]{64}$")
RULE_KINDS = frozenset({
    "legacy_raw_header", "custom_raw_header", "raw_header_contains",
    "click_destination", "sender_exact", "sender_domain",
    "header_exact", "header_contains", "subject_exact",
})


class ManagedError(RuntimeError):
    pass


def normalize(kind: str, field: str, value: str, label: str) -> dict:
    if type(kind) is not str or type(field) is not str or type(value) is not str or type(label) is not str:
        raise ManagedError("Invalid rule fields")
    if kind not in RULE_KINDS:
        raise ManagedError("Unsupported rule matcher")
    if kind in ("legacy_raw_header", "custom_raw_header"):
        if field not in ("raw", "All raw headers"):
            raise ManagedError("Unexpected raw header field")
        if (not 8 <= len(value) <= 255 or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ManagedError("Invalid original raw-header signature")
    else:
        try:
            if validate_rule(kind, field, value) != value:
                raise ManagedError("Matcher needs review before applying")
        except ValueError:
            raise ManagedError("Invalid candidate matcher") from None
    if (not 1 <= len(label) <= 200 or
            any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
        raise ManagedError("Invalid rule label")
    return {"kind": kind, "field": field, "pattern": value, "label": label}


def _validate_override(record) -> dict:
    if type(record) is not dict or set(record) != {"kind", "field", "pattern", "label"}:
        raise ManagedError("Invalid rule override schema")
    return normalize(record["kind"], record["field"], record["pattern"], record["label"])


def _validate_items(items: list, *, legacy: bool):
    ids = set()
    expected = {"id", "sha256", "enabled", "override"} if legacy else {
        "id", "sha256", "override"}
    for entry in items:
        if (type(entry) is not dict or set(entry) != expected
                or type(entry["id"]) is not int
                or not 1 <= entry["id"] < 2**63
                or entry["id"] in ids or type(entry["sha256"]) is not str
                or not HEX.fullmatch(entry["sha256"])
                or (legacy and type(entry["enabled"]) is not bool)):
            raise ManagedError("Invalid managed rule entry")
        if entry["override"] is not None:
            _validate_override(entry["override"])
        ids.add(entry["id"])


def read_managed(path: Path | None = None, *, require_root: bool = True) -> dict:
    path = Path(MANAGED_PATH if path is None else path)
    empty = {"legacy": [], "custom": []}
    try:
        state = path.lstat()
    except FileNotFoundError:
        return empty
    if (not stat.S_ISREG(state.st_mode) or not 0 < state.st_size <= MAX_FILE_BYTES
            or (require_root and (state.st_uid != 0 or state.st_mode & 0o022))):
        raise ManagedError("Unsafe managed-rule approval file")
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError, TypeError):
        raise ManagedError("Invalid managed-rule policy") from None
    if (type(payload) is not dict or set(payload) !=
            {"schema", "legacy_sha256", "legacy", "custom"}
            or type(payload["schema"]) is not int or payload["schema"] != 1
            or payload["legacy_sha256"] != LEGACY_SOURCE_SHA
            or type(payload["legacy"]) is not list or type(payload["custom"]) is not list
            or len(payload["legacy"]) > 22 or len(payload["custom"]) > 64):
        raise ManagedError("Unexpected managed-rule approval schema")
    _validate_items(payload["legacy"], legacy=True)
    _validate_items(payload["custom"], legacy=False)
    if set(x["id"] for x in payload["legacy"]) & set(x["id"] for x in payload["custom"]):
        raise ManagedError("Conflicting rule overrides")
    return {"legacy": payload["legacy"], "custom": payload["custom"]}


def effective(rule: dict, item: dict | None) -> dict:
    row = dict(rule)
    if item is None:
        return row
    if source_digest(rule) != item["sha256"]:
        raise ManagedError("Managed rule no longer matches approved source")
    if item["override"]:
        row.update(_validate_override(item["override"]))
    return row


def effective_legacy(scoped: list[dict], store, account_id: int,
                     *, path: Path | None = None,
                     require_root: bool = True) -> list[dict]:
    changes = read_managed(path, require_root=require_root)["legacy"]
    if not changes:
        return scoped
    with store.db() as db:
        originals = {
            row["id"]: dict(row) for row in db.execute(
                "SELECT id,kind,field,pattern,label FROM rules "
                "WHERE kind='legacy_raw_header'")}
    source_ids = set(originals)
    if len(source_ids) != 22:
        raise ManagedError("Imported rule baseline is incomplete")
    changes_by_id = {}
    for entry in changes:
        row = originals.get(entry["id"])
        if not row or source_digest(row) != entry["sha256"]:
            raise ManagedError("Imported rule changed after root authorization")
        changes_by_id[entry["id"]] = entry
    result = []
    for rule in scoped:
        entry = changes_by_id.get(rule["id"])
        if entry and not entry["enabled"]:
            continue
        result.append(effective({**originals[rule["id"]]}, entry))
    return result


def effective_custom(rule: dict, *, path: Path | None = None,
                     require_root: bool = True) -> dict:
    entries = read_managed(path, require_root=require_root)["custom"]
    match = next((item for item in entries if item["id"] == rule["id"]), None)
    return effective(rule, match)


def _write(path: Path, items: dict) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ManagedError("Missing protected rule directory")
    state = parent.stat()
    if state.st_uid != 0 or state.st_mode & 0o022:
        raise ManagedError("Unsafe protected rule directory")
    if path.is_symlink():
        raise ManagedError("Unsafe managed-rule destination")
    blob = json.dumps({
        "schema": 1, "legacy_sha256": LEGACY_SOURCE_SHA,
        "legacy": sorted(items["legacy"], key=lambda x: x["id"]),
        "custom": sorted(items["custom"], key=lambda x: x["id"]),
    }, sort_keys=True, separators=(",", ":")).encode()
    if len(blob) > MAX_FILE_BYTES:
        raise ManagedError("Too many managed rules")
    import grp
    fd, name = tempfile.mkstemp(prefix=".managed-rules.", dir=parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(blob)
            out.flush()
            os.fsync(out.fileno())
        os.chown(name, 0, grp.getgrnam("filtervision").gr_gid)
        os.chmod(name, 0o640)
        os.replace(name, path)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def apply_managed(store, action: str, rule_id: int, fingerprint: str,
                  override: dict | None = None, *, activate: bool = False,
                  path: Path | None = None,
                  policy_loader=load_policy) -> str:
    """Root-only atomic override; old imported SQLite state never altered."""
    path = Path(MANAGED_PATH if path is None else path)
    if os.geteuid() != 0:
        raise ManagedError("Root-managed rule action required")
    if action not in ("legacy-enable", "legacy-disable", "legacy-edit", "custom-edit"):
        raise ManagedError("Unsupported managed-rule action")
    if (type(rule_id) is not int or not 1 <= rule_id < 2**63
            or type(fingerprint) is not str or not HEX.fullmatch(fingerprint)
            or type(activate) is not bool
            or (action.endswith("-edit") != (override is not None))):
        raise ManagedError("Invalid managed-rule request")
    if override is not None:
        _validate_override(override)
    try:
        policy = policy_loader()
    except (LiveSafetyError, ValueError, OSError, TypeError):
        raise ManagedError("Protected legacy policy unavailable") from None
    from .live import _active_rules
    for account_id in policy["accounts"]:
        _active_rules(store, account_id, policy, include_extra=False)
    with store.db() as db:
        row = db.execute("SELECT id,label,kind,field,pattern,enabled,action "
                         "FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ManagedError("Rule was removed")
        row = dict(row)
        scopes = {
            int(x[0]) for x in db.execute(
                "SELECT account_id FROM rule_scopes WHERE rule_id=?", (rule_id,))}
    if source_digest(row) != fingerprint:
        raise ManagedError("Rule changed after edit was requested")
    legacy = action.startswith("legacy-")
    if legacy:
        if row["kind"] != "legacy_raw_header" or scopes != set(policy["accounts"]):
            raise ManagedError("Original rule is not baseline-approved")
        if override is not None and override["kind"] == "legacy_raw_header":
            _validate_override(override)
    else:
        if (row["kind"] == "legacy_raw_header" or scopes
                or row["enabled"] != 0 or row["action"] != "draft"):
            raise ManagedError("Cannot edit non-draft custom rule")
    managed = read_managed(path)
    kind = "legacy" if legacy else "custom"
    entry = next((x for x in managed[kind] if x["id"] == rule_id), None)
    if entry is None:
        entry = {"id": rule_id, "sha256": fingerprint, "override": None}
        if legacy:
            entry["enabled"] = True
        managed[kind].append(entry)
    if entry["sha256"] != fingerprint:
        raise ManagedError("Existing managed approval has stale source")
    if action == "legacy-disable":
        entry["enabled"] = False
    elif action == "legacy-enable":
        entry["enabled"] = True
    else:
        entry["override"] = _validate_override(override)
        if legacy and activate:
            entry["enabled"] = True
    if legacy and entry["enabled"] and entry["override"] is None:
        managed["legacy"].remove(entry)
    # Commit effective matcher first. When edit+enable is requested for an
    # inactive custom draft, the still-disabled rule cannot delete even if a
    # later root approval write fails. The UI reports activation only when
    # both protected files agree.
    _write(path, managed)
    if not legacy and activate:
        from .rule_activation import apply_approval, ActivationError, read_approvals
        if not any(x["id"] == rule_id for x in read_approvals()):
            try:
                apply_approval(
                    store, "enable-rule", rule_id, sorted(policy["accounts"]),
                    fingerprint, policy_loader=lambda: policy)
            except ActivationError:
                raise ManagedError(
                    "Custom rule edit saved but activation failed") from None
    return ("Rule #%d %s" % (rule_id, {
        "legacy-enable": "activated", "legacy-disable": "disabled",
        "legacy-edit": "updated", "custom-edit": "updated",
    }[action]))
