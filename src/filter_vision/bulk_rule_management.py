"""Bounded, atomic unprivileged Rules-page duplicate/delete actions.

No live approval, legacy source or existing account scope is mutated.
"""
from __future__ import annotations

import time
from .managed_rules import read_managed, effective, normalize, ManagedError
from .rule_activation import read_approvals, source_digest, ActivationError
from .rule_management import draft_guard, DRAFT_KINDS, RuleManagementError

MAX_RULES_BULK = 64


def validate_ids(ids: list[int]) -> list[int]:
    if (type(ids) is not list or not 1 <= len(ids) <= MAX_RULES_BULK
            or any(type(i) is not int or not 1 <= i < 2**63 for i in ids)
            or len(set(ids)) != len(ids)):
        raise RuleManagementError("Select between 1 and 64 distinct rules", 400)
    return ids


def duplicate_rules(store, ids: list[int]) -> int:
    ids = validate_ids(ids)
    managed = read_managed()
    originals = {group: {item["id"]: item for item in managed[group]}
                 for group in ("legacy", "custom")}
    read_approvals()  # A damaged approval sidecar must block structural changes.
    new_ids = []
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        for rid in ids:
            row = con.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
            if row is None:
                raise RuleManagementError("Selected rule no longer exists", 409)
            source = dict(row)
            group = "legacy" if source["kind"] == "legacy_raw_header" else "custom"
            overlay = originals[group].get(rid)
            if overlay is not None and overlay["sha256"] != source_digest(source):
                raise RuleManagementError("Selected managed rule has changed", 409)
            resolved = effective(source, overlay)
            if source["kind"] == "legacy_raw_header" and resolved["kind"] == "legacy_raw_header":
                resolved["kind"], resolved["field"] = "custom_raw_header", "All raw headers"
            if resolved["kind"] not in DRAFT_KINDS:
                raise RuleManagementError("Unsupported rule type for duplication", 409)
            try:
                entry = normalize(resolved["kind"], resolved["field"],
                                  resolved["pattern"], ("Copy of " + resolved["label"])[:200])
            except ManagedError:
                raise RuleManagementError("Invalid rule for duplication", 409) from None
            cursor = con.execute(
                "INSERT INTO rules(label,kind,field,pattern,created_at) "
                "VALUES(?,?,?,?,?)",
                (entry["label"], entry["kind"], entry["field"],
                 entry["pattern"], int(time.time())))
            new_ids.append(int(cursor.lastrowid))
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rules_bulk_duplicated", f"count={len(new_ids)}"))
    return len(new_ids)


def delete_rules(store, ids: list[int]) -> int:
    ids = validate_ids(ids)
    # Draft guard enforces no original, no effective approval and no scope.
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        for rid in ids:
            draft_guard(con, rid)
        for rid in ids:
            result = con.execute(
                "DELETE FROM rules WHERE id=? AND enabled=0 AND action='draft'", (rid,))
            if result.rowcount != 1:
                raise RuleManagementError("Selected rule changed while deleting", 409)
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rules_bulk_deleted", f"count={len(ids)}"))
    return len(ids)



def apply_root_bulk_rule_state(store, ids: list[dict], accounts: list[int],
                               activate: bool, *, managed_path=None,
                               approvals_path=None, policy_loader=None) -> str:
    """Root-only bounded desired-state transaction across protected sidecars.

    All source/policy validation runs before writes. The two independent root
    sidecars are written in the safest order (managed first), and rollback is
    attempted if the second write fails. Never touch frozen SQLite originals.
    """
    import copy
    import os
    from pathlib import Path
    from .live import load_policy, _active_rules, LiveSafetyError
    from .rule_activation import (_draft_rule, read_approvals, _write_root_policy,
                                  MAX_APPROVALS, ActivationError)
    from .managed_rules import read_managed, _write as _write_managed, effective_custom, ManagedError

    if os.geteuid() != 0:
        raise RuleManagementError("Root control required", 403)
    if (type(activate) is not bool or type(ids) is not list or
            not 1 <= len(ids) <= MAX_RULES_BULK or
            type(accounts) is not list or not accounts or len(accounts) > 2 or
            len(set(accounts)) != len(accounts) or
            any(type(i) is not int or i not in (1,2) for i in accounts)):
        raise RuleManagementError("Invalid rule batch", 400)
    from .rule_activation import HEX
    seen = set()
    for entry in ids:
        if (type(entry) is not dict or set(entry) != {"id", "sha256"}
                or type(entry["id"]) is not int or not 1 <= entry["id"] < 2**63
                or entry["id"] in seen or type(entry["sha256"]) is not str
                or not HEX.fullmatch(entry["sha256"])):
            raise RuleManagementError("Invalid rule source", 400)
        seen.add(entry["id"])
    loader = load_policy if policy_loader is None else policy_loader
    policy = loader()
    if set(accounts) != set(policy["accounts"]):
        raise RuleManagementError("Account approval has changed", 409)
    # Preserve original legacy validation. It does not consider extra approvals.
    for aid in policy["accounts"]:
        _active_rules(store, aid, policy, include_extra=False)
    import filter_vision.managed_rules as managed_mod
    import filter_vision.rule_activation as approval_mod
    mp = Path(managed_mod.MANAGED_PATH if managed_path is None else managed_path)
    ap = Path(approval_mod.EXTRA_POLICY if approvals_path is None else approvals_path)
    managed_before = read_managed(mp)
    approvals_before = read_approvals(ap)
    managed = copy.deepcopy(managed_before)
    approvals = copy.deepcopy(approvals_before)
    legacy_map = {x["id"]: x for x in managed["legacy"]}
    custom_map = {x["id"]: x for x in managed["custom"]}
    approval_map = {x["id"]: x for x in approvals}
    n_legacy = n_custom = 0
    with store.db() as con:
        for item in ids:
            rid = item["id"]
            row = con.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
            if row is None:
                raise RuleManagementError("Selected rule no longer exists", 409)
            rule = dict(row)
            if source_digest(rule) != item["sha256"]:
                raise RuleManagementError("Selected rule has changed", 409)
            if rule["kind"] == "legacy_raw_header":
                scopes = {r[0] for r in con.execute(
                    "SELECT account_id FROM rule_scopes WHERE rule_id=?", (rid,))}
                if scopes != set(accounts):
                    raise RuleManagementError("Legacy rule scope mismatch", 409)
                overlay = legacy_map.get(rid)
                if overlay is not None and overlay["sha256"] != item["sha256"]:
                    raise RuleManagementError("Stale protected legacy state", 409)
                currently_active = overlay is None or overlay["enabled"]
                if currently_active == activate:
                    continue
                if activate:
                    if overlay is None:
                        continue
                    overlay["enabled"] = True
                    if overlay["override"] is None:
                        managed["legacy"].remove(overlay)
                else:
                    if overlay is None:
                        overlay = {"id":rid,"sha256":item["sha256"],
                                   "enabled":False,"override":None}
                        managed["legacy"].append(overlay)
                    else:
                        overlay["enabled"] = False
                n_legacy += 1
            else:
                from .rule_activation import _draft_rule
                _draft_rule(con,rid)
                if rid in custom_map and custom_map[rid]["sha256"] != item["sha256"]:
                    raise RuleManagementError("Stale managed custom source",409)
                if rid in custom_map:
                    effective_custom(rule, path=mp)
                currently_active = rid in approval_map
                if currently_active:
                    current = approval_map[rid]
                    if current["sha256"] != item["sha256"] or current["accounts"] != accounts:
                        raise RuleManagementError("Custom approval scope changed",409)
                if currently_active == activate:
                    continue
                if activate:
                    approvals.append({"id":rid, "sha256":item["sha256"],
                                      "accounts":sorted(accounts)})
                else:
                    approvals.remove(approval_map[rid])
                n_custom += 1
    if len(approvals) > MAX_APPROVALS:
        raise RuleManagementError("Maximum custom rule approvals reached",409)
    if not n_legacy and not n_custom:
        return "Selected rules are already in requested state"
    # Root control service operates under a single systemd queue lock. If the
    # second filesystem write fails, restore the first root-owned policy.
    wrote_managed = False
    try:
        if n_legacy:
            _write_managed(mp, managed)
            wrote_managed = True
        if n_custom:
            _write_root_policy(ap, approvals)
    except (OSError, ValueError, ActivationError, ManagedError) as exc:
        if wrote_managed:
            try:
                _write_managed(mp, managed_before)
            except (OSError, ValueError, ManagedError):
                raise RuleManagementError(
                    "Bulk change failed and protected rollback needs operator review",409) from None
        raise RuleManagementError("Protected bulk rule transition rejected",409) from None
    return "%d rule(s) %s" % (n_legacy + n_custom,
                             "enabled" if activate else "disabled")
