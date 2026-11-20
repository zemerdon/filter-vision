"""Staged management for every Filter Vision rule without modifying live mail deletion.

The root-approved legacy signatures/scopes/policy are never written here.
New rule activation and changing an approved rule remain explicit pending
reviews; their actual execution requires a separately authorised root-policy
workflow, not a browser direct DB toggle.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time

from .rule_management import (
    RuleManagementError, DEFINITION_CODES, parse_edit, draft_guard,
)

REQUEST_OPERATIONS = frozenset({"enable", "disable", "edit", "duplicate"})
REVIEW_STATUSES = frozenset({"pending_review", "cancelled"})
LEGACY_CODE = "legacy_raw_header:raw"
MAX_REVIEW_REQUESTS = 500


def _rule(con: sqlite3.Connection, rule_id: int) -> tuple[dict, list[int]]:
    if type(rule_id) is not int or not (1 <= rule_id <= 2**63 - 1):
        raise RuleManagementError("Invalid rule ID", 404)
    row = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if row is None:
        raise RuleManagementError("Rule not found", 404)
    scopes = [int(x[0]) for x in con.execute(
        "SELECT account_id FROM rule_scopes WHERE rule_id=? ORDER BY account_id",
        (rule_id,))]
    return dict(row), scopes


def _fingerprint(row: dict, scopes: list[int]) -> str:
    fields = ("id", "label", "kind", "field", "pattern", "enabled", "action", "created_at")
    payload = {"row": {key: row[key] for key in fields}, "scopes": scopes}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def source_snapshot(store, rule_id: int) -> dict:
    with store.db() as con:
        row, scopes = _rule(con, rule_id)
    return {**row, "scope_ids": scopes, "source_sha256": _fingerprint(row, scopes)}


def _assert_unchanged(con: sqlite3.Connection, review: dict) -> dict:
    source, scopes = _rule(con, int(review["source_rule_id"]))
    if _fingerprint(source, scopes) != review["source_sha256"]:
        raise RuleManagementError("Source rule changed; review must be recreated")
    return source


def _editor_fields(definition: str, value: str, label: str) -> tuple[str, str, str, str]:
    if definition != LEGACY_CODE:
        return parse_edit(definition, value, label)
    # Legacy raw-header candidates are inert. They cannot become live rules
    # through the normal draft matcher or WebUI review request.
    value = value.strip()
    label = label.strip() or "Proposed raw-header signature"
    if (not 6 <= len(value) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or not 1 <= len(label) <= 200
            or any(ord(c) < 32 or ord(c) == 127 for c in label)):
        raise RuleManagementError("Invalid proposed raw-header signature", 400)
    return "legacy_raw_header", "raw", value, label


def _validate_accounts(con: sqlite3.Connection, raw_ids) -> list[int]:
    try:
        ids = sorted({int(x) for x in raw_ids})
    except (TypeError, ValueError):
        raise RuleManagementError("Invalid rule account selection", 400) from None
    if not ids or len(ids) > 12 or any(x <= 0 for x in ids):
        raise RuleManagementError("Select at least one supported account", 400)
    existing = {
        int(row[0]) for row in con.execute(
            "SELECT id FROM accounts WHERE id IN (" + ",".join("?" for _ in ids) + ")",
            ids)
    }
    if existing != set(ids):
        raise RuleManagementError("Unknown account selection", 400)
    return ids


def _insert_review(con: sqlite3.Connection, row: dict, scopes: list[int],
                   operation: str, account_ids: list[int],
                   label: str, kind: str, field: str, pattern: str) -> int:
    # A bounded review queue prevents untrusted LAN browsers from exhausting
    # SQLite with unlimited form requests.
    pending = con.execute(
        "SELECT COUNT(*) FROM rule_review_requests WHERE status='pending_review'"
    ).fetchone()[0]
    if pending >= MAX_REVIEW_REQUESTS:
        raise RuleManagementError("Pending rule review queue is full")
    now = int(time.time())
    result = con.execute(
        "INSERT INTO rule_review_requests("
        "source_rule_id,source_sha256,operation,label,kind,field,pattern,"
        "account_ids,status,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?, 'pending_review', ?,?)",
        (row["id"], _fingerprint(row, scopes), operation, label, kind,
         field, pattern, json.dumps(account_ids), now, now))
    return int(result.lastrowid)


def queue_review(store, rule_id: int, operation: str,
                 *, definition: str = "", value: str = "", label: str = "",
                 account_ids=()) -> int:
    if operation not in REQUEST_OPERATIONS:
        raise RuleManagementError("Unsupported review operation", 400)
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        row, scopes = _rule(con, rule_id)
        # No active/scoped record is modified. Even editing imported rule
        # #1..#22 only copies its proposed replacement into this table.
        if operation in {"edit", "duplicate"}:
            if operation == "duplicate" and not definition:
                kind, field, pattern, title = (
                    row["kind"], row["field"], row["pattern"], ("Copy of " + row["label"])[:200])
            else:
                kind, field, pattern, title = _editor_fields(definition, value, label)
            requested_accounts = []
        elif operation == "enable":
            # The root-owned deletion policy is unchanged by this request.
            requested_accounts = _validate_accounts(con, account_ids)
            kind, field, pattern, title = (
                row["kind"], row["field"], row["pattern"], row["label"])
        else:
            if not scopes:
                raise RuleManagementError("This rule has no active account scopes", 409)
            requested_accounts = scopes
            kind, field, pattern, title = (
                row["kind"], row["field"], row["pattern"], row["label"])
        new_id = _insert_review(
            con, row, scopes, operation, requested_accounts,
            title, kind, field, pattern)
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_review_queued",
             f"request_id={new_id} source_id={rule_id} operation={operation}"))
        return new_id


def load_review(store, request_id: int) -> dict:
    if type(request_id) is not int or not (1 <= request_id <= 2**63 - 1):
        raise RuleManagementError("Invalid review request", 404)
    with store.db() as con:
        row = con.execute(
            "SELECT * FROM rule_review_requests WHERE id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise RuleManagementError("Review request not found", 404)
        review = dict(row)
        _assert_unchanged(con, review)
    return review


def revise_review(store, request_id: int, definition: str,
                  value: str, label: str) -> None:
    kind, field, pattern, title = _editor_fields(definition, value, label)
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT * FROM rule_review_requests WHERE id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise RuleManagementError("Review request not found", 404)
        review = dict(row)
        if review["status"] != "pending_review" or review["operation"] not in ("edit", "duplicate"):
            raise RuleManagementError("This review request cannot be edited")
        _assert_unchanged(con, review)
        con.execute(
            "UPDATE rule_review_requests SET label=?,kind=?,field=?,pattern=?,updated_at=? "
            "WHERE id=? AND status='pending_review'",
            (title, kind, field, pattern, int(time.time()), request_id))
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_review_edited", f"request_id={request_id}"))


def cancel_review(store, request_id: int) -> None:
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT status FROM rule_review_requests WHERE id=?",
                          (request_id,)).fetchone()
        if row is None:
            raise RuleManagementError("Review request not found", 404)
        if row["status"] != "pending_review":
            raise RuleManagementError("Review request is already closed")
        con.execute(
            "UPDATE rule_review_requests SET status='cancelled',updated_at=? WHERE id=?",
            (int(time.time()), request_id))
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_review_cancelled", f"request_id={request_id}"))
