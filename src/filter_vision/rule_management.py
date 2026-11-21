"""Validated draft editing, with reversible root-owned active overrides.

Direct SQLite draft mutations stay inert; protected and activated rules are
edited through separate signed root-controlled actions.
"""
from __future__ import annotations

import sqlite3
import time

from .analysis import validate_rule

# Explicit UI definitions, not arbitrary SQL column or rule kinds from clients.
RULE_DEFINITIONS = (
    ("sender_exact", "From", "Exact sender email"),
    ("sender_domain", "From", "Sender domain"),
    ("header_exact", "X-VMTA-Source", "Exact X-VMTA-Source header"),
    ("header_exact", "X-Relaying-Domain", "Exact X-Relaying-Domain header"),
    ("header_contains", "Feedback-ID", "Feedback-ID campaign marker"),
    ("subject_exact", "Subject", "Exact subject"),
    ("click_destination", "HTML click destination",
       "HTML click hostname — exact destination match"),
    ("raw_header_contains", "All raw headers",
     "Raw-header substring — legacy-style matching"),
    ("custom_raw_header", "All raw headers",
     "Original-style raw-header substring"),
)
DEFINITION_CODES = {f"{kind}:{field}": (kind, field)
                    for kind, field, _ in RULE_DEFINITIONS}
DRAFT_KINDS = frozenset(kind for kind, _, _ in RULE_DEFINITIONS)


class RuleManagementError(Exception):
    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


def draft_guard(con: sqlite3.Connection, rule_id: int) -> dict:
    if not 1 <= rule_id <= 2**63 - 1:
        raise RuleManagementError("Invalid rule ID", 404)
    row = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if row is None:
        raise RuleManagementError("Rule not found", 404)
    record = dict(row)
    # A legacy rule is part of the root-owned, frozen 22-rule safety policy,
    # even if its visible enabled/action fields say 0/draft.
    if record["kind"] == "legacy_raw_header":
        raise RuleManagementError(
            "Protected live rule. Changing or removing an imported signature "
            "requires a reviewed replacement and root approval.")
    # Some old drafts used lowercase 'from' or another presentation field.
    # They are still safely editable: Save requires choosing a validated
    # definition, and no live/legacy approval can be bypassed.
    if (record["kind"] not in DRAFT_KINDS
            or record["enabled"] != 0 or record["action"] != "draft"):
        raise RuleManagementError("Rule is not an editable, disabled draft")
    if con.execute(
        "SELECT 1 FROM rule_scopes WHERE rule_id=? LIMIT 1", (rule_id,)
    ).fetchone():
        raise RuleManagementError(
            "Scoped rule cannot be modified until its approval is reviewed")
    # The original draft row remains disabled even after a separate root
    # approval. Editing or deleting its text must never silently affect a
    # destructive matcher. Disable it first with the one-click control.
    from .rule_activation import read_approvals, ActivationError
    from .managed_rules import read_managed, ManagedError
    try:
        if (any(item["id"] == rule_id for item in read_approvals())
                or any(item["id"] == rule_id for item in read_managed()["custom"])):
            raise RuleManagementError(
                "This rule is managed by the protected control; use Edit")
    except (ActivationError, ManagedError):
        raise RuleManagementError("Protected rule approvals are unavailable") from None
    return record


def parse_edit(definition: str, value: str, label: str) -> tuple[str, str, str, str]:
    pair = DEFINITION_CODES.get(definition)
    if pair is None:
        raise RuleManagementError("Invalid rule definition", 400)
    kind, field = pair
    try:
        value = validate_rule(kind, field, value)
    except ValueError as error:
        raise RuleManagementError(str(error), 400) from None
    label = label.strip()
    if not label:
        label = f"{field}: {value}"[:200]
    if (len(label) > 200 or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)
            or not label):
        raise RuleManagementError("Invalid rule label", 400)
    return kind, field, value, label


def update_draft(store, rule_id: int, definition: str, value: str, label: str) -> None:
    kind, field, pattern, title = parse_edit(definition, value, label)
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        draft_guard(con, rule_id)
        con.execute(
            "UPDATE rules SET label=?,kind=?,field=?,pattern=? "
            "WHERE id=? AND enabled=0 AND action='draft'",
            (title, kind, field, pattern, rule_id))
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_draft_edited", f"rule_id={rule_id}"))


def duplicate_draft(store, rule_id: int) -> int:
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        old = draft_guard(con, rule_id)
        new_label = ("Copy of " + old["label"])[:200]
        cursor = con.execute(
            "INSERT INTO rules(label,kind,field,pattern,enabled,action,created_at) "
            "VALUES(?,?,?,?,0,'draft',?)",
            (new_label, old["kind"], old["field"], old["pattern"], int(time.time())))
        new_id = int(cursor.lastrowid)
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_draft_duplicated",
             f"source_id={rule_id} new_rule_id={new_id}"))
        return new_id


def delete_draft(store, rule_id: int) -> None:
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        draft_guard(con, rule_id)
        result = con.execute(
            "DELETE FROM rules WHERE id=? AND enabled=0 AND action='draft'",
            (rule_id,))
        if result.rowcount != 1:
            raise RuleManagementError("Rule changed during deletion")
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_draft_deleted", f"rule_id={rule_id}"))
