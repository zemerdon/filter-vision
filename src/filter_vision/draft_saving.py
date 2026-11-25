"""Atomic, idempotent disabled/unscoped candidate draft saving.

Never changes existing rules, account scopes or protected root policy.
"""
from __future__ import annotations

import time

from .analysis import candidate_signature, validate_rule

MAX_BATCH_DRAFTS = 64


def saved_signatures(con) -> set[tuple[str, str, str]]:
    return {candidate_signature(row["kind"], row["field"], row["pattern"])
            for row in con.execute("SELECT kind,field,pattern FROM rules")}


def save_disabled_drafts(store, entries: list[tuple[str, str, str]]) -> int:
    if not 1 <= len(entries) <= MAX_BATCH_DRAFTS:
        raise ValueError("Select between 1 and 64 candidate rules")
    validated = [(kind, field, validate_rule(kind, field, value))
                 for kind, field, value in entries]
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        existing = saved_signatures(con)
        added = 0
        for kind, field, value in validated:
            signature = candidate_signature(kind, field, value)
            if signature in existing:
                continue
            con.execute(
                "INSERT INTO rules(label,kind,field,pattern,created_at) "
                "VALUES(?,?,?,?,?)",
                (f"{field}: {value}"[:200], kind, field, value, int(time.time())))
            existing.add(signature)
            added += 1
        # Administrative audit must not contain private campaign values.
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_drafts_saved", f"added={added} requested={len(entries)}"))
    return added


def save_enable_candidates(store, entries: list[tuple[str, str, str]]) -> list[dict]:
    """Insert only fresh inactive drafts and return their source digests.

    Reject a raced existing candidate instead of enabling a different record.
    The browser has already run read-only previews; root rechecks sources.
    """
    if not 1 <= len(entries) <= 32:
        raise ValueError("Select between 1 and 32 rules for activation")
    validated = [(kind, field, validate_rule(kind, field, value))
                 for kind, field, value in entries]
    signatures = [candidate_signature(*item) for item in validated]
    if len(set(signatures)) != len(signatures):
        raise ValueError("Duplicate selected rule")
    from .rule_activation import source_digest
    results = []
    with store.db() as con:
        con.execute("BEGIN IMMEDIATE")
        if set(signatures) & saved_signatures(con):
            raise ValueError("Selected candidates changed; refresh and retry")
        for kind, field, value in validated:
            cursor = con.execute(
                "INSERT INTO rules(label,kind,field,pattern,created_at) "
                "VALUES(?,?,?,?,?)",
                (f"{field}: {value}"[:200], kind, field, value, int(time.time())))
            rule_id = int(cursor.lastrowid)
            results.append({"id": rule_id, "sha256": source_digest({
                "id": rule_id, "kind": kind, "field": field, "pattern": value})})
        con.execute(
            "INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
            (int(time.time()), "rule_batch_enable_drafts_created",
             f"count={len(results)}"))
    return results
