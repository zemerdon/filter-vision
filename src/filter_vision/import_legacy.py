"""Safe, idempotent importer for an offline snapshot of the legacy cleaner.

The export must contain only non-secret account identities, operational settings,
and literal header signatures. OAuth credentials are intentionally excluded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path

from .storage import Store


def legacy_matches(raw_headers: bytes, rule: str) -> bool:
    """Exact parity: old cleaner lowercases UTF-8-replaced raw header text."""
    return rule.lower() in raw_headers.decode("utf-8", errors="replace").lower()


def validate_payload(data: object) -> dict:
    if not isinstance(data, dict) or set(data) != {
        "schema", "source_sha256", "accounts", "rules", "folder",
        "scan_interval_minutes", "legacy_action",
    }:
        raise ValueError("Invalid legacy import manifest")
    if data["schema"] != 1 or not isinstance(data["source_sha256"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", data["source_sha256"]
    ):
        raise ValueError("Invalid legacy source reference")
    if data["folder"] != "Junk" or data["legacy_action"] != "permanent_delete":
        raise ValueError("Unknown legacy folder or disposition")
    if data["scan_interval_minutes"] != 30:
        raise ValueError("Unexpected legacy schedule")
    accounts, rules = data["accounts"], data["rules"]
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 40 or len(accounts) != len(set(accounts)):
        raise ValueError("Invalid account list")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 500 or len(rules) != len(set(rules)):
        raise ValueError("Invalid rule list")
    for account in accounts:
        if not isinstance(account, str) or not re.fullmatch(
            r"[^\s@]{1,80}@[^\s@]{1,160}\.[^\s@]{2,30}", account
        ):
            raise ValueError("Invalid account identifier")
    for rule in rules:
        if not isinstance(rule, str) or not 3 <= len(rule) <= 255 or any(
            ord(c) < 32 or ord(c) == 127 for c in rule
        ):
            raise ValueError("Invalid raw header signature")
    # Distinct strings differing only in case are semantically redundant and indicate drift.
    if len({r.lower() for r in rules}) != len(rules):
        raise ValueError("Duplicate case-insensitive legacy rule")
    return data


def import_payload(store: Store, payload: object) -> dict:
    data = validate_payload(payload)
    count_accounts, count_rules = 0, 0
    with store.db() as con:
        old = con.execute(
            "SELECT account_count, rule_count FROM legacy_imports WHERE source_sha256=?",
            (data["source_sha256"],),
        ).fetchone()
        if old:
            if old["account_count"] != len(data["accounts"]) or old["rule_count"] != len(data["rules"]):
                raise RuntimeError("Import source hash previously used for different configuration")
            return {"accounts": 0, "rules": 0, "already_imported": True}
        ids = []
        for index, email in enumerate(data["accounts"], 1):
            previous = con.execute(
                "SELECT id FROM accounts WHERE provider=? AND lower(username)=lower(?)",
                ("outlook", email),
            ).fetchone()
            if previous is not None:
                raise RuntimeError("Existing account requires manual reconciliation")
            label = "Hotmail" if email.lower().endswith("@hotmail.com") else (
                "Live" if email.lower().endswith("@live.com") else f"Microsoft {index}"
            )
            cursor = con.execute(
                "INSERT INTO accounts(label,provider,host,port,username,folder,"
                "interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (label, "outlook", "outlook.office365.com", 993, email, "Junk",
                 data["scan_interval_minutes"], 0, int(time.time())),
            )
            ids.append(cursor.lastrowid)
            count_accounts += 1
        for literal in data["rules"]:
            existing = con.execute(
                "SELECT id FROM rules WHERE kind='legacy_raw_header' AND lower(pattern)=lower(?)",
                (literal,),
            ).fetchone()
            if existing is not None:
                raise RuntimeError("Existing legacy rule requires manual reconciliation")
            cursor = con.execute(
                "INSERT INTO rules(label,kind,field,pattern,enabled,action,created_at)"
                " VALUES(?,?,?,?,0,'draft',?)",
                ("Imported header signature", "legacy_raw_header", "All raw headers", literal,
                 int(time.time())),
            )
            rule_id = cursor.lastrowid
            con.executemany(
                "INSERT INTO rule_scopes(rule_id,account_id) VALUES(?,?)",
                [(rule_id, account_id) for account_id in ids],
            )
            count_rules += 1
        con.execute(
            "INSERT INTO legacy_imports(source_sha256,account_count,rule_count,imported_at)"
            " VALUES(?,?,?,?)",
            (data["source_sha256"], count_accounts, count_rules, int(time.time())),
        )
    store.audit("legacy_draft_import", "Imported disabled account and exact-match rule drafts")
    return {"accounts": count_accounts, "rules": count_rules, "already_imported": False}


def main() -> None:
    parser = argparse.ArgumentParser(description="Import legacy cleaner data (disabled only)")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.input.is_symlink() or args.input.stat().st_size > 128 * 1024:
        raise SystemExit("Unsafe import input")
    raw = args.input.read_bytes()
    payload = json.loads(raw)
    result = import_payload(Store(args.data_dir), payload)
    # Never print account names, rule values, tokens or full input.
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
