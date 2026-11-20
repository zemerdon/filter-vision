"""SQLite schema and secure local storage. No mailbox actions in this release."""
from __future__ import annotations

import os
import secrets
import sqlite3
import json
import time
from cryptography.fernet import Fernet, InvalidToken
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 3
DDL = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id),
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    client TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    last_attempt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    provider TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    folder TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled = 0),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    field TEXT NOT NULL,
    pattern TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled = 0),
    action TEXT NOT NULL DEFAULT 'draft' CHECK (action = 'draft'),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL
);
PRAGMA user_version = 1;
"""

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS rule_scopes (
    rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY(rule_id, account_id)
);
CREATE TABLE IF NOT EXISTS legacy_imports (
    source_sha256 TEXT PRIMARY KEY,
    account_count INTEGER NOT NULL,
    rule_count INTEGER NOT NULL,
    imported_at INTEGER NOT NULL
);
PRAGMA user_version = 2;
"""

SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS app_preferences (
    id INTEGER PRIMARY KEY CHECK(id=1),
    activity_limit INTEGER NOT NULL DEFAULT 50 CHECK(activity_limit IN (25,50,100,250,500))
);
INSERT OR IGNORE INTO app_preferences(id,activity_limit) VALUES(1,50);
CREATE TABLE IF NOT EXISTS message_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    imap_uid INTEGER NOT NULL,
    rule_ids TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','deleted')),
    preview_ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_actions_date ON message_actions(created_at DESC);
PRAGMA user_version = 3;
"""
ACTIVITY_LIMITS = (25,50,100,250,500)


class Store:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.db_path = self.directory / "filter-vision.sqlite3"
        self._init_db()
        self.activity_key_path = self.directory / "activity.key"
        if not self.activity_key_path.exists():
            with self.db() as c:
                recorded = c.execute("SELECT COUNT(*) FROM message_actions").fetchone()[0]
            if recorded:
                raise RuntimeError("Activity encryption key missing from existing history")
            try:
                fd = os.open(self.activity_key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as out:
                    out.write(Fernet.generate_key())
        if self.activity_key_path.is_symlink():
            raise RuntimeError("Unsafe activity encryption key")
        os.chmod(self.activity_key_path, 0o600)
        self.activity_cipher = Fernet(self.activity_key_path.read_bytes())
        self.browser_key_path = self.directory / "browser-session.key"
        if not self.browser_key_path.exists():
            try:
                fd = os.open(self.browser_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as f:
                    f.write(secrets.token_bytes(32))
        os.chmod(self.browser_key_path, 0o600)
        self.browser_key = self.browser_key_path.read_bytes()
        if len(self.browser_key) != 32:
            raise RuntimeError("Invalid local browser-session key")
        # Legacy setup tokens are obsolete in passwordless mode.
        (self.directory / "setup-token").unlink(missing_ok=True)

    @contextmanager
    def db(self):
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=10000")
            yield con
            con.commit()
        except BaseException:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_db(self):
        with self.db() as con:
            ver = con.execute("PRAGMA user_version").fetchone()[0]
            if ver > SCHEMA_VERSION:
                raise RuntimeError("Database is newer than installed Filter Vision")
            if ver == 0:
                con.executescript(DDL)
                ver = 1
            if ver == 1:
                con.executescript(SCHEMA_V2)
                ver = 2
            if ver == 2:
                con.executescript(SCHEMA_V3)
        os.chmod(self.db_path, 0o600)

    def audit(self, event: str, detail: str):
        import time
        with self.db() as con:
            con.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                        (int(time.time()), event, detail[:240]))


    def activity_limit(self) -> int:
        with self.db() as con:
            row = con.execute("SELECT activity_limit FROM app_preferences WHERE id=1").fetchone()
        return int(row["activity_limit"]) if row else 50

    def set_activity_limit(self, limit: int) -> None:
        if type(limit) is not int or limit not in ACTIVITY_LIMITS:
            raise ValueError("Unsupported Activity entry limit")
        with self.db() as con:
            con.execute("UPDATE app_preferences SET activity_limit=? WHERE id=1", (limit,))

    def record_pending_action(self, account_id: int, uid: int,
                              rule_ids: list[int], preview: dict) -> int:
        if not rule_ids or len(rule_ids) > 22 or not all(
                type(r) is int and r > 0 for r in rule_ids):
            raise ValueError("Invalid matched rule IDs")
        if not 1 <= uid <= 2**63-1:
            raise ValueError("Invalid message UID")
        payload = json.dumps(preview, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > 16_384:
            raise ValueError("Oversized private message preview")
        cipher = self.activity_cipher.encrypt(payload)
        with self.db() as con:
            cursor = con.execute(
                "INSERT INTO message_actions(created_at,account_id,imap_uid,rule_ids,state,preview_ciphertext) "
                "VALUES(?,?,?,?,?,?)",
                (int(time.time()), account_id, uid, json.dumps(rule_ids), "pending", cipher))
            return int(cursor.lastrowid)

    def mark_action_deleted(self, action_id: int) -> None:
        with self.db() as con:
            row = con.execute(
                "UPDATE message_actions SET state='deleted' WHERE id=? AND state='pending'",
                (action_id,))
            if row.rowcount != 1:
                raise RuntimeError("Cannot mark unknown pending mail action")

    def decrypt_message_preview(self, encrypted: bytes) -> dict:
        try:
            result = json.loads(self.activity_cipher.decrypt(encrypted))
            if not isinstance(result, dict):
                raise ValueError("Invalid preview structure")
            return {key: str(result.get(key, ""))[:4096 if key == "body" else 400]
                    for key in ("from", "to", "subject", "date", "body")}
        except (InvalidToken, ValueError, TypeError, UnicodeError):
            return {"from": "", "to": "", "subject": "Preview unavailable",
                    "date": "", "body": "Private preview could not be decrypted"}
