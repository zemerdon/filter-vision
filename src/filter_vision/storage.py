"""SQLite schema and secure local storage. No mailbox actions in this release."""
from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 2
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


class Store:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.db_path = self.directory / "filter-vision.sqlite3"
        self._init_db()
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
        os.chmod(self.db_path, 0o600)

    def audit(self, event: str, detail: str):
        import time
        with self.db() as con:
            con.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                        (int(time.time()), event, detail[:240]))
