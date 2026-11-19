"""SQLite schema and secure local storage. No mailbox actions in this release."""
from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
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


class Store:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.db_path = self.directory / "filter-vision.sqlite3"
        self.setup_path = self.directory / "setup-token"
        self._init_db()

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
        os.chmod(self.db_path, 0o600)
        # A first-run bootstrap secret is required before admin creation.
        if not self.has_admin() and not self.setup_path.exists():
            fd = os.open(self.setup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(32) + "\n")
        if self.setup_path.exists():
            os.chmod(self.setup_path, 0o600)

    def has_admin(self) -> bool:
        with self.db() as con:
            return con.execute("SELECT 1 FROM admins WHERE id=1").fetchone() is not None

    def audit(self, event: str, detail: str):
        import time
        with self.db() as con:
            con.execute("INSERT INTO audit_events(created_at,event,detail) VALUES(?,?,?)",
                        (int(time.time()), event, detail[:240]))
