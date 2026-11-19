"""Encrypted and verified Filter Vision configuration/OAuth state recovery.

Never print secrets. Restores only into NEW EMPTY staging directories; operators
must stop services and verify before manually promoting a restore to live state.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import stat
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FVBK1"
MAX_ARCHIVE = 64 * 1024 * 1024
CONFIG_NAMES = {"web.env", "tls.crt", "tls.key", "oauth-clients.json",
                "cleaner-policy.json", "legacy-offline"}
DATA_NAMES = {"browser-session.key", "oauth/fernet.key", "filter-vision.sqlite3"}


class BackupError(RuntimeError):
    pass


def _allowed(name: str) -> bool:
    return name in {f"data/{v}" for v in DATA_NAMES} | {
        f"config/{v}" for v in CONFIG_NAMES} or bool(
        re.fullmatch(r"data/oauth/[1-9]\d*\.token", name)
    )


def create_key(path: Path):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(secrets.token_bytes(32))


def _read_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise BackupError("Missing or insecure backup recovery key")
    key = path.read_bytes()
    if len(key) != 32:
        raise BackupError("Invalid backup recovery key")
    return key


def _read_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise BackupError("Missing/unsafe/oversized backup file")
    return path.read_bytes()


def _snapshot_database(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BackupError("Database missing or symlink")
    with tempfile.TemporaryDirectory() as name:
        output = Path(name) / "snapshot.sqlite3"
        source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        destination = sqlite3.connect(output)
        try:
            source.backup(destination)
            if destination.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("SQLite snapshot integrity failure")
        finally:
            destination.close()
            source.close()
        return _read_file(output)


def _collect(data_dir: Path, config_dir: Path) -> dict[str, bytes]:
    files = {"data/filter-vision.sqlite3":
             _snapshot_database(data_dir / "filter-vision.sqlite3")}
    for name in DATA_NAMES - {"filter-vision.sqlite3"}:
        p = data_dir / name
        if p.exists() or p.is_symlink():
            files[f"data/{name}"] = _read_file(p)
    p = data_dir / "oauth"
    if p.exists() and (p.is_symlink() or not p.is_dir()):
        raise BackupError("Unsafe OAuth vault directory")
    if p.exists():
        for token in sorted(p.glob("*.token")):
            if not _allowed(f"data/oauth/{token.name}"):
                raise BackupError("Unexpected token filename")
            files[f"data/oauth/{token.name}"] = _read_file(token)
    if any(k.endswith(".token") for k in files) and "data/oauth/fernet.key" not in files:
        raise BackupError("OAuth key missing from backup")
    for name in CONFIG_NAMES:
        f = config_dir / name
        if f.exists() or f.is_symlink():
            files[f"config/{name}"] = _read_file(f)
    if sum(len(x) for x in files.values()) > MAX_ARCHIVE:
        raise BackupError("Backup too large")
    return files


def _pack(files: dict[str, bytes]) -> bytes:
    meta = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    meta_payload = json.dumps({"format": 1, "hashes": meta}, sort_keys=True).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in sorted({**files, "manifest.json": meta_payload}.items()):
            if name != "manifest.json" and not _allowed(name):
                raise BackupError("Unsupported data in encrypted backup")
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def _unpack(payload: bytes) -> dict[str, bytes]:
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if not 2 <= len(members) <= 60:
                raise BackupError("Unexpected backup contents")
            for member in members:
                name = member.name
                if (not member.isfile() or name in files or member.size > MAX_ARCHIVE
                        or (name != "manifest.json" and not _allowed(name))):
                    raise BackupError("Unsupported archive entry")
                f = archive.extractfile(member)
                if f is None:
                    raise BackupError("Unreadable backup entry")
                files[name] = f.read(MAX_ARCHIVE + 1)
    except (tarfile.TarError, OSError, EOFError):
        raise BackupError("Invalid encrypted archive contents") from None
    try:
        manifest = json.loads(files.pop("manifest.json"))
        expected = manifest["hashes"]
    except (KeyError, ValueError, TypeError):
        raise BackupError("Backup manifest missing or invalid") from None
    if (manifest.get("format") != 1 or set(expected) != set(files)
            or not all(hashlib.sha256(data).hexdigest() == expected[name]
                       for name, data in files.items())):
        raise BackupError("Backup content integrity failure")
    if "data/filter-vision.sqlite3" not in files:
        raise BackupError("Backup has no SQLite state")
    with tempfile.TemporaryDirectory() as name:
        p = Path(name) / "test.sqlite3"
        p.write_bytes(files["data/filter-vision.sqlite3"])
        connection = sqlite3.connect(p)
        try:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("Backup database integrity failure")
        finally:
            connection.close()
    if any(name.endswith(".token") for name in files) and "data/oauth/fernet.key" not in files:
        raise BackupError("Encrypted OAuth tokens without vault key")
    return files


def backup(data_dir: Path, config_dir: Path, destination: Path, key: Path):
    files = _collect(data_dir, config_dir)
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_read_key(key))
    encrypted = MAGIC + nonce + cipher.encrypt(nonce, _pack(files), MAGIC)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    verify(destination, key)


def verify(archive: Path, key: Path) -> dict[str, bytes]:
    encrypted = _read_file(archive)
    if not encrypted.startswith(MAGIC) or len(encrypted) < 48:
        raise BackupError("Invalid encrypted backup")
    nonce = encrypted[len(MAGIC):len(MAGIC) + 12]
    try:
        payload = AESGCM(_read_key(key)).decrypt(
            nonce, encrypted[len(MAGIC) + 12:], MAGIC,
        )
    except Exception:
        raise BackupError("Backup decrypt/authenticity check failed") from None
    if len(payload) > MAX_ARCHIVE:
        raise BackupError("Decrypted backup too large")
    return _unpack(payload)


def restore_staging(archive: Path, key: Path, data_dest: Path, config_dest: Path):
    # This cannot overwrite live data. Operators stage/test recovery separately.
    for dest in (data_dest, config_dest):
        if dest.is_symlink() or dest.exists():
            raise BackupError("Restore destination must not exist")
    files = verify(archive, key)
    for dest in (data_dest, config_dest):
        dest.mkdir(mode=0o700, parents=True)
    for name, content in sorted(files.items()):
        dest = data_dest if name.startswith("data/") else config_dest
        rel = name.split("/", 1)[1]
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(content)
    return {"files": len(files), "token_files": sum(n.endswith(".token") for n in files)}


def main():
    parser = argparse.ArgumentParser(description="Private encrypted full-state backup and staging")
    parser.add_argument("operation", choices=["init-key", "backup", "verify", "restore-staging"])
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--restore-data", type=Path)
    parser.add_argument("--restore-config", type=Path)
    args = parser.parse_args()
    if args.operation == "init-key":
        create_key(args.key)
        print("Recovery encryption key initialized")
    elif args.operation == "backup":
        backup(args.data_dir, args.config_dir, args.archive, args.key)
        print("Encrypted full backup created and verified")
    elif args.operation == "verify":
        files = verify(args.archive, args.key)
        print(f"Encrypted backup integrity confirmed: {len(files)} files")
    else:
        info = restore_staging(args.archive, args.key, args.restore_data, args.restore_config)
        print(f"Offline staging restore verified: {info['files']} files, "
              f"{info['token_files']} encrypted account tokens")


if __name__ == "__main__":
    main()
