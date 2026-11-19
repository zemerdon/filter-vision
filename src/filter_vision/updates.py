"""Stable-only update request interface; no privileged actions in the WebUI."""
from __future__ import annotations
import json
import os
from pathlib import Path


def status() -> dict:
    path = Path(os.environ.get(
        "FV_UPDATE_STATUS_PATH", "/var/lib/filter-vision-updater/status.json"))
    try:
        with path.open("rb") as f:
            payload = f.read(16 * 1024 + 1)
        if len(payload) > 16 * 1024:
            return {"state": "error", "detail": "Update status oversized"}
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Bad status type")
        return {
            "state": str(data.get("state", "unknown"))[:48],
            "detail": str(data.get("detail", ""))[:500],
            "version": str(data.get("version", ""))[:36],
            "updated_at": str(data.get("updated_at", ""))[:40],
        }
    except FileNotFoundError:
        return {}
    except (ValueError, OSError, UnicodeError):
        return {"state": "error", "detail": "Cannot read update status"}


def request_update(data_dir: Path) -> bool:
    """Atomically trigger only the fixed latest stable update action.

    A root-owned systemd.path unit listens for this file. The WebUI cannot
    choose an arbitrary executable, URL, shell command, or version.
    """
    request = data_dir / "update-request"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(request, flags, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(b"latest-stable\n")
        f.flush()
        os.fsync(f.fileno())
    return True
