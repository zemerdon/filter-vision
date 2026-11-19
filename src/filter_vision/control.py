"""Constrained read-only systemd status and privileged cleaner-control queue.

The trusted-network WebUI can only request pre-approved actions. A separately
installed root-owned systemd.path handler validates the fixed action schema,
root-owned legacy approval and timer state; it never runs user shell input.
"""
from __future__ import annotations

import argparse
import fcntl
import grp
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .live import load_policy, LiveSafetyError

TIMER = "filter-vision-cleaner.timer"
SERVICE = "filter-vision-cleaner.service"
CONTROL_PATH_UNIT = "filter-vision-control.path"
REQUEST = "cleaner-control-request"
STATUS_PATH = Path("/var/lib/filter-vision-control/status.json")
OVERRIDE = Path("/etc/systemd/system/filter-vision-cleaner.timer.d/10-schedule.conf")
INTERVALS = (5, 10, 15, 20, 30, 60, 120, 240, 360, 720, 1440)
ACTIONS = ("start", "stop", "restart", "run-now", "set-interval")
STATUS_FIELDS = {
    "timer": ("ActiveState", "UnitFileState", "LastTriggerUSec",
              "NextElapseUSecRealtime"),
    "service": ("ActiveState", "Result", "ExecMainStatus",
                "ExecMainStartTimestamp", "ExecMainExitTimestamp"),
}


class ControlError(RuntimeError):
    """Safe errors never contain command stderr or user-controlled data."""


def calendar_for(minutes: int) -> str:
    if type(minutes) is not int or minutes not in INTERVALS:
        raise ControlError("Unsupported schedule interval")
    if minutes < 60:
        return f"*-*-* *:00/{minutes}:00"
    hours = minutes // 60
    return ("*-*-* *:00:00" if hours == 1 else
            "*-*-* 00:00:00" if hours == 24 else
            f"*-*-* 00/{hours}:00:00")


def _read_interval(path: Path = OVERRIDE) -> int:
    try:
        content = path.read_text(encoding="ascii")
        if len(content) > 256:
            return 30
        match = re.fullmatch(r"\[Timer\]\nOnCalendar=\nOnCalendar=(.+)\n",
                             content)
        if match:
            for minutes in INTERVALS:
                if match.group(1) == calendar_for(minutes):
                    return minutes
    except (ValueError, OSError, UnicodeError):
        pass
    return 30


def _show_unit(name: str, fields: tuple[str, ...]) -> dict:
    if name not in (TIMER, SERVICE, CONTROL_PATH_UNIT):
        raise ControlError("Unknown service")
    try:
        completed = subprocess.run(
            ["systemctl", "show", name, "--no-pager",
             "--property=" + ",".join(fields)],
            capture_output=True, text=True, timeout=3, check=True,
        )
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return {key: "unknown" for key in fields}
    values = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in fields:
            values[key] = value[:120]
    return {key: values.get(key, "unknown") for key in fields}


def service_status() -> dict:
    timer = _show_unit(TIMER, STATUS_FIELDS["timer"])
    cleaner = _show_unit(SERVICE, STATUS_FIELDS["service"])
    return {
        "timer": timer,
        "service": cleaner,
        "interval": _read_interval(),
        "schedule_active": timer["ActiveState"] == "active",
        "scan_running": cleaner["ActiveState"] in ("activating", "active"),
        "available": timer["ActiveState"] != "unknown",
    }


def _bounded_status(path: Path = STATUS_PATH) -> dict:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2048:
            return {}
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("state") not in (
                "success", "failed", "processing"):
            return {}
        return {
            "state": result["state"],
            "action": str(result.get("action", ""))[:32],
            "detail": str(result.get("detail", ""))[:180],
            "updated_at": str(result.get("updated_at", ""))[:40],
        }
    except (OSError, ValueError, UnicodeError):
        return {}


def control_view(data_dir: Path) -> dict:
    result = service_status()
    path_state = _show_unit(CONTROL_PATH_UNIT, ("ActiveState",))
    result["control_installed"] = (STATUS_PATH.parent.is_dir()
                                  and path_state["ActiveState"] == "active")
    result["request_pending"] = (data_dir / REQUEST).exists()
    result["last_action"] = _bounded_status()
    return result


def request_control(data_dir: Path, action: str, interval: int | None = None) -> bool:
    if action not in ACTIONS:
        raise ControlError("Unsupported cleaner action")
    if action == "set-interval":
        calendar_for(interval)
    elif interval is not None:
        raise ControlError("Interval not permitted for this action")
    payload = json.dumps({"schema": 1, "action": action,
                          "minutes": interval}, separators=(",", ":")).encode()
    # PathExists= watches the final filename. Publish a complete, synced
    # request atomically; opening the watched filename before filling it can
    # race with the privileged consumer and drop an otherwise valid command.
    fd, temporary = tempfile.mkstemp(prefix=".cleaner-request.", dir=data_dir)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, data_dir / REQUEST, follow_symlinks=False)
        except FileExistsError:
            return False
        return True
    finally:
        os.unlink(temporary)


def _systemctl(*args: str) -> None:
    try:
        subprocess.run(["systemctl", *args], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=360 if args == ("start", SERVICE) else 30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ControlError("System service rejected the requested operation") from None


def _write_interval(minutes: int, override: Path = OVERRIDE) -> None:
    expression = calendar_for(minutes)
    override.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if override.parent.is_symlink() or override.is_symlink():
        raise ControlError("Unsafe timer override path")
    parent_state = override.parent.stat()
    if parent_state.st_uid != 0 or parent_state.st_mode & 0o022:
        raise ControlError("Insecure timer configuration directory")
    fd, tmp = tempfile.mkstemp(prefix=".schedule.", dir=override.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(f"[Timer]\nOnCalendar=\nOnCalendar={expression}\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, override)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _execute(action: str, interval: int | None = None,
             *, check_policy=load_policy) -> str:
    if action not in ACTIONS:
        raise ControlError("Unsupported cleaner action")
    if action == "set-interval":
        calendar_for(interval)
    elif interval is not None:
        raise ControlError("Interval not permitted for this action")
    # Stop is always permitted, even if the approval policy is damaged.
    if action != "stop":
        try:
            check_policy()
        except (LiveSafetyError, OSError, ValueError, KeyError, TypeError):
            raise ControlError("Root cleaner approval is missing or invalid") from None
    state = service_status()
    if not state["available"]:
        raise ControlError("Cleaner service status is unavailable")
    if action == "start":
        _systemctl("enable", "--now", TIMER)
        return "Automatic cleaning schedule started"
    if action == "stop":
        _systemctl("disable", "--now", TIMER)
        return "Schedule paused; an already running scan is not interrupted"
    if action == "restart":
        if not state["schedule_active"]:
            raise ControlError("Schedule is paused; use Start to resume")
        _systemctl("restart", TIMER)
        return "Automatic cleaning schedule restarted"
    if action == "run-now":
        if state["scan_running"]:
            raise ControlError("A mailbox scan is already in progress")
        _systemctl("start", SERVICE)
        return "Immediate cleaner scan completed"
    if action == "set-interval":
        previous = OVERRIDE.read_bytes() if OVERRIDE.exists() else None
        try:
            _write_interval(interval)
            _systemctl("daemon-reload")
            if state["schedule_active"]:
                _systemctl("restart", TIMER)
        except (ControlError, OSError):
            # A rejected timer edit must not strand the original schedule.
            try:
                if previous is None:
                    OVERRIDE.unlink(missing_ok=True)
                else:
                    fd, tmp = tempfile.mkstemp(prefix=".restore.", dir=OVERRIDE.parent)
                    with os.fdopen(fd, "wb") as out:
                        out.write(previous)
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, OVERRIDE)
                _systemctl("daemon-reload")
                if state["schedule_active"]:
                    _systemctl("restart", TIMER)
            except (ControlError, OSError):
                raise ControlError("Schedule change failed; previous timer needs attention") from None
            raise ControlError("Schedule rejected; previous timer setting restored") from None
        return f"Schedule set to every {interval} minutes"
    raise ControlError("Unknown operation")


def _write_status(state: str, action: str, detail: str,
                  directory: Path = STATUS_PATH.parent):
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".status.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump({
                "state": state,
                "action": action[:32],
                "detail": detail[:180],
                "updated_at": datetime.now(tz=ZoneInfo("Australia/Brisbane")).isoformat(),
            }, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chown(tmp, 0, grp.getgrnam("filtervision").gr_gid)
        os.chmod(tmp, 0o640)
        os.replace(tmp, directory / "status.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def consume_request(data_dir: Path, *, uid: int, status_dir: Path = STATUS_PATH.parent):
    request = data_dir / REQUEST
    fd = None
    action = "unknown"
    try:
        fd = os.open(request, os.O_RDONLY | os.O_NOFOLLOW)
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > 512):
            raise ControlError("Unsafe control request")
        payload = os.read(fd, 513)
        if len(payload) > 512:
            raise ControlError("Oversized control request")
        data = json.loads(payload)
        if (not isinstance(data, dict) or set(data) != {"schema", "action", "minutes"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or type(data["action"]) is not str):
            raise ControlError("Invalid control request")
        action = data["action"]
        interval = data["minutes"]
        if action not in ACTIONS:
            raise ControlError("Unsupported cleaner action")
        if action == "set-interval":
            calendar_for(interval)
        elif interval is not None:
            raise ControlError("Invalid interval")
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise ControlError("Invalid or unreadable control request") from None
    finally:
        if fd is not None:
            os.close(fd)
        request.unlink(missing_ok=True)
    _write_status("processing", action, "Operation in progress", status_dir)
    try:
        detail = _execute(action, interval)
        _write_status("success", action, detail, status_dir)
    except ControlError as error:
        _write_status("failed", action, str(error), status_dir)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("execute",))
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--request-uid", required=True, type=int)
    args = parser.parse_args()
    lock = os.open("/run/lock/filter-vision-control.lock",
                   os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (args.data_dir / REQUEST).exists():
            consume_request(args.data_dir, uid=args.request_uid)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
