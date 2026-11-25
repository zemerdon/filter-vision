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
RULE_ACTIONS = ("enable-rule", "disable-rule")
MANAGED_ACTIONS = ("legacy-enable", "legacy-disable", "legacy-edit", "custom-edit")
BATCH_ACTION = "enable-batch"
MAX_BATCH_CONTROL_BYTES = 8192


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
        rule_id = result.get("rule_id")
        batch_id = result.get("batch_id")
        batch_id = batch_id if type(batch_id) is str and re.fullmatch(r"[a-f0-9]{24}", batch_id) else None
        return {
            "batch_id": batch_id,
            "state": result["state"],
            "action": str(result.get("action", ""))[:32],
            "detail": str(result.get("detail", ""))[:180],
            "updated_at": str(result.get("updated_at", ""))[:40],
            "rule_id": rule_id if type(rule_id) is int and 0 < rule_id < 2**63 else None,
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


def request_rule_control(data_dir: Path, action: str, rule_id: int,
                         accounts: list[int], source_sha256: str) -> bool:
    """Queue exactly one root-managed, per-account rule transition.

    This is not a shell command and cannot change the 22 legacy rules.
    The root handler revalidates the source SHA, account scopes, legacy
    approval and draft restrictions before committing root-owned policy.
    """
    from .rule_activation import HEX
    if action not in RULE_ACTIONS:
        raise ControlError("Unsupported rule action")
    if (type(rule_id) is not int or not 1 <= rule_id < 2**63
            or type(accounts) is not list or not accounts or len(accounts) > 2
            or len(set(accounts)) != len(accounts)
            or any(type(i) is not int or i not in (1, 2) for i in accounts)
            or type(source_sha256) is not str or not HEX.fullmatch(source_sha256)):
        raise ControlError("Invalid rule transition request")
    payload = json.dumps({
        "schema": 2, "action": action, "rule_id": rule_id,
        "accounts": sorted(accounts), "source_sha256": source_sha256,
    }, separators=(",", ":")).encode()
    fd, temporary = tempfile.mkstemp(prefix=".rule-request.", dir=data_dir)
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


def request_managed_control(data_dir: Path, action: str, rule_id: int,
                            fingerprint: str, override: dict | None = None,
                            *, activate: bool = False) -> bool:
    """One action, no confirmation UI: send fixed validated metadata to root."""
    from .managed_rules import HEX, normalize, ManagedError
    if (action not in MANAGED_ACTIONS or type(rule_id) is not int
            or not 1 <= rule_id < 2**63 or type(fingerprint) is not str
            or not HEX.fullmatch(fingerprint) or type(activate) is not bool
            or ((action.endswith("-edit")) != (override is not None))):
        raise ControlError("Invalid managed rule operation")
    if override is not None:
        try:
            if type(override) is not dict or set(override) != {
                    "kind", "field", "pattern", "label"}:
                raise ControlError("Invalid managed rule fields")
            override = normalize(
                override["kind"], override["field"], override["pattern"],
                override["label"])
        except ManagedError:
            raise ControlError("Invalid managed rule matcher") from None
    payload = json.dumps({
        "schema": 3, "action": action, "rule_id": rule_id,
        "source_sha256": fingerprint, "override": override,
        "activate": activate,
    }, separators=(",", ":"), ensure_ascii=False).encode()
    if len(payload) > 1536:
        raise ControlError("Rule control request too large")
    fd, temporary = tempfile.mkstemp(prefix=".managed-request.", dir=data_dir)
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


def request_batch_enable(data_dir: Path, entries: list[dict],
                         accounts: list[int], batch_id: str) -> bool:
    """Queue a bounded list of source fingerprints for one root policy write."""
    from .rule_activation import HEX
    if (type(batch_id) is not str or not re.fullmatch(r"[a-f0-9]{24}", batch_id)
            or type(entries) is not list or not 1 <= len(entries) <= 32
            or type(accounts) is not list or not accounts or len(accounts) > 2
            or len(set(accounts)) != len(accounts)
            or any(type(i) is not int or i not in (1, 2) for i in accounts)):
        raise ControlError("Invalid batch activation request")
    ids = set()
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {"id", "sha256"}
                or type(entry["id"]) is not int or not 1 <= entry["id"] < 2**63
                or entry["id"] in ids
                or type(entry["sha256"]) is not str or not HEX.fullmatch(entry["sha256"])):
            raise ControlError("Invalid batch activation source")
        ids.add(entry["id"])
    payload = json.dumps({
        "schema": 4, "action": BATCH_ACTION, "batch_id": batch_id,
        "accounts": sorted(accounts), "entries": entries,
    }, separators=(",", ":")).encode()
    if len(payload) > MAX_BATCH_CONTROL_BYTES:
        raise ControlError("Batch request too large")
    fd, temporary = tempfile.mkstemp(prefix=".batch-request.", dir=data_dir)
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


def _apply_batch_request(data_dir: Path, data: dict) -> str:
    from .rule_activation import apply_batch_approvals, ActivationError
    from .storage import Store
    db_path = data_dir / "filter-vision.sqlite3"
    if db_path.is_symlink() or not db_path.is_file():
        raise ControlError("Rule database unavailable")
    state = service_status()
    if state["service"]["ActiveState"] == "unknown" or state["scan_running"]:
        raise ControlError("Cleaner state unavailable or busy; batch not activated")
    try:
        store = Store(data_dir)
        store.audit("root_rule_batch_attempted", f"count={len(data['entries'])}")
        result = apply_batch_approvals(store, data["entries"], data["accounts"])
        store.audit("root_rule_batch_enabled", f"count={len(data['entries'])}")
        return result
    except (ActivationError, OSError, ValueError, TypeError):
        raise ControlError("Protected batch approval rejected; no batch activated") from None


def request_rules_bulk(data_dir: Path, entries: list[dict],
                       accounts: list[int], action: str, batch_id: str) -> bool:
    """Queue one protected enable/disable transition across selected rule IDs."""
    from .bulk_rule_management import MAX_RULES_BULK
    from .rule_activation import HEX
    if (action not in ("rules-enable", "rules-disable")
            or type(batch_id) is not str or not re.fullmatch(r"[a-f0-9]{24}", batch_id)
            or type(entries) is not list or not 1 <= len(entries) <= MAX_RULES_BULK
            or type(accounts) is not list or not accounts or len(accounts)>2
            or len(set(accounts)) != len(accounts)
            or any(type(i) is not int or i not in (1,2) for i in accounts)):
        raise ControlError("Invalid selected rules")
    seen = set()
    for item in entries:
        if (type(item) is not dict or set(item) != {"id","sha256"}
                or type(item["id"]) is not int or not 1 <= item["id"] < 2**63
                or item["id"] in seen or type(item["sha256"]) is not str
                or not HEX.fullmatch(item["sha256"])):
            raise ControlError("Invalid selected rule source")
        seen.add(item["id"])
    payload = json.dumps({
        "schema":5, "action":action, "batch_id":batch_id,
        "accounts":sorted(accounts), "entries":entries,
    },separators=(",",":")).encode()
    if len(payload)>MAX_BATCH_CONTROL_BYTES:
        raise ControlError("Rule selection exceeds control size limit")
    fd,temp = tempfile.mkstemp(prefix=".rules-bulk.",dir=data_dir)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp,0o600)
        try:
            os.link(temp,data_dir/REQUEST,follow_symlinks=False)
        except FileExistsError:
            return False
        return True
    finally:
        os.unlink(temp)


def _apply_rules_bulk_request(data_dir: Path, data: dict) -> str:
    from .bulk_rule_management import apply_root_bulk_rule_state, RuleManagementError
    from .storage import Store
    db_path = data_dir / "filter-vision.sqlite3"
    if db_path.is_symlink() or not db_path.is_file():
        raise ControlError("Rule database unavailable")
    scanner = service_status()
    if scanner["service"]["ActiveState"] == "unknown" or scanner["scan_running"]:
        raise ControlError("Cleaner unavailable or busy; no rule action applied")
    try:
        store=Store(data_dir)
        store.audit("root_rules_bulk_attempted", f"count={len(data['entries'])} action={data['action']}")
        result=apply_root_bulk_rule_state(
            store,data["entries"],data["accounts"],data["action"]=="rules-enable")
        store.audit("root_rules_bulk_changed", f"count={len(data['entries'])} action={data['action']}")
        return result
    except (RuleManagementError,LiveSafetyError,OSError,ValueError,TypeError):
        raise ControlError("Protected bulk rule transition rejected") from None


def _apply_managed_request(data_dir: Path, data: dict) -> str:
    from .managed_rules import apply_managed, ManagedError
    from .storage import Store
    db_path = data_dir / "filter-vision.sqlite3"
    if db_path.is_symlink() or not db_path.is_file():
        raise ControlError("Managed rule database unavailable")
    state = service_status()
    if state["service"]["ActiveState"] == "unknown" or state["scan_running"]:
        raise ControlError("Cleaner scan state unavailable or busy; retry rule change")
    try:
        store = Store(data_dir)
        store.audit("root_managed_rule_attempted",
                    "rule_id=%d action=%s" % (data["rule_id"], data["action"]))
        result = apply_managed(
            store, data["action"], data["rule_id"], data["source_sha256"],
            override=data["override"], activate=data["activate"])
        store.audit("root_managed_rule_changed",
                    "rule_id=%d action=%s" % (data["rule_id"], data["action"]))
        return result
    except (ManagedError, OSError, ValueError, TypeError):
        raise ControlError("Protected managed rule change was rejected") from None


def _apply_rule_request(data_dir: Path, action: str, rule_id: int,
                        accounts: list[int], source_sha256: str) -> str:
    from .rule_activation import apply_approval, ActivationError
    from .storage import Store
    db_path = data_dir / "filter-vision.sqlite3"
    if db_path.is_symlink() or not db_path.is_file():
        raise ControlError("Rule database unavailable")
    scanner = service_status()
    if scanner["service"]["ActiveState"] == "unknown":
        raise ControlError("Cannot verify cleaner state; rule change rejected")
    if scanner["scan_running"]:
        raise ControlError("Cleaner scan is running; retry rule change afterwards")
    try:
        store = Store(data_dir)
        # Persist the attempted transition BEFORE touching root-owned approval
        # state. A failed audit write must never produce an unlogged deletion
        # authorization. A second event marks successful completion.
        store.audit("root_rule_change_attempted",
                    f"rule_id={rule_id} action={action} accounts={len(accounts)}")
        text = apply_approval(store, action, rule_id, accounts, source_sha256)
        store.audit("root_rule_approval_changed",
                    f"rule_id={rule_id} action={action} accounts={len(accounts)}")
        return text
    except (ActivationError, OSError, ValueError, TypeError):
        raise ControlError("Root rule approval rejected; inspect rule and accounts") from None


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
                  directory: Path = STATUS_PATH.parent, *, rule_id: int | None = None,
                  batch_id: str | None = None):
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".status.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            payload = {
                "state": state,
                "action": action[:32],
                "detail": detail[:180],
                "updated_at": datetime.now(tz=ZoneInfo("Australia/Brisbane")).isoformat(),
            }
            if rule_id is not None:
                payload["rule_id"] = rule_id
            if batch_id is not None:
                payload["batch_id"] = batch_id
            json.dump(payload, output)
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
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_size > MAX_BATCH_CONTROL_BYTES):
            raise ControlError("Unsafe control request")
        payload = os.read(fd, MAX_BATCH_CONTROL_BYTES + 1)
        if len(payload) > MAX_BATCH_CONTROL_BYTES:
            raise ControlError("Oversized control request")
        data = json.loads(payload)
        if not isinstance(data, dict) or type(data.get("schema")) is not int:
            raise ControlError("Invalid control request")
        if data["schema"] != 4 and len(payload) > 1536:
            raise ControlError("Oversized legacy control request")
        if data["schema"] == 1:
            if (set(data) != {"schema", "action", "minutes"}
                    or type(data["action"]) is not str):
                raise ControlError("Invalid control request")
            action, interval = data["action"], data["minutes"]
            if action not in ACTIONS:
                raise ControlError("Unsupported cleaner action")
            if action == "set-interval":
                calendar_for(interval)
            elif interval is not None:
                raise ControlError("Invalid interval")
        elif data["schema"] == 2:
            from .rule_activation import HEX
            if (set(data) != {"schema", "action", "rule_id", "accounts", "source_sha256"}
                    or data["action"] not in RULE_ACTIONS
                    or type(data["rule_id"]) is not int
                    or not 1 <= data["rule_id"] < 2**63
                    or type(data["accounts"]) is not list
                    or not data["accounts"]
                    or len(data["accounts"]) > 2
                    or any(type(i) is not int or i not in (1, 2)
                           for i in data["accounts"])
                    or len(set(data["accounts"])) != len(data["accounts"])
                    or type(data["source_sha256"]) is not str
                    or not HEX.fullmatch(data["source_sha256"])):
                raise ControlError("Invalid rule control request")
            action, interval = data["action"], None
        elif data["schema"] == 3:
            from .managed_rules import HEX, normalize, ManagedError
            if (set(data) != {"schema", "action", "rule_id", "source_sha256",
                             "override", "activate"}
                    or data["action"] not in MANAGED_ACTIONS
                    or type(data["rule_id"]) is not int or
                    not 1 <= data["rule_id"] < 2**63
                    or type(data["source_sha256"]) is not str or
                    not HEX.fullmatch(data["source_sha256"])
                    or type(data["activate"]) is not bool
                    or (data["override"] is not None) != data["action"].endswith("-edit")):
                raise ControlError("Invalid managed-rule request")
            if data["override"] is not None:
                try:
                    override = data["override"]
                    if type(override) is not dict or set(override) != {
                            "kind", "field", "pattern", "label"}:
                        raise ControlError("Invalid managed rule fields")
                    normalize(override["kind"], override["field"],
                              override["pattern"], override["label"])
                except ManagedError:
                    raise ControlError("Invalid managed rule matcher") from None
            action, interval = data["action"], None
        elif data["schema"] == 4:
            from .rule_activation import HEX
            items = data.get("entries")
            accounts = data.get("accounts")
            if (set(data) != {"schema", "action", "batch_id", "accounts", "entries"}
                    or data["action"] != BATCH_ACTION
                    or type(data["batch_id"]) is not str
                    or not re.fullmatch(r"[a-f0-9]{24}", data["batch_id"])
                    or type(items) is not list or not 1 <= len(items) <= 32
                    or type(accounts) is not list or not accounts
                    or len(accounts) > 2 or len(set(accounts)) != len(accounts)
                    or any(type(i) is not int or i not in (1, 2) for i in accounts)):
                raise ControlError("Invalid batch control request")
            ids = set()
            for item in items:
                if (type(item) is not dict or set(item) != {"id", "sha256"}
                        or type(item["id"]) is not int
                        or not 1 <= item["id"] < 2**63 or item["id"] in ids
                        or type(item["sha256"]) is not str
                        or not HEX.fullmatch(item["sha256"])):
                    raise ControlError("Invalid batch source")
                ids.add(item["id"])
            action, interval = BATCH_ACTION, None
        elif data["schema"] == 5:
            from .rule_activation import HEX
            items=data.get("entries")
            accounts=data.get("accounts")
            if (set(data)!={"schema","action","batch_id","accounts","entries"}
                    or data["action"] not in ("rules-enable","rules-disable")
                    or type(data["batch_id"]) is not str
                    or not re.fullmatch(r"[a-f0-9]{24}",data["batch_id"])
                    or type(items) is not list or not 1 <= len(items) <= 64
                    or type(accounts) is not list or not accounts or len(accounts)>2
                    or len(set(accounts))!=len(accounts)
                    or any(type(i) is not int or i not in (1,2) for i in accounts)):
                raise ControlError("Invalid Rules bulk request")
            ids=set()
            for item in items:
                if (type(item) is not dict or set(item)!={"id","sha256"}
                        or type(item["id"]) is not int or not 1 <= item["id"] < 2**63
                        or item["id"] in ids or type(item["sha256"]) is not str
                        or not HEX.fullmatch(item["sha256"])):
                    raise ControlError("Invalid Rules bulk source")
                ids.add(item["id"])
            action,interval=data["action"],None
        else:
            raise ControlError("Unsupported control request schema")
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise ControlError("Invalid or unreadable control request") from None
    finally:
        if fd is not None:
            os.close(fd)
        request.unlink(missing_ok=True)
    def update(state: str, detail: str):
        if data["schema"] in (2, 3):
            _write_status(state, action, detail, status_dir, rule_id=data["rule_id"])
        elif data["schema"] in (4,5):
            _write_status(state, action, detail, status_dir,
                          batch_id=data["batch_id"])
        else:
            _write_status(state, action, detail, status_dir)
    update("processing", "Operation in progress")
    try:
        detail = (_apply_rule_request(
            data_dir, action, data["rule_id"], data["accounts"],
            data["source_sha256"]) if data["schema"] == 2 else
            _apply_managed_request(data_dir, data) if data["schema"] == 3 else
            _apply_batch_request(data_dir, data) if data["schema"] == 4 else
            _apply_rules_bulk_request(data_dir, data) if data["schema"] == 5 else
            _execute(action, interval))
        update("success", detail)
    except ControlError as error:
        update("failed", str(error))
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
