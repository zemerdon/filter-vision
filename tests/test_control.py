"""Fixed-action privileged helper and read-only Settings UI regression tests."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import filter_vision.app as app_module
import filter_vision.control as control


@pytest.mark.parametrize("minutes", control.INTERVALS)
def test_calendar_is_allowlisted_and_deterministic(minutes):
    text = control.calendar_for(minutes)
    assert text.startswith("*-*-* ")
    assert "\n" not in text
    assert control.INTERVALS.count(minutes) == 1


@pytest.mark.parametrize("minutes", [0, 1, 4, 7, 16, 1441, True, False,
                                       "30", "30; rm -rf /", None])
def test_calendar_rejects_untrusted_intervals(minutes):
    with pytest.raises(control.ControlError):
        control.calendar_for(minutes)


def test_form_queue_validates_actions_and_is_atomic(tmp_path):
    assert control.request_control(tmp_path, "set-interval", 15)
    path = tmp_path / control.REQUEST
    data = json.loads(path.read_text())
    assert data == {"schema": 1, "action": "set-interval", "minutes": 15}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".cleaner-request.*"))
    assert not control.request_control(tmp_path, "stop")
    assert not list(tmp_path.glob(".cleaner-request.*"))
    for action, minutes in [
        ("", None), ("systemctl stop ssh.service", None),
        ("restart; reboot", None), ("run-now", 30), ("start", 15),
        ("set-interval", 7), ("set-interval", True),
    ]:
        with pytest.raises(control.ControlError):
            control.request_control(tmp_path, action, minutes)
    path.unlink()
    assert control.request_control(tmp_path, "stop")
    assert json.loads(path.read_text())["minutes"] is None


def test_root_consumer_is_single_use_and_reports_safe_status(tmp_path, monkeypatch):
    assert control.request_control(tmp_path, "restart")
    statuses = []
    calls = []
    monkeypatch.setattr(control, "_write_status",
                        lambda state, action, detail, directory: statuses.append((state, action, detail)))
    monkeypatch.setattr(control, "_execute",
                        lambda action, interval: calls.append((action, interval)) or "Restarted")
    control.consume_request(tmp_path, uid=os.getuid(), status_dir=tmp_path/"status")
    assert not (tmp_path / control.REQUEST).exists()
    assert calls == [("restart", None)]
    assert statuses == [("processing", "restart", "Operation in progress"),
                        ("success", "restart", "Restarted")]


def test_root_consumer_fails_closed_on_bad_owner_or_permissions(tmp_path, monkeypatch):
    request = tmp_path / control.REQUEST
    request.write_text('{"schema": 1, "action": "stop", "minutes": null}')
    request.chmod(0o644)
    monkeypatch.setattr(control, "_execute",
                        lambda *a, **kw: pytest.fail("Unsafe request executed"))
    with pytest.raises(control.ControlError, match="Unsafe"):
        control.consume_request(tmp_path, uid=os.getuid(), status_dir=tmp_path/"status")
    assert not request.exists()
    request.symlink_to(tmp_path/"other")
    with pytest.raises(control.ControlError):
        control.consume_request(tmp_path, uid=os.getuid(), status_dir=tmp_path/"status")


def test_root_actions_respect_existing_schedule_and_approval(monkeypatch):
    actions = []
    monkeypatch.setattr(control, "_systemctl", lambda *args: actions.append(args))
    monkeypatch.setattr(control, "service_status",
                        lambda: {"available": True, "schedule_active": True,
                                 "scan_running": False})
    approved = lambda: {"accounts": [1, 2]}
    assert "started" in control._execute("start", check_policy=approved)
    assert actions == [("enable", "--now", control.TIMER)]
    actions.clear()
    assert "paused" in control._execute("stop", check_policy=lambda: pytest.fail("stop requires no approval"))
    assert actions == [("disable", "--now", control.TIMER)]
    actions.clear()
    assert "restarted" in control._execute("restart", check_policy=approved)
    assert actions == [("restart", control.TIMER)]
    actions.clear()
    assert "completed" in control._execute("run-now", check_policy=approved)
    assert actions == [("start", control.SERVICE)]
    actions.clear()
    with pytest.raises(control.ControlError, match="approval"):
        control._execute("start", check_policy=lambda: (_ for _ in ()).throw(
            control.LiveSafetyError("missing approval")))
    assert actions == []


def test_paused_schedule_cannot_restart_and_manual_run_refuses_busy_scan(monkeypatch):
    actions = []
    monkeypatch.setattr(control, "_systemctl", lambda *args: actions.append(args))
    monkeypatch.setattr(control, "service_status",
                        lambda: {"available": True, "schedule_active": False,
                                 "scan_running": True})
    with pytest.raises(control.ControlError, match="paused"):
        control._execute("restart", check_policy=lambda: {})
    with pytest.raises(control.ControlError, match="already"):
        control._execute("run-now", check_policy=lambda: {})
    assert actions == []


def test_schedule_save_does_not_resume_paused_timer(tmp_path, monkeypatch):
    path = tmp_path/"root-owned-override.conf"
    calls = []
    monkeypatch.setattr(control, "OVERRIDE", path)
    monkeypatch.setattr(control, "service_status",
                        lambda: {"available": True, "schedule_active": False,
                                 "scan_running": False})
    monkeypatch.setattr(control, "_systemctl", lambda *args: calls.append(args))
    monkeypatch.setattr(control, "_write_interval",
                        lambda minutes: path.write_text(f"{minutes}"))
    assert "15 minutes" in control._execute("set-interval", 15, check_policy=lambda: {})
    assert path.read_text() == "15"
    assert calls == [("daemon-reload",)]


def test_failed_schedule_change_rolls_back_previous_file(tmp_path, monkeypatch):
    path = tmp_path/"override.conf"
    old = b"[Timer]\nOnCalendar=\nOnCalendar=*-*-* *:00/30:00\n"
    path.write_bytes(old)
    monkeypatch.setattr(control, "OVERRIDE", path)
    monkeypatch.setattr(control, "service_status",
                        lambda: {"available": True, "schedule_active": True,
                                 "scan_running": False})
    monkeypatch.setattr(control, "_write_interval",
                        lambda minutes: path.write_text("new"))
    calls = []
    def systemctl(*args):
        calls.append(args)
        if args == ("restart", control.TIMER) and calls.count(("restart", control.TIMER)) == 1:
            raise control.ControlError("test rejected")
    monkeypatch.setattr(control, "_systemctl", systemctl)
    with pytest.raises(control.ControlError, match="restored"):
        control._execute("set-interval", 15, check_policy=lambda: {})
    assert path.read_bytes() == old
    assert calls == [("daemon-reload",), ("restart", control.TIMER),
                     ("daemon-reload",), ("restart", control.TIMER)]


def _fake_status(**changes):
    sample = {
        "timer": {
            "ActiveState": "active",
            "UnitFileState": "enabled",
            "LastTriggerUSec": "Thu 2026-11-19 23:00:00 AEST",
            "NextElapseUSecRealtime": "Thu 2026-11-19 23:30:00 AEST",
        },
        "service": {
            "ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
            "ExecMainStartTimestamp": "Thu 2026-11-19 23:00:00 AEST",
            "ExecMainExitTimestamp": "Thu 2026-11-19 23:00:14 AEST",
        },
        "schedule_active": True, "scan_running": False, "available": True,
        "control_installed": True, "request_pending": False,
        "last_action": {"state": "success", "action": "set-interval",
                        "detail": "Schedule set to every 30 minutes",
                        "updated_at": "2026-11-19T23:15:00+10:00"},
        "interval": 30,
    }
    sample.update(changes)
    return sample


def test_settings_shows_actual_service_timer_and_working_capabilities(client, monkeypatch):
    import importlib
    web = importlib.import_module("filter_vision.app")
    monkeypatch.setattr(web, "control_view", lambda data_dir: _fake_status())
    result = client.get("/settings")
    assert result.status_code == 200
    for expected in (
        "Cleaner Service", "23:30:00 AEST", "Every 30 minutes",
        "Start Schedule", "Stop Schedule", "Restart Schedule", "Run Now",
        "Save interval", "Stable GitHub WebUI updates",
        "Encrypted full-state backup", "Schedule set to every 30 minutes",
        "Systemd-backed",
    ):
        assert expected in result.text, expected
    assert "Disabled by design" not in result.text
    assert "Not yet available" not in result.text
    assert "No mailbox scanning/deletion in this build" not in result.text
    assert "Not yet available" not in client.get("/").text


def test_settings_csrf_validates_all_service_actions(signed_in, monkeypatch, tmp_path):
    import importlib
    web = importlib.import_module("filter_vision.app")
    client, csrf = signed_in
    monkeypatch.setattr(web, "control_view", lambda data_dir: _fake_status())
    requests = []
    monkeypatch.setattr(web, "request_control", lambda data_dir,action,interval:
                        requests.append((action,interval)) or True)
    assert client.post("/settings/cleaner", data={"action": "stop"}).status_code == 403
    assert client.post("/settings/cleaner", data={"csrf": csrf, "action": "stop"},
                       headers={"Origin": "https://attacker.invalid"}).status_code == 403
    for data in [
        {"csrf": csrf, "action": "stop; sudo reboot"},
        {"csrf": csrf, "action": "set-interval", "interval": "7"},
        {"csrf": csrf, "action": "set-interval", "interval": "5; rm -rf /"},
        {"csrf": csrf, "action": "restart", "interval": "15"},
    ]:
        assert client.post("/settings/cleaner", data=data).status_code == 400
    assert requests == []
    for action in ("start", "stop", "restart", "run-now"):
        data = {"csrf": csrf, "action": action}
        if action == "run-now":
            assert client.post("/settings/cleaner", data=data).status_code == 400
            data["confirm_run"] = "yes"
        result = client.post("/settings/cleaner",
                             data=data,
                             follow_redirects=False)
        assert result.status_code == 303
        assert result.headers["location"] == "/settings#cleaner-service"
    assert requests == [(a,None) for a in ("start","stop","restart","run-now")]
    status = client.post("/settings/cleaner",
                         data={"csrf": csrf, "action": "set-interval", "interval": "15"},
                         follow_redirects=False)
    assert status.status_code == 303
    assert requests[-1] == ("set-interval", 15)


def test_settings_controls_disabled_if_root_handler_is_missing(client, monkeypatch):
    import importlib
    web = importlib.import_module("filter_vision.app")
    monkeypatch.setattr(web, "control_view",
                        lambda data_dir: _fake_status(control_installed=False))
    settings = client.get("/settings")
    assert "not installed on this instance" in settings.text
    assert settings.text.count("disabled") >= 2
