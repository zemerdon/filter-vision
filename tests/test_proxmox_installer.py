"""No Proxmox host is changed: simulate all PVE commands in memory."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "packaging" / "install-proxmox.sh"
UI = ROOT / "packaging" / "proxmox-ui.sh"
SOURCE = BACKEND.read_text()
PYTHON_BACKEND = SOURCE.split("exec python3 - \"$@\" <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


def test_installer_is_syntactically_valid_and_safe():
    from filter_vision import __version__
    assert __version__ == "0.2.2"
    compile(PYTHON_BACKEND, "<embedded-proxmox-provisioner>", "exec")
    menu = UI.read_text()
    for choice in ("Default Install", "Advanced Install", "User Defaults", "Settings"):
        assert choice in menu
    for feature in ("fv_timezone", "fv_storage", "fv_bridge",
                    "--root-ssh", "--root-password-file", "set +u"):
        assert feature in menu
    assert "unset NEWT_COLORS" in menu
    assert "npm" not in menu.lower()
    assert "docker" not in SOURCE.lower()
    assert "--unprivileged\", \"1\"" in SOURCE
    assert "pct destroy" not in SOURCE
    assert "'pct', 'destroy'" not in SOURCE
    assert "latest" in SOURCE and "sha256" in SOURCE.lower()
    script = ROOT / "dist" / "install-proxmox.sh"
    if script.is_file():
        subprocess.run(["bash", "-n", str(script)], check=True)
        text = script.read_text()
        assert text.count("<<'PY'") == 1
        assert 'python3 - "$@"' in text
        assert "Default Install" in text and "No mailbox cleaning" in text


class StubProxmox:
    def __init__(self, collision=False, malformed_checksum=False):
        self.commands = []
        self.collision = collision
        self.malformed_checksum = malformed_checksum
        self.expected_archive = b"FAKE-RELEASE-ARCHIVE"

    def command(self, args, **kwargs):
        args = [str(x) for x in args]
        self.commands.append(args)
        output = ""
        status = 0
        if args[:3] == ["pvesh", "get", "/cluster/nextid"]:
            output = "145\n"
        elif args[:3] == ["pvesh", "get", "/cluster/resources"]:
            output = json.dumps([{"vmid": 145}] if self.collision else []) + "\n"
        elif args[:3] == ["pvesm", "status", "--content"]:
            if args[3] == "rootdir":
                output = "Name Type Status Total Used Available\nlocal-lvm lvmthin active 1000 100 900\n"
            else:
                output = "Name Type Status Total Used Available\nlocal dir active 1000 100 900\n"
        elif args[:2] == ["pveam", "list"]:
            output = "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst 250000000\n"
        elif args[:2] == ["pct", "config"]:
            status = 1
        elif args[:3] == ["ip", "link", "show"]:
            status = 0
        elif args[:2] == ["pct", "exec"] and "addr" in args:
            output = "2: eth0 inet 10.10.30.123/24 brd 10.10.30.255 scope global eth0\n"
        elif args[:2] == ["pveam", "available"]:
            output = "system debian-13-standard_13.1-1_amd64.tar.zst\n"
        else:
            assert args[0] in ("pct", "pveam", "bash"), args
        if kwargs.get("check", False) and status != 0:
            raise subprocess.CalledProcessError(status, args)
        return SimpleNamespace(returncode=status, stdout=output)

    def urlopen(self, request, timeout=30):
        url = request.full_url
        if url.endswith("/releases/latest"):
            content = json.dumps({
                "tag_name": "v0.2.2", "draft": False, "prerelease": False,
            }).encode()
        elif url.endswith("/install.sh"):
            content = b"#!/usr/bin/env bash\nexit 0\n"
        elif url.endswith("/filter-vision-v0.2.2.tar.gz"):
            content = self.expected_archive
        elif url.endswith("/filter-vision-v0.2.2.sha256"):
            digest = ("0"*64 if self.malformed_checksum else
                      hashlib.sha256(self.expected_archive).hexdigest())
            content = f"{digest}  filter-vision-v0.2.2.tar.gz\n".encode()
        else:
            raise AssertionError(f"Unexpected network URL: {url}")
        class Response(io.BytesIO):
            def geturl(self): return url
        return Response(content)


def simulate(monkeypatch, capsys, *, args=None, collision=False, malformed_checksum=False):
    import pathlib, shutil
    stub = StubProxmox(collision=collision,
                       malformed_checksum=malformed_checksum)
    original_is_dir = pathlib.Path.is_dir
    monkeypatch.setattr(pathlib.Path, "is_dir",
                        lambda path: True if str(path) == "/etc/pve" else original_is_dir(path))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(shutil, "which", lambda binary: "/mocked/" + binary)
    monkeypatch.setattr(subprocess, "run", stub.command)
    monkeypatch.setattr(urllib.request, "urlopen", stub.urlopen)
    monkeypatch.setattr(sys, "argv", ["install-proxmox.sh"] + (args or [
        "--ctid", "145", "--yes", "--dry-run"]))
    try:
        exec(compile(PYTHON_BACKEND, "<in-memory-Proxmox-mock>", "exec"), {"__name__": "__main__"})
    except SystemExit as result:
        code = result.code
    else:
        code = 0
    return code, stub.commands, capsys.readouterr()


def test_dry_run_has_media_vision_defaults_and_no_ct_creation(monkeypatch, capsys):
    code, calls, output = simulate(monkeypatch, capsys)
    assert code == 0
    assert "2 vCPU, 2048 MB RAM" in output.out
    assert "16 GB disk" in output.out
    assert "Australia/Brisbane" in output.out
    assert "NO connected accounts" not in output.err
    assert "DRY-RUN" in output.out
    assert not any(args[:2] == ["pct", "create"] for args in calls)
    assert not any(args[:2] == ["pveam", "download"] for args in calls)


def test_existing_ctid_rejected_before_mutation(monkeypatch, capsys):
    code, calls, output = simulate(monkeypatch, capsys, collision=True)
    assert code == 1
    assert "already exists" in output.err
    assert not any(args[:2] == ["pct", "create"] for args in calls)


@pytest.mark.parametrize("args", [
    ["--ctid", "145", "--yes", "--dry-run", "--cores", "0"],
    ["--ctid", "145", "--yes", "--dry-run", "--disk", "5"],
    ["--ctid", "145", "--yes", "--dry-run", "--ip", "not-an-ip"],
    ["--ctid", "145", "--yes", "--dry-run", "--ip", "10.1.1.10/24"],
    ["--ctid", "145", "--yes", "--dry-run", "--ip", "10.1.1.10/24",
     "--gateway", "10.1.2.1"],
    ["--ctid", "145", "--yes", "--dry-run", "--root-ssh", "yes"],
    ["--ctid", "145", "--yes", "--dry-run", "--version", "develop"],
])
def test_invalid_options_fail_before_creating_container(monkeypatch, capsys, args):
    code, calls, output = simulate(monkeypatch, capsys, args=args)
    assert code == 1
    assert "ERROR" in output.err
    assert not any(args[:2] == ["pct", "create"] for args in calls)


def test_fresh_guest_provisioning_is_stable_and_never_enables_deletion(monkeypatch, capsys):
    code, calls, output = simulate(monkeypatch, capsys, args=["--ctid", "145", "--yes"])
    assert code == 0, output.err
    created = [args for args in calls if args[:2] == ["pct", "create"]]
    assert len(created) == 1
    assert "--unprivileged" in created[0]
    assert created[0][created[0].index("--unprivileged")+1] == "1"
    assert created[0][created[0].index("--cores")+1] == "2"
    assert created[0][created[0].index("--memory")+1] == "2048"
    assert created[0][created[0].index("--rootfs")+1] == "local-lvm:16"
    assert any(args[:2] == ["pct", "start"] for args in calls)
    assert any(args[:2] == ["pct", "push"] for args in calls)
    assert not any(args[:2] == ["pct", "destroy"] for args in calls)
    assert not any("filter-vision-cleaner.timer" in " ".join(args)
                   and "enable" in " ".join(args) for args in calls)
    assert "SUCCESS" in output.out
    assert "NO connected accounts" in output.out

def test_invalid_release_digest_fails_before_proxmox_create(monkeypatch, capsys):
    code, calls, output = simulate(monkeypatch, capsys,
                                   args=["--ctid", "145", "--yes"],
                                   malformed_checksum=True)
    assert code == 1
    assert "checksum mismatch" in output.err
    assert not any(cmd[:2] == ["pct", "create"] for cmd in calls)


def test_headless_install_without_confirmation_refused(monkeypatch, capsys):
    monkeypatch.delenv("FV_UNATTENDED", raising=False)
    code, calls, output = simulate(monkeypatch, capsys,
                                   args=["--ctid", "145", "--version", "v0.2.2"])
    assert code == 1
    assert "No interactive terminal" in output.err
    assert not any(cmd[:2] == ["pct", "create"] for cmd in calls)
