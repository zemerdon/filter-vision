"""Public-facing installer is unique; internal bootstrap and legacy updater stay safe."""
from __future__ import annotations
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_only_fresh_proxmox_oneliner_is_advertised():
    public_readme = ROOT / "packaging/README.public.md"
    readme = (public_readme if public_readme.exists() else ROOT / "README.md").read_text()
    assert "only supported public installation entry point" in readme
    assert readme.count("https://github.com/zemerdon/filter-vision/releases/latest/download/") == 1
    assert "latest/download/install-proxmox.sh" in readme
    assert "latest/download/install.sh" not in readme
    assert "existing Debian 13 LXC" not in readme


def test_root_updater_uses_internal_guest_bootstrap_instead_of_public_script():
    source = (ROOT / "packaging/update-stable.sh").read_text()
    assert 'names=("filter-vision-$tag.tar.gz" "filter-vision-$tag.sha256")' in source
    assert 'names=[f"filter-vision-{tag}.tar.gz",f"filter-vision-{tag}.sha256"]' in source
    assert 'bundle.getmember("filter-vision/packaging/install.sh")' in source
    assert 'bash -n "$work/guest-install.sh"' in source
    assert 'bash "$work/guest-install.sh"' in source
    assert 'names=(install.sh ' not in source
    subprocess.run(["bash","-n",str(ROOT/"packaging/update-stable.sh")],check=True)


def test_versioned_archive_includes_internal_guest_setup_and_installer_only_once():
    from filter_vision import __version__
    file = ROOT / "dist" / f"filter-vision-v{__version__}.tar.gz"
    if not file.exists():
        pytest.skip("Release builder has not been invoked")
    with tarfile.open(file, "r:gz") as archive:
        members = archive.getmembers()
        matches = [m for m in members if m.name == "filter-vision/packaging/install.sh"]
        assert len(matches) == 1
        guest = archive.extractfile(matches[0]).read()
        assert guest.startswith(b"#!/usr/bin/env bash")
        assert b"INTERNAL Debian 13 guest bootstrap" in guest
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"guest-install.sh"
            path.write_bytes(guest)
            subprocess.run(["bash","-n",str(path)],check=True)


def test_updater_embedded_tar_reader_accepts_real_built_archive():
    from filter_vision import __version__
    file = ROOT/"dist"/f"filter-vision-v{__version__}.tar.gz"
    if not file.exists():
        pytest.skip("Release builder has not been invoked")
    source=(ROOT/"packaging/update-stable.sh").read_text()
    code = source.split("python3 - \"$work/filter-vision-$tag.tar.gz\" \"$work/guest-install.sh\" <<'PYINSTALL'\n",1)[1].split("\nPYINSTALL",1)[0]
    with tempfile.TemporaryDirectory() as d:
        target=Path(d)/"guest-install.sh"
        subprocess.run(["python3","-",str(file),str(target)],input=code,
                       check=True,text=True)
        assert target.read_bytes() == (ROOT/"packaging/install.sh").read_bytes()
        subprocess.run(["bash","-n",str(target)],check=True)


def test_public_entry_asset_contains_no_second_asset_request():
    from filter_vision import __version__
    script=ROOT/"dist/install-proxmox.sh"
    if not script.exists():pytest.skip("Release builder has not been invoked")
    data=script.read_text()
    assert 'fetch(base + "/install.sh"' not in data
    assert 'getmember("filter-vision/packaging/install.sh")' in data
