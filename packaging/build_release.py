"""Create an allowlisted, versioned stable release bundle with SHA256 manifest."""
from __future__ import annotations
import hashlib
import io
import tarfile
from pathlib import Path
from filter_vision import __version__

REPO = Path(__file__).resolve().parents[1]
TAG = "v" + __version__
DIST = REPO / "dist"

def build() -> tuple[Path, Path]:
    DIST.mkdir(exist_ok=True)
    artifact = DIST / f"filter-vision-{TAG}.tar.gz"
    digest = DIST / f"filter-vision-{TAG}.sha256"
    # This guest bootstrap is required *inside* the signed application
    # archive, but is no longer a separate publicly advertised installer.
    inputs = [REPO / "pyproject.toml", REPO / "packaging" / "install.sh",
              REPO / "packaging" / "update-stable.sh",
              REPO / "packaging" / "install-cleaner.sh",
              REPO / "packaging" / "install-controls.sh",
              REPO / "packaging" / "install-proxmox.sh",
              REPO / "packaging" / "proxmox-ui.sh"]
    inputs += sorted(path for path in (REPO / "src").rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts and
                     path.suffix in {".py", ".html", ".css"})
    if len(inputs) < 8:
        raise SystemExit("Missing expected application files")
    with artifact.open("wb") as raw:
        import gzip
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as tf:
                for path in inputs:
                    if path.is_symlink():
                        raise SystemExit(f"Unexpected source symlink: {path}")
                    rel = path.relative_to(REPO)
                    name = f"filter-vision/{rel.as_posix()}"
                    content = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    info.size = len(content)
                    tf.addfile(info, io.BytesIO(content))
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    digest.write_text(f"{sha}  {artifact.name}\n", encoding="ascii")
    # Self-contained Proxmox installer: visual Media Vision-style Whiptail
    # frontend followed by the safeguarded native LXC backend.
    ui = (REPO / "packaging" / "proxmox-ui.sh").read_text(encoding="utf-8")
    backend = (REPO / "packaging" / "install-proxmox.sh").read_text(encoding="utf-8")
    marker = "exec python3 - " + chr(34) + "$@" + chr(34) + " <<'PY'\n"
    if backend.count(marker) != 1 or not ui.strip():
        raise SystemExit("Broken Proxmox installer sources")
    # Do not exec away the parent shell: its EXIT trap securely cleans any
    # optional root-SSH password file created by the Whiptail frontend.
    combined = backend.replace(marker, ui.rstrip() + "\n" + marker.replace(
        "exec python3", "python3"), 1)
    host_script = DIST / "install-proxmox.sh"
    host_script.write_text(combined, encoding="utf-8")
    host_script.chmod(0o755)
    host_sha = hashlib.sha256(host_script.read_bytes()).hexdigest()
    host_manifest = DIST / "install-proxmox.sh.sha256"
    host_manifest.write_text(f"{host_sha}  install-proxmox.sh\n", encoding="ascii")
    print(f"Proxmox one-liner asset: {len(combined.encode())} bytes, sha256 {host_sha}")
    print(f"Release {TAG}: {len(inputs)} source files, {artifact.stat().st_size} bytes")
    print(f"SHA256 {sha}")
    return artifact, digest

if __name__ == "__main__":
    build()
