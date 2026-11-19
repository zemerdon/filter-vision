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
    inputs = [REPO / "pyproject.toml", REPO / "packaging" / "update-stable.sh",
              REPO / "packaging" / "install-cleaner.sh",
              REPO / "packaging" / "install-controls.sh"]
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
    print(f"Release {TAG}: {len(inputs)} source files, {artifact.stat().st_size} bytes")
    print(f"SHA256 {sha}")
    return artifact, digest

if __name__ == "__main__":
    build()
