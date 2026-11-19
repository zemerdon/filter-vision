#!/usr/bin/env bash
# Root-owned, fixed-purpose stable updater; invoked only by systemd.path.
set -Eeuo pipefail
umask 077
REQUEST=/var/lib/filter-vision/update-request
STATE=/var/lib/filter-vision-updater
BACKUPS="$STATE/backups"
REPO=zemerdon/filter-vision
SERVICE=filter-vision-web.service
CURRENT=/opt/filter-vision/current
mkdir -p "$STATE" "$BACKUPS"
chown root:filtervision "$STATE"
chmod 750 "$STATE"
chown root:root "$BACKUPS"
chmod 700 "$BACKUPS"
exec 9>/run/lock/filter-vision-updater.lock
flock -n 9 || exit 0
[[ -e "$REQUEST" ]] || exit 0
if [[ -L "$REQUEST" ]]; then
  rm -f -- "$REQUEST"
  exit 1
fi
# The file is only an event trigger, never arbitrary instructions.
[[ "$(stat -c %u "$REQUEST")" == "$(id -u filtervision)" ]] || exit 1
[[ "$(stat -c %a "$REQUEST")" == 600 ]] || exit 1
[[ "$(cat "$REQUEST")" == "latest-stable" ]] || exit 1
rm -f -- "$REQUEST"
status() {
  python3 - "$STATE/status.json" "$1" "$2" "$3" <<'PY'
import json,os,sys,tempfile,time,grp
path,state,version,detail=sys.argv[1:]
dest=os.path.dirname(path)
fd,tmp=tempfile.mkstemp(prefix=".status.",dir=dest)
try:
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(dict(state=state,version=version,detail=detail,
             updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())),f)
        f.write("\n")
        f.flush();os.fsync(f.fileno())
    os.chown(tmp,0,grp.getgrnam("filtervision").gr_gid)
    os.chmod(tmp,0o640)
    os.replace(tmp,path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
}
previous="$(readlink -f "$CURRENT" 2>/dev/null || true)"
before=""
if [[ -x "$CURRENT/venv/bin/python" ]]; then
  before="$("$CURRENT/venv/bin/python" -c 'import filter_vision;print(filter_vision.__version__)')"
fi
work="$(mktemp -d /tmp/fv-stable-update.XXXXXXXX)"
attempted=0
backup=""
restore_on_error() {
  rc=$?
  trap - ERR
  set +e
  detail="Update failed; installed version unchanged"
  if [[ "$attempted" == 1 && -n "$previous" && -d "$previous" ]]; then
    systemctl stop "$SERVICE"
    if [[ -n "$backup" && -f "$backup" ]]; then
      cp -p -- "$backup" /var/lib/filter-vision/filter-vision.sqlite3
      chown filtervision:filtervision /var/lib/filter-vision/filter-vision.sqlite3
      chmod 600 /var/lib/filter-vision/filter-vision.sqlite3
    fi
    ln -s "$previous" /opt/filter-vision/.rollback-latest
    mv -Tf /opt/filter-vision/.rollback-latest "$CURRENT"
    systemctl restart "$SERVICE"
    if curl -kfsS --max-time 10 https://127.0.0.1:9494/healthz >/dev/null 2>&1; then
      detail="Update failed; previous service and database restored"
    else
      detail="Update failed; rollback attempted, check service health"
    fi
  fi
  status failed "$before" "$detail"
  rm -rf -- "$work"
  exit "$rc"
}
trap restore_on_error ERR
trap 'rm -rf -- "$work"' EXIT
status checking "$before" "Checking GitHub latest stable release"
metadata="$(python3 - <<'PY'
import json,re,urllib.request
repo="zemerdon/filter-vision"
req=urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                           headers={"User-Agent":"FilterVisionUpdater/1","Accept":"application/vnd.github+json"})
with urllib.request.urlopen(req,timeout=20) as response:
    blob=response.read(128*1024+1)
if len(blob)>128*1024: raise SystemExit("Unexpected release metadata size")
d=json.loads(blob)
tag=str(d.get("tag_name",""))
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+",tag):raise SystemExit("Invalid stable release version")
if d.get("draft") or d.get("prerelease"):raise SystemExit("Only stable releases are supported")
if d.get("target_commitish") != "stable":raise SystemExit("Release is not published from stable")
names=["install.sh",f"filter-vision-{tag}.tar.gz",f"filter-vision-{tag}.sha256"]
a={v.get("name"):v for v in d.get("assets",[])}
out=[tag]
for name in names:
    v=a[name]
    if v.get("browser_download_url") != f"https://github.com/{repo}/releases/download/{tag}/{name}":
        raise SystemExit("Unexpected release asset URL")
    digest=str(v.get("digest",""))
    if not re.fullmatch(r"sha256:[a-f0-9]{64}",digest):
        raise SystemExit("Missing verified release asset digest")
    out.append(digest.removeprefix("sha256:"))
print("\n".join(out))
PY
)"
mapfile -t md <<< "$metadata"
tag="$(printf %s "${md[0]}")"
if [[ -n "$before" ]]; then
  is_newer="$(python3 - "$before" "$tag" <<'PY'
import sys
old=tuple(map(int,sys.argv[1].lstrip("v").split(".")))
new=tuple(map(int,sys.argv[2].lstrip("v").split(".")))
print("yes" if new>old else "no")
PY
)"
  if [[ "$is_newer" != yes ]]; then
    status current "$before" "Already running the latest stable release"
    exit 0
  fi
fi
status downloading "$tag" "Downloading verified stable release"
base="https://github.com/$REPO/releases/download/$tag"
names=(install.sh "filter-vision-$tag.tar.gz" "filter-vision-$tag.sha256")
for i in 0 1 2; do
  name="${names[$i]}"
  curl -fLsS --retry 3 --retry-all-errors --connect-timeout 8 --max-time 150     -o "$work/$name" "$base/$name"
  observed="$(sha256sum "$work/$name" | awk '{print $1}')"
  expected="${md[$((i+1))]}"
  [[ "$observed" == "$expected" ]] || { echo "Asset checksum mismatch" >&2; false; }
done
bash -n "$work/install.sh"
if [[ -f /var/lib/filter-vision/filter-vision.sqlite3 ]]; then
  backup="$BACKUPS/before-$tag-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
  python3 - /var/lib/filter-vision/filter-vision.sqlite3 "$backup" <<'PY'
import sqlite3,sys,os
src=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro",uri=True)
dst=sqlite3.connect(sys.argv[2])
try: src.backup(dst)
finally: dst.close(); src.close()
os.chmod(sys.argv[2],0o600)
PY
fi
status applying "$tag" "Installing verified stable release and checking health"
attempted=1
bash "$work/install.sh" --version "$tag"   --archive "$work/filter-vision-$tag.tar.gz"   --sha256 "$work/filter-vision-$tag.sha256" >"$work/installer.log" 2>&1
installed="$("$CURRENT/venv/bin/python" -c 'import filter_vision;print(filter_vision.__version__)')"
[[ "v$installed" == "$tag" ]] || { echo "Installed version mismatch" >&2; false; }
systemctl is-active --quiet "$SERVICE"
curl -kfsS --max-time 10 https://127.0.0.1:9494/healthz >/dev/null
attempted=0
status success "$tag" "Installed and verified the latest GitHub stable release"
# Restrict historic backups: keep five most recent, but never wipe all.
find "$BACKUPS" -maxdepth 1 -type f -name 'before-v*.sqlite3' -printf '%T@ %p\n' |
  sort -rn | awk 'NR>5{print substr($0,index($0," ")+1)}' |
  while IFS= read -r old; do rm -f -- "$old"; done
