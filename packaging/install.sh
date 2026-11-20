#!/usr/bin/env bash
# Filter Vision — INTERNAL Debian 13 guest bootstrap for verified stable bundles.
# Invoked by the Proxmox one-liner and by the root-owned WebUI updater.
# Not advertised as a second public fresh-installation method.
set -Eeuo pipefail
umask 077
REPO="zemerdon/filter-vision"
ROOT="/opt/filter-vision"
DATA="/var/lib/filter-vision"
CFG="/etc/filter-vision"
UNIT="/etc/systemd/system/filter-vision-web.service"
SERVICE="filter-vision-web.service"
TAG="${FV_VERSION_TAG:-}"
PORT="${FV_PORT:-9494}"
ARCHIVE=""
CHECKSUM=""
while (( $# )); do
  case "$1" in
    --archive) ARCHIVE="${2:?}"; shift 2;;
    --sha256) CHECKSUM="${2:?}"; shift 2;;
    --version) TAG="${2:?}"; shift 2;;
    --port) PORT="${2:?}"; shift 2;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
fail() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || fail "Run as root"
. /etc/os-release
[[ "$ID" == "debian" && "$VERSION_ID" == "13" ]] || fail "Debian 13 required"
[[ "$(uname -m)" == "x86_64" ]] || fail "Only tested on x86_64"
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && (( PORT>=1024 && PORT<=65535 )) || fail "Bad port"
[[ -z "$ARCHIVE" || -n "$CHECKSUM" ]] || fail "--sha256 is required with --archive"
[[ -z "$CHECKSUM" || -n "$ARCHIVE" ]] || fail "--sha256 needs --archive"
[[ -z "$ARCHIVE" || -n "$TAG" ]] || fail "--archive needs --version"
if [[ -z "$ARCHIVE" && -z "$TAG" ]]; then
  command -v curl >/dev/null || fail "Install curl first"
  TAG="$(curl -fLsS --connect-timeout 8 --max-time 25 \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$REPO/releases/latest" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert not d.get("draft") and not d.get("prerelease"); print(d["tag_name"])')" ||
    fail "Cannot determine latest stable release"
fi
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Stable version must be vX.Y.Z"
if ! command -v curl >/dev/null || ! command -v openssl >/dev/null ||
    ! python3 -m venv --help >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update
  apt-get -y -qq install --no-install-recommends curl ca-certificates openssl python3-venv python3-pip
fi
if [[ -f "$UNIT" ]] && ! grep -q '^# Managed by Filter Vision stable installer$' "$UNIT"; then
  fail "Unmanaged service unit already exists"
fi
if command -v ss >/dev/null 2>&1 &&
   ss -H -lnt "sport = :$PORT" | grep -q . &&
   ! systemctl is-active --quiet "$SERVICE"; then
  fail "Port $PORT already in use"
fi
work="$(mktemp -d -t fv-release.XXXXXXXX)"
stage=""
cleanup() {
  rm -rf -- "$work"
  if [[ -n "$stage" && -d "$stage" ]]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
bundle="$work/filter-vision-$TAG.tar.gz"
manifest="$work/filter-vision-$TAG.sha256"
if [[ -n "$ARCHIVE" ]]; then
  cp -- "$ARCHIVE" "$bundle"
  cp -- "$CHECKSUM" "$manifest"
else
  url="https://github.com/$REPO/releases/download/$TAG"
  curl -fLsS --retry 2 --max-time 120 -o "$bundle" "$url/filter-vision-$TAG.tar.gz"
  curl -fLsS --retry 2 --max-time 30 -o "$manifest" "$url/filter-vision-$TAG.sha256"
fi
expected="$(awk -v f="filter-vision-$TAG.tar.gz" '$2==f {print $1}' "$manifest")"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail "Invalid release digest"
actual="$(sha256sum "$bundle" | cut -d' ' -f1)"
[[ "$actual" == "${expected,,}" ]] || fail "Release SHA256 mismatch"
python3 - "$bundle" <<'PY'
import sys,tarfile
with tarfile.open(sys.argv[1],"r:gz") as f:
    items=f.getmembers()
    if not items or len(items)>200: raise SystemExit("Bad archive")
    for x in items:
        if not x.name.startswith("filter-vision/") or ".." in x.name.split("/") or not (x.isfile() or x.isdir()) or x.size>10*1024*1024:
            raise SystemExit("Unsafe release archive member")
PY
mkdir -p "$ROOT/releases"
target="$ROOT/releases/$TAG"
previous=""
if [[ -L "$ROOT/current" ]]; then
  linkval="$(readlink "$ROOT/current")"
  if [[ "$linkval" == "$ROOT/current" ]]; then
    # Recover from a prior failed fresh installation; never restore a self-link.
    rm -- "$ROOT/current"
  else
    previous="$(readlink -f "$ROOT/current" 2>/dev/null || true)"
    [[ "$previous" != "$ROOT/current" && -d "$previous" ]] || fail "Invalid installed release symlink"
  fi
elif [[ -e "$ROOT/current" ]]; then
  fail "Refusing to replace a non-symlink current installation"
fi
if [[ -e "$target" ]]; then
  [[ -f "$target/RELEASE_SHA256" && "$(cat "$target/RELEASE_SHA256")" == "$actual" ]] ||
    fail "Existing installation version differs from stable bundle"
else
  stage="$(mktemp -d "$ROOT/releases/.staging.XXXXXXXX")"
  tar -xzf "$bundle" -C "$stage"
  [[ -f "$stage/filter-vision/pyproject.toml" ]] || fail "Missing pyproject.toml"
  # Python venv shebangs embed absolute paths: create it only at the final location.
  mv "$stage" "$target"
  stage=""
  if ! python3 -m venv "$target/venv" ||
     ! "$target/venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -q "$target/filter-vision" ||
     ! "$target/venv/bin/python" -c 'import filter_vision.app'; then
    rm -rf -- "$target"
    fail "Python environment provisioning failed"
  fi
  echo "$actual" > "$target/RELEASE_SHA256"
fi
# Files produced with umask 077 are intentionally private during staging.
# Release code and venv must be readable/traversable by the unprivileged service.
chmod 755 "$ROOT" "$ROOT/releases"
chmod -R a+rX "$target"
getent group filtervision >/dev/null || groupadd --system filtervision
id -u filtervision >/dev/null 2>&1 ||
  useradd --system -g filtervision --home-dir /nonexistent --shell /usr/sbin/nologin filtervision
install -d -o filtervision -g filtervision -m 700 "$DATA"
install -d -o root -g filtervision -m 750 "$CFG"
ip="$(hostname -I | awk '{print $1}')"
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Cannot determine instance IPv4"
if [[ ! -e "$CFG/tls.crt" && ! -e "$CFG/tls.key" ]]; then
  openssl req -new -newkey rsa:3072 -x509 -nodes -days 365 \
    -subj '/CN=Filter Vision' \
    -addext "subjectAltName=IP:$ip,IP:127.0.0.1,DNS:filter-vision,DNS:localhost" \
    -keyout "$CFG/tls.key" -out "$CFG/tls.crt" >/dev/null 2>&1
else
  [[ -f "$CFG/tls.crt" && -f "$CFG/tls.key" ]] || fail "Incomplete TLS certificate/key pair"
fi
chown root:filtervision "$CFG/tls.key"
chmod 640 "$CFG/tls.key"
chmod 644 "$CFG/tls.crt"
# Preserve operator-managed network access policy across stable updates.
# Passwordless WebUI: never implicitly bind access to the public internet.
if [[ ! -f "$CFG/web.env" ]]; then
  iface_cidr="$(ip -4 -o addr show scope global | awk 'NR==1{print $4}')"
  [[ -n "$iface_cidr" ]] || fail "Could not determine trusted interface network"
  python3 - "$CFG/web.env" "$iface_cidr" "$ip" "$(hostname -s)" <<'PYENV'
import ipaddress,sys
path,iface,host_ip,host_name=sys.argv[1:]
network=ipaddress.ip_interface(iface).network
prefix="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
with open(path,"x",encoding="ascii") as out:
    out.write(f"FV_TRUSTED_CIDRS={prefix},{network}\n")
    out.write(f"FV_ALLOWED_HOSTS=localhost,127.0.0.1,{host_ip},{host_name}\n")
PYENV
fi
chown root:filtervision "$CFG/web.env"
chmod 640 "$CFG/web.env"
cat > "$UNIT" <<EOF
# Managed by Filter Vision stable installer
[Unit]
Description=Filter Vision stable WebUI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=filtervision
Group=filtervision
WorkingDirectory=$ROOT/current/filter-vision
Environment=FV_DATA_DIR=$DATA
Environment=FV_SECURE_COOKIES=1
EnvironmentFile=-$CFG/web.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$ROOT/current/venv/bin/uvicorn filter_vision.asgi:app --host 0.0.0.0 --port $PORT --ssl-keyfile $CFG/tls.key --ssl-certfile $CFG/tls.crt --no-server-header
Restart=on-failure
RestartSec=4
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$UNIT"
if [[ -f "$target/filter-vision/packaging/update-stable.sh" ]]; then
  # Root update executor is never writable by the application service user.
  install -d -o root -g root -m 755 /usr/local/libexec/filter-vision
  install -o root -g root -m 755 "$target/filter-vision/packaging/update-stable.sh" \
    /usr/local/libexec/filter-vision/update-stable.sh
  install -d -o root -g filtervision -m 750 /var/lib/filter-vision-updater
  cat > /etc/systemd/system/filter-vision-update.service <<'SVUPDATE'
[Unit]
Description=Filter Vision - verify, back up and apply latest stable release
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/libexec/filter-vision/update-stable.sh
TimeoutStartSec=360
SVUPDATE
  cat > /etc/systemd/system/filter-vision-update.path <<'SVPATH'
[Unit]
Description=Watch for safe Filter Vision stable update requests

[Path]
PathExists=/var/lib/filter-vision/update-request
Unit=filter-vision-update.service

[Install]
WantedBy=multi-user.target
SVPATH
  chmod 644 /etc/systemd/system/filter-vision-update.service \
            /etc/systemd/system/filter-vision-update.path
fi
ln -s "$target" "$ROOT/.next.$$"
mv -Tf "$ROOT/.next.$$" "$ROOT/current"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
if [[ -f /etc/systemd/system/filter-vision-update.path ]]; then
  systemctl enable --now filter-vision-update.path >/dev/null
fi
# System-control requests are processed by a root-owned, fixed-action handler.
# This never starts/stops the cleaning timer merely because an app is updated.
if [[ -f "$target/filter-vision/packaging/install-controls.sh" ]]; then
  bash "$target/filter-vision/packaging/install-controls.sh"
fi
restore() {
  if [[ -n "$previous" && -d "$previous" ]]; then
    ln -s "$previous" "$ROOT/.rollback.$$"
    mv -Tf "$ROOT/.rollback.$$" "$ROOT/current"
    systemctl restart "$SERVICE" || true
  else
    systemctl stop "$SERVICE" || true
  fi
}
if ! systemctl restart "$SERVICE"; then restore; fail "Service could not start"; fi
healthy=0
for _ in {1..25}; do
  if curl -kfsS --max-time 2 "https://127.0.0.1:$PORT/healthz" 2>/dev/null |
    python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"' 2>/dev/null; then
    healthy=1; break
  fi
  sleep 1
done
[[ "$healthy" == 1 ]] || { restore; fail "Health check failed"; }
echo
echo "Filter Vision $TAG installed, HTTPS health verified"
echo "WebUI: https://$(hostname -I | awk '{print $1}'):$PORT/"
echo "Release SHA256: $actual"
openssl x509 -in "$CFG/tls.crt" -noout -fingerprint -sha256
if [[ -f "$DATA/setup-token" ]]; then
  echo "Initial admin setup token: $DATA/setup-token (root-read-only)"
fi
echo "Automatic Junk cleaning remains separately gated by a root-managed cutover policy."
