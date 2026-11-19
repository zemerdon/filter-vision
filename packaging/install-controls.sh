#!/usr/bin/env bash
# Install constrained root-backed WebUI cleaner controls without activating mail deletion.
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Root access required' >&2; exit 2; }
id -u filtervision >/dev/null
[[ -x /opt/filter-vision/current/venv/bin/python ]] || {
 echo 'Filter Vision app not installed' >&2; exit 2;
}
install -d -o root -g filtervision -m 0750 /var/lib/filter-vision-control
install -d -o root -g root -m 0755 /etc/systemd/system/filter-vision-cleaner.timer.d
cat > /etc/systemd/system/filter-vision-control.service <<'UNIT'
[Unit]
Description=Filter Vision - validate requested cleaner control action
After=filter-vision-web.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/libexec/filter-vision/cleaner-control
TimeoutStartSec=370
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/filter-vision /var/lib/filter-vision-control /run/lock -/etc/systemd/system/filter-vision-cleaner.timer.d
RestrictAddressFamilies=AF_UNIX
UNIT
cat > /etc/systemd/system/filter-vision-control.path <<'UNIT'
[Unit]
Description=Watch validated Filter Vision cleaner control requests

[Path]
PathExists=/var/lib/filter-vision/cleaner-control-request
Unit=filter-vision-control.service

[Install]
WantedBy=multi-user.target
UNIT
install -d -o root -g root -m 0755 /usr/local/libexec/filter-vision
cat > /usr/local/libexec/filter-vision/cleaner-control <<'SHIM'
#!/bin/sh
set -eu
exec /opt/filter-vision/current/venv/bin/python -m filter_vision.control execute \
 --data-dir /var/lib/filter-vision --request-uid "$(id -u filtervision)"
SHIM
chmod 0755 /usr/local/libexec/filter-vision/cleaner-control
chmod 0644 /etc/systemd/system/filter-vision-control.{path,service}
systemctl daemon-reload
systemctl enable --now filter-vision-control.path >/dev/null
echo 'Filter Vision cleaner controls available (no changes to cleaner schedule)'
