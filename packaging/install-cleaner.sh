#!/usr/bin/env bash
# Install *disabled* live-cleaner units. Activation is separately approved.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Root is required' >&2; exit 2; }
[[ -L /opt/filter-vision/current ]] || { echo 'Filter Vision is not installed' >&2; exit 2; }
[[ -x /opt/filter-vision/current/venv/bin/python ]] || exit 2
cat > /etc/systemd/system/filter-vision-cleaner.service <<'UNIT'
[Unit]
Description=Filter Vision - approved legacy-compatible Junk scan
Wants=network-online.target
After=network-online.target
Conflicts=hotmail-junk-cleaner.service

[Service]
Type=oneshot
User=filtervision
Group=filtervision
WorkingDirectory=/opt/filter-vision/current/filter-vision
Environment=FV_DATA_DIR=/var/lib/filter-vision
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/filter-vision/current/venv/bin/python -m filter_vision.live --data-dir /var/lib/filter-vision
TimeoutStartSec=300
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/filter-vision
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UNIT
cat > /etc/systemd/system/filter-vision-cleaner.timer <<'TIMER'
[Unit]
Description=Filter Vision - every 30 minutes, legacy schedule
[Timer]
OnCalendar=*-*-* *:00,30:00
Persistent=false
AccuracySec=1min
Unit=filter-vision-cleaner.service
[Install]
WantedBy=timers.target
TIMER
chmod 644 /etc/systemd/system/filter-vision-cleaner.service /etc/systemd/system/filter-vision-cleaner.timer
systemctl daemon-reload
echo 'Filter Vision cleaner units installed, NOT activated'
