#!/usr/bin/env bash
# Filter Vision — Proxmox VE host-side stable Debian 13 LXC installer.
# The Python helper executes fixed Proxmox commands without a shell.
set -euo pipefail
exec python3 - "$@" <<'PY'
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

REPO = "zemerdon/filter-vision"
TEMPLATE_RE = re.compile(r"debian-13-standard_[A-Za-z0-9.+~_-]+_amd64\.tar\.(?:zst|xz|gz)")
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
STORAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
HOST_RE = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
BRIDGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,30}")

def fail(message):
    raise RuntimeError(message)

def run(args, *, capture=False, check=True, timeout=90):
    result = subprocess.run(args, check=check, text=True, timeout=timeout,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else result

def number(value, low, high, label):
    try: n = int(value)
    except (TypeError, ValueError): fail(f"{label} must be an integer")
    if not low <= n <= high: fail(f"{label} must be {low}–{high}")
    return n

def valid_ip(value):
    try: return str(ipaddress.IPv4Address(value))
    except ValueError: fail("Invalid IPv4 address: " + value)

def storage(content, requested, preferred):
    rows = run(["pvesm", "status", "--content", content], capture=True)
    choices = []
    for line in rows.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 3 and cols[2] == "active":
            choices.append(cols[0])
    if requested:
        if requested not in choices: fail(f"Storage {requested!r} is not active for {content}")
        return requested
    if preferred in choices: return preferred
    if not choices: fail(f"No active Proxmox storage for {content}")
    return choices[0]

def template_choice(template_storage):
    rows = run(["pveam", "list", template_storage], capture=True, check=False)
    existing = sorted(set(TEMPLATE_RE.findall(rows)), key=lambda s: list(map(
        lambda x: int(x) if x.isdigit() else x, re.split(r"(\d+)", s))))
    if existing: return existing[-1], True
    rows = run(["pveam", "available", "--section", "system"], capture=True)
    if not TEMPLATE_RE.search(rows):
        # Media Vision's bootstrap updates the template index when stale.
        run(["pveam", "update"], timeout=120)
        rows = run(["pveam", "available", "--section", "system"], capture=True)
    options = sorted(set(TEMPLATE_RE.findall(rows)), key=lambda s: list(map(
        lambda x: int(x) if x.isdigit() else x, re.split(r"(\d+)", s))))
    if not options: fail("No Debian 13 amd64 template; run pveam update, then retry")
    return options[-1], False

def fetch(url, path):
    if not url.startswith("https://"):
        fail("Refusing a non-HTTPS release URL")
    with urllib.request.urlopen(urllib.request.Request(url, headers={
        "User-Agent": "FilterVision-Proxmox-Installer",
        "Accept": "application/vnd.github+json",
    }), timeout=35) as response:
        if not response.geturl().startswith("https://"):
            fail("Release redirected to insecure URL")
        with open(path, "xb") as out:
            size = 0
            while True:
                block = response.read(65536)
                if not block: break
                size += len(block)
                if size > 100 * 1024 * 1024:
                    fail("Release asset is unexpectedly large")
                out.write(block)
    return pathlib.Path(path)

parser = argparse.ArgumentParser(
    description="Create a NEW Debian 13 unprivileged LXC and install Filter Vision stable")
env = os.environ.get
parser.add_argument("--ctid", "--vmid", default=env("FV_CTID"))
parser.add_argument("--storage", default=env("FV_STORAGE"))
parser.add_argument("--template-storage", default=env("FV_TEMPLATE_STORAGE"))
parser.add_argument("--bridge", default=env("FV_BRIDGE", "vmbr0"))
parser.add_argument("--ip", default=env("FV_IP", "dhcp"))
parser.add_argument("--gateway", default=env("FV_GATEWAY"))
parser.add_argument("--nameserver", default=env("FV_NAMESERVER"))
parser.add_argument("--vlan", default=env("FV_VLAN"))
parser.add_argument("--cores", default=env("FV_CORES", "2"))
parser.add_argument("--memory", default=env("FV_MEMORY", "2048"))
parser.add_argument("--swap", default=env("FV_SWAP", "512"))
parser.add_argument("--disk", "--disk-size", default=env("FV_DISK", "16"))
parser.add_argument("--hostname", default=env("FV_HOSTNAME", "filter-vision"))
parser.add_argument("--timezone", default=env("FV_TIMEZONE", "Australia/Brisbane"))
parser.add_argument("--root-ssh", choices=("yes", "no"), default=env("FV_ROOT_SSH", "no"))
parser.add_argument("--root-password-file", default=env("FV_ROOT_PASSWORD_FILE"))
parser.add_argument("--version", default=env("FV_VERSION_TAG"))
parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
parser.add_argument("--dry-run", action="store_true",
                    help="Validate/show plan without creating or downloading anything")
args = parser.parse_args()
ct_created = False
ctid = None
try:
    if os.geteuid() != 0: fail("Run as root on the Proxmox VE host")
    if not pathlib.Path("/etc/pve").is_dir(): fail("Run on a Proxmox VE host (/etc/pve missing)")
    for command in ("pct", "pvesh", "pvesm", "pveam", "ip"):
        if not shutil.which(command): fail(f"Missing Proxmox command: {command}")
    if os.uname().machine != "x86_64": fail("Only x86_64 Proxmox has been tested")
    if not HOST_RE.fullmatch(args.hostname): fail("Invalid CT hostname")
    if not BRIDGE_RE.fullmatch(args.bridge): fail("Invalid network bridge")
    run(["ip", "link", "show", args.bridge], capture=True)
    cores = number(args.cores, 1, 64, "vCPUs")
    mem = number(args.memory, 512, 131072, "RAM MB")
    swap = number(args.swap, 0, 131072, "Swap MB")
    disk = number(args.disk, 8, 2048, "Root disk GB")
    vlan = number(args.vlan, 1, 4094, "VLAN") if args.vlan else None
    if not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+){0,3}", args.timezone):
        fail("Invalid timezone")
    if not pathlib.Path("/usr/share/zoneinfo", args.timezone).is_file():
        fail("Timezone not available on Proxmox host")
    if args.version and not TAG_RE.fullmatch(args.version):
        fail("Release must be stable tag vX.Y.Z")
    if args.root_ssh == "yes":
        if not args.root_password_file: fail("Root SSH needs a 0600 root-owned password file")
        credential = pathlib.Path(args.root_password_file)
        if credential.is_symlink() or not credential.is_file():
            fail("Root SSH password must be supplied in a regular file")
        st = credential.stat()
        if st.st_uid != 0 or (st.st_mode & 0o777) != 0o600 or not 1 <= st.st_size <= 4096:
            fail("Root SSH password file must be root-owned, mode 0600, nonempty")
    elif args.root_password_file:
        fail("Password file is only permitted with --root-ssh yes")
    if args.ip == "dhcp":
        if args.gateway: fail("Gateway must be omitted with DHCP")
        ip_setting = "dhcp"
    else:
        try:
            iface = ipaddress.IPv4Interface(args.ip)
            gw = ipaddress.IPv4Address(args.gateway or "")
            if gw not in iface.network:
                fail("Static IP gateway must belong to the configured subnet")
            ip_setting = str(iface)
        except ipaddress.AddressValueError: fail("Invalid static IPv4/CIDR or gateway")
        except ipaddress.NetmaskValueError: fail("Invalid IPv4 subnet mask")
    if args.nameserver: valid_ip(args.nameserver)
    ctid = number(args.ctid or
                  run(["pvesh", "get", "/cluster/nextid"], capture=True).strip(),
                  100, 999999999, "CT ID")
    resources = json.loads(run([
        "pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"
    ], capture=True))
    if not isinstance(resources, list): fail("Unexpected Proxmox cluster resource data")
    if any(int(row.get("vmid", -1)) == ctid for row in resources):
        fail(f"CT/VM {ctid} already exists somewhere in the cluster")
    if subprocess.run(["pct", "config", str(ctid)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        fail(f"CT {ctid} already exists locally")
    for name in (args.storage, args.template_storage):
        if name and not STORAGE_RE.fullmatch(name): fail("Invalid Proxmox storage name")
    root_storage = storage("rootdir", args.storage, "local-lvm")
    template_storage = storage("vztmpl", args.template_storage, "local")
    template, cached = template_choice(template_storage)
    net = f"name=eth0,bridge={args.bridge},ip={ip_setting}"
    if args.gateway: net += f",gw={args.gateway}"
    if vlan: net += f",tag={vlan}"
    print("\nFilter Vision Proxmox stable installation plan")
    print(f"  NEW unprivileged Debian 13 CT: {ctid} ({args.hostname})")
    print(f"  Resources: {cores} vCPU, {mem} MB RAM, {swap} MB swap, {disk} GB disk")
    print(f"  Storage: {root_storage}; template: {template_storage}:vztmpl/{template}")
    print(f"  Network: {net}; DNS: {args.nameserver or 'host default'}")
    print(f"  Timezone: {args.timezone}")
    print(f"  Root SSH: {args.root_ssh} (default disabled)")
    print(f"  Version: {args.version or 'latest stable at installation'}")
    print("  HTTPS WebUI: port 9494, passwordless TRUSTED LAN ONLY")
    print("  Mailbox connections/automatic deletion: disabled by default")
    if args.dry_run:
        print("DRY-RUN: no container or service was changed; no release was downloaded")
        sys.exit(0)
    if not args.yes:
        if not sys.stdin.isatty():
            if os.environ.get("FV_UNATTENDED") != "1":
                fail("No interactive terminal: supply --yes or explicitly set FV_UNATTENDED=1")
        else:
            reply = input(f"Create CT {ctid} and install Filter Vision? [y/N] ").strip().lower()
            if reply not in ("y", "yes"): fail("Cancelled; no changes made")
    with tempfile.TemporaryDirectory(prefix="fv-pve.") as directory:
        work = pathlib.Path(directory)
        if not cached:
            print("Downloading official Debian 13 LXC template...")
            run(["pveam", "download", template_storage, template], timeout=180)
        if args.version:
            tag = args.version
        else:
            latest_url = f"https://api.github.com/repos/{REPO}/releases/latest"
            response = fetch(latest_url, work / "latest.json")
            metadata = json.loads(response.read_text())
            tag = metadata.get("tag_name", "")
            if metadata.get("draft") or metadata.get("prerelease") or not TAG_RE.fullmatch(tag):
                fail("Latest GitHub release is not a stable semver tag")
        base = f"https://github.com/{REPO}/releases/download/{tag}"
        print(f"Retrieving pinned {tag} release and SHA256 manifest...")
        installer = fetch(base + "/install.sh", work / "install.sh")
        archive = fetch(base + f"/filter-vision-{tag}.tar.gz",
                        work / f"filter-vision-{tag}.tar.gz")
        checksum = fetch(base + f"/filter-vision-{tag}.sha256",
                         work / f"filter-vision-{tag}.sha256")
        expected = None
        for line in checksum.read_text("ascii").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == archive.name:
                expected = parts[0]
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            fail("Invalid stable release SHA256 manifest")
        if actual.lower() != expected.lower():
            fail("Stable release artifact checksum mismatch; CT not created")
        run(["bash", "-n", str(installer)])
        # Recheck cluster collision just before creation, to reject stale defaults.
        updated = json.loads(run([
            "pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"
        ], capture=True))
        if any(int(row.get("vmid", -1)) == ctid for row in updated):
            fail(f"CT/VM {ctid} appeared during download; refusing to overwrite")
        opts = [
            "pct", "create", str(ctid), f"{template_storage}:vztmpl/{template}",
            "--hostname", args.hostname, "--ostype", "debian", "--unprivileged", "1",
            "--cores", str(cores), "--memory", str(mem), "--swap", str(swap),
            "--rootfs", f"{root_storage}:{disk}", "--net0", net,
            "--onboot", "1", "--start", "0", "--features", "nesting=0",
        ]
        if args.nameserver: opts += ["--nameserver", args.nameserver]
        print(f"Creating NEW CT {ctid}...")
        run(opts, timeout=180)
        ct_created = True
        run(["pct", "start", str(ctid)], timeout=120)
        ready = False
        for _ in range(30):
            probe = subprocess.run([
                "pct", "exec", str(ctid), "--", "/bin/sh", "-c",
                "test -r /etc/debian_version && ip -4 -o addr show dev eth0 scope global | grep -q inet"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(2)
        if not ready: fail(f"CT {ctid} has no usable IPv4 address; check DHCP/VLAN/bridge")
        # Media Vision's Debian-template safety preflight: never repair host
        # filesystem permissions on a damaged/newly extracted guest blindly.
        run(["pct", "exec", str(ctid), "--", "/bin/sh", "-c",
             'test "$(stat -c %a /etc)" = 755 && test "$(stat -c %u:%g /etc)" = 0:0'])
        # Confirm resolver/apt availability before continuing; on failure leave
        # the fresh CT intact with an actionable error (never remove an LXC).
        for attempt in range(12):
            probe = subprocess.run(["pct", "exec", str(ctid), "--", "/bin/sh", "-c",
                'getent hosts deb.debian.org >/dev/null && apt-get update -qq >/dev/null 2>&1'],
                timeout=50, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(3)
        else:
            fail(f"New CT {ctid} cannot reach Debian package mirrors; check DNS/gateway/firewall")
        run(["pct", "exec", str(ctid), "--", "/usr/bin/apt-get",
             "install", "-y", "--no-install-recommends", "tzdata"], timeout=180)
        run(["pct", "exec", str(ctid), "--", "/bin/sh", "-c",
             'test -f "/usr/share/zoneinfo/$1" && ln -sfn "/usr/share/zoneinfo/$1" /etc/localtime && printf "%s\\n" "$1" > /etc/timezone',
             "_", args.timezone])
        if args.root_ssh == "yes":
            run(["pct", "exec", str(ctid), "--", "/usr/bin/apt-get",
                 "install", "-y", "--no-install-recommends", "openssh-server"], timeout=180)
            run(["pct", "push", str(ctid), args.root_password_file,
                 "/root/.fv-root-pass", "--perms", "0600"])
            try:
                run(["pct", "exec", str(ctid), "--", "/bin/bash", "-c",
                     'set -eu; pw="$(cat /root/.fv-root-pass)"; '
                     'printf "root:%s\\n" "$pw" | chpasswd; '
                     'install -d -m 0755 /etc/ssh/sshd_config.d; '
                     'printf "PermitRootLogin yes\\nPasswordAuthentication yes\\n" '
                     '> /etc/ssh/sshd_config.d/99-filter-vision-root.conf; '
                     'systemctl restart ssh'], timeout=40)
            finally:
                run(["pct", "exec", str(ctid), "--", "/bin/rm",
                     "-f", "/root/.fv-root-pass"], check=False)
        print("Copying pinned stable release into the new container...")
        for source, dest in (
            (installer, "/root/fv-install.sh"),
            (archive, f"/root/{archive.name}"),
            (checksum, f"/root/{checksum.name}"),
        ):
            run(["pct", "push", str(ctid), str(source), dest, "--perms", "0600"])
        print(f"Installing and checking Filter Vision {tag}...")
        run(["pct", "exec", str(ctid), "--", "/bin/bash", "/root/fv-install.sh",
             "--version", tag, "--archive", f"/root/{archive.name}",
             "--sha256", f"/root/{checksum.name}"], timeout=540)
        run(["pct", "exec", str(ctid), "--", "/bin/sh", "-c",
             'systemctl is-active --quiet filter-vision-web.service && '
             'curl -kfsS --max-time 10 https://127.0.0.1:9494/healthz | '
             'grep -q "\\"status\\":\\"ok\\""'], timeout=30)
        run(["pct", "exec", str(ctid), "--", "/bin/sh", "-c",
             'test ! -e /etc/filter-vision/cleaner-policy.json && '
             '! systemctl is-active --quiet filter-vision-cleaner.timer'])
        run(["pct", "exec", str(ctid), "--", "/bin/rm", "-f",
             "/root/fv-install.sh", f"/root/{archive.name}", f"/root/{checksum.name}"])
        ip_lines = run(["pct", "exec", str(ctid), "--", "ip", "-4", "-o", "addr",
                        "show", "dev", "eth0", "scope", "global"], capture=True)
        ip_match = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)/\d+", ip_lines)
        display_ip = ip_match.group(1) if ip_match else "(see Proxmox CT IP)"
    print(f"\nSUCCESS: Filter Vision {tag} in new Proxmox CT {ctid}")
    print(f"  WebUI: https://{display_ip}:9494/")
    print("  Self-signed TLS warning is expected until a trusted certificate is installed.")
    print("  Restrict passwordless WebUI access to a trusted LAN; never publish port 9494.")
    print("  New installation has NO connected accounts or automatic live deletion.")
except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError,
        subprocess.TimeoutExpired) as e:
    print(f"ERROR: {e}", file=sys.stderr)
    if ct_created:
        print(f"New CT {ctid} was PRESERVED for diagnosis (pct config/status/enter {ctid}).",
              file=sys.stderr)
        print("No unrelated CT or legacy cleaner was modified.", file=sys.stderr)
    sys.exit(1)
PY
