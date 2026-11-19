# Filter Vision

A self-hosted email analysis and filtering management WebUI for Debian 13.

**Stable foundation v0.1.0** includes local administrator login, offline multi-file EML header analysis, disabled account and rule drafts, activity history and a stable-only Updates screen. It does **not** connect to email accounts, scan mailboxes, or delete emails. The button to apply updates is also disabled until a safe rollback-capable updater is implemented and tested.

## Install on an existing Debian 13 LXC

Use the versioned GitHub stable release and run as root:

    curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install.sh -o /tmp/filter-vision-install.sh && sudo bash /tmp/filter-vision-install.sh

It uses the latest *stable* GitHub release only, verifies the application archive's SHA256 manifest, then starts the native systemd WebUI on port 9494 over HTTPS using a generated self-signed certificate.

Before submitting passwords or private email files, verify and explicitly trust the certificate or configure a trusted HTTPS reverse proxy. The setup token remains in the protected local file /var/lib/filter-vision/setup-token. Do not share it in reports.

## Important limits

There is no mail worker, IMAP OAuth connector, or enabled filtering engine in v0.1.0. Account and rule records are configuration drafts only.

Project continuity and operational infrastructure remain private. This repository contains only deliberately published application source and stable artifacts, never private project documents, account data or credentials.
