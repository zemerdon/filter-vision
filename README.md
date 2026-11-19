# Filter Vision

A self-hosted, native Debian 13 email-analysis and filtering administration UI.

**v0.1.3 stable foundation:** passwordless WebUI restricted to trusted source networks, signed HTTPS browser cookies/CSRF, offline multi-file EML header analysis, disabled account/rule drafts, legacy noncredential configuration importer, activity history, GitHub stable-only update checks and a fixed-action root update service.

**Important:** Live OAuth2/IMAP connectivity, scheduled scanning and deletion are **not enabled in this release**. Existing mail cleaners must remain running until migration is verified.

## Install in an existing Debian 13 LXC

    curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install.sh -o /tmp/filter-vision-install.sh && sudo bash /tmp/filter-vision-install.sh

The installer fetches the latest published stable release and checks its archive's SHA256, then starts an unprivileged systemd WebUI on port 9494 over HTTPS. The initial certificate is self-signed.

**Passwordless:** anyone on an allowed source-IP network who can reach the WebUI can administer it. Review /etc/filter-vision/web.env (CIDR and Host-header restrictions). Do not expose port 9494 directly on the internet or via an unrestricted proxy. The user never needs a WebUI password or setup code.

Updates download published GitHub stable assets through a fixed root-owned update helper; verify backup/rollback before relying on unattended updates.

Public GitHub source must never contain private project instructions, OAuth credentials, protected user emails or message samples.
