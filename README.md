# Filter Vision

A self-hosted, native Debian 13 email-analysis and filtering administration UI.

**v0.1.4 stable foundation:** passwordless WebUI restricted to trusted source networks, signed HTTPS browser cookies/CSRF, offline EML header analysis, imported account/rule drafts, Microsoft device-code OAuth2 reauthorization with encrypted tokens, read-only Junk rule previews, and the verified GitHub stable updater.

**Important:** Microsoft account authorization and read-only IMAP previews are available, but **scheduled scanning and deletion are not enabled**. Existing mail cleaners must remain running until the new account authorization, rule parity, backup/restore and safe cutover are verified.

## Install in an existing Debian 13 LXC

    curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install.sh -o /tmp/filter-vision-install.sh && sudo bash /tmp/filter-vision-install.sh

The installer fetches the latest published stable release and checks its archive's SHA256, then starts an unprivileged systemd WebUI on port 9494 over HTTPS. The initial certificate is self-signed.

**Passwordless:** anyone on an allowed source-IP network who can reach the WebUI can administer it. Review /etc/filter-vision/web.env (CIDR and Host-header restrictions). Do not expose port 9494 directly on the internet or via an unrestricted proxy. The user never needs a WebUI password or setup code.

Updates download published GitHub stable assets through a fixed root-owned update helper; verify backup/rollback before relying on unattended updates.

Public GitHub source must never contain private project instructions, OAuth credentials, protected user emails or message samples.
