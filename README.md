# Filter Vision

A self-hosted, native Debian 13 email-analysis and filtering application with an HTTPS administration console.

**v0.2.2 stable:** passwordless trusted-network WebUI, Microsoft browser OAuth2 + PKCE, encrypted account credentials, read-only Junk previews, and carefully root-gated UID-specific deletion of legacy-approved exact-header matches. The web console includes live cleaner status, schedule adjustment, Start/Stop/Restart Schedule, and protected Run Now actions. Root systemd helpers accept only validated fixed operations.

**Important:** New installations do not begin deleting messages automatically. Root-managed rule approval and verified legacy-offline state must be present before any live cleaning action. Existing installations keep their approved cleaner and schedule during updates. Matching messages that are expunged are permanently deleted.

## Install in an existing Debian 13 LXC

    curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install.sh -o /tmp/filter-vision-install.sh && sudo bash /tmp/filter-vision-install.sh

The installer fetches the latest published stable release and checks its archive's SHA256, then starts an unprivileged systemd WebUI on port 9494 over HTTPS. The initial certificate is self-signed.

**Passwordless:** anyone on an allowed source-IP network who can reach the WebUI can administer it. Review /etc/filter-vision/web.env (CIDR and Host-header restrictions). Do not expose port 9494 directly on the internet or via an unrestricted proxy. The user never needs a WebUI password or setup code.

Updates download published GitHub stable assets through a fixed root-owned update helper; verify backup/rollback before relying on unattended updates.

Public GitHub source must never contain private project instructions, OAuth credentials, protected user emails or message samples.

## v0.1.5 browser form compatibility

Fixed an overly strict Origin/Host comparison affecting the Microsoft Connect and Check for Updates POST forms with some browser origin representations. Cross-site and mixed-scheme origins remain blocked; all mutating routes still require the signed, SameSite browser session cookie and matching CSRF token. Restored missing imports for OAuth refresh and read-only Junk preview.

## v0.1.6 Microsoft device-authorization compatibility

Accepts Microsoft's verified HTTPS device-login hostname login.microsoft.com in the authorization response. The previous restricted hostname list excluded this legitimate response and prevented the verification code from appearing even after the browser Origin fix. Other hosts and non-HTTPS verification URLs remain blocked.

## v0.1.7 Microsoft device-code usability and IMAP XOAUTH2 fix

Use the official Microsoft device-login URL displayed alongside the device user code. Never use a 127.0.0.1 callback for the device-code flow. Corrected the XOAUTH2 SASL separator bytes for real Outlook IMAP authentication, with regression tests protecting the protocol payload. Existing cleaner and mail deletion remain unchanged.

## v0.1.8 Microsoft browser sign-in fallback

Added an alternative Microsoft authorization-code flow using the existing, explicitly configured localhost redirect and PKCE (S256). After signing in, users can privately paste the redirected callback URL back into Filter Vision over HTTPS for state verification and single-use token redemption. The browser code is not stored in logs, Git, or account rows. The original device-code flow remains available; both ways still require successful read-only IMAP authentication before encrypted credentials are saved. No cleaner scheduler or mailbox delete action is activated.

## v0.1.9 Browser authorization feedback

After a pasted OAuth callback fails, Filter Vision redirects directly to a visible, accessible result beside the browser sign-in form, with clear next steps. It does not silently discard attempts or rely on the user finding an error at the top of a long mobile page. Safe, categorical audit events record the stage (callback, Microsoft response, token exchange, IMAP validation, token storage) without recording codes or callback URLs. Successful connections are still marked only after Microsoft token redemption, read-only IMAP validation and encrypted credential storage. No automatic scanning or deletion is enabled.

## v0.2.0 Legacy-compatible cleaner and recovery

Includes conservative, account-scoped, exact legacy raw-header matching with UIDPLUS-only targeted UID EXPUNGE (never blanket EXPUNGE), root-owned explicit cutover approval, per-mailbox locking and systemd 30-minute scheduling. The cleaner units are installed disabled, requiring verified legacy shutdown and a separate root-owned policy before any live mutation. Also includes full encrypted database/configuration/OAuth vault backup, integrity verification and restore into isolated staging directories. Live permanent deletions cannot be reversed. Both accounts must be authorized and the owner must explicitly approve cutover; no installation alone activates deletion.


## v0.2.1 — Cleaner Service and accurate capabilities

Settings exposes the live systemd timer, last scan result, next scheduled scan, and current cleaner process state. The global scan interval can be set to 5, 10, 15, 20, 30, 60, 120, 240, 360, 720 or 1440 minutes. Start, Stop and Restart control the schedule without interrupting an in-flight deletion; Run Now initiates an explicitly confirmed live scan. The privileged root-owned helper validates only fixed actions, enforces the existing protected filtering policy, prevents injected commands, and restores the prior timer configuration if a schedule update fails. Installed WebUI updates, Rules status, Accounts effective schedules, service status and footer now accurately reflect the live filtering capability. Microsoft sign-in offers only the successful browser PKCE method, without invalidating existing tokens.


## v0.2.2 — Native Proxmox LXC one-liner

New native, **unprivileged Debian 13 LXC** installer for Proxmox VE, matching Media Vision's established Whiptail menus (Default Install, Advanced Install, User Defaults, Settings), storage/bridge selectors, network and timezone configuration, and optional root-SSH password setup (disabled by default). Defaults: **2 vCPU, 2 GiB RAM, 16 GiB disk, 512 MiB swap**, DHCP and Australia/Brisbane. A single stable release script runs on the **Proxmox host**, never inside an existing container:

    bash -c "$(curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install-proxmox.sh)"

No Docker, no development channel. Provisioning refuses existing cluster CT/VM IDs, checks Proxmox storages/bridge and Debian 13 template, pins the latest stable application release, validates its SHA256 archive before creating the CT, and preserves a newly created CT for diagnostics if installation fails. The installer does not connect mail accounts, enable rules or activate permanent deletion. An existing Debian 13 LXC can continue using install.sh from the same stable release. Advanced CLI and --dry-run support unattended operators. Only enable this passwordless HTTPS interface on trusted internal networks.
