# Filter Vision

A self-hosted, native Debian 13 email-analysis and filtering administration UI.

**v0.1.8 stable foundation:** passwordless WebUI restricted to trusted source networks, signed HTTPS browser cookies/CSRF, offline EML header analysis, imported account/rule drafts, Microsoft device-code OAuth2 reauthorization with encrypted tokens, read-only Junk rule previews, and the verified GitHub stable updater.

**Important:** Microsoft account authorization and read-only IMAP previews are available, but **scheduled scanning and deletion are not enabled**. Existing mail cleaners must remain running until the new account authorization, rule parity, backup/restore and safe cutover are verified.

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
