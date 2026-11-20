<div align="center">

# 🛡️ Filter Vision

### Your email. Your rules. Your server.

A self-hosted email analysis and Junk-filtering console for Proxmox, built around precise rules and cautious mailbox operations.

[![Latest stable release](https://img.shields.io/github/v/release/zemerdon/filter-vision?label=stable%20release&color=20b8b0)](https://github.com/zemerdon/filter-vision/releases/latest)
![Platform](https://img.shields.io/badge/platform-Proxmox%20VE-E57000)
![Guest](https://img.shields.io/badge/guest-Debian%2013-2878b8)
![Updates](https://img.shields.io/badge/updates-stable%20only-5967b4)

[**Install**](#-installation) · [**Features**](#-features) · [**WebUI**](#-webui) · [**Safety**](#-security--deletion-safety) · [**Releases**](https://github.com/zemerdon/filter-vision/releases) · [**Issues**](https://github.com/zemerdon/filter-vision/issues)

</div>

---

## What is Filter Vision?

Filter Vision is a standalone, self-hosted application for examining suspicious email, reviewing filtering rules, and managing a conservative scheduled Junk-mail cleaner.

It combines a compact, responsive dark-themed HTTPS WebUI with native Debian services. Account connections, filter rules, schedules and audit records remain under your control.

**Current focus:** Microsoft Outlook / Hotmail consumer accounts, using OAuth2 and exact-header legacy-compatible filtering. More providers and more flexible rule activation are planned, not advertised as working today.

## 🚀 Installation

**This is the only supported public installation entry point.** Run the following **as root on a Proxmox VE host**, not inside an existing container:

    bash -c "$(curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install-proxmox.sh)"

The one-liner opens a Media Vision-style terminal installer:

| Menu | Purpose |
| --- | --- |
| **Default Install** | Create a new LXC with recommended defaults |
| **Advanced Install** | Select storage, networking, resources, timezone and optional root SSH |
| **User Defaults** | Review the proposed setup |
| **Settings** | Adjust installer defaults |

### Default configuration

| Setting | Default |
| --- | --- |
| Platform | Proxmox VE, x86_64 |
| Container | New **unprivileged Debian 13 LXC** |
| CPU | **2 vCPU** |
| RAM | **2048 MiB** |
| Swap | 512 MiB |
| Root disk | **16 GiB** |
| Network | DHCP on a Proxmox bridge |
| Timezone | Australia/Brisbane |
| Root SSH password login | Disabled |
| WebUI | **HTTPS, port 9494** |
| Update channel | GitHub **stable** releases only |
| Connected mailboxes / active deletion | **None / disabled** |

**Prerequisites:** Proxmox VE with an available bridge and suitable storage, Python 3 on the host, the Whiptail terminal menu package, and outbound access to GitHub and Debian package mirrors. The installer can obtain the Debian 13 container template using Proxmox tools.

The script checks for an unused cluster-wide VMID, validates storage and networking, and verifies the versioned application archive's SHA256 **before** creating the container. It never overwrites an existing CT. If installation fails after creating a new container, that new CT is retained for troubleshooting rather than automatically destroyed.

### When installation finishes

The installer prints the new container's IP address. Open the WebUI at an address of this form:

    https://YOUR-LXC-IP:9494/

The first certificate is self-signed; an initial browser warning is expected. Restrict access to your trusted internal network.

**New installs do not connect accounts, approve rules or start permanent deletion.** Follow the [Getting started](#-getting-started) section to connect a mailbox.

> **Installation test status:** release assets, archive checksums and mocked Proxmox provisioning have been verified. A real new-LXC installation on a Proxmox node has not yet completed end-to-end acceptance testing.

## ✨ Features

| Capability | Available today |
| --- | --- |
| **Private WebUI** | Responsive dark console, served over HTTPS |
| **Microsoft OAuth2** | Browser authorization-code + PKCE for Outlook/Hotmail; encrypted token vault |
| **Junk preview** | Read-only IMAP inspection before live filtering |
| **Email analyzer** | Analyze uploaded .eml samples and suggest narrow header fingerprints |
| **Rule management** | Edit or duplicate inactive drafts directly; propose edits/duplicates of protected rules; request Enable/Disable for review only (not a live toggle) |
| **Legacy-compatible cleaner** | Exact-header matches for separately authorized Microsoft accounts |
| **Targeted deletion** | Requires IMAP UIDPLUS; UID-specific STORE/EXPUNGE rather than blanket expunge |
| **Schedule controls** | Status, last/next run, adjustable 5-minute to 24-hour interval |
| **Service controls** | Start, Stop and Restart Schedule; confirmed Run Now |
| **Activity & statistics** | Readable server-local timestamps, total scans/examined/matched/deleted counts, failures and confirmed per-rule filtering counts |
| **Expandable filtered emails** | Future confirmed matches show exact applied rules and encrypted text-only previews, with no attachments or active HTML |
| **Activity settings** | Show 25, 50, 100, 250 or 500 recent records; full audit statistics remain retained |
| **Updates** | In-app GitHub stable release check, readable bullet-point changelog and actual running-version verification |
| **Recovery** | Encrypted full-state backup including the private activity decryption key, with verified staging restore through protected server tooling |

### Designed to avoid false positives

Filter Vision does **not** treat a suspicious message as permission to delete it.

- Uploaded message analysis suggests rules; it does not activate them.
- Ordinary disabled and unscoped drafts can be edited, duplicated or deleted without changing live filtering.
- All rules have Edit, Duplicate and Enable/Disable request controls. Protected rule edits and duplicates are isolated proposals; enable/disable creates **pending review**, not a live change.
- The original 22 root-approved signatures and account scopes remain unchanged until an independently reviewed, root-controlled approval workflow authorizes an exact transition.
- Connecting Microsoft does not automatically start deletion.
- Live filtering requires protected account-and-rule approval.
- The worker checks the Junk folder, UID validity, message headers and UIDPLUS capabilities before deleting an approved match.
- A bounded, encrypted message-action history record is required **before** a future matched message can be permanently deleted; if that record cannot be saved, deletion is refused.
- Required safety checks fail closed rather than falling back to a mailbox-wide EXPUNGE.

**A permanently expunged message cannot be restored by an application backup.**

## 🖥️ WebUI

Filter Vision has seven main pages:

| Page | What it shows or does |
| --- | --- |
| **Dashboard** | Account and rule totals, cleaner status and shortcuts |
| **Accounts** | Microsoft connect/reauthorize, account drafts and read-only Junk preview |
| **Analyze Email** | Read-only scan connected Microsoft Junk folders or upload .eml samples; select emails, manually test headers and wildcards, view matched/missed results and save only inactive supported drafts |
| **Rules** | Edit/duplicate drafts; prepare protected-rule replacements, request Enable/Disable for specified accounts, review/cancel pending requests (no automatic live activation) |
| **Activity** | Scan and filtering statistics, per-rule effectiveness, readable server time and expandable text-only matched-message details |
| **Updates** | Check/apply verified GitHub stable releases, read the in-app bullet changelog and see the actual running version |
| **Settings** | Timer status, scan interval, Activity display length and cleaner Start/Stop/Restart with a clearly separated Run Now confirmation |

The current .eml analyzer accepts **up to 20 files**, **2 MiB per file**, **10 MiB total**; it does not automatically activate filtering.

**History and privacy:** Activity defaults to the newest 50 records, configurable to 25–500, and shows readable times in the **server's actual timezone**. Lifetime totals include older aggregate audit records, but per-rule email attribution and expandable encrypted message previews are available **only for future matches logged since v0.2.4**; email previously deleted cannot be reconstructed. The preview retains only bounded safe text, not attachments, scripts or raw HTML. Searchable history, exports and retention controls remain planned.

## Read-only Junk analysis and manual evaluation

On Analyze Email, select **Scan Junk folders** to list the latest 40 Junk messages from each connected Microsoft account. Choose up to 20 messages across accounts, then select **Analyze selected Junk emails**. You can still upload .eml samples instead.

Switch to **Manual evaluation** and choose a field (From address/domain, Subject, Reply-To, Return-Path, a named header, any header or HTML clickable destination) and a comparison (exact, contains, starts with, ends with or literal * wildcard). A pattern such as *hockey.com can show 2/4 matched and the exact matched and missed messages. It is read-only, never enables deletion and does not save a rule. Broad patterns can match legitimate mail.

Selection evidence is kept temporarily in server RAM for at most 15 minutes, not saved as copies of email in SQLite. The live cleaner remains restricted to separately root-approved signatures.

## 🔗 Getting started

1. **Install** with the Proxmox one-liner and open the HTTPS WebUI.
2. Under **Accounts**, create an Outlook/Hotmail account draft. Gmail and generic IMAP are not yet live connectors.
3. **Configure a Microsoft OAuth client** for each mailbox. The current implementation expects an existing Microsoft client configuration in the protected server file at **/etc/filter-vision/oauth-clients.json**. The installer does not create this for you automatically.
4. Choose **Connect Microsoft**. Sign in through the browser authorization-code + PKCE flow.
5. The current redirect points at a registered **localhost** URL. The browser may show an unreachable page; copy the full callback URL from the address bar and paste it **only into the Filter Vision authorization form**. Never share callback URLs, OAuth codes, tokens or client settings in issues or chat.
6. Select **Test Junk (read-only)** to inspect the mailbox safely.
7. Review rule drafts separately. Root-managed authorization is required for live deletion; fresh installations do **not** automatically enable it.

An automatic HTTPS OAuth callback and broader self-service rule activation are future work.

## ⚙️ Scheduling & service controls

Once live cleaning has been explicitly authorized, **Settings → Cleaner Service** shows real systemd timer and worker status.

- Intervals available: **5, 10, 15, 20, 30, 60, 120, 240, 360, 720 or 1440 minutes**.
- **Stop Schedule** pauses future timer runs; it does not interrupt a scan already in progress.
- **Start Schedule** resumes scheduled scanning; **Restart Schedule** restarts an active timer.
- **Run Now** immediately executes the approved cleaner after an explicit permanent-deletion acknowledgement.

These fixed controls do not offer general root command execution and do not bypass protected rule/account approval.

## 🔒 Security & deletion safety

**The WebUI is deliberately passwordless.** Anyone on an allowed network who can reach it can administer the application and request supported cleaner operations. It is intended for **trusted internal networks only**.

- **Never expose TCP 9494 directly to the public internet** or via an unrestricted reverse proxy.
- Review allowed source CIDRs and Host restrictions in **/etc/filter-vision/web.env**.
- Use HTTPS, and replace the self-signed certificate if a trusted certificate is required.
- Keep private mail, credentials, OAuth secrets and backup keys out of public repositories and issue attachments.
- Preserve encrypted backups **and the separate recovery encryption key** before irreversible migration or rule changes.
- Never run two destructive cleaners against the same mailbox concurrently.

OAuth tokens are stored encrypted. The WebUI uses signed browser cookies, CSRF/Origin protections and a restricted privileged helper for service operations. None of these controls make a passwordless console appropriate for unrestricted internet access.

## 🔄 Stable updates

In the WebUI, open **Updates → Check for updates**, then **Apply** when a newer stable release is available.

There is **no develop update channel**. The updater checks verified release assets, takes a database snapshot, installs the new version and verifies service health. A rollback is attempted on failure, but full update-failure injection testing remains on the roadmap. Maintain your own protected encrypted backups.

[**View stable releases and changelogs**](https://github.com/zemerdon/filter-vision/releases)

## 🧱 Technology

- **Runtime:** native Debian 13 unprivileged LXC on Proxmox
- **Application:** Python, FastAPI, Uvicorn and Jinja2
- **Storage:** SQLite and protected local account/token files
- **Services:** systemd-managed HTTPS WebUI, cleaner timer and stable updater
- **Mail:** TLS IMAP and Microsoft OAuth2/XOAUTH2
- **Frontend:** responsive HTML/CSS; **no Docker dependency**

## 🚧 Current status & roadmap

Filter Vision is an **early stable release** with a working Microsoft-focused legacy-compatible cleaner. It is **not yet a general-purpose multi-provider spam filtering engine**.

Planned improvements include searchable privacy-aware Activity history and export/retention controls, more complete scan health alerts, reviewed per-account/per-rule activation, more email providers, automatic Microsoft callback handling, in-page recovery controls and real Proxmox field-install acceptance.

## 💬 Feedback

Bug reports and ideas are welcome in [**GitHub Issues**](https://github.com/zemerdon/filter-vision/issues). Include the Filter Vision version, affected page, expected result and **sanitized** diagnostics. Do not attach message contents, OAuth callback URLs, tokens, recovery keys or unredacted logs.

Follow the [**stable releases**](https://github.com/zemerdon/filter-vision/releases) for updates.

---

<div align="center">

**Filter Vision** · Self-hosted email analysis and cautious filtering

*One Proxmox installation method. One stable update channel. Your mail stays on your server.*

</div>
