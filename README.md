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

**Current focus:** Microsoft Outlook / Hotmail consumer accounts, using OAuth2, original raw-header signatures, reviewed new header rules and a bounded HTML-link-host matcher. Other providers are not yet tested live connectors.

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
| **Rule management** | One-click Edit, Duplicate, Enable and Disable for imported and custom rules, protected root-managed activation and verified status |
| **Bulk Rules actions** | Per-rule checkboxes and Select all for Delete, Enable, Disable and Duplicate; root verification and protected-rule limits remain in place |
| **Analyze candidate workflow** | Save drafts without leaving Analyze; hide saved suggestions; select and save or request approval for multiple new rules together |
| **Collapsible activity and analysis** | Expandable filtering/history, manual evaluation and campaign evidence with clear disclosure indicators |
| **Legacy-compatible cleaner** | Original 22 signatures retained as a recoverable baseline; protected overrides can edit or disable any imported rule |
| **Targeted deletion** | Requires IMAP UIDPLUS; UID-specific STORE/EXPUNGE rather than blanket expunge |
| **Schedule controls** | Status, last/next run, adjustable 5-minute to 24-hour interval |
| **Service controls** | Start, Stop and Restart Schedule; confirmed Run Now |
| **Activity & statistics** | Readable server-local timestamps, total scans/examined/matched/deleted counts, failures and confirmed per-rule filtering counts |
| **Expandable filtered emails** | Future confirmed matches show exact applied rules and encrypted text-only previews, with no attachments or active HTML |
| **Activity settings** | Show 25, 50, 100, 250 or 500 recent records; full audit statistics remain retained |
| **Updates** | Three compact controls: Check for updates, Update and a collapsed expandable Changelog |
| **Recovery** | Encrypted full-state backup including the private activity decryption key, with verified staging restore through protected server tooling |

### Designed to avoid false positives

Filter Vision does **not** treat a suspicious message as permission to delete it.

- Uploaded message analysis suggests rules; it does not activate them.
- **Every rule** offers Edit, Duplicate, Enable and Disable, without confirmation tick boxes or a separate approval form.
- Enable automatically previews up to 20 recent Junk messages per approved Microsoft account read-only, then requests a **root-owned, fingerprint-validated** policy update. The WebUI reports **Activated** only once the protected policy confirms that state.
- Editing an active rule uses the root-managed update path, never an unnoticed direct SQLite edit. Duplicates start disabled and never inherit account approvals.
- The original 22 imported signatures and 44 account scope links are preserved as a checksum-verified, **recoverable baseline**. Root-owned overrides store effective edits and disabled states without rewriting original data.
- The optional HTML click-host and raw-header draft matchers must be explicitly enabled; sample-only spam coverage is not evidence of safety against legitimate mail.
- Connecting Microsoft does not automatically start deletion.
- Live filtering requires protected account-and-rule approval.
- The worker checks Junk, UID validity, message headers and UIDPLUS capabilities before deleting an approved match. For explicitly approved HTML-link rules, it parses bounded MIME without external network requests and verifies an unchanged second fetch before any UID-specific deletion.
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
| **Rules** | Edit, Duplicate, Enable or Disable original and new rules directly; shows effective status only after root-controlled confirmation |
| **Activity** | Scan and filtering statistics, per-rule effectiveness, readable server time and expandable text-only matched-message details |
| **Updates** | Check for updates, Update when newer stable exists, and expand Changelog on demand |
| **Settings** | Timer status, scan interval, Activity display length and cleaner Start/Stop/Restart with a clearly separated Run Now confirmation |

The current .eml analyzer accepts **up to 20 files**, **2 MiB per file**, **10 MiB total**; it does not automatically activate filtering.

**History and privacy:** Activity defaults to the newest 50 records, configurable to 25–500, and shows readable times in the **server's actual timezone**. Lifetime totals include older aggregate audit records, but per-rule email attribution and expandable encrypted message previews are available **only for future matches logged since v0.2.4**; email previously deleted cannot be reconstructed. The preview retains only bounded safe text, not attachments, scripts or raw HTML. Searchable history, exports and retention controls remain planned.

## Read-only Junk analysis and manual evaluation

In v0.2.11, **Save draft** returns directly to Analyze, and previously saved candidates are hidden. Header-only coverage plans offer per-rule checkboxes, **Select all**, **Save selected drafts** and **Enable selected**. Activation is requested only after a bounded read-only Junk preview and verified root approval; sample coverage alone is not a false-positive guarantee.

On Analyze Email, select **Scan Junk folders** to list the latest 40 Junk messages from each connected Microsoft account. Use **Select all** to select up to the first 20 messages (or select specific messages manually), then choose **Analyze selected Junk emails**. You can still upload .eml samples instead.

The **Header-only coverage options** section uses the same literal, case-insensitive raw-header substring matching logic as the original cleaner, alongside exact campaign fields, sender domains and sender addresses. It searches a bounded set of uncommon, non-sensitive headers for stable campaign fragments (including repeated portions of changing IDs), then proposes a **compact combination with the fewest conditions found**. It shows matched messages, uncovered messages, and a note when a bounded heuristic was used instead of a proven minimum among the generated candidates. Common Microsoft transit/authentication/spam-score headers are deliberately excluded from automatic suggestions.

Suggestions are **saved disabled**, never activated automatically. On Rules, a saved header or HTML click-host draft can then be enabled with one click. The protected helper validates the exact rule/account approval and performs a bounded read-only Junk preview before applying. A shared spam link or fingerprint does **not** prove safe matching on legitimate mail. Enabled matches may be permanently deleted from the authorized Junk folders; review broad candidates carefully. The 22 imported signatures and original 44 account scope links are kept as a rollback baseline.

Switch to **Manual evaluation** and choose a field (From address/domain, Subject, Reply-To, Return-Path, a named header, any header or HTML clickable destination) and a comparison (exact, contains, starts with, ends with or literal * wildcard). A pattern such as *hockey.com can show 2/4 matched and the exact matched and missed messages. It is read-only, never enables deletion and does not save a rule. Broad patterns can match legitimate mail.

Selection evidence is kept temporarily in server RAM for at most 15 minutes, not saved as copies of email in SQLite. The live cleaner remains restricted to separately root-approved signatures.

## 🔗 Getting started

1. **Install** with the Proxmox one-liner and open the HTTPS WebUI.
2. Under **Accounts**, create an Outlook/Hotmail account draft. Gmail and generic IMAP are not yet live connectors.
3. **Configure a Microsoft OAuth client** for each mailbox. The current implementation expects an existing Microsoft client configuration in the protected server file at **/etc/filter-vision/oauth-clients.json**. The installer does not create this for you automatically.
4. Choose **Connect Microsoft**. Sign in through the browser authorization-code + PKCE flow.
5. The current redirect points at a registered **localhost** URL. The browser may show an unreachable page; copy the full callback URL from the address bar and paste it **only into the Filter Vision authorization form**. Never share callback URLs, OAuth codes, tokens or client settings in issues or chat.
6. Select **Test Junk (read-only)** to inspect the mailbox safely.
7. Review saved drafts and choose **Enable** on the Rules page when you intend to activate the condition. A fresh installation still requires separately authorized account connections and a root-owned live-cleaner policy before any deletion can occur.

An automatic HTTPS OAuth callback remains future work; self-service per-rule activation is supported on systems with the protected live cleaner already authorized.

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

On **Updates**, choose **Check for updates**; when a newer stable release is available, **Update** becomes available. Choose **Changelog** to expand the release notes below the three controls. The changelog is collapsed by default.

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
