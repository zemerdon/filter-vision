# Filter Vision

**Filter Vision** is a self-hosted email spam analysis and filtering application. It provides an HTTPS administration WebUI, Microsoft browser OAuth2/PKCE sign-in, read-only Junk previews, exact-header spam filtering, scan history and protected cleaner scheduling.

## Install — Proxmox VE

Run **one command as root on your Proxmox VE host**:

    bash -c "$(curl -fsSL https://github.com/zemerdon/filter-vision/releases/latest/download/install-proxmox.sh)"

This is the **only supported public installation entry point**. It creates a **new Debian 13 unprivileged LXC** and installs the latest **stable** release of Filter Vision. It does not overwrite an existing container, and no Docker or develop channel is used.

The installer follows Media Vision's familiar menus: **Default Install**, **Advanced Install**, **User Defaults**, and **Settings**. Advanced options include Proxmox storage, bridge, DHCP/static IPv4, gateway, DNS, VLAN, timezone and optional root SSH (disabled by default). Whiptail must be available on the Proxmox host for the interactive menus.

### Installation defaults

| Option | Default |
| --- | --- |
| Debian | 13, x86_64, unprivileged LXC |
| CPU | 2 vCPU |
| Memory | 2048 MiB |
| Root disk | 16 GiB |
| Swap | 512 MiB |
| Networking | DHCP, host-selected bridge |
| Timezone | Australia/Brisbane |
| WebUI | HTTPS, port **9494** |
| GitHub update channel | **Stable only** |
| Root SSH | Disabled |
| Account connections / live mail deletion | **Disabled on new installs** |

After installation, the installer prints the new container's IP address and HTTPS address on port 9494. The initial certificate is self-signed, so a browser certificate warning is expected.

**Security:** The passwordless WebUI is intended only for trusted internal networks. Keep port 9494 off the public internet. Live message deletion remains separately approved and limited to explicitly authorized account/rule policies. Expunged mail cannot be restored by an application backup.

The installer pins an official stable release, checks its application-archive SHA256, extracts its **internal** guest bootstrap, creates a new CT only after validation and verifies HTTPS health. A newly created CT is retained for diagnosis on installation failure instead of being deleted.

### Updates and maintenance

Subsequent updates use the built-in **Updates** page in Filter Vision's WebUI. The versioned archive includes the internal native guest setup required for provisioning and updates; **there is no separate public existing-LXC installation command**.

A fresh Proxmox CT has been covered by automated simulated Proxmox tests, but an actual on-host new-CT installation remains to be verified. Release notes and versions are available under [GitHub Releases](https://github.com/zemerdon/filter-vision/releases).

## Existing core features

- Microsoft OAuth2 authorization with browser PKCE; encrypted account tokens.
- Read-only Junk previews and conservative reviewed legacy-header rules.
- Root-approved UID-specific STORE/EXPUNGE filtering with UIDPLUS safety checks.
- Cleaner service status, configurable scan intervals and controlled Start, Stop, Restart and Run Now.
- SQLite audit activity, HTTPS/CSRF protection, encrypted full-state recovery and stable GitHub updates.

**Project policy:** private mail contents, credentials, OAuth keys, protected recovery archives and internal project documents never belong in the public GitHub repository.
