# shellcheck shell=bash
# Visual Proxmox bootstrap, modelled on Media Vision's established native installer.
# Included verbatim in the release entry script immediately before the Python backend.
# Supplying flags, --dry-run or FV_UNATTENDED=1 bypasses the interactive menus.
# Environment defaults are optional under the final entry script's set -u.
set +u
if [ "$#" -eq 0 ] && [ "$FV_UNATTENDED" != 1 ] && [ -r /dev/tty ]; then
    [ "$(id -u)" -eq 0 ] || { echo "Run on the Proxmox host as root" >&2; exit 2; }
    for cmd in pvesh pvesm pveam pct ip python3; do
        command -v "$cmd" >/dev/null 2>&1 || {
            echo "Not a Proxmox VE host: $cmd unavailable" >&2; exit 2;
        }
    done
    command -v whiptail >/dev/null 2>&1 || {
        echo "Visual menu requires whiptail (apt install whiptail on Proxmox)" >&2
        echo "For a headless install, use FV_UNATTENDED=1 with FV_CTID and options" >&2
        exit 2
    }
    # Same TAB-button highlighting fix used by Media Vision's native installer.
    unset NEWT_COLORS
    fv_visual() {
        whiptail --backtitle "Filter Vision Proxmox Installer" --title "Filter Vision Options" \
          "$@" 3>&1 1>&2 2>&3
    }
    fv_field() {
        local label="$1" def="$2"
        fv_visual --ok-button "Save" --cancel-button "Back" \
          --inputbox "$label" 12 74 "$def"
    }
    fv_storage() {
        local content="$1" selected="$2" title="$3" name type state rest
        local -a choices=()
        while read -r name type state rest; do
            [ "$state" = active ] || continue
            choices+=("$name" "$type")
        done < <(pvesm status --content "$content" | tail -n +2)
        [ "${#choices[@]}" -gt 0 ] || { echo "No active $content storage" >&2; exit 3; }
        fv_visual --default-item "$selected" --menu "$title" 20 76 12 "${choices[@]}"
    }
    fv_bridge() {
        local selected="$1" name
        local -a choices=()
        while IFS= read -r name; do
            [ -z "$name" ] || choices+=("$name" "Linux bridge")
        done < <(ip -o link show type bridge | awk -F': ' '{sub(/@.*/, "", $2);print $2}')
        if [ "${#choices[@]}" -eq 0 ]; then choices+=("$selected" "Network bridge"); fi
        fv_visual --default-item "$selected" --menu "Select Proxmox network bridge" \
          20 76 12 "${choices[@]}"
    }
    fv_timezone() {
        local selected="$1" tab region zone
        local -a regions=() zones=()
        tab=/usr/share/zoneinfo/zone1970.tab
        [ -r "$tab" ] || tab=/usr/share/zoneinfo/zone.tab
        [ -r "$tab" ] || { echo "Timezone list missing" >&2; return 1; }
        while IFS= read -r region; do
            [ -z "$region" ] || regions+=("$region" "Region")
        done < <(awk '!/^#/ && NF>=3 {split($3,a,"/");if(a[2]!="")print a[1]}' "$tab" | sort -u)
        region="$(fv_visual --default-item "$(printf '%s' "$selected" | cut -d/ -f1)" --menu \
          "Select timezone region: UP/DOWN, TAB buttons" 21 76 12 "${regions[@]}")" || return 1
        while IFS= read -r zone; do
            [ -z "$zone" ] || zones+=("$zone" "$zone")
        done < <(awk '!/^#/ && NF>=3 {print $3}' "$tab" | grep -F "$region/" | sort -u)
        [ "${#zones[@]}" -gt 0 ] || return 1
        fv_visual --default-item "$selected" --menu \
          "Select timezone: UP/DOWN, TAB buttons" 22 76 13 "${zones[@]}"
    }
    fv_default_gateway() {
        local address="$1"
        address="$(printf '%s' "$address" | cut -d/ -f1)"
        if [[ "$address" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}$ ]]; then
            printf '%s.%s.%s.1' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
        fi
    }
    ctid="$(pvesh get /cluster/nextid 2>/dev/null | tr -cd 0-9)"
    root="$(pvesm status --content rootdir | awk 'NR>1 && $3=="active"{print $1;exit}')"
    templates="$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active"{print $1;exit}')"
    bridge="$FV_BRIDGE"
    [ -n "$bridge" ] || bridge=vmbr0
    if ! ip link show "$bridge" >/dev/null 2>&1; then
        bridge="$(ip -o link show type bridge | awk -F': ' 'NR==1{sub(/@.*/, "", $2);print $2}')"
    fi
    [ -n "$ctid" ] && [ -n "$root" ] && [ -n "$templates" ] && [ -n "$bridge" ] ||
      { echo "Unable to inspect Proxmox cluster settings" >&2; exit 2; }
    ctid="$FV_CTID"; [ -n "$ctid" ] || ctid="$(pvesh get /cluster/nextid)"
    root="$FV_STORAGE"; [ -n "$root" ] || root="$(pvesm status --content rootdir | awk 'NR>1 && $3=="active"{print $1;exit}')"
    templates="$FV_TEMPLATE_STORAGE"; [ -n "$templates" ] || templates="$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active"{print $1;exit}')"
    hostname="$FV_HOSTNAME"; [ -n "$hostname" ] || hostname=filter-vision
    ip4="$FV_IP"; [ -n "$ip4" ] || ip4=dhcp
    gateway="$FV_GATEWAY"
    dns="$FV_NAMESERVER"
    vlan="$FV_VLAN"
    cores="$FV_CORES"; [ -n "$cores" ] || cores=2
    memory="$FV_MEMORY"; [ -n "$memory" ] || memory=2048
    swap="$FV_SWAP"; [ -n "$swap" ] || swap=512
    disk="$FV_DISK"; [ -n "$disk" ] || disk=16
    timezone="$FV_TIMEZONE"; [ -n "$timezone" ] || timezone=Australia/Brisbane
    version="$FV_VERSION_TAG"
    rootssh=no
    passwordfile=""
    private="$(mktemp -d -t fv-installer.XXXXXXXX)"
    chmod 0700 "$private"
    trap 'rm -rf -- "$private"' EXIT
    fv_defaults() {
        fv_visual --msgbox \
          "Current user defaults:\n\nCTID: $ctid\nRoot storage: $root\nTemplate storage: $templates\nBridge: $bridge\nIPv4: $ip4\nGateway: $gateway\nHostname: $hostname\nCPU: $cores  RAM: $memory MiB  Disk: $disk GiB\nTimezone: $timezone\nRelease: stable\n\nMailbox cleaning is OFF on new installations." 20 76
    }
    while :; do
        selection="$(fv_visual --notags --ok-button "Select" --cancel-button "Exit Script" \
          --default-item 1 --menu "UP/DOWN select; TAB moves buttons; ENTER confirms." 21 76 8 \
          1 "Default Install" 2 "Advanced Install" 3 "User Defaults" 4 "Settings")" ||
          { echo "Installation cancelled"; exit 0; }
        case "$selection" in
            1) mode=default; break ;;
            2) mode=advanced; break ;;
            3) fv_defaults || exit 0
               if fv_visual --yesno "Continue with these user defaults?" 10 65; then
                   mode=default; break
               fi ;;
            4)
                while :; do
                    setting="$(fv_visual --notags --menu \
                      "Installer defaults and networking" 21 76 10 \
                      1 "LXC VMID" 2 "Root storage" 3 "Template storage" \
                      4 "Network bridge" 5 "IPv4" 6 "Gateway" 7 "Hostname" 8 "Back")" || break
                    case "$setting" in
                        1) ctid="$(fv_field "New unused VMID" "$ctid")" || break ;;
                        2) root="$(fv_storage rootdir "$root" "Root storage")" || break ;;
                        3) templates="$(fv_storage vztmpl "$templates" "Template storage")" || break ;;
                        4) bridge="$(fv_bridge "$bridge")" || break ;;
                        5) ip4="$(fv_field "IPv4: dhcp or static CIDR" "$ip4")" || break ;;
                        6) gateway="$(fv_field "Static gateway" "$gateway")" || break ;;
                        7) hostname="$(fv_field "LXC hostname" "$hostname")" || break ;;
                        8) break ;;
                    esac
                done ;;
        esac
    done
    ctid="$(fv_field "New, unused Proxmox LXC VMID" "$ctid")" || exit 0
    if [ "$mode" = advanced ]; then
        root="$(fv_storage rootdir "$root" "ROOT STORAGE")" || exit 0
        templates="$(fv_storage vztmpl "$templates" "TEMPLATE STORAGE")" || exit 0
        bridge="$(fv_bridge "$bridge")" || exit 0
        network_mode="$(fv_visual --menu "IPv4 CONFIGURATION" 16 76 4 \
          dhcp "DHCP (recommended)" static "Static IPv4/CIDR")" || exit 0
        if [ "$network_mode" = dhcp ]; then ip4=dhcp; gateway=""
        else
            [ "$ip4" != dhcp ] || ip4=""
            ip4="$(fv_field "Static IPv4/CIDR" "$ip4")" || exit 0
            [ -n "$gateway" ] || gateway="$(fv_default_gateway "$ip4")"
            gateway="$(fv_field "Static gateway" "$gateway")" || exit 0
        fi
        hostname="$(fv_field "LXC hostname" "$hostname")" || exit 0
        disk="$(fv_field "Root disk GiB (default 16)" "$disk")" || exit 0
        cores="$(fv_field "CPU cores" "$cores")" || exit 0
        memory="$(fv_field "Memory MiB" "$memory")" || exit 0
        swap="$(fv_field "Swap MiB" "$swap")" || exit 0
        dns="$(fv_field "DNS (blank means Proxmox default)" "$dns")" || exit 0
        vlan="$(fv_field "VLAN tag (blank means none)" "$vlan")" || exit 0
        timezone="$(fv_timezone "$timezone")" || exit 0
        if fv_visual --defaultno --yesno \
          "Enable password-based root SSH in this NEW LXC?\n\nDefault: no; access via Proxmox console." 13 72; then
            rootssh=yes
            password="$(fv_visual --passwordbox "ROOT SSH PASSWORD" 12 74)" || exit 0
            [ -n "$password" ] || { echo "Empty password refused" >&2; exit 3; }
            confirm="$(fv_visual --passwordbox "CONFIRM PASSWORD" 12 74)" || exit 0
            [ "$password" = "$confirm" ] || { echo "Passwords do not match" >&2; exit 3; }
            unset confirm
            passwordfile="$private/root-pass"
            ( umask 077; printf '%s\n' "$password" > "$passwordfile" )
            unset password
        fi
    fi
    fv_visual --ok-button "Create LXC" --cancel-button "Cancel" --yesno \
      "CONFIRM FILTER VISION INSTALL\n\nNew CTID: $ctid\nStorage: $root\nHostname: $hostname\nCPU: $cores; RAM: $memory MiB; Disk: $disk GiB\nBridge: $bridge\nIPv4: $ip4\nTimezone: $timezone\nRoot SSH: $rootssh\nUpdate channel: stable only\n\nPasswordless HTTPS WebUI is trusted LAN only.\nNo existing LXC is overwritten.\nNo mailbox cleaning starts by default.\n\nCreate this new LXC?" 22 76 ||
      { echo "Cancelled before creating a container"; exit 0; }
    set -- --ctid "$ctid" --storage "$root" --template-storage "$templates" \
      --bridge "$bridge" --ip "$ip4" --hostname "$hostname" \
      --cores "$cores" --memory "$memory" --swap "$swap" --disk "$disk" \
      --timezone "$timezone" --root-ssh "$rootssh" --yes
    [ -z "$gateway" ] || set -- "$@" --gateway "$gateway"
    [ -z "$dns" ] || set -- "$@" --nameserver "$dns"
    [ -z "$vlan" ] || set -- "$@" --vlan "$vlan"
    [ -z "$version" ] || set -- "$@" --version "$version"
    [ -z "$passwordfile" ] || set -- "$@" --root-password-file "$passwordfile"
fi
set -u
