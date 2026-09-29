#!/usr/bin/env bash
# Naboo hardware configuration. All selected checks run; nonzero exit means FAIL.
# Maintain Naboo's expected quantities here, not in the cycle wizard.
set -uo pipefail
export LC_ALL=C
CPU_MIN=2
DIMM_EXPECTED=16
NVMe_MIN=2
NIC_MIN=22
BF4_EXPECTED=1
PCIEFAB_MIN=20
USB_MIN=1
BMC_MIN=1
FAILURES=0
fail() {
    printf 'ISSUE|%s|%s|%s\n' "$1" "$2" "$3"
    FAILURES=$((FAILURES + 1))
}
minimum() {
    local component="$1" actual="$2" expected="$3" code="${4:-DEVICE_MISSING}"
    printf 'CHECK|%s|actual=%s|minimum=%s\n' "$component" "$actual" "$expected"
    if ((actual < expected)); then fail "$code" "$component" "Expected at least $expected; detected $actual"; fi
}
collect() {
    local variable="$1" component="$2"
    shift 2
    local value rc
    value=$("$@" 2>&1); rc=$?
    printf -v "$variable" '%s' "$value"
    printf '\n[Evidence] %s\n%s\n' "$component" "$value"
    if ((rc != 0)); then fail COLLECTION_FAILED "$component" "Command exited $rc"; fi
    return "$rc"
}
cpu_check() {
    local data qty
    collect data CPU dmidecode -t processor || return
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Status:.*Populated/ && !/Unpopulated/ {n++} END {print n+0}')
    minimum CPU "$qty" "$CPU_MIN"
}
dimm_check() {
    local data qty
    collect data DIMM dmidecode -t memory || return
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Size:[[:space:]]+[0-9]+[[:space:]]+(MB|GB|TB)/ {if ($2+0>0) n++} END {print n+0}')
    printf 'CHECK|DIMM|actual=%s|exact=%s\n' "$qty" "$DIMM_EXPECTED"
    if ((qty != DIMM_EXPECTED)); then fail DIMM_COUNT DIMM "Expected exactly $DIMM_EXPECTED installed SOCAMM devices; detected $qty"; fi
}
nvme_check() {
    local data qty
    collect data NVMe nvme list || return
    qty=$(printf '%s\n' "$data" | awk '$1 ~ /^\/dev\/nvme[0-9]+n[0-9]+$/ {v=$1; sub(/n[0-9]+$/, "", v); a[v]=1} END {for (v in a) n++; print n+0}')
    minimum NVMe "$qty" "$NVMe_MIN"
}
nic_bf4_check() {
    local data nic bf4_cards bf4_ports modules
    local mst_valid=true
    collect data MST mst status -v || mst_valid=false
    # Count Vera devices from the mst device table. The MST column is only
    # populated when the MST kernel module is loaded, so keying on '/dev/mst/'
    # alone reports 0 NICs on a healthy host whose module is not yet loaded.
    # A Vera row that carries a PCI BDF is the evidence we want.
    nic=$(printf '%s\n' "$data" | awk 'tolower($1) ~ /^vera(\(|$)/ {for (i=2;i<=NF;i++) if ($i ~ /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$/) {n++; break}} END {print n+0}')
    if ((nic == 0)) && printf '%s\n' "$data" | grep -q 'MST PCI module is not loaded'; then
        fail MST_MODULE MST "MST kernel module is not loaded; Vera NIC count is unavailable (run: mst start)"
    fi
    if "$mst_valid"; then minimum NIC "$nic" "$NIC_MIN"; fi
    # The PCI function count is not the physical card count. Require a shared
    # VPD board serial for every BF4 function; never guess from port count.
    if [[ "$PCI_VALID" != true ]]; then return; fi
    bf4_ports=$(printf '%s\n' "$PCI" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ && /(^|[^[:alnum:]])(BlueField[ -]?4|BF4)([^[:alnum:]]|$)/ {n++} END {print n+0}')
    if ((bf4_ports == 0)); then
        printf 'CHECK|BF4|actual=0|exact=%s|pci_functions=0\n' "$BF4_EXPECTED"
        if ((BF4_EXPECTED != 0)); then fail BF4_MISSING BF4 "Expected exactly $BF4_EXPECTED physical card(s); detected 0"; fi
        return
    fi
    local verbose identities identified
    collect verbose BF4-identity lspci -Dvvv || return
    identities=$(printf '%s\n' "$verbose" | awk '
      function flush() {if (bf4) print bdf "|" serial}
      /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {
        flush(); bdf=$1; serial=""; bf4=($0 ~ /(^|[^[:alnum:]])(BlueField[ -]?4|BF4)([^[:alnum:]]|$)/)
      }
      bf4 && /\[SN\][[:space:]]+Serial number:/ {
        serial=$0; sub(/^.*Serial number:[[:space:]]*/, "", serial); sub(/[[:space:]]*$/, "", serial)
      }
      END {flush()}')
    printf 'CHECK|BF4_IDENTITIES|bdf_and_board_serial=%s\n' "${identities//$'\n'/, }"
    identified=$(printf '%s\n' "$identities" | awk -F '|' '$2 != "" && tolower($2) !~ /^(unknown|n\/a|none|0+)$/ {n++} END {print n+0}')
    if ((identified != bf4_ports)); then
        fail BF4_IDENTITY_UNAVAILABLE BF4 "Detected $bf4_ports PCI functions, but only $identified have a VPD board serial; physical card count cannot be confirmed"
        return
    fi
    bf4_cards=$(printf '%s\n' "$identities" | cut -d '|' -f2 | sort -u | awk 'END {print NR}')
    printf 'CHECK|BF4|actual=%s|exact=%s|pci_functions=%s|source=lspci VPD board serial\n' "$bf4_cards" "$BF4_EXPECTED" "$bf4_ports"
    if ((bf4_cards != BF4_EXPECTED)); then
        fail BF4_COUNT BF4 "Expected exactly $BF4_EXPECTED physical card(s); detected $bf4_cards from $bf4_ports PCI functions"
    fi
}
pci_count() {
    local component="$1" pattern="$2" expected="$3" qty
    [[ "$PCI_VALID" == true ]] || return
    qty=$(printf '%s\n' "$PCI" | grep -Eic "$pattern" || :)
    minimum "$component" "$qty" "$expected"
}
link_check() {
    local data bdf="unknown" name="" line endpoint=false
    collect data PCIe-links lspci -Dvv || return
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7] ]]; then
            bdf=${line%% *}; name=${line#* }; endpoint=false
            continue
        fi
        if [[ "$line" =~ Express.*(Legacy[[:space:]]+)?Endpoint ]]; then endpoint=true; fi
        [[ "$endpoint" == true && "$line" == *LnkSta:* ]] || continue
        if printf '%s\n' "$line" | grep -qiE 'down[[:space:]-]*grad|degrad'; then
            printf 'CHECK|PCIE_DOWNGRADE|bdf=%s|lnksta=%s\n' "$bdf" "$line"
            fail PCIE_DOWNGRADE "$bdf" "${name}: ${line#"${line%%[![:space:]]*}"}"
        elif printf '%s\n' "$line" | grep -qiE 'Speed[[:space:]]+unknown|Width[[:space:]]+x0([^0-9]|$)'; then
            printf 'CHECK|PCIE_LINK_UNAVAILABLE|bdf=%s|lnksta=%s\n' "$bdf" "$line"
            fail PCIE_LINK_UNAVAILABLE "$bdf" "${name}: ${line#"${line%%[![:space:]]*}"}"
        fi
    done <<< "$data"
}
firmware() {
    local data
    # BMC firmware is collected through the authenticated OOB channel by
    # cycle_engine.py. The OS-side ipmitool mc info path requires /dev/ipmi0,
    # which is absent on this platform and would create a false FAIL.
    collect data BIOS-firmware dmidecode -t bios
}
mode="${1:-all}"
case "$mode" in all|-S|-N|-B|-F) ;; *) echo 'Usage: naboo_config.sh [-S|-N|-B|-F]'; exit 2;; esac
PCI_VALID=true
if [[ "$mode" != -F ]]; then collect PCI PCI-inventory lspci -Dnn || PCI_VALID=false; fi
case "$mode" in
    all) cpu_check; dimm_check; nvme_check; nic_bf4_check
         pci_count PCIeFAB 'NVIDIA.*bridge|bridge.*NVIDIA' "$PCIEFAB_MIN"
         pci_count USB 'USB controller' "$USB_MIN"
         pci_count BMC 'AST1150' "$BMC_MIN"
         link_check; firmware ;;
    -S) dimm_check; nvme_check; nic_bf4_check
        pci_count PCIeFAB 'NVIDIA.*bridge|bridge.*NVIDIA' "$PCIEFAB_MIN"
        pci_count USB 'USB controller' "$USB_MIN"
        pci_count BMC 'AST1150' "$BMC_MIN"
        link_check ;;
    -N) nvme_check; link_check ;;
    -B) pci_count PCIeFAB 'NVIDIA.*bridge|bridge.*NVIDIA' "$PCIEFAB_MIN"; link_check ;;
    -F) firmware ;;
esac
if ((FAILURES > 0)); then
    printf '\n[Fail] %s issue(s)\nRESULT|FAIL\n' "$FAILURES"
    exit 1
fi
printf '\n[Pass] All selected checks passed\nRESULT|PASS\n'
