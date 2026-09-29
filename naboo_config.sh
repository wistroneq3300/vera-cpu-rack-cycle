#!/usr/bin/env bash
# Naboo hardware configuration. All selected checks run; nonzero exit means FAIL.
# Maintain Naboo's expected quantities here, not in the cycle wizard.
set -uo pipefail
export LC_ALL=C
CPU_MIN=2
DIMM_EXPECTED=16
NVMe_MIN=2
NIC_MIN=22
BF4_MIN=1
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
}
cpu_check() {
    local data qty
    collect data CPU dmidecode -t processor
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Status:.*Populated/ && !/Unpopulated/ {n++} END {print n+0}')
    minimum CPU "$qty" "$CPU_MIN"
}
dimm_check() {
    local data qty
    collect data DIMM dmidecode -t memory
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Size:[[:space:]]+[0-9]+[[:space:]]+(MB|GB|TB)/ {if ($2+0>0) n++} END {print n+0}')
    printf 'CHECK|DIMM|actual=%s|exact=%s\n' "$qty" "$DIMM_EXPECTED"
    if ((qty != DIMM_EXPECTED)); then fail DIMM_COUNT DIMM "Expected exactly $DIMM_EXPECTED installed SOCAMM devices; detected $qty"; fi
}
nvme_check() {
    local data qty
    collect data NVMe nvme list
    qty=$(printf '%s\n' "$data" | awk '$1 ~ /^\/dev\/nvme[0-9]+n[0-9]+$/ {v=$1; sub(/n[0-9]+$/, "", v); a[v]=1} END {for (v in a) n++; print n+0}')
    minimum NVMe "$qty" "$NVMe_MIN"
}
nic_bf4_check() {
    local data nic bf4_cards bf4_ports modules
    collect data MST mst status -v
    # Count Vera devices from the mst device table. The MST column is only
    # populated when the MST kernel module is loaded, so keying on '/dev/mst/'
    # alone reports 0 NICs on a healthy host whose module is not yet loaded.
    # A Vera row that carries a PCI BDF is the evidence we want.
    nic=$(printf '%s\n' "$data" | awk 'tolower($1) ~ /^vera(\(|$)/ {for (i=2;i<=NF;i++) if ($i ~ /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$/) {n++; break}} END {print n+0}')
    if ((nic == 0)) && printf '%s\n' "$data" | grep -q 'MST PCI module is not loaded'; then
        fail MST_MODULE MST "MST kernel module is not loaded; Vera NIC count is unavailable (run: mst start)"
    fi
    minimum NIC "$nic" "$NIC_MIN"
    # BF4 is detected from lspci only. MST rows describe ports/functions and
    # can double-count one physical dual-port card. Prefer a physical slot or
    # serial identity from lspci -Dvmm; if the platform does not expose one,
    # use the explicit Dual BlueField-4 product name to collapse two ports.
    bf4_ports=$(printf '%s\n' "$PCI" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ && /(^|[^[:alnum:]])(BlueField[ -]?4|BF4)([^[:alnum:]]|$)/ {n++} END {print n+0}')
    bf4_cards=0
    local verbose phy serial
    verbose=$(lspci -Dvmm 2>/dev/null || :)
    phy=$(printf '%s\n' "$verbose" | awk -v RS='' '/(^|\n)Device:.*(BlueField[ -]?4|BF4)/ && /(^|\n)PhySlot:/ {for (i=1;i<=NF;i++) if ($i == "PhySlot:") print $(i+1)}' | sort -u)
    serial=$(printf '%s\n' "$verbose" | awk -v RS='' '/(^|\n)Device:.*(BlueField[ -]?4|BF4)/ && /(^|\n)Serial:/ {for (i=1;i<=NF;i++) if ($i == "Serial:") print $(i+1)}' | sort -u)
    if [[ -n "$phy" ]]; then
        bf4_cards=$(printf '%s\n' "$phy" | awk 'NF {n++} END {print n+0}')
    elif [[ -n "$serial" ]]; then
        bf4_cards=$(printf '%s\n' "$serial" | awk 'NF {n++} END {print n+0}')
    elif ((bf4_ports > 0)); then
        # The current Naboo card is explicitly identified as Dual BF4.
        # This fallback keeps two lspci functions from becoming two cards.
        local ports_per_card=1
        if printf '%s\n' "$PCI" | grep -qiE 'Dual[ -]+BlueField[ -]?4'; then ports_per_card=2; fi
        bf4_cards=$(( (bf4_ports + ports_per_card - 1) / ports_per_card ))
    fi
    printf 'CHECK|BF4|cards=%s|ports=%s\n' "$bf4_cards" "$bf4_ports"
    minimum BF4 "$bf4_cards" "$BF4_MIN" BF4_MISSING
}
pci_count() {
    local component="$1" pattern="$2" expected="$3" qty
    qty=$(printf '%s\n' "$PCI" | grep -Eic "$pattern" || :)
    minimum "$component" "$qty" "$expected"
}
link_check() {
    local data bdf="unknown" name="" class="" line
    collect data PCIe-links lspci -Dvv
    # Device name comes from the header line, kept here so a downgrade can be
    # reported with something an operator recognises instead of a bare BDF.
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7] ]]; then
            bdf=${line%% *}
            name=${line#* }                       # e.g. 'Non-Volatile memory controller: KIOXIA ...'
            class=${name%%:*}                     # e.g. 'Non-Volatile memory controller'
            continue
        fi
        [[ "$line" == *LnkSta:* ]] || continue
        printf '%s\n' "$line" | grep -qiE 'down[[:space:]-]*grad|degrad' || continue
        fail PCIE_DOWNGRADE "$bdf" "${name}: ${line#"${line%%[![:space:]]*}"}"
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
if [[ "$mode" != -F ]]; then collect PCI PCI-inventory lspci -Dnn; fi
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
