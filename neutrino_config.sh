#!/usr/bin/env bash
# Neutrino hardware configuration. All selected checks run; nonzero exit means FAIL.
# Maintain Neutrino's expected quantities here, not in the cycle wizard.
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
MEMORY_MIN_RATIO="${MEMORY_MIN_RATIO:-0.90}"
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

# One ``lspci -Dvv -nn`` call answers everything the checks need: full BDF and
# class ids for the inventory, LnkCap/LnkSta for link validation, and the VPD
# ``[SN] Serial number`` used to count BlueField cards. Capturing it once keeps
# hardware.txt to a single copy instead of three near-identical ones.
pci_capture() {
    local rc
    PCI_VERBOSE=$(lspci -Dvv -nn 2>&1); rc=$?
    PCI=$(printf '%s\n' "$PCI_VERBOSE" | grep -E '^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7] ')
    printf '\n[Evidence] PCI-inventory\n%s\n' "$PCI"
    printf '\n[Evidence] PCIe-links\n%s\n' "$PCI_VERBOSE"
    # A failed lspci run must not leave the dependent PCI checks silently
    # skipped while the run still reports PASS: record a structured failure so
    # the missing inventory is visible and the script exits nonzero.
    if ((rc != 0)); then fail COLLECTION_FAILED PCI-inventory "lspci exited $rc"; fi
    return "$rc"
}
cpu_check() {
    local data qty
    collect data CPU dmidecode -t processor || return
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Status:.*Populated/ && !/Unpopulated/ {n++} END {print n+0}')
    minimum CPU "$qty" "$CPU_MIN"
    local enabled topology sockets total online threads row_errors missing_socket
    enabled=$(printf '%s\n' "$data" | awk '/Status:.*Populated/ && /Enabled/ && !/Unpopulated/ {n++} END {print n+0}')
    if ((enabled != qty)); then fail CPU_DISABLED CPU "Only $enabled of $qty populated CPUs are enabled"; fi
    threads=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Thread Count:/ {n+=$3} END {print n+0}')
    collect topology CPU-online lscpu --all -p=CPU,SOCKET,ONLINE || return
    read -r sockets total online row_errors missing_socket <<< "$(printf '%s\n' "$topology" | awk -F, '
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      {for (i=1;i<=NF;i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i)
       if (NF!=3 || $1 !~ /^[0-9]+$/) {bad++; next}
       if (seen[$1]++) {bad++; next}
       n++; if ($3=="Y") on++; else if ($3!="N") bad++
       if ($2 ~ /^[0-9]+$/) s[$2]=1; else missing++}
      END {for (v in s) ns++; print ns+0, n+0, on+0, bad+0, missing+0}')"
    printf 'CHECK|CPU_ONLINE|sockets=%s|logical=%s|online=%s|smbios_threads=%s|row_errors=%s|missing_socket=%s\n' "$sockets" "$total" "$online" "$threads" "$row_errors" "$missing_socket"
    if ((row_errors > 0 || missing_socket > 0 || sockets != enabled || total == 0 || online != total || (threads > 0 && threads != total))); then
        fail CPU_TOPOLOGY CPU "SMBIOS enabled=$enabled threads=$threads; lscpu sockets=$sockets logical=$total online=$online row_errors=$row_errors missing_socket=$missing_socket"
    fi
}
dimm_check() {
    local data qty
    collect data DIMM dmidecode -t memory || return
    qty=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Size:[[:space:]]+[0-9]+[[:space:]]+(MB|GB|TB)/ {if ($2+0>0) n++} END {print n+0}')
    printf 'CHECK|DIMM|actual=%s|exact=%s\n' "$qty" "$DIMM_EXPECTED"
    if ((qty != DIMM_EXPECTED)); then fail DIMM_COUNT DIMM "Expected exactly $DIMM_EXPECTED installed SOCAMM devices; detected $qty"; fi
    local installed meminfo visible
    installed=$(printf '%s\n' "$data" | awk '/^[[:space:]]*Size:[[:space:]]+[0-9]+[[:space:]]+(MB|GB|TB)/ {
      factor=($3=="TB" ? 1073741824 : ($3=="GB" ? 1048576 : 1024)); n+=$2*factor} END {printf "%.0f", n}')
    collect meminfo OS-memory cat /proc/meminfo || return
    visible=$(printf '%s\n' "$meminfo" | awk '/^MemTotal:[[:space:]]+[0-9]+[[:space:]]+kB/ {print $2}')
    printf 'CHECK|MEMORY_VISIBLE|installed_kib=%s|visible_kib=%s|minimum_ratio=%s\n' "$installed" "$visible" "$MEMORY_MIN_RATIO"
    if ! awk -v installed="$installed" -v visible="$visible" -v ratio="$MEMORY_MIN_RATIO" 'BEGIN {
      exit !(ratio ~ /^(0(\.[0-9]+)?|1(\.0+)?)$/ && ratio>0 && installed>0 && visible ~ /^[0-9]+$/ && visible>=installed*ratio && visible<=installed)}'; then
        fail MEMORY_VISIBLE DIMM "OS MemTotal does not match installed capacity within the configured ratio"
    fi
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
    nic=$(printf '%s\n' "$data" | awk 'tolower($1) ~ /^vera(\(|$)/ {for (i=2;i<=NF;i++) if ($i ~ /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$/) {a[tolower($i)]=1; break}} END {for (v in a) n++; print n+0}')
    local duplicates
    duplicates=$(printf '%s\n' "$data" | awk 'tolower($1) ~ /^vera(\(|$)/ {for (i=2;i<=NF;i++) if ($i ~ /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$/) {v=tolower($i); if (++a[v]==2) print v; break}}')
    if [[ -n "$duplicates" ]]; then fail DUPLICATE_BDF MST "Duplicate full BDF: ${duplicates//$'\n'/, }"; fi
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
    verbose="$PCI_VERBOSE"
    identities=$(printf '%s\n' "$verbose" | awk '
      function flush() {if (bf4) print bdf "|" serial}
      /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {
        flush(); bdf=$1; serial=""; bf4=($0 ~ /(^|[^[:alnum:]])(BlueField[ -]?4|BF4)([^[:alnum:]]|$)/)
      }
      bf4 && /\[SN\][[:space:]]+Serial number:/ {
        serial=$0; sub(/^.*Serial number:[[:space:]]*/, "", serial); sub(/[[:space:]]*$/, "", serial)
      }
      END {flush()}')
    local expected_bdfs actual_bdfs duplicate_bdfs
    expected_bdfs=$(printf '%s\n' "$PCI" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ && /(^|[^[:alnum:]])(BlueField[ -]?4|BF4)([^[:alnum:]]|$)/ {print tolower($1)}' | sort -u)
    actual_bdfs=$(printf '%s\n' "$identities" | cut -d '|' -f1 | tr '[:upper:]' '[:lower:]' | sort -u)
    duplicate_bdfs=$(printf '%s\n' "$identities" | cut -d '|' -f1 | tr '[:upper:]' '[:lower:]' | sort | uniq -d)
    if [[ "$expected_bdfs" != "$actual_bdfs" || -n "$duplicate_bdfs" ]]; then
        fail BF4_INVENTORY_UNSTABLE BF4 "lspci inventory and VPD function identities do not match uniquely"
        return
    fi
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
    local data line bdf="" name="" endpoint=false integrated=false seen=false denied=false pcie=false
    data="$PCI_VERBOSE"
    # Flush at every function boundary, including the last function.
    while IFS= read -r line; do
        if [[ "$line" == __END__ || "$line" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7] ]]; then
            if [[ -n "$bdf" ]]; then
                if [[ "$denied" == true || ( "$endpoint" == true && "$seen" != true ) || ( "$pcie" == true && "$seen" != true ) ]]; then
                    printf 'CHECK|PCIE_LINK|bdf=%s|state=unreadable\n' "$bdf"
                    fail PCIE_LINK_UNAVAILABLE "$bdf" "$name: required link status was not readable"
                elif [[ "$endpoint" != true && "$seen" != true ]]; then
                    printf 'CHECK|PCIE_LINK|bdf=%s|state=unsupported\n' "$bdf"
                fi
            fi
            [[ "$line" == __END__ ]] && break
            bdf=${line%% *}; name=${line#* }; endpoint=false; integrated=false; seen=false; denied=false; pcie=false
            continue
        fi
        [[ "$line" == *'<access denied>'* ]] && denied=true
        if [[ "$line" =~ Express[[:space:]]+(\(v[0-9]+\)[[:space:]]+)?Root[[:space:]]+Complex[[:space:]]+(Integrated[[:space:]]+Endpoint|Event[[:space:]]+Collector)(,|$) ]]; then
            integrated=true
        elif [[ "$line" =~ Express[[:space:]]+(\(v[0-9]+\)[[:space:]]+)?(Legacy[[:space:]]+)?Endpoint(,|$) ]]; then
            endpoint=true
        fi
        # LnkCap with no Express capability header is still an unreadable PCIe link.
        [[ "$line" == *LnkCap:* ]] && pcie=true
        [[ "$line" == *LnkSta:* ]] || continue
        seen=true
        [[ "$endpoint" == true || "$integrated" == true ]] || continue
        printf 'CHECK|PCIE_LINK|bdf=%s|state=evaluated|lnksta=%s\n' "$bdf" "$line"
        if printf '%s\n' "$line" | grep -qiE 'down[[:space:]-]*grad|degrad'; then
            printf 'CHECK|PCIE_DOWNGRADE|bdf=%s|lnksta=%s\n' "$bdf" "$line"
            fail PCIE_DOWNGRADE "$bdf" "${name}: $line"
        elif ! printf '%s\n' "$line" | grep -qE 'Speed[[:space:]]+[0-9]+(\.[0-9]+)?GT/s.*Width[[:space:]]+x[1-9][0-9]*([^0-9]|$)'; then
            fail PCIE_LINK_UNAVAILABLE "$bdf" "${name}: $line"
        fi
    done <<< "$data
__END__"
    local expected actual
    expected=$(printf '%s\n' "$PCI" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {print tolower($1)}' | sort -u)
    actual=$(printf '%s\n' "$data" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {print tolower($1)}' | sort -u)
    if [[ "$expected" != "$actual" ]]; then fail PCIE_INVENTORY_UNSTABLE PCIe "Inventory differs between enumeration and link collection"; fi
}
firmware() {
    local data
    # BMC firmware is collected through the authenticated OOB channel by
    # cycle_engine.py. The OS-side ipmitool mc info path requires /dev/ipmi0,
    # which is absent on this platform and would create a false FAIL.
    collect data BIOS-firmware dmidecode -t bios
}
mode="${1:-all}"
case "$mode" in all|-S|-N|-B|-F) ;; *) echo 'Usage: neutrino_config.sh [-S|-N|-B|-F]'; exit 2;; esac
PCI_VALID=true
if [[ "$mode" != -F ]]; then pci_capture || PCI_VALID=false; fi
if [[ "$mode" != -F && "$PCI_VALID" == true ]]; then
    duplicates=$(printf '%s\n' "$PCI" | awk '/^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {v=tolower($1); if (++a[v]==2) print v}')
    if [[ -n "$duplicates" ]]; then fail DUPLICATE_BDF PCIe "Duplicate full BDF: ${duplicates//$'\n'/, }"; fi
fi
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
