#!/bin/bash
#Version: 2026/09/27
#Modified for NVIDIA Vera CPU Rack (CPU-only node)
#Based on Ryan_SH_Tsai X-wing GPU server script.
#
#Differences vs GPU server:
#  - CPU-only node: NO GPU, NO NVSwitch, NO Broadcom E810 NIC
#  - CPU : 2x Vera (NVIDIA Olympus cores)
#  - DIMM: 16 slots, LPDDR5X (SOCAMM)
#  - NIC : ConnectX-9 SuperNIC, reported by MST as "Vera(rev:0)"
#          (mt12181/12182/12183/12184). NOT visible via lspci; flint -q
#          returns MFE_UNSUPPORTED_DEVICE, so we parse `mst status -v`.
#  - BF4 : BlueField-4 DPU is the EXPECTED-but-MISSING device on this
#          rack. A dedicated detector reports it explicitly when absent.
#  - PCIe fabric: NVIDIA internal bridges (2f95-2f98) replace the
#          Broadcom PCIe switch of the GPU platform.
#
#Usage:
#  ./vera_rack.sh          full inventory + Pass/Fail summary
#  ./vera_rack.sh -S       short (DIMM/NVMe/NIC/PCIe/USB)
#  ./vera_rack.sh -N       NVMe only
#  ./vera_rack.sh -B       PCIe fabric only
#  ./vera_rack.sh -F       firmware version only

### Parameter (minimum expected quantity per node) ###
CPU_MIN=2
DIMM_MIN=16
NVMe_MIN=2
NIC_MIN=17        # total Vera SuperNIC RDMA endpoints (mt12181/82/83/84)
BF4_MIN=1         # Vera CPU: expect 1x BlueField-4 DPU card
PCIEFAB_MIN=17    # NVIDIA internal fabric bridges
USB_MIN=1
BMC_MIN=1         # ASPEED AST1150 BMC (PCI-to-PCI bridge on host PCIe)
GPU_MIN=0
NVSW_MIN=0
BRCM_MIN=0

### Device-identifier constants ###
VERA_CPU_TAG="Vera"

#Ensure MST PCI devices are registered. Read-only (no restart of services).
#Must run once before any mst parsing; otherwise `mst status -v` lists 0 devices.
MST_ready(){
        if ! command -v mst > /dev/null 2>&1; then
                return 1
        fi
        if ! mst status -v 2>/dev/null | grep -q '/dev/mst/'; then
                mst start > /dev/null 2>&1
        fi
        mst status -v 2>/dev/null | grep -q '/dev/mst/'
}

function MLNX_fun(){
        #Restore default IFS (a prior function may have set IFS=$'\n').
        #Needed because `set -- $row` below splits on whitespace.
        IFS=$' \t\n'
        #Collection: parse `mst status -v`.
        #Data rows look like:
        #   Vera(rev:0)   /dev/mst/mt12183_pciconf6   000c:80:00.0   1   [NUMA][VFIO][FWCTL][STATE]
        #flint -q is NOT used here: on this platform it returns
        #MFE_UNSUPPORTED_DEVICE, so identity is derived from the MST device id.
        MLNX_Qty=0; MLNX_ERROR=0
        if ! MST_ready; then
                echo "+ Failed: please install MLNX (MFT) packages !!"
                MLNX_ERROR=1
                echo -e "\n[Info] Vera MST / PCIe Fabric Devices"
                return
        fi

        #Grab only the device rows into an array (skip headers / module lines)
        mapfile -t MST_ROWS < <(mst status -v 2>/dev/null | grep '/dev/mst/')
        for row in "${MST_ROWS[@]}"; do
                #strip leading/trailing whitespace
                row="$(echo "$row" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
                [ -z "$row" ] && continue
                #field 1 = DEVICE_TYPE, 2 = MST, 3 = PCI, rest optional
                set -- $row
                DEVTYPE="$1"; MST="$2"; PCI="$3"
                MLNX_Qty=$((MLNX_Qty+1))
                MLNX_DEVTYPE[$MLNX_Qty]="$DEVTYPE"
                MLNX_MST[$MLNX_Qty]="$MST"
                MLNX_BUS[$MLNX_Qty]="$PCI"
                MLNX_RDMA[$MLNX_Qty]="${4:-}"
                MLNETNUMA[$MLNX_Qty]="${5:-}"
                MLNX_VFIO[$MLNX_Qty]="${6:-}"
                MLNX_FWCTL[$MLNX_Qty]="${7:-}"
                MLNX_STATE[$MLNX_Qty]="${8:-}"
                MLNX_MT[$MLNX_Qty]="$(basename "$MST" | grep -oE 'mt[0-9]+')"
                MLNX_MTID[$MLNX_Qty]="${MLNX_MT[$MLNX_Qty]#mt}"
                #NET-Port: on the Vera CPU Rack the fabric NIC exposes no
                #netdev to the host, so this is normally empty; kept as a
                #column so the table matches the general Mellanox report.
                MLNX_NET[$MLNX_Qty]=""
                #PSID/Firmware: `flint -d <mst> q` reports MFE_UNSUPPORTED_DEVICE
                #for Vera(rev:0) devices, so these columns stay blank on this
                #platform. Kept for layout parity with the general report.
                MLNX_PSID[$MLNX_Qty]="$(flint -d "$MST" q 2>/dev/null | awk -F: '/PSID:/{gsub(/^[ \t]+/,"",$2); print $2}')"
                MLNX_FW[$MLNX_Qty]="$(flint -d "$MST" q 2>/dev/null | awk -F: '/FW Version:/{gsub(/^[ \t]+/,"",$2); print $2}')"
                #Link: `ibstat` is empty on this platform (no IB ports exposed);
                #fall back to the mst STATE field, else blank.
                MLNX_LINK[$MLNX_Qty]="$(ibstat 2>/dev/null | grep -A9 "'${MST}'" | awk '/Physical/{print $3}' | head -1)"
                [ -z "${MLNX_LINK[$MLNX_Qty]}" ] && MLNX_LINK[$MLNX_Qty]="${MLNX_STATE[$MLNX_Qty]}"
                #PCIe link: query the device's OWN full BDF (do NOT truncate to
                #bus -- that returned the link of a *neighbouring* bridge).
                MLNX_Speed[$MLNX_Qty]="$(lspci -s "$PCI" -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
        done

        #Output. Note: mst reports DEVICE_TYPE as "Vera(rev:0)"; the exact NIC
        #part number (e.g. ConnectX-x) is NOT exposed to the host OS on this
        #platform (lspci/flint see only the fabric bridge), so we show the
        #type mst actually reports rather than a guessed model.
        #Output. Same column set as the general Mellanox report (No / PCI /
        #RDMA / MST / PSID / Firmware / NET-Port / Link / Speed & Width).
        #Values come from the collected arrays (not a re-slice of the raw mst
        #row), so every column starts at a fixed offset and aligns no matter
        #how many optional fields a device exposes. Empty columns (PSID and
        #Firmware on Vera, NET-Port/Link when no netdev/IB port is exposed)
        #render as '-' to keep the row readable.
        echo -e "\n[Info] Mellanox"
        printf "%-4s  %-14s  %-5s  %-29s  %-12s  %-11s  %-14s  %-11s  %s\n" \
                "No." "PCI" "RDMA" "MST" "PSID" "Firmware" "NET-Port" "Link" "Speed & Width"
        for No in $(seq 1 $MLNX_Qty); do
                printf "%-4s  %-14s  %-5s  %-29s  %-12s  %-11s  %-14s  %-11s  %s\n" \
                        "$No:" \
                        "${MLNX_BUS[$No]:--}" \
                        "${MLNX_RDMA[$No]:--}" \
                        "${MLNX_MST[$No]:--}" \
                        "${MLNX_PSID[$No]:--}" \
                        "${MLNX_FW[$No]:--}" \
                        "${MLNX_NET[$No]:--}" \
                        "${MLNX_LINK[$No]:--}" \
                        "${MLNX_Speed[$No]:--}"
        done
        if [ $MLNX_Qty -eq 0 ]; then
                echo "  (no NIC endpoints detected via mst)"
        fi
}


#BlueField-4 DPU detector.
#On the Vera CPU Rack a single B4280VS card carries TWO BF4 SoCs, each exposing
#one 800G datapath function, plus one SoC Management Interface on SoC#1.
#A PCI function count is therefore not a card count: functions 3, SoCs 2,
#cards 1. Cards are counted the only way that cannot be guessed wrong — by
#distinct VPD board serial ([SN] in lspci -vv), which every function of the
#same physical card shares.
function BF4_fun(){
        IFS=$' \t\n'
        BF4_Qty=0
        BF4_ERROR_TAG=0
        echo -e "\n[Info] BlueField-4 (DPU)"

        #1) MST: a BF4 SoC shows as DEVICE_TYPE "BlueField4(rev:0)".
        #   Only match BF4 — exclude BF3/BF2, GB100 (GPU), ConnectX (NIC), Vera (SuperNIC).
        local mst_bf4
        mst_bf4="$(mst status -v 2>/dev/null | grep '/dev/mst/' | awk '{print $1}' | grep -i 'bluefield4' | sort -u)"

        #2) lspci fallback. BF4 data functions are 15b3:a2df and the SoC
        #   Management Interface is 15b3:c2d6; 2618/2619 are the BF3 ids and
        #   never match on a BF4 host. Keep the name match for older lspci -nn
        #   output that prints the class name instead of the id.
        local lspci_bf4
        lspci_bf4="$(lspci -Dnn 2>/dev/null | grep -iE 'bluefield[ -]?4|15b3:a2df|15b3:c2d6|2618|2619')"

        if [ -z "$mst_bf4" ] && [ -z "$lspci_bf4" ]; then
                echo "  !! No BlueField-4 detected (expect ${BF4_MIN}x DPU on this rack -- MISSING) !!"
                BF4_ERROR_TAG=1
                return
        fi

        #Per-function identity: BDF | board serial. The board serial is the VPD
        #``[SN]`` line inside that function's own lspci stanza. Functions whose
        #class name marks the SoC Management Interface are tagged "MGMT".
        local verbose
        verbose=$(lspci -Dvv -nn 2>/dev/null | awk '
          function flush() {
                  if (!bf4) return
                  if (mgmt_now) print "MGMT|" bdf
                  else print bdf "|" (serial == "" ? "-" : serial)
          }
          /^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]/ {
                  flush(); bdf=$1; serial=""
                  bf4 = ($0 ~ /(BlueField[ -]?4|15b3:a2df|15b3:c2d6)/)
                  mgmt_now = ($0 ~ /Management Interface/)
          }
          bf4 && /\[SN\][[:space:]]+Serial number:/ {
                  serial=$0; sub(/^.*Serial number:[[:space:]]*/, "", serial); sub(/[[:space:]]*$/, "", serial)
          }
          END {flush()}')

        #Cards = distinct non-placeholder board serials. Serial-less functions
        #still count as present but cannot be attributed to a card.
        BF4_Qty=$(printf '%s\n' "$verbose" | awk -F '|' '$1 != "MGMT" && $2 != "-" && tolower($2) !~ /^(unknown|n\/a|none|0+)$/ {print $2}' | sort -u | awk 'END {print NR+0}')

        local bf4_mgmt
        bf4_mgmt=$(printf '%s\n' "$verbose" | awk -F '|' '$1 == "MGMT" {print $2}')
        printf '  Cards (distinct VPD board serial) : %s   (expected %s)\n' "$BF4_Qty" "$BF4_MIN"
        printf '  %-5s %-15s %-28s %-14s\n' "No." "BDF" "Role" "Board serial"
        # Each datapath function is labelled by its PCI domain, which is how the
        # two SoCs are told apart on this card (0003 and 000b). No running index:
        # an index would imply an order the hardware does not guarantee.
        printf '%s\n' "$verbose" | awk -F '|' '
        $1 == "MGMT" {next}
        {
                n++
                split($1, parts, ":")
                role = "800G datapath, domain " parts[1]
                printf "  %-5s %-15s %-28s %-14s\n", n ":", $1, role, $2
        }'
        if [ -n "$bf4_mgmt" ]; then
                while read -r b; do
                        printf '  %-5s %-15s %-28s %-14s\n' "-" "$b" "SoC management interface" "-"
                done <<< "$bf4_mgmt"
        fi

        if [ $BF4_Qty -lt $BF4_MIN ]; then
                echo "  !! Detected $BF4_Qty physical card(s); expected ${BF4_MIN}x on this rack -- MISSING !!"
                BF4_ERROR_TAG=1
        fi
}


function CPU_fun(){
        CPU_Qty=0; echo -e "\n[Info] CPU"
        No=0; IFS=$'\n'
        for i in `dmidecode -t processor`; do
                if [[ $i == *'Socket Designation'* ]]; then
                        No=$(($No+1))
                fi
                if [[ $i == *Version* ]]; then
                        CPU[$No]=`echo $i | cut -c 11-41`
                fi
        done
        IFS=$' \t\n'
        CPU_Qty=$No
        for No in $(seq 1 $CPU_Qty); do
                printf "%2s: " $No
                echo "${CPU[$No]}"
        done
}


function DIMM_fun(){
        IFS=$' \t\n'
        DIMM_Qty=0; echo -e "\n[Info] DIMM (LPDDR5X)"
        printf "%3s  %-16s  %-10s  %-25s  %-12s  %-14s  %-12s  %-16s\n" \
                "No." "Locator" "Manu" "PN" "SN" "Size" "Type" "Configured-Speed"
        No=0
        #Scan the raw dmidecode output line by line; key fields are single
        #tokens after their label, so awk $2/$3 is reliable (no cut -c needed).
        while IFS= read -r i; do
                if [[ $i == *'Memory Device'* ]]; then
                        No=$(($No+1))
                fi
                case "$i" in
                        *'Size:'*)
                                #standalone "Size:" (not Volatile/Cache/Logical/Non-Volatile)
                                if echo "$i" | grep -qE '^[[:space:]]*Size:'; then
                                        Size[$No]="$(echo "$i" | awk '{print $2 " " $3}')"
                                fi
                                ;;
                        *'Locator:'*)
                                #inner grep excludes "Bank Locator:" (line must start with Locator:)
                                if echo "$i" | grep -qE '^[[:space:]]*Locator:'; then
                                        Locator[$No]="$(echo "$i" | awk '{print $2}')"
                                fi
                                ;;
                        *'Manufacturer:'*)
                                Manufacturer[$No]="$(echo "$i" | awk '{print $2}')"
                                ;;
                        *'Serial Number:'*)
                                Serial_Number[$No]="$(echo "$i" | awk '{print $3}')"
                                ;;
                        *'Part Number:'*)
                                Part_Number[$No]="$(echo "$i" | awk '{print $3}')"
                                ;;
                        *'Type:'*)
                                #inner grep excludes "Module ... Type:" and "Firmware Version" etc.
                                if echo "$i" | grep -qE '^[[:space:]]*Type:'; then
                                        DimmType[$No]="$(echo "$i" | awk '{print $2}')"
                                fi
                                ;;
                        *'Configured Memory Speed:'*)
                                Configured_Memory_Speed[$No]="$(echo "$i" | awk '{print $4 " " $5}')"
                                ;;
                esac
        done < <(dmidecode -t memory 2>/dev/null)

        DIMM_Qty=$No
        for No in $(seq 1 $DIMM_Qty); do
                #skip empty slots (size unset)
                [ -z "${Size[$No]}" ] && continue
                printf "%2s:  %-16s  %-10s  %-25s  %-12s  %-14s  %-12s  %-16s\n" \
                        $No "${Locator[$No]}" "${Manufacturer[$No]}" "${Part_Number[$No]}" \
                        "${Serial_Number[$No]}" "${Size[$No]}" "${DimmType[$No]}" "${Configured_Memory_Speed[$No]}"
                DIMM[$No]="${Manufacturer[$No]}_${Part_Number[$No]}"
        done
        if [ $DIMM_Qty -eq 0 ]; then
                echo "  (no DIMM detected)"
        fi
}


function NVMe_fun(){
        No=0
        #nvme list columns:
        #  Node  Generic  SN  Model  Namespace  Usage  Format  FW Rev
        #SN=col2, Model=col3-4, FW=last field. Total capacity = the last
        #"N TB"/"N GB" token (the one after the "/" in the Usage column).
        while IFS= read -r i; do
                [[ "$i" == /dev/* ]] || continue
                No=$(($No+1))
                NVMe_Name[$No]="$(echo "$i" | awk '{print $1}' | cut -d / -f 3)"
                NVMe_Gen[$No]="$(echo "$i" | awk '{print $2}')"
                NVMe_SN[$No]="$(echo "$i" | awk '{print $3}')"
                NVMe_Model[$No]="$(echo "$i" | awk '{print $4 " " $5}')"
                NVMe_FW[$No]="$(echo "$i" | awk '{print $NF}')"
                #total capacity = last field that is a number+unit (TB/GB)
                NVMe_Size[$No]="$(echo "$i" | grep -oE '[0-9.]+[[:space:]]+(TB|GB)' | tail -1 | awk '{print $1 " " $2}')"
                #PCI BDF via list-subsys (keep the FULL domain:bus:dev.fn --
                #truncating to bus:dev.fn returned a *neighbouring* bridge's link)
                NVMe_No="nvme$(echo "$i" | awk '{print $1}' | cut -c 10- | cut -d n -f 1)"
                NVMe_BUS[$No]="$(nvme list-subsys 2>/dev/null | grep "${NVMe_No} " | awk '{print $4}')"
                NVMe_Speed[$No]="$(lspci -s "${NVMe_BUS[$No]}" -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
        done < <(nvme list 2>/dev/null)

        NVMe_Qty=$No
        echo -e "\n[Info] NVMe"
        printf "%3s  %-12s  %-8s  %-27s  %-16s  %-9s  %-10s  %s\n" \
                "No." "PCI" "NVMe" "Model" "SN" "Size" "FW" "LnkSta"
        for No in $(seq 1 $NVMe_Qty); do
                printf "%2s:  %-12s  %-8s  %-27s  %-16s  %-9s  %-10s  %s\n" \
                        "$No" "${NVMe_BUS[$No]}" "${NVMe_Name[$No]}" "${NVMe_Model[$No]}" \
                        "${NVMe_SN[$No]}" "${NVMe_Size[$No]}" "${NVMe_FW[$No]}" "${NVMe_Speed[$No]}"
        done
        if [ $NVMe_Qty -eq 0 ]; then
                echo "  (no NVMe detected)"
        fi
}


#GPU: CPU-only rack. Kept so the inventory is explicit; reports "not detected".
function GPU_fun(){
        GPU_Qty=0; echo -e "\n[Info] GPU"
        No=0
        for i in `lspci 2>/dev/null | grep -iE "75a3|V100|A100|H100|H200|B100|B200|Rubin"`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                GPU[$No]=`echo $i | cut -c 9-`
                GPU_BUS[$No]=`echo $i | awk '{print $1}'`
                GPU_Speed[$No]="$(lspci -s ${GPU_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: " $No
                echo "${GPU_BUS[$No]} ${GPU[$No]} - ${GPU_Speed[$No]}"
        done
        GPU_Qty=$No
        if [ $GPU_Qty -eq 0 ]; then
                echo "  (no GPU detected -- expected, this is a CPU-only Vera Rack node)"
        fi
}


#NVSwitch: not present on a CPU rack. Kept for parity; reports "not detected".
function NVSW_fun(){
        NVSW_Qty=0; echo -e "\n[Info] NVSwitch"
        No=0
        for i in `lspci 2>/dev/null | grep -i "NVIDIA" | grep -i "switch"`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                NVSW[$No]=`echo $i | awk '{print $2 " " $3 " " $4}'`
                NVSW_BUS[$No]=`echo $i | awk '{print $1}'`
                NVSW_Speed[$No]="$(lspci -s ${NVSW_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: " $No
                echo "${NVSW_BUS[$No]} ${NVSW[$No]} - ${NVSW_Speed[$No]}"
        done
        NVSW_Qty=$No
        if [ $NVSW_Qty -eq 0 ]; then
                echo "  (no NVSwitch detected -- expected, no GPU NVLink domain on a CPU node)"
        fi
}


#NVIDIA internal PCIe fabric bridges (replace the Broadcom PCIe switch of the GPU platform).
function PCIeFAB_fun(){
        PCIeFAB_Qty=0; echo -e "\n[Info] NVIDIA PCIe Fabric (internal bridges)"
        No=0; IFS=$'\n'
        for i in `lspci 2>/dev/null | grep -i "nvidia" | grep -i "bridge"`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                PCIeFAB[$No]="$(echo "$i" | sed 's/^[0-9a-f:]*\.[0-9a-f] //')"
                PCIeFAB_BUS[$No]=`echo $i | awk '{print $1}'`
                PCIeFAB_Speed[$No]="$(lspci -s ${PCIeFAB_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: " $No
                echo "${PCIeFAB_BUS[$No]} ${PCIeFAB[$No]} - ${PCIeFAB_Speed[$No]}"
        done
        IFS=$' \t\n'
        PCIeFAB_Qty=$No
        if [ $PCIeFAB_Qty -eq 0 ]; then
                echo "  (no NVIDIA fabric bridges detected)"
        fi
}


#Broadcom E810 NIC: not present on this rack. Kept for parity; reports "not detected".
function BRCM_fun(){
        BRCM_Qty=0
        echo -e "\n[Info] Broadcom-NIC (E810)"
        No=0
        for i in `lspci 2>/dev/null | grep -i 1760`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                BRCM[$No]="Broadcom NIC"
                BRCM_Desc[$No]=`echo $i`
                BRCM_BUS[$No]=`echo $i | awk '{print $1}'`
                BRCM_Speed[$No]="$(lspci -s ${BRCM_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: ${BRCM_Desc[$No]} - ${BRCM_Speed[$No]}\n" $No
        done
        BRCM_Qty=$No
        if [ $BRCM_Qty -eq 0 ]; then
                echo "  (no Broadcom E810 detected -- expected on this rack)"
        fi
}


function USB_fun(){
        USB_Qty=0; echo -e "\n[Info] USB"
        No=0; IFS=$'\n'
        for i in `lspci 2>/dev/null | grep -i "USB"`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                USB[$No]="$(echo "$i" | sed 's/^[0-9a-f:]*\.[0-9a-f] //')"
                USB_BUS[$No]=`echo $i | awk '{print $1}'`
                USB_Speed[$No]="$(lspci -s ${USB_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: " $No
                echo "${USB_BUS[$No]} ${USB[$No]} - ${USB_Speed[$No]}"
        done
        IFS=$' \t\n'
        USB_Qty=$No
        if [ $USB_Qty -eq 0 ]; then
                echo "  (no USB controller detected)"
        fi
}


#BMC detector: ASPEED AST1150 is the BMC SoC on this rack, attached to the
#host PCIe bus as a PCI-to-PCI bridge. Identify by the AST1150 device string
#(NOT by the "PCI bridge" class -- that is a PCIe role, not an ID).
function BMC_fun(){
        BMC_Qty=0; echo -e "\n[Info] BMC"
        No=0; IFS=$'\n'
        for i in `lspci 2>/dev/null | grep -iEw "AST1150"`; do
                if [ -n "$i" ]; then No=$(($No+1)); fi
                BMC[$No]="$(echo "$i" | sed 's/^[0-9a-f:]*\.[0-9a-f] //')"
                BMC_BUS[$No]=`echo "$i" | awk '{print $1}'`
                BMC_Speed[$No]="$(lspci -s ${BMC_BUS[$No]} -vv 2>/dev/null | grep -m1 LnkSta: | cut -c 11-)"
                printf "%2s: " $No
                echo "${BMC_BUS[$No]} ${BMC[$No]} - ${BMC_Speed[$No]}"
        done
        IFS=$' \t\n'
        BMC_Qty=$No
        if [ $BMC_Qty -eq 0 ]; then
                echo "  (no AST1150 BMC detected)"
        fi
}


function Firmware_fun(){
        echo -e "\n\033[33m[FW Version]\033[0m"

        # --- out-of-band: discover BMC IP, then read Redfish ---
        BMC_USER="root"
        BMC_PASS="${BMC_PASS:-0penBmc}"
        BMC_IP="$(ipmitool lan print 2>/dev/null \
                | awk -F: '/^[[:space:]]*IP Address[[:space:]]*:/{gsub(/^[ \t]+/,"",$2); print $2; exit}')"

        if [ -n "$BMC_IP" ] && curl -sk -u "$BMC_USER:$BMC_PASS" -o /dev/null \
                "https://$BMC_IP/redfish/v1/Systems/System_0" 2>/dev/null; then
                BASE="https://$BMC_IP/redfish/v1"
                CURL="curl -sk -u $BMC_USER:$BMC_PASS"
                jget() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1],"") if isinstance(d,dict) else "")' "$1" 2>/dev/null; }

                echo "BMC IP : $BMC_IP"
                echo
                printf '%-32s %s\n' "Component" "Version"
                printf '%-32s %s\n' "--------------------------------" "------------------------------"
                printf '%-32s %s\n' "BIOS" "$($CURL "$BASE/Systems/System_0" | jget BiosVersion)"
                for k in FW_BMC_0 FW_ERoT_BMC_0 FW_CPLD_0 FW_ProcessorModule_SMA_0 \
                         FW_StorageBackplane_SMA_0 SBIOS_FMC_0 SBIOS_FMC_1 SBIOS_FW_0 SBIOS_FW_1; do
                        printf '%-32s %s\n' "$k" "$($CURL "$BASE/UpdateService/FirmwareInventory/$k" | jget Version)"
                done
        else
                # --- fallback: in-band ipmitool + dmidecode ---
                echo "BMC : (Redfish unreachable, falling back to in-band)"
                if ! ipmitool mc info > /dev/null 2>&1; then
                        echo "BMC : (ipmitool not available / BMC not reachable)"
                else
                        BMC_M_V=$(ipmitool mc info 2>/dev/null | grep "Firmware Revision" | awk '{print $4}')
                        BMC_S_V=$(ipmitool mc info 2>/dev/null | grep "Aux Firmware Rev Info" -A 1 | tail -n1 | cut -d x -f 2)
                        BMC_T_V=$(ipmitool mc info 2>/dev/null | grep "Aux Firmware Rev Info" -A 2 | tail -n1 | cut -d x -f 2)
                        BMC_FW="$BMC_M_V${BMC_S_V:+.$BMC_S_V}${BMC_T_V:+.$BMC_T_V}"
                        echo "BMC : $BMC_FW"
                fi
                BIOS_Version="$(dmidecode -t bios 2>/dev/null | grep -m1 'Version:' | sed 's/^[[:space:]]*Version:[[:space:]]*//')"
                BIOS_Date="$(dmidecode -t bios 2>/dev/null | grep -m1 'Release Date:' | sed 's/^[[:space:]]*Release Date:[[:space:]]*//')"
                echo "BIOS: $BIOS_Version ($BIOS_Date)"
        fi
}


function Device_fun(){
        Device_Name=$1
        Device_Range=$2
        total=1; Device_Type[1]=""
        for i in $(seq 1 $Device_Range); do
                if [ "${Device[$i]}" != "" ]; then
                        count=0
                        for j in $(seq 1 $total); do
                                if [ "${Device[$i]}" != "${Device_Type[$j]}" ]; then
                                        count=$(($count+1))
                                fi
                        done
                        if [ $count == $total ]; then
                                total=$(($total+1))
                                Device_Type[$total]="${Device[$i]}"
                        fi
                fi
        done
        for j in $(seq 2 $total); do
                Device_Qty[$j]=0
                for i in $(seq 1 32); do
                        if [ "${Device[$i]}" == "${Device_Type[$j]}" ]; then
                                Device_Qty[$j]=$((Device_Qty[$j]+1))
                        fi
                done
        done
        for j in $(seq 2 $total); do
                echo "$Device_Name: ${Device_Type[$j]} x${Device_Qty[$j]}"
        done
}


Lost_tag=""; Warning_tag=0
function Lost_fun(){
        if [ $2 -lt $3 ]; then
                if [ $Warning_tag -eq 0 ]; then
                        echo -n "Lost Device: "
                        Warning_tag=1
                fi
                Lost_Qty=`expr $3 - $2`
                echo -n "$Lost_tag$1 x$Lost_Qty"
                Lost_tag=", "
        fi
}


function Sum_fun(){
        echo -e "\n\033[32m[Pass]\033[0m"
                for i in $(seq 1 ${#CPU[@]}); do Device[$i]=${CPU[$i]}; done; Device_fun "CPU" "${#CPU[@]}"
                for i in $(seq 1 ${#DIMM[@]}); do Device[$i]=${DIMM[$i]}; done; Device_fun "DIMM" "${#DIMM[@]}"
                for i in $(seq 1 ${#NVMe_Model[@]}); do Device[$i]=${NVMe_Model[$i]}; done; Device_fun "NVMe" "${#NVMe_Model[@]}"
                for i in $(seq 1 ${#NIC_DEVTYPE[@]}); do Device[$i]=${NIC_DEVTYPE[$i]}; done; Device_fun "NIC" "${#NIC_DEVTYPE[@]}"
                for i in $(seq 1 ${#PCIeFAB[@]}); do Device[$i]=${PCIeFAB[$i]}; done; Device_fun "PCIeFAB" "${#PCIeFAB[@]}"
                for i in $(seq 1 ${#USB[@]}); do Device[$i]=${USB[$i]}; done; Device_fun "USB" "${#USB[@]}"
                for i in $(seq 1 ${#BMC[@]}); do Device[$i]=${BMC[$i]}; done; Device_fun "BMC" "${#BMC[@]}"
                #for i in $(seq 1 ${#GPU[@]}) ; do Device[$i]=${GPU[$i]}; done; Device_fun "GPU" "${#GPU[@]}"
                #for i in $(seq 1 ${#NVSW[@]}); do Device[$i]=${NVSW[$i]}; done; Device_fun "NVSW" "${#NVSW[@]}"
                #for i in $(seq 1 ${#BRCM[@]}); do Device[$i]=${BRCM[$i]}; done; Device_fun "BRCM" "${#BRCM[@]}"

        echo -e "\n\033[31m[Fail]\033[0m"
                Lost_fun "CPU"     "$CPU_Qty"     "$CPU_MIN"
                Lost_fun "DIMM"    "$DIMM_Qty"    "$DIMM_MIN"
                Lost_fun "NVMe"    "$NVMe_Qty"    "$NVMe_MIN"
                Lost_fun "NIC"     "$MLNX_Qty"    "$NIC_MIN"
                Lost_fun "PCIeFAB" "$PCIeFAB_Qty" "$PCIEFAB_MIN"
                Lost_fun "USB"     "$USB_Qty"     "$USB_MIN"
                Lost_fun "BMC"     "$BMC_Qty"     "$BMC_MIN"
                #Lost_fun "GPU"     "$GPU_Qty"     "$GPU_MIN"
                #Lost_fun "NVSW"    "$NVSW_Qty"    "$NVSW_MIN"
                #Lost_fun "BRCM"    "$BRCM_Qty"    "$BRCM_MIN"
                echo
                if [ $BF4_Qty -lt $BF4_MIN ]; then
                        Lost_fun "BF4(DPU)" "$BF4_Qty" "$BF4_MIN"
                fi
                echo

        #MLNX_ERROR / BF4_ERROR_TAG are 0 on success, non-zero on failure
        if [ -z "$Lost_tag" ] && [ "${MLNX_ERROR:-0}" -eq 0 ] && [ "${BF4_ERROR_TAG:-0}" -eq 0 ]; then
                echo -e "\n\033[33m[Summary]\033[0m"
                echo -n "All devices are detected successfully !!"
        fi
        echo -e "\n"
}


### Start ###
code="$1"
case $code in
        "-S")
                DIMM_fun
                NVMe_fun
                MLNX_fun
                BF4_fun
                PCIeFAB_fun
                USB_fun
                BMC_fun
                ;;
        "-N")
                NVMe_fun
                ;;
        "-B")
                PCIeFAB_fun
                ;;
        "-F")
                Firmware_fun
                ;;
        *)
                CPU_fun
                DIMM_fun
                NVMe_fun
                MLNX_fun
                BF4_fun
                #GPU_fun      # disabled: CPU-only rack, no GPU
                #NVSW_fun     # disabled: no GPU NVLink domain
                PCIeFAB_fun
                #BRCM_fun     # disabled: no Broadcom E810 on this rack
                USB_fun
                BMC_fun
                Firmware_fun
                #mirror NIC device types for the summary
                for i in $(seq 1 $MLNX_Qty); do NIC_DEVTYPE[$i]="${MLNX_DEVTYPE[$i]}"; done
                Sum_fun
                ;;
esac
