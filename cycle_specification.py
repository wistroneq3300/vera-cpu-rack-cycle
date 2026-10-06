"""Generate the offline, project-independent Vera Cycle validation specification.

The specification is intentionally kept separate from the campaign report.  The
content model below is bilingual and describes only behaviour implemented by the
shared framework and the structured project-config contract; project inventory
quantities are never rendered here.
"""
from __future__ import annotations

import html
from pathlib import Path

from cycle_core import atomic_write, now
from cycle_report import _wistron_logo


BASE = Path(__file__).resolve().parent
LANGS = ("zh-TW", "en")


def t(zh: str, en: str) -> dict[str, str]:
    return {"zh-TW": zh, "en": en}


def item(number: str, key: str, name: dict[str, str], phase: dict[str, str], source: dict[str, str],
         purpose: dict[str, str], collection: dict[str, str], logic: dict[str, str],
         passed: dict[str, str], warned: dict[str, str], failed: dict[str, str],
         retry: dict[str, str], comparison: dict[str, str], evidence: dict[str, str],
         issue_code: dict[str, str], notes: dict[str, str] | None = None, kind: str = "validation") -> dict:
    if notes == "collection":
        kind, notes = notes, None
    notes = notes or t("N/A", "N/A")
    return dict(number=number, key=key, name=name, phase=phase, source=source,
                purpose=purpose, collection=collection, logic=logic, passed=passed,
                warned=warned, failed=failed, retry=retry, comparison=comparison,
                evidence=evidence, issue_code=issue_code, notes=notes, kind=kind)


PRE = t("前置驗證", "PRE-CHECK")
PRE_POST = t("前置驗證與後置驗證", "PRE-CHECK / POST-CHECK")
POST = t("後置驗證", "POST-CHECK")
CYCLE = t("Cycle 執行", "CYCLE EXECUTION")
ALL_PHASES = t("前置、Cycle 與後置驗證", "PRE-CHECK, CYCLE EXECUTION and POST-CHECK")


ITEMS = [
    item(
        "01", "endpoint-identity", t("Endpoint Identity Verification", "Endpoint Identity Verification"), PRE_POST,
        t("SSH 執行：`printf 'HOSTNAME='; hostname; printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id`。來源為 inventory 的 endpoint IP 與 expected hostname。", "SSH command: `printf 'HOSTNAME='; hostname; printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id`. The endpoint IP and expected hostname come from the inventory."),
        t("確認每個選定 endpoint 是 inventory 指定的目標，並以 boot ID 保護不可誤操作的主機。", "Confirm that every selected endpoint is the inventory target and use boot ID to guard against acting on the wrong host."),
        t("以 Paramiko SSH 對 selected roles 執行 command；PRE 保存 identity evidence。Loop 的 transient identity polls 進入 record metadata，不為每次 poll 另存檔案。", "Run the command through Paramiko SSH for each selected role. PRE retains identity evidence; transient loop polls remain in record metadata rather than creating one file per poll."),
        t("hostname 去除尾端句點後不分大小寫比對 expected hostname；OS boot ID 必須符合 UUID 形狀。", "The hostname matches the expected hostname case-insensitively after trimming a trailing dot; the OS boot ID matches the required UUID shape."),
        t("所有已檢查 endpoint identity 通過，且 OS boot ID 有效。", "All checked endpoint identities pass and the OS boot ID is valid."),
        t("N/A", "N/A"),
        t("SSH/identity 不可用、hostname 不符、OS boot ID 無效，或在已核准 scope 中發生未預期 boot transition；目標會被 block 或停止。", "SSH/identity is unavailable, the hostname mismatches, the OS boot ID is invalid, or an unexpected boot transition occurs in the approved scope; the target is blocked or stopped."),
        t("Recovery 期間只對 transient connection failure 重試至 boot deadline；identity mismatch 不會用重試掩蓋。", "During recovery, transient connection failures retry until the boot deadline; an identity mismatch is not hidden by retries."),
        t("PRE identity 建立 immutable reference。每次 action 前後以及 POST checks 後重新驗證；是否應變更由 cycle action 與 boot transition semantics 決定。", "PRE identity establishes the immutable reference. Identity is rechecked before and after actions and after POST checks; whether boot should change is determined by the cycle-action semantics."),
        t("PRE identity evidence、`campaign.json` 的 `identities` 與 `recovery` metadata、`PRE_BLOCKED` / `IDENTITY_UNSAFE` / `UNEXPECTED_BOOT_TRANSITION` finding。", "PRE identity evidence, `identities` and `recovery` metadata in `campaign.json`, and `PRE_BLOCKED` / `IDENTITY_UNSAFE` / `UNEXPECTED_BOOT_TRANSITION` findings."),
        t("PRE_BLOCKED; IDENTITY_UNSAFE; UNEXPECTED_BOOT_TRANSITION; NODE_UNAVAILABLE", "PRE_BLOCKED; IDENTITY_UNSAFE; UNEXPECTED_BOOT_TRANSITION; NODE_UNAVAILABLE"),
        t("Inventory 的缺少 IP、缺少 expected hostname、重複 endpoint 會在送出遠端 command 前 block target。", "Missing inventory IPs, missing expected hostnames, and duplicate endpoints block a target before remote commands are sent."),
    ),
    item(
        "02", "connectivity-auth", t("OS / BMC Connectivity and Authentication", "OS / BMC Connectivity and Authentication"), PRE_POST,
        t("OS/BMC/Lily endpoint 的 SSH identity command；OOB IPMI 使用 `ipmitool -I lanplus`；Redfish 使用 authenticated `curl` session。", "SSH identity commands for OS/BMC/Lily endpoints; OOB IPMI uses `ipmitool -I lanplus`; Redfish uses an authenticated `curl` session."),
        t("確認驗證所需的 OS、BMC 與可選 endpoint 可達且 authentication context 正確。", "Confirm that the OS, BMC, and optional endpoints required by validation are reachable with the correct authentication context."),
        t("每個 transport 都保留 exit code、state、duration 與必要的 output excerpt；credential 不進 argv，也不寫入 evidence。", "Each transport retains exit code, state, duration, and necessary output excerpts; credentials are not placed in argv or evidence."),
        t("identity command、IPMI 或 Redfish collection 在實作允許的 path 成功返回，且後續資料可被解析。", "The identity command, IPMI operation, or Redfish collection returns successfully on its implemented path and the resulting data is parseable."),
        t("N/A", "N/A"),
        t("transport command failed、HTTP gate 未通過、authentication/session 失敗，或 output 無法作為有效 collection；對應 check 會 FAIL 或標記 UNAVAILABLE。", "The transport command fails, the HTTP gate is not successful, authentication/session fails, or output cannot be treated as a valid collection; the check fails or is marked UNAVAILABLE."),
        t("只在實作明確提供的 recovery polling 中重試 transient connection；Redfish login 每次 capture 重新建立 session。", "Retries occur only for the implemented recovery polling of transient connections; Redfish login creates a new session for each capture."),
        t("PRE connectivity 建立執行基礎；POST 重新確認 endpoint identity，不以單次成功推論整個 campaign 永久可達。", "PRE connectivity establishes the execution basis; POST rechecks endpoint identity and does not infer permanent campaign reachability from one successful call."),
        t("command records、transport evidence、Redfish evidence、`BMC_UNAVAILABLE` 與 collection findings。", "Command records, transport evidence, Redfish evidence, `BMC_UNAVAILABLE`, and collection findings."),
        t("COLLECTION_FAILED; IPMI_REPORTED_ERROR; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; BMC_UNAVAILABLE", "COLLECTION_FAILED; IPMI_REPORTED_ERROR; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; BMC_UNAVAILABLE"),
        t("一個 service 確認不存在與 collection 不可用是不同狀態；不可把 unreadable 當成空結果。", "A service confirmed absent is different from a collection that is unavailable; unreadable data must not be treated as an empty result."),
    ),
    item(
        "03", "root-dependencies", t("Root / Dependency Readiness", "Root / Dependency Readiness"), PRE,
        t("`id -u`（sudo）、`command -v` probes、必要時的 apt-get install/recheck，以及 `command -v mst`。", "`id -u` through sudo, `command -v` probes, an apt-get install/recheck when needed, and `command -v mst`."),
        t("確認 privileged validation、標準 OS tools 與 MST 依賴已可使用。", "Confirm that privileged validation, standard OS tools, and the MST dependency are available."),
        t("先 probe；缺少工具時嘗試透過 apt-get 安裝，之後一定重新 probe。MFT/mst 不由 framework 自動安裝。", "Probe first; if tools are missing, attempt apt-get installation and always probe again. The framework does not install MFT/mst."),
        t("root UID 為 0，必要工具在 recheck 後可找到，且 `mst` 可用。", "Root UID is 0, required tools are available after recheck, and `mst` is available."),
        t("N/A", "N/A"),
        t("root 不可用、dependency probe/install/recheck 失敗、必要工具仍缺少，或 MST 不可用；相關 finding 會使該 record 非 PASS。", "Root is unavailable, dependency probe/install/recheck fails, required tools remain missing, or MST is unavailable; the related finding keeps the record from PASS."),
        t("缺少工具時只有一次安裝後 recheck；不會因工具缺少而重複無限安裝。", "A missing tool gets one post-install recheck; the framework does not loop through repeated installations."),
        t("PRE 完成後視為本 campaign 的 readiness snapshot；POST 仍透過 command validity 反映 collection 狀態，不會重建一個新的 project threshold。", "PRE is the campaign readiness snapshot; POST still reflects command validity, without inventing a new project threshold."),
        t("`pre_root_uid.txt`、dependency/package evidence、MST evidence 與 `DEPENDENCY_*` / `MST_MISSING` findings。", "`pre_root_uid.txt`, dependency/package evidence, MST evidence, and `DEPENDENCY_*` / `MST_MISSING` findings."),
        t("ROOT_UNAVAILABLE; DEPENDENCY_CHECK; PACKAGE_INSTALL_FAILED; DEPENDENCY_MISSING; MST_MISSING", "ROOT_UNAVAILABLE; DEPENDENCY_CHECK; PACKAGE_INSTALL_FAILED; DEPENDENCY_MISSING; MST_MISSING"),
        t("這是 readiness gate，不是 project hardware quantity evaluator。", "This is a readiness gate, not a project hardware quantity evaluator."),
    ),
    item(
        "04", "clean-start", t("Clean-start Preparation", "Clean-start Preparation"), PRE,
        t("`dmesg -C`；IPMI `sel list` 後才允許 `sel clear`；Redfish 動態 discovery、Entries collection 與 `Actions/LogService.ClearLog`。", "`dmesg -C`; IPMI `sel list` before allowing `sel clear`; Redfish dynamic discovery, Entries collection, and `Actions/LogService.ClearLog`."),
        t("讓 PRE baseline 與之後的 delta 從已知的 log state 開始，避免把 campaign 之前的 backlog 當成本次 finding。", "Start the PRE baseline and later deltas from a known log state so backlog from before the campaign is not treated as a campaign finding."),
        t("先讀取並驗證可讀性；只有 valid read 才清除。Redfish pre-clear history 另存為 diagnosis evidence，且不進 PRE health baseline。", "Read and validate first; clear only after a valid read. Redfish pre-clear history is retained as diagnostic evidence and excluded from the PRE health baseline."),
        t("可讀取且清除動作完成；後續 PRE capture 建立 clean baseline。", "The source can be read and the clear action completes; the subsequent PRE capture establishes the clean baseline."),
        t("清除被跳過或清除 action 回報 warning 時記錄 `CLEAR_SKIPPED` / clear warning；這不等同於 silent PASS。", "A skipped clear or a clear action warning records `CLEAR_SKIPPED` or a clear warning; it is not a silent PASS."),
        t("讀取 command failure、invalid log collection、Redfish discovery/collection failure 或 dmesg clear command failure；原始狀態不可在 unreadable 時盲目清除。", "A read command failure, invalid log collection, Redfish discovery/collection failure, or dmesg clear command failure; the original state is not blindly cleared when unreadable."),
        t("沒有針對 clean-start 的額外 retry loop；只使用各 transport 與既有 recovery path。", "There is no additional clean-start retry loop; only the existing transport and recovery paths are used."),
        t("N/A；clean-start 是 baseline preparation，不是 PRE↔POST health comparison。", "N/A; clean-start prepares the baseline and is not a PRE↔POST health comparison."),
        t("Redfish pre-clear text、command metadata、clear status、`CLEAR_SKIPPED` 與 collection findings。dmesg/SEL clear 的 command evidence 依實作保留 metadata。", "Redfish pre-clear text, command metadata, clear status, `CLEAR_SKIPPED`, and collection findings. dmesg/SEL clear command evidence follows the implementation's retention rules."),
        t("CLEAR_SKIPPED; COLLECTION_FAILED; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED", "CLEAR_SKIPPED; COLLECTION_FAILED; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED"),
        t("IPMI SEL 不在 loop 內清除；loop 只做 before-cycle 與 POST comparison。", "IPMI SEL is not cleared inside a loop; a loop only performs before-cycle and POST comparison."),
    ),
    item(
        "05", "pci-inventory", t("PCIe Inventory", "PCIe Inventory"), PRE_POST,
        t("OS command：`lspci -Dnn`；使用 `parse_pci` 解析 full BDF 與 vendor/device ID。", "OS command: `lspci -Dnn`; `parse_pci` parses full BDF and vendor/device ID."),
        t("建立可比較的 PCI inventory，確認 collection 不是空或無法辨識的資料。", "Build a comparable PCI inventory and ensure the collection is neither empty nor unrecognisable."),
        t("command output 寫入 phase evidence；POST 以 full-domain BDF 與 ID 對照 immutable PRE。", "Command output is written to phase evidence; POST compares full-domain BDFs and IDs with immutable PRE."),
        t("有 valid full-BDF inventory，且 POST 的 device identity 與 PRE 一致。", "A valid full-BDF inventory exists and POST device identities match PRE."),
        t("N/A", "N/A"),
        t("command 失敗、沒有 valid full-BDF inventory，或 device added/removed/identity changed；對應為 `PCI_EMPTY` 或 `PCI_DRIFT`。", "The command fails, no valid full-BDF inventory exists, or a device is added, removed, or changes identity; the result is `PCI_EMPTY` or `PCI_DRIFT`."),
        t("N/A；framework 不會用 retry 把空 inventory 猜成有效 inventory。", "N/A; the framework does not retry an empty inventory into an assumed valid inventory."),
        t("PRE inventory 是 comparison baseline；POST 對每個 BDF 做 set comparison。", "PRE inventory is the comparison baseline; POST compares the set for every BDF."),
        t("`pre_pci.txt` / `pci.txt`、`record['pci']`、`PCI_EMPTY` / `PCI_DRIFT` 與 issue snippet。", "`pre_pci.txt` / `pci.txt`, `record['pci']`, `PCI_EMPTY` / `PCI_DRIFT`, and issue snippets."),
        t("PCI_EMPTY; PCI_DRIFT; COLLECTION_FAILED", "PCI_EMPTY; PCI_DRIFT; COLLECTION_FAILED"),
        t("這是 identity/inventory comparison，不是 project-specific device quantity policy。", "This is an identity/inventory comparison, not a project-specific device quantity policy."),
    ),
    item(
        "06", "pci-topology", t("PCIe Topology", "PCIe Topology"), PRE_POST,
        t("OS command：`lspci -Dtv`。", "OS command: `lspci -Dtv`."),
        t("保留 PCI tree topology 供 reviewer 對照。", "Retain the PCI tree topology for reviewer inspection."),
        t("command output 原樣保存為 phase evidence；目前 framework 沒有針對 topology tree 建立 golden topology evaluator。", "Command output is retained as phase evidence; the framework does not implement a golden-topology evaluator for this tree."),
        t("command 成功且 topology output 被保留。此項狀態是 collection status。", "The command succeeds and topology output is retained. This item's status is collection status."),
        t("N/A", "N/A"),
        t("command 失敗或 evidence collection invalid。不要把 topology tree 的存在誤寫成 health PASS。", "The command fails or evidence collection is invalid. The existence of a topology tree must not be written as a health PASS."),
        t("N/A", "N/A"),
        t("N/A；沒有 PRE↔POST evaluator。", "N/A; there is no PRE↔POST evaluator."),
        t("`pre_pci_tree.txt` / `pci_tree.txt` 與 command record。", "`pre_pci_tree.txt` / `pci_tree.txt` and the command record."),
        t("COLLECTION_FAILED", "COLLECTION_FAILED"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "07", "pci-link", t("PCIe Verbose / Link Validation", "PCIe Verbose / Link Validation"), PRE_POST,
        t("OS command：`lspci -Dvvv`；project hardware script 另可使用 `lspci -Dvv`。Parser 讀取 Express type、`LnkCap` 與 `LnkSta`。", "OS command: `lspci -Dvvv`; the project hardware script may also use `lspci -Dvv`. The parser reads Express type, `LnkCap`, and `LnkSta`."),
        t("提供 endpoint link facts，並把實作已判定的 downgrade / unavailable finding 帶入 record。", "Provide endpoint link facts and carry implemented downgrade or unavailable findings into the record."),
        t("verbose raw evidence 只保留 report 所需的 end-device blocks；完整 hardware script output 仍在 hardware evidence。", "Verbose raw evidence retains the end-device blocks used by the report; full hardware-script output remains in hardware evidence."),
        t("可評估的 Endpoint 有 usable speed 與 non-zero width，且沒有 downgrade；RCiEP/RCEC 沒有 physical link capability 時標為 N/A。", "An applicable Endpoint has usable speed and non-zero width with no downgrade; RCiEP/RCEC without a physical link capability is N/A."),
        t("N/A", "N/A"),
        t("collection failed、Endpoint 的 `LnkSta` missing/unreadable、speed unknown、width x0、downgrade/degradation、access denied，或 enumeration/link BDF set 不一致；實際 issue 必須由目前 parser 或 structured project check 產生。", "Collection fails; an Endpoint has missing/unreadable `LnkSta`, unknown speed, x0 width, downgrade/degradation, access denied, or inconsistent enumeration/link BDF sets; the actual issue must be produced by the current parser or structured project check."),
        t("N/A；不會因 `LnkCap` 高於 `LnkSta` 單獨重試或判 FAIL。", "N/A; `LnkCap` being higher than `LnkSta` alone is not retried or treated as FAIL."),
        t("PRE 與 POST 都解析 link facts；project hardware link findings 以同一 record 的 `CHECK` / `ISSUE` 帶入。", "PRE and POST both parse link facts; project hardware link findings enter through the same record's `CHECK` / `ISSUE` output."),
        t("`pre_pci_verbose.txt` / `pci_verbose.txt`、PCI device rows、hardware output、link issue snippet。", "`pre_pci_verbose.txt` / `pci_verbose.txt`, PCI device rows, hardware output, and link issue snippets."),
        t("PCIE_DOWNGRADE; PCIE_LINK_UNAVAILABLE; PCIE_INVENTORY_UNSTABLE; COLLECTION_FAILED", "PCIE_DOWNGRADE; PCIE_LINK_UNAVAILABLE; PCIE_INVENTORY_UNSTABLE; COLLECTION_FAILED"),
        t("Root ports/bridges 不產生 endpoint downgrade finding；unsupported device 必須明確標記。", "Root ports and bridges do not generate endpoint downgrade findings; unsupported devices must be explicitly marked."),
    ),
    item(
        "08", "block-devices", t("Block Device Collection", "Block Device Collection"), PRE_POST,
        t("OS command：`lsblk`。", "OS command: `lsblk`."),
        t("保留 block device inventory 供 cycle 前後 review。", "Retain the block-device inventory for before/after cycle review."),
        t("command output 原樣保存；目前 shared framework 沒有從 `lsblk` output 建立通用 health evaluator。", "Command output is retained as-is; the shared framework does not implement a generic health evaluator from `lsblk` output."),
        t("command 成功且 raw output 可追溯。", "The command succeeds and raw output is traceable."),
        t("N/A", "N/A"),
        t("command 失敗或 raw collection invalid。", "The command fails or the raw collection is invalid."),
        t("N/A", "N/A"),
        t("N/A；只做 PRE/POST evidence retention。", "N/A; only PRE/POST evidence retention is implemented."),
        t("`pre_disks.txt` / `disks.txt` 與 command record。", "`pre_disks.txt` / `disks.txt` and the command record."),
        t("COLLECTION_FAILED", "COLLECTION_FAILED"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "09", "nvme", t("NVMe Collection", "NVMe Collection"), PRE_POST,
        t("OS command：`nvme list`；NVMe I/O error / controller state 另由 dmesg parser 處理。", "OS command: `nvme list`; NVMe I/O errors and controller state are also handled by the dmesg parser."),
        t("保留 NVMe enumeration，並把 kernel NVMe error diagnostics 分開判定。", "Retain NVMe enumeration while evaluating kernel NVMe error diagnostics separately."),
        t("command output 原樣保存；framework 不從 `nvme list` 自行發明 project quantity threshold。", "Command output is retained as-is; the framework does not invent a project quantity threshold from `nvme list`."),
        t("command 成功且 output 可追溯；dmesg 中沒有實作所識別的 NVMe error event。", "The command succeeds and output is traceable; dmesg has no NVMe error event recognised by the implementation."),
        t("N/A", "N/A"),
        t("`nvme list` collection failure；或 dmesg parser 捕捉到 I/O error、timeout、controller down 等 event。project quantity failure 只能由 selected config 的 structured result 回報。", "`nvme list` collection failure; or the dmesg parser captures an I/O error, timeout, or controller-down event. A project quantity failure may only be reported by the selected config's structured result."),
        t("N/A", "N/A"),
        t("PRE/POST 保留 collection；dmesg finding 依 PRE fingerprint 做 classification。", "PRE/POST retain the collection; dmesg findings are classified by PRE fingerprint."),
        t("`pre_nvme.txt` / `nvme.txt`、dmesg evidence 與 structured hardware evidence。", "`pre_nvme.txt` / `nvme.txt`, dmesg evidence, and structured hardware evidence."),
        t("COLLECTION_FAILED; DMESG_NVME; project ISSUE codes from selected config", "COLLECTION_FAILED; DMESG_NVME; project ISSUE codes from selected config"),
        t("Normal shutdown-timeout configuration messages are not classified as NVMe errors by the current parser。", "Normal shutdown-timeout configuration messages are not classified as NVMe errors by the current parser."),
    ),
    item(
        "10", "usb", t("USB Collection", "USB Collection"), PRE_POST,
        t("OS command：`lsusb`。", "OS command: `lsusb`."),
        t("保留 USB device evidence。", "Retain USB device evidence."),
        t("command output 原樣保存；沒有 shared USB health evaluator。", "Command output is retained as-is; there is no shared USB health evaluator."),
        t("command 成功且 raw output 可追溯。", "The command succeeds and raw output is traceable."),
        t("N/A", "N/A"),
        t("command 失敗或 output 不可用。", "The command fails or output is unavailable."),
        t("N/A", "N/A"),
        t("N/A；沒有通用 PRE↔POST evaluator。", "N/A; there is no generic PRE↔POST evaluator."),
        t("`pre_usb.txt` / `usb.txt` 與 command record。", "`pre_usb.txt` / `usb.txt` and the command record."),
        t("COLLECTION_FAILED", "COLLECTION_FAILED"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "11", "memory", t("Memory Collection", "Memory Collection"), PRE_POST,
        t("OS command：`free -m`；project hardware script 可用 SMBIOS 與 `/proc/meminfo` 做 project check。", "OS command: `free -m`; the project hardware script may use SMBIOS and `/proc/meminfo` for project checks."),
        t("保留 OS memory snapshot，並讓 project config 透過 structured contract 回報其選定的 capacity/visibility finding。", "Retain the OS memory snapshot and let the project config report its selected capacity/visibility finding through the structured contract."),
        t("shared capture 只保存 `free -m`；project script 的檢查與量測由 script 自己產生 `CHECK` / `ISSUE`。", "The shared capture only retains `free -m`; the project script produces its own `CHECK` / `ISSUE` for its selected measurements."),
        t("command 成功且 raw output 可追溯；project checks 回報 PASS。", "The command succeeds and raw output is traceable; project checks report PASS."),
        t("N/A", "N/A"),
        t("command 失敗，或 selected project hardware check 回報 memory visibility/capacity failure。", "The command fails, or the selected project hardware check reports a memory visibility/capacity failure."),
        t("N/A", "N/A"),
        t("OS collection 在 PRE/POST 保留；project result 不與 framework 自行重算的 quantity 混合。", "The OS collection is retained in PRE/POST; project results are not mixed with a framework-invented quantity calculation."),
        t("`pre_memory.txt` / `memory.txt` 與 hardware script evidence。", "`pre_memory.txt` / `memory.txt` and hardware-script evidence."),
        t("COLLECTION_FAILED; selected project ISSUE codes", "COLLECTION_FAILED; selected project ISSUE codes"),
        t("不要把 project config 的 capacity ratio 或 expected quantity 寫入共用規範。", "Do not write a project config's capacity ratio or expected quantity into the shared specification."),
    ),
    item(
        "12", "network", t("Network Collection", "Network Collection"), PRE_POST,
        t("OS command：`ip address show`；project config 的 NIC/MST check 使用 script 自己指定的 source。", "OS command: `ip address show`; project-config NIC/MST checks use the source selected by the script."),
        t("保留 network interface evidence，並分離 project hardware finding 與 shared collection。", "Retain network interface evidence and keep project hardware findings separate from shared collection."),
        t("command output 原樣保存；shared framework 不從 interface list 發明 NIC quantity evaluator。", "Command output is retained as-is; the shared framework does not invent a NIC quantity evaluator from the interface list."),
        t("command 成功且 evidence 可追溯；project check 若存在則由 structured result 表達。", "The command succeeds and evidence is traceable; any project check is expressed through the structured result."),
        t("N/A", "N/A"),
        t("command 失敗，或 selected project hardware check 回報 NIC/MST finding。", "The command fails, or the selected project hardware check reports a NIC/MST finding."),
        t("N/A", "N/A"),
        t("N/A；shared network capture 是 evidence，project result 是 selected configuration 的責任。", "N/A; the shared network capture is evidence, while project results belong to the selected configuration."),
        t("`pre_network.txt` / `network.txt` 與 hardware evidence。", "`pre_network.txt` / `network.txt` and hardware evidence."),
        t("COLLECTION_FAILED; selected project ISSUE codes", "COLLECTION_FAILED; selected project ISSUE codes"),
        t("Collection / Evidence Only（shared capture）。", "Collection / Evidence Only (shared capture)."),
        "collection",
    ),
    item(
        "13", "firmware", t("Firmware Collection", "Firmware Collection"), PRE_POST,
        t("OS command：`dmidecode -t bios`；BMC version 使用 OOB `mc info`。", "OS command: `dmidecode -t bios`; BMC version uses OOB `mc info`."),
        t("保留 BIOS 與 BMC firmware identity，讓 reviewer 可追溯實際版本。", "Retain BIOS and BMC firmware identity so the reviewer can trace the actual versions."),
        t("OS/BMC command output 寫入 evidence；目前沒有 expected-version 或 downgrade policy。", "OS/BMC command output is written to evidence; the current implementation has no expected-version or downgrade policy."),
        t("command 成功且 raw version output 可追溯。", "The command succeeds and raw version output is traceable."),
        t("N/A", "N/A"),
        t("command 失敗或 firmware evidence 不可收集。不能把版本與未存在的 expected-version policy 比較。", "The command fails or firmware evidence cannot be collected. A version must not be compared against a policy that does not exist."),
        t("N/A", "N/A"),
        t("PRE/POST 各自保留 output；沒有 implementation-level version delta evaluator。", "PRE/POST each retain their output; there is no implementation-level version delta evaluator."),
        t("`pre_firmware.txt` / `firmware.txt`、BMC `mc info` evidence。", "`pre_firmware.txt` / `firmware.txt` and BMC `mc info` evidence."),
        t("COLLECTION_FAILED", "COLLECTION_FAILED"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "14", "system-info", t("System Information", "System Information"), PRE_POST,
        t("OS command：`uname -a; cat /etc/os-release; lscpu`。", "OS command: `uname -a; cat /etc/os-release; lscpu`."),
        t("保留 OS release、kernel 與 CPU information 作為 cycle evidence。", "Retain OS release, kernel, and CPU information as cycle evidence."),
        t("command output 原樣保存；shared framework 不從 system text 發明 health threshold。", "Command output is retained as-is; the shared framework does not invent a health threshold from system text."),
        t("command 成功且 evidence 可追溯。", "The command succeeds and evidence is traceable."),
        t("N/A", "N/A"),
        t("command 失敗或 output 不可用。", "The command fails or output is unavailable."),
        t("N/A", "N/A"),
        t("N/A；只做 collection retention。", "N/A; only collection retention is implemented."),
        t("`pre_system.txt` / `system.txt` 與 command record。", "`pre_system.txt` / `system.txt` and the command record."),
        t("COLLECTION_FAILED", "COLLECTION_FAILED"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "15", "sensors", t("Sensor Validation", "Sensor Validation"), PRE_POST,
        t("OOB command：`sensor list`；由 `parse_sensors` 與 `sensor_issues` / `compare_sensors` 判定。", "OOB command: `sensor list`; evaluated by `parse_sensors` and `sensor_issues` / `compare_sensors`."),
        t("確認 sensor table 可讀、格式完整、status 可判定，並檢查 PRE sensor rows 是否在 POST 消失。", "Confirm that the sensor table is readable and structurally complete, statuses are judgeable, and PRE sensor rows do not disappear in POST."),
        t("每次收集保留 raw sensor output。POST command failure 先 retry；baseline row 缺少時再做 immediate confirmation reread。", "Each collection retains raw sensor output. A POST command failure is retried first; a missing baseline row gets an immediate confirmation reread."),
        t("critical/nr/lower-upper critical status 會 FAIL；non-critical status WARN；合法 `ok` / `0x0000` 或實作明確支援的 discrete hex field 不產生 finding。", "Critical/nr/lower-upper critical statuses FAIL; non-critical statuses WARN; valid `ok` / `0x0000` or an implementation-supported discrete hexadecimal field produces no finding."),
        t("所有 row 可解析且沒有 health finding；POST 缺少 row 但 reread 恢復時為 `SENSOR_RECOVERED` WARN。", "All rows are parseable with no health finding; a POST row missing initially but recovered on reread is `SENSOR_RECOVERED` WARN."),
        t("duplicate sensor name、non-critical、reread recovered 會 WARN。", "A duplicate sensor name, non-critical status, or reread recovery is WARN."),
        t("collection empty/failed、malformed row、garbled name/control character、critical/non-recoverable、generic unreadable/unknown、或 confirmation 後仍缺少 baseline row；分別產生 `SENSOR_*` finding。", "An empty/failed collection, malformed row, garbled name/control character, critical/non-recoverable status, generic unreadable/unknown value, or a baseline row still missing after confirmation produces a `SENSOR_*` finding."),
        t("POST sensor command failure retry 一次；missing-row confirmation 再 reread 一次。PRE command failure 也依實作做一次 retry。", "A POST sensor command failure retries once; a missing-row confirmation rereads once more. A PRE command failure also follows the implemented one-retry path."),
        t("PRE rows 以 name multiplicity 建立 baseline；POST 比對 missing rows 與 current status。沒有全域唯一 sensor ID，因此不以 dict overwrite duplicate rows。", "PRE rows establish the baseline using name multiplicity; POST compares missing rows and current status. There is no globally unique sensor ID, so duplicate rows are not overwritten in a dict."),
        t("`pre_sensor.txt` / `sensor.txt` / `sensor_retry.txt` / `sensor_confirm.txt` 與 row-level snippet。", "`pre_sensor.txt` / `sensor.txt` / `sensor_retry.txt` / `sensor_confirm.txt` and row-level snippets."),
        t("SENSOR_EMPTY; SENSOR_MALFORMED; SENSOR_NAME_MALFORMED; SENSOR_CRITICAL; SENSOR_NONCRITICAL; SENSOR_UNREADABLE; SENSOR_UNRECOGNIZED; SENSOR_DUPLICATE; SENSOR_MISSING; SENSOR_RECOVERED; SENSOR_CONFIRM_FAILED", "SENSOR_EMPTY; SENSOR_MALFORMED; SENSOR_NAME_MALFORMED; SENSOR_CRITICAL; SENSOR_NONCRITICAL; SENSOR_UNREADABLE; SENSOR_UNRECOGNIZED; SENSOR_DUPLICATE; SENSOR_MISSING; SENSOR_RECOVERED; SENSOR_CONFIRM_FAILED"),
        t("只有精確符合 `PrMo<number>CP<number>CorUti<number>` 且 reading/status 都是已知 no-reading token 的 row 才會被 whitelist；generic `na` 不會被當成健康。", "Only an exact `PrMo<number>CP<number>CorUti<number>` row with both reading and status as known no-reading tokens is whitelisted; generic `na` is not treated as healthy."),
    ),
    item(
        "16", "dmesg", t("dmesg Validation", "dmesg Validation"), PRE_POST,
        t("OS commands：PRE `dmesg`；POST 的 collection 使用 `dmesg` 與最後的 `dmesg -c`；clean-start 使用 `dmesg -C`。Parser：`dmesg_issues`。", "OS commands: PRE `dmesg`; POST collection uses `dmesg` and the final `dmesg -c`; clean-start uses `dmesg -C`. Parser: `dmesg_issues`."),
        t("偵測 kernel、APEI/CPER、PCIe、NVMe、NIC、memory 與 observed GPU diagnostic events，保留 raw location 與 native severity。", "Detect kernel, APEI/CPER, PCIe, NVMe, NIC, memory, and observed GPU diagnostic events while retaining raw locations and native severity."),
        t("PRE 保存完整 dmesg。Loop 在 action 前保存 before-action；POST 的 clear read 保存完整 output，finding link 指向實際 raw evidence。", "PRE retains complete dmesg. A loop retains before-action dmesg; the POST clear read retains complete output and findings link to the actual raw evidence."),
        t("APEI corrected/recoverable 與 corrected AER/EDAC 為 WARN；fatal/uncorrected/unknown 或 truncated/unclassifiable error 為 FAIL。Kernel panic/oops/lockup、ARM SError、MCE、AER/DPC、NVMe I/O、mlx5 health 與 GPU Xid 有明確 parser family。", "APEI corrected/recoverable and corrected AER/EDAC are WARN; fatal/uncorrected/unknown or truncated/unclassifiable errors are FAIL. Kernel panic/oops/lockup, ARM SError, MCE, AER/DPC, NVMe I/O, mlx5 health, and GPU Xid have explicit parser families."),
        t("沒有 parsed event 且 collection 成功，或 APEI block 全部是 info；record 不因這些內容產生 finding。", "No parsed event is present with successful collection, or an APEI block is entirely info; the record gets no finding from those contents."),
        t("corrected/recoverable event 為 WARN。", "A corrected/recoverable event is WARN."),
        t("collection 失敗、unknown/truncated event、fatal/uncorrected event 或實作識別的 kernel/hardware error 為 FAIL。", "A collection failure, unknown/truncated event, fatal/uncorrected event, or an implementation-recognised kernel/hardware error is FAIL."),
        t("沒有 automatic dmesg parser retry；clear failure 依 clean-start 規則留痕。", "There is no automatic dmesg parser retry; clear failure is retained under the clean-start rules."),
        t("issue fingerprint 去除 timestamps、sequence tags 與 severity；PRE baseline 之後對照 occurrence count、native severity 與 native error count。", "The issue fingerprint excludes timestamps, sequence tags, and severity; after PRE, occurrence count, native severity, and native error count are compared."),
        t("`pre_dmesg.txt`、`before_action_dmesg.txt`、`dmesg_clear.txt`、raw line positions、family/subtype/device metadata。", "`pre_dmesg.txt`, `before_action_dmesg.txt`, `dmesg_clear.txt`, raw line positions, and family/subtype/device metadata."),
        t("DMESG_APEI; DMESG_KERNEL; DMESG_ARM; DMESG_MCE; DMESG_EDAC; DMESG_PCIE; DMESG_NVME; DMESG_NIC; DMESG_GPU; COLLECTION_FAILED", "DMESG_APEI; DMESG_KERNEL; DMESG_ARM; DMESG_MCE; DMESG_EDAC; DMESG_PCIE; DMESG_NVME; DMESG_NIC; DMESG_GPU; COLLECTION_FAILED"),
        t("這些是 diagnostics，不是單獨證明 root cause；missing GPU 不會因為此 CPU framework 而 FAIL。", "These are diagnostics, not proof of root cause; a missing GPU does not FAIL this CPU framework."),
    ),
    item(
        "17", "ipmi-sel", t("IPMI SEL", "IPMI SEL"), PRE_POST,
        t("inband：`ipmitool sel list`；outband：authenticated LANPlus `sel list`；PRE clean-start 使用對應的 `sel clear`。", "Inband: `ipmitool sel list`; outband: authenticated LANPlus `sel list`; PRE clean-start uses the corresponding `sel clear`."),
        t("確認 SEL collection 可用，並在每個 loop 比較 action 前與 POST 的新增 records。", "Confirm that SEL collection is usable and compare records added between before-action and POST for each loop."),
        t("empty `SEL has no entries` 是 valid empty result；其他 output 必須是可解析的 SEL rows。Loop 不清除 SEL。", "Empty `SEL has no entries` is a valid empty result; other output must be parseable SEL rows. Loops do not clear SEL."),
        t("command valid 且格式正確；delta comparison 完成時標示 `COMPARED`，不代表 event content 已被 health evaluator 判 PASS。", "The command is valid and correctly formatted; a completed delta is marked `COMPARED`, which does not mean event content was health-evaluated as PASS."),
        t("N/A；SEL event content 目前是 review evidence，不是 shared automatic severity evaluator。", "N/A; SEL event content is review evidence, not a shared automatic severity evaluator."),
        t("command failure、empty/malformed output、before 或 POST collection unavailable；delta 標為 `UNAVAILABLE`，不是 0。", "Command failure, empty/malformed output, or unavailable before/POST collection; the delta is `UNAVAILABLE`, not zero."),
        t("PRE clear 前會先 probe；POST/loop collection 依 implementation 的一次 retry/transport path，不會在 loop 盲目 clear。", "PRE probes before clearing; POST/loop collection follows the implemented transport path and does not blindly clear inside a loop."),
        t("每個 loop 用 before-cycle SEL snapshot 對 POST snapshot 做 multiset delta；PRE SEL 不是 POST comparison source。", "Each loop computes a multiset delta from the before-cycle SEL snapshot to the POST snapshot; PRE SEL is not the POST comparison source."),
        t("`sel_before.txt`、`sel.txt`、`sel_delta.txt`、`sel_*_meta`；delta 有新增 record 時保留 raw line。", "`sel_before.txt`, `sel.txt`, `sel_delta.txt`, `sel_*_meta`; raw lines are retained when the delta has added records."),
        t("SEL_FORMAT_ERROR; COLLECTION_FAILED; IPMI_REPORTED_ERROR; CLEAR_SKIPPED", "SEL_FORMAT_ERROR; COLLECTION_FAILED; IPMI_REPORTED_ERROR; CLEAR_SKIPPED"),
        t("`REVIEW REQUIRED` 表示需要 reviewer 讀取 evidence；它不等同於 framework 自動判定 failure。", "`REVIEW REQUIRED` means the reviewer must inspect the evidence; it is not an automatic framework failure verdict."),
    ),
    item(
        "18", "redfish-eventlog", t("Redfish EventLog", "Redfish EventLog"), PRE_POST,
        t("Authenticated Redfish：`/redfish/v1/Systems` → `<System>/LogServices` → `Entries`；dynamic discovery、pagination 與 member reference resolution。", "Authenticated Redfish: `/redfish/v1/Systems` → `<System>/LogServices` → `Entries`; dynamic discovery, pagination, and member-reference resolution."),
        t("收集 EventLog 並以最高 severity 判定，讓 PRE 與每次 loop 的新增事件可追溯。", "Collect EventLog and evaluate it by worst severity so PRE and each loop's new events are traceable."),
        t("每次 capture 重新 login；HTTP status gate 必須成功；不把 invalid JSON、bad Members 或 page 2 failure 當作空 collection。", "Login again for each capture; the HTTP status gate must succeed; invalid JSON, bad Members, or a page-2 failure is not treated as an empty collection."),
        t("Critical → FAIL；Warning → WARN；只有 OK 或空 collection → PASS。可讀取 listing 且沒有此 service 是 `NOT PRESENT` / PASS。", "Critical → FAIL; Warning → WARN; only OK or an empty collection → PASS. A readable listing with no such service is `NOT PRESENT` / PASS."),
        t("沒有 Critical/Warning 且 collection 完整。", "There are no Critical/Warning entries and the collection is complete."),
        t("Warning entry；或 clear action 回報 warning。", "A Warning entry; or a clear action reports a warning."),
        t("Critical entry、discovery/collection unavailable、pagination incomplete、invalid member/JSON 或 HTTP failure。", "A Critical entry, discovery/collection unavailable, incomplete pagination, invalid member/JSON, or HTTP failure."),
        t("N/A；每次 capture re-login，但沒有對同一個 failed collection 的額外 retry contract。", "N/A; each capture re-logs in, but there is no additional retry contract for the same failed collection."),
        t("PRE capture 建立 severity baseline；loop 在 before snapshot 與 POST 之間以 Id + Message + Severity 做 content delta，timestamp 不參與 identity。", "PRE capture establishes the severity baseline; a loop compares before snapshot to POST by Id + Message + Severity, excluding timestamp from identity."),
        t("`pre_eventlog.txt`、`eventlog.txt`、`eventlog_delta.txt`、pre-clear history、meta/Counts/Pages/Reason。", "`pre_eventlog.txt`, `eventlog.txt`, `eventlog_delta.txt`, pre-clear history, and meta/Counts/Pages/Reason."),
        t("REDFISH_CRITICAL; REDFISH_WARNING; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED", "REDFISH_CRITICAL; REDFISH_WARNING; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED"),
        t("Service absent 只有在 valid LogServices listing 下才可宣告；discovery failed 時必須是 UNAVAILABLE。", "A service may be declared absent only after a valid LogServices listing; discovery failure must remain UNAVAILABLE."),
    ),
    item(
        "19", "redfish-sel", t("Redfish SEL", "Redfish SEL"), PRE_POST,
        t("同 EventLog 的 authenticated dynamic Redfish discovery，但 service name 為 `SEL`。", "The same authenticated dynamic Redfish discovery as EventLog, with service name `SEL`."),
        t("收集 BMC Redfish SEL（若該 BMC 提供），並以相同 severity/delta contract 記錄。", "Collect the BMC Redfish SEL when exposed by the BMC and apply the same severity/delta contract."),
        t("Members 可能是 expanded entry 或 `@odata.id` reference；全部 page 完成後才算 valid。", "Members may be expanded entries or `@odata.id` references; all pages must complete before the collection is valid."),
        t("Critical → FAIL；Warning → WARN；OK/empty → PASS；valid listing 確認 absent → NOT PRESENT / PASS。", "Critical → FAIL; Warning → WARN; OK/empty → PASS; a valid listing that confirms absence is NOT PRESENT / PASS."),
        t("沒有 Critical/Warning 且 collection 完整。", "There are no Critical/Warning entries and the collection is complete."),
        t("Warning entry 或 clear warning。", "A Warning entry or clear warning."),
        t("Critical、unavailable、invalid/incomplete collection、bad member、HTTP failure。", "Critical, unavailable, invalid/incomplete collection, bad member, or HTTP failure."),
        t("N/A；每次 capture 重新登入 Redfish session。", "N/A; each capture creates a new Redfish session."),
        t("PRE/loop 同 EventLog；delta 只在 before 與 POST 都 valid/complete 時標示 `COMPARED`。", "Same as EventLog for PRE/loop; delta is `COMPARED` only when both before and POST are valid/complete."),
        t("`pre_redfish_sel.txt`、`redfish_sel.txt`、`redfish_sel_delta.txt`、meta/Counts/Pages/Reason。", "`pre_redfish_sel.txt`, `redfish_sel.txt`, `redfish_sel_delta.txt`, and meta/Counts/Pages/Reason."),
        t("REDFISH_CRITICAL; REDFISH_WARNING; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED", "REDFISH_CRITICAL; REDFISH_WARNING; REDFISH_UNAVAILABLE; REDFISH_COLLECTION_FAILED; REDFISH_CLEAR_FAILED"),
        t("只收集實際 dynamic discovery 到的 EventLog/SEL；不延伸到未實作的 PostCodes、Journal、HostLogger 或 Dump。", "Only EventLog/SEL found through dynamic discovery are collected; the framework does not claim PostCodes, Journal, HostLogger, or Dump coverage."),
    ),
    item(
        "20", "bmc-firmware", t("BMC Firmware", "BMC Firmware"), PRE_POST,
        t("OOB command：`mc info`。", "OOB command: `mc info`."),
        t("保留 BMC firmware identity 供 review 與 evidence traceability。", "Retain BMC firmware identity for review and evidence traceability."),
        t("command output 原樣保存；目前沒有 expected version/downgrade evaluator。", "Command output is retained as-is; there is no expected-version/downgrade evaluator."),
        t("command 成功且 output 可讀。", "The command succeeds and output is readable."),
        t("N/A", "N/A"),
        t("command failure 或 firmware evidence 不可取得。", "The command fails or firmware evidence cannot be collected."),
        t("N/A", "N/A"),
        t("PRE/POST 各自保存，沒有 automatic version comparison。", "PRE/POST are each retained, with no automatic version comparison."),
        t("`pre_bmc_firmware.txt` / `bmc_firmware.txt`。", "`pre_bmc_firmware.txt` / `bmc_firmware.txt`."),
        t("COLLECTION_FAILED; IPMI_REPORTED_ERROR", "COLLECTION_FAILED; IPMI_REPORTED_ERROR"),
        t("Collection / Evidence Only。", "Collection / Evidence Only."),
        "collection",
    ),
    item(
        "21", "chassis-power", t("Chassis Power", "Chassis Power"), PRE_POST,
        t("OOB command：`power status`；required text：`Chassis Power is on`。", "OOB command: `power status`; required text: `Chassis Power is on`."),
        t("確認 POST 時 chassis power 仍為 on，並作為 valid cycle 的一部分。", "Confirm that chassis power is on during POST and use it as part of valid-cycle determination."),
        t("command validity 與 output token 都檢查；record 保存 `power_on`。", "Both command validity and the output token are checked; the record retains `power_on`."),
        t("command valid 且 output 明確包含 `Chassis Power is on`。", "The command is valid and explicitly contains `Chassis Power is on`."),
        t("N/A", "N/A"),
        t("command/transport failure，或未確認 chassis power on；產生 `POWER_NOT_ON` 或 collection failure。", "Command/transport failure, or chassis power is not confirmed on; produces `POWER_NOT_ON` or a collection failure."),
        t("N/A", "N/A"),
        t("POST power evidence 不與 PRE 內容做 health delta；它與 boot recovery、script verification、hardware execution 一起決定 valid cycle。", "POST power evidence is not a PRE content health delta; with boot recovery, script verification, and hardware execution it contributes to valid-cycle determination."),
        t("`pre_power.txt` / `power.txt`、`power_on` 與 `POWER_NOT_ON`。", "`pre_power.txt` / `power.txt`, `power_on`, and `POWER_NOT_ON`."),
        t("POWER_NOT_ON; COLLECTION_FAILED; IPMI_REPORTED_ERROR", "POWER_NOT_ON; COLLECTION_FAILED; IPMI_REPORTED_ERROR"),
        t("Cycle command 回應遺失只有在 boot changed 且 power-on confirmed 時才可 reconcile。", "A lost cycle-command response is reconciled only when boot changed and power-on is confirmed."),
    ),
    item(
        "22", "host-power", t("Host Power", "Host Power"), PRE_POST,
        t("BMC SSH command：`/usr/bin/powerctrl.sh power_status`；required text：`Host: Running` 與 `Chassis Power: On`。", "BMC SSH command: `/usr/bin/powerctrl.sh power_status`; required text: `Host: Running` and `Chassis Power: On`."),
        t("確認 host 與 chassis 都在可進行 POST 的 power state。", "Confirm that host and chassis are in the power state required for POST."),
        t("command code 與兩個 required tokens 都驗證；raw output 保留。", "The command code and both required tokens are verified; raw output is retained."),
        t("command successful 且兩個 required tokens 都存在。", "The command succeeds and both required tokens are present."),
        t("N/A", "N/A"),
        t("command failure，或 host/chassis state 未確認；record 產生 `HOST_NOT_RUNNING` 或 collection failure。", "The command fails, or host/chassis state is not confirmed; the record produces `HOST_NOT_RUNNING` or a collection failure."),
        t("N/A", "N/A"),
        t("每次 POST 重新檢查；沒有用 PRE power state 代替 POST。", "Recheck on every POST; PRE power state is not used as a substitute for POST."),
        t("`pre_host_power.txt` / `host_power.txt` 與 `HOST_NOT_RUNNING`。", "`pre_host_power.txt` / `host_power.txt` and `HOST_NOT_RUNNING`."),
        t("HOST_NOT_RUNNING; COLLECTION_FAILED; IPMI_REPORTED_ERROR", "HOST_NOT_RUNNING; COLLECTION_FAILED; IPMI_REPORTED_ERROR"),
        t("這是 power-state validation，不是對 BMC event log 的替代。", "This is power-state validation, not a substitute for BMC event-log validation."),
    ),
    item(
        "23", "cycle-command", t("Cycle Command Dispatch", "Cycle Command Dispatch"), CYCLE,
        t("由 cycle mode/channel dispatch：`reboot`→OS `reboot` 或 OOB `power reset`；`power_cycle`→inband `ipmitool power cycle` 或 OOB `power cycle`；`aux_cycle`→BMC `/usr/bin/stbypowerctrl.sh aux_cycle`。", "Dispatch by cycle mode/channel: `reboot` → OS `reboot` or OOB `power reset`; `power_cycle` → inband `ipmitool power cycle` or OOB `power cycle`; `aux_cycle` → BMC `/usr/bin/stbypowerctrl.sh aux_cycle`."),
        t("確認選定 action 被送出、回應 state 被記錄，且不把 response lost 誤報成成功。", "Confirm that the selected action is dispatched, its response state is recorded, and a lost response is not reported as success."),
        t("以 transport command 執行；record `action` 保存 role、command、state、code。", "Execute through the transport; the record's `action` retains role, command, state, and code."),
        t("valid response → `SENT`。不要求 BMC boot ID 改變；真正完成由後續 boot/recovery/POST evidence 確認。", "A valid response → `SENT`. A BMC boot ID change is not required; completion is confirmed by later boot/recovery/POST evidence."),
        t("N/A", "N/A"),
        t("not issued、command failed → `CYCLE_COMMAND_FAILED`；response lost → `RESPONSE_LOST`，後續只能透過 evidence reconcile 或成為 `COMMAND_UNCONFIRMED`。", "Not issued or command failed → `CYCLE_COMMAND_FAILED`; response lost → `RESPONSE_LOST`, which can only later be reconciled by evidence or become `COMMAND_UNCONFIRMED`."),
        t("不 retry ambiguous power command；只等待 recovery evidence。", "An ambiguous power command is not retried; the framework waits for recovery evidence."),
        t("Command state 只與同一 loop 的 boot transition、power-on、POST completion 一起判定，不與 PRE hardware quantity 比較。", "Command state is judged with the same loop's boot transition, power-on, and POST completion, not against PRE hardware quantities."),
        t("`cycle_command.txt`、`action` metadata、`CYCLE_COMMAND_FAILED`、`COMMAND_RECONCILED` / `COMMAND_UNCONFIRMED`。", "`cycle_command.txt`, `action` metadata, `CYCLE_COMMAND_FAILED`, `COMMAND_RECONCILED` / `COMMAND_UNCONFIRMED`."),
        t("CYCLE_COMMAND_FAILED; COMMAND_RECONCILED; COMMAND_UNCONFIRMED", "CYCLE_COMMAND_FAILED; COMMAND_RECONCILED; COMMAND_UNCONFIRMED"),
        t("`aux_cycle` 的實際 action 固定在 BMC controller，不因 channel label 改成 OS action。", "The actual `aux_cycle` action is fixed to the BMC controller and does not change into an OS action because of the channel label."),
    ),
    item(
        "24", "boot-transition", t("Boot ID Transition", "Boot ID Transition"), CYCLE,
        t("反覆執行 identity command，對照 action 前 `old_boot_id` 與 recovery 後 `new_boot_id`。", "Repeat the identity command and compare `old_boot_id` before action with `new_boot_id` after recovery."),
        t("確認送出的 cycle action 導致一次可辨識的 OS boot transition。", "Confirm that a dispatched cycle action resulted in one identifiable OS boot transition."),
        t("在 boot deadline 內 polling OS identity；boot ID 改變後再確認其他 selected endpoints。", "Poll OS identity within the boot deadline; after the boot ID changes, confirm the other selected endpoints."),
        t("對已送出的 action，OS boot ID 改變且 recovery identity 成功。", "For a dispatched action, the OS boot ID changes and recovery identity succeeds."),
        t("N/A", "N/A"),
        t("在 deadline 內沒有 changed boot ID → `BOOT_TIMEOUT`；額外或不符合預期的 transition → `UNEXPECTED_BOOT_TRANSITION` / identity stop。", "No changed boot ID within the deadline → `BOOT_TIMEOUT`; an extra or unexpected transition → `UNEXPECTED_BOOT_TRANSITION` / identity stop."),
        t("只對 transient identity connection failure polling 至 deadline；不重新送出 power action。", "Only transient identity connection failures are polled until the deadline; the power action is not resent."),
        t("before-action boot identity 是 loop reference；POST entry 預期為新 boot（action sent）或原 boot（action rejected/not sent）。", "The before-action boot identity is the loop reference; POST entry expects the new boot when the action was sent, or the old boot when it was rejected/not sent."),
        t("`recovery` metadata：old/new/post-entry boot IDs、attempts、boot_changed、`BOOT_TIMEOUT`。", "`recovery` metadata: old/new/post-entry boot IDs, attempts, boot_changed, and `BOOT_TIMEOUT`."),
        t("BOOT_TIMEOUT; UNEXPECTED_BOOT_TRANSITION; IDENTITY_UNSAFE; NODE_UNAVAILABLE", "BOOT_TIMEOUT; UNEXPECTED_BOOT_TRANSITION; IDENTITY_UNSAFE; NODE_UNAVAILABLE"),
        t("被拒絕或未送出的 action 若 boot 未變，仍可進行 POST；這不算 confirmed cycle。", "A rejected or unissued action with an unchanged boot can still receive POST; it is not a confirmed cycle."),
    ),
    item(
        "25", "endpoint-recovery", t("Endpoint Recovery", "Endpoint Recovery"), POST,
        t("OS/BMC/Lily identity probes、boot polling、POST capture 後的 OS identity，以及 BMC failure-path `sel list` / `power status`。", "OS/BMC/Lily identity probes, boot polling, OS identity after POST capture, and BMC failure-path `sel list` / `power status`."),
        t("確認 endpoint 在 boot recovery 與 POST 期間持續可用且 identity 穩定。", "Confirm that endpoints remain available and identity-stable during boot recovery and POST."),
        t("Recovery 失敗時仍嘗試在 identity 安全的前提下保存 BMC diagnostic evidence；identity unsafe 時不再碰其他 endpoint。", "On recovery failure, retain BMC diagnostic evidence when identity-safe; when identity is unsafe, do not touch other endpoints."),
        t("recovery identity success、POST identity stable、power-on、script verified、hardware execution complete，才可形成 valid cycle。", "Recovery identity succeeds, POST identity is stable, power is on, the script is verified, and hardware execution is complete before a valid cycle is formed."),
        t("N/A", "N/A"),
        t("recovery deadline、identity/auth failure、POST identity change、BMC diagnostic unavailable；target 停止或 campaign 變 INCOMPLETE。", "Recovery deadline, identity/auth failure, POST identity change, or unavailable BMC diagnostics; the target stops or the campaign becomes INCOMPLETE."),
        t("transient connections 在 deadline 內 polling；不對 identity mismatch retry。", "Transient connections are polled within the deadline; identity mismatch is not retried."),
        t("POST 先完成 independent captures，再確認 POST identity；不以 partial hardware capture 代替 recovery completion。", "POST completes independent captures before final POST identity confirmation; a partial hardware capture does not replace recovery completion."),
        t("recovery metadata、BMC failure evidence、POST records、`post_complete`、`boot_confirmed`、`valid_cycle`。", "Recovery metadata, BMC failure evidence, POST records, `post_complete`, `boot_confirmed`, and `valid_cycle`."),
        t("BOOT_TIMEOUT; IDENTITY_UNSAFE; NODE_UNAVAILABLE; BMC_UNAVAILABLE", "BOOT_TIMEOUT; IDENTITY_UNSAFE; NODE_UNAVAILABLE; BMC_UNAVAILABLE"),
        t("Hardware/FW collection failure 不會自動移除仍可安全 recovery 的 node；identity safety failure 才會停止該 node。", "A hardware/firmware collection failure does not automatically remove a safely recoverable node; identity-safety failure stops the node."),
    ),
    item(
        "26", "unexpected-boot", t("Unexpected Boot Transition Detection", "Unexpected Boot Transition Detection"), PRE_POST,
        t("比較 expected boot ID 與每個 cycle boundary 的 identity output。", "Compare the expected boot ID with identity output at every cycle boundary."),
        t("偵測 action 以外的額外 reboot 或 POST 期間 boot ID 變更。", "Detect an extra reboot or a boot-ID change during POST outside the expected action."),
        t("before action、POST entry 與 post-check identity 都有明確的 expected boot。", "Before-action, POST-entry, and post-check identity each have an explicit expected boot."),
        t("實際 boot ID 符合 expected sequence，且 POST checks 期間穩定。", "The actual boot ID follows the expected sequence and remains stable during POST checks."),
        t("N/A", "N/A"),
        t("不符合 expected boot、POST capture 後 boot ID 再次變更，或等待 action 前已發生 reboot；`UNEXPECTED_BOOT_TRANSITION` / `IDENTITY_UNSAFE`。", "The boot differs from expected, changes again after POST capture, or reboots while waiting for approval; `UNEXPECTED_BOOT_TRANSITION` / `IDENTITY_UNSAFE`."),
        t("N/A；這是 safety detection，不是可重試的 collection。", "N/A; this is a safety detection, not a retryable collection."),
        t("與 old/new boot IDs、cycle action state、POST identity 一起比較；不把 unchanged rejected action 誤標成 unexpected。", "Compare with old/new boot IDs, cycle action state, and POST identity; an unchanged rejected action is not marked unexpected."),
        t("`recovery` metadata、identity outputs、`UNEXPECTED_BOOT_TRANSITION` finding。", "`recovery` metadata, identity outputs, and `UNEXPECTED_BOOT_TRANSITION` finding."),
        t("UNEXPECTED_BOOT_TRANSITION; IDENTITY_UNSAFE", "UNEXPECTED_BOOT_TRANSITION; IDENTITY_UNSAFE"),
        t("此 safety gate 保障 cycle attribution，不宣稱能在 host 外部 log 已被清除時恢復所有歷史事件。", "This safety gate protects cycle attribution; it does not claim to recover every historical event when external logs were cleared."),
    ),
    item(
        "27", "project-hardware", t("Project-Specific Hardware Validation Interface", "Project-Specific Hardware Validation Interface"), ALL_PHASES,
        t("Selected project configuration script；framework 以 `MEMORY_MIN_RATIO=<configured value> bash <verified script>` 執行。", "The selected project configuration script; the framework runs `MEMORY_MIN_RATIO=<configured value> bash <verified script>`."),
        t("讓 project-owned hardware checks 在 PRE 與每次 POST 執行，同時保持 shared SOP 不含 project-specific expected quantity。", "Run project-owned hardware checks in PRE and every POST while keeping project-specific expected quantities out of the shared SOP."),
        t("Framework upload once；每次執行前檢查 regular file、非 symlink、owner、mode 0700 與 SHA-256。執行 output 以 line contract parse。", "Upload once; before every execution verify regular-file type, non-symlink status, owner, mode 0700, and SHA-256. Parse execution output by line contract."),
        t("`CHECK|...` 是量測/檢查結果；`ISSUE|code|component|reason` 是 finding；最後必須是 `RESULT|PASS` 或 `RESULT|FAIL`，並與 exit status 一致。", "`CHECK|...` reports measurements/checks; `ISSUE|code|component|reason` reports findings; the final line must be `RESULT|PASS` or `RESULT|FAIL` consistent with exit status."),
        t("script verified，command returned，且最後 structured RESULT 與 exit status 一致。`RESULT|PASS` 且無 findings 才是 hardware PASS；`RESULT|FAIL` 可代表 execution complete 但 health FAIL。", "The script is verified, the command returned, and the final structured RESULT matches exit status. Hardware is PASS only for `RESULT|PASS` with no findings; `RESULT|FAIL` can be execution-complete but health FAIL."),
        t("N/A；script 自己回報的 findings 經 framework 進入 record health。", "N/A; script-reported findings enter record health through the framework."),
        t("upload/verification failure、script missing/changed/unsafe、command not returned、missing/non-final RESULT、exit/RESULT mismatch，或 script 回報 `ISSUE` / `RESULT|FAIL`。", "Upload/verification failure, missing/changed/unsafe script, command not returned, missing/non-final RESULT, exit/RESULT mismatch, or a script-reported `ISSUE` / `RESULT|FAIL`."),
        t("不會 overwrite 或 re-upload changed script；verification failure 不以 retry 掩蓋。", "A changed script is not overwritten or re-uploaded; verification failure is not hidden by retry."),
        t("PRE hardware result 是 baseline finding；每次 POST 重跑 selected config，framework 只以 structured output 反映 current result。", "The PRE hardware result is a baseline finding; each POST reruns the selected config and the framework reflects the current result only through structured output."),
        t("`<project>_config.snapshot.sh`、`pre_hardware.txt` / `hardware.txt`、CHECK lines、ISSUE lines、RESULT、SHA evidence。", "`<project>_config.snapshot.sh`, `pre_hardware.txt` / `hardware.txt`, CHECK lines, ISSUE lines, RESULT, and SHA evidence."),
        t("SCRIPT_VALIDATION_FAILED; HARDWARE_EXECUTION_INCOMPLETE; CONFIG_FAILED; CONFIG_INCOMPLETE; script-defined ISSUE codes", "SCRIPT_VALIDATION_FAILED; HARDWARE_EXECUTION_INCOMPLETE; CONFIG_FAILED; CONFIG_INCOMPLETE; script-defined ISSUE codes"),
        t("本節定義 interface 與 propagation，不列出任何 project 的 expected quantity、platform name 或 hardware threshold。", "This section defines the interface and propagation, without listing any project's expected quantity, platform name, or hardware threshold."),
    ),
    item(
        "28", "evidence-generation", t("Evidence Generation", "Evidence Generation"), ALL_PHASES,
        t("`NodeSession.command`、phase folder layout、`campaign.json`、record evidence list 與 issue evidence reference。", "`NodeSession.command`, phase folder layout, `campaign.json`, record evidence lists, and issue evidence references."),
        t("讓每個 collection、finding、action 與 recovery decision 能回到 raw evidence。", "Make every collection, finding, action, and recovery decision traceable to raw evidence."),
        t("text evidence header 包含 UTC+8、role、command、exit、state、duration；output 以 HTML escaping 顯示。", "Text evidence headers include UTC+8, role, command, exit, state, and duration; output is HTML-escaped when rendered."),
        t("command/record/evidence path 一致，且 FAIL/WARN finding 有 evidence 或明確顯示 unavailable。", "Command, record, and evidence paths are consistent, and FAIL/WARN findings have evidence or explicitly show unavailable."),
        t("N/A", "N/A"),
        t("evidence file missing、command output unavailable、raw collection failed，或 issue 無法指向 retained evidence。", "An evidence file is missing, command output is unavailable, raw collection fails, or an issue cannot point to retained evidence."),
        t("各 command 只依實作的 transport timeout/recovery；不重造 raw evidence。", "Each command follows the implemented transport timeout/recovery; raw evidence is not recreated."),
        t("PRE evidence、before-action/loop evidence、POST evidence、delta、recovery metadata 與 report 都由同一 record graph 連結。", "PRE evidence, before-action/loop evidence, POST evidence, delta, recovery metadata, and the report are linked by the same record graph."),
        t("Campaign bundle 的 raw text、JSON records、delta files、`CYCLE_REVIEW_REPORT.html` 與本 specification。", "Raw text, JSON records, delta files, `CYCLE_REVIEW_REPORT.html`, and this specification in the campaign bundle."),
        t("COLLECTION_FAILED; evidence-specific missing annotations; recovery integrity findings", "COLLECTION_FAILED; evidence-specific missing annotations; recovery integrity findings"),
        t("Evidence path 使用相對路徑；bundle 搬移後 report ↔ specification link 仍有效。", "Evidence paths are relative; report ↔ specification links remain valid when the bundle is moved."),
    ),
    item(
        "29", "recovery-integrity", t("Recovery / Report Integrity", "Recovery / Report Integrity"), ALL_PHASES,
        t("`campaign.json` journal、per-node `pre_report.json` / loop `report.json`、`cycle_summary.json` 與 `cycle_recovery.py` merge rules。", "The `campaign.json` journal, per-node `pre_report.json` / loop `report.json`, `cycle_summary.json`, and `cycle_recovery.py` merge rules."),
        t("在中斷、sidecar 缺少或 record 不完整時保留已知歷史，並把完整性問題明確標成 campaign outcome。", "Retain known history after interruption, missing sidecars, or incomplete records, while making integrity problems explicit in campaign outcome."),
        t("rebuild 在 writer lock 內執行；live owner 會被拒絕；records 依 node/loop identity merge，保留 conflict findings/evidence。", "Rebuild runs under the writer lock; a live owner is rejected; records merge by node/loop identity while retaining conflicting findings/evidence."),
        t("完整 record 可在其 evidence/findings 包含 partial prefix 時取代 partial prefix；PRE 保持 immutable。", "A complete record may supersede a partial prefix only when its evidence/findings include that prefix; PRE remains immutable."),
        t("N/A", "N/A"),
        t("missing/corrupt sidecar、conflicting terminal data、unsupported counters 或 evidence integrity issue → explicit integrity note、INCOMPLETE/FAIL。", "A missing/corrupt sidecar, conflicting terminal data, unsupported counter, or evidence-integrity issue produces an explicit integrity note and INCOMPLETE/FAIL."),
        t("N/A；rebuild 不是重新執行 hardware validation。", "N/A; rebuild does not rerun hardware validation."),
        t("recovered record 仍使用原始 PRE baseline 與原始 issue history；新的 partial record 不可抹除歷史 FAIL。", "Recovered records still use the original PRE baseline and issue history; a newer partial record cannot erase a historical FAIL."),
        t("journal、sidecars、`cycle_summary.json`、`CYCLE_REVIEW_REPORT.html`、`recovery_notes` 與 recovery issue。", "The journal, sidecars, `cycle_summary.json`, `CYCLE_REVIEW_REPORT.html`, `recovery_notes`, and recovery findings."),
        t("EXECUTION_ERROR; recovery integrity findings; INCOMPLETE/FAIL outcome", "EXECUTION_ERROR; recovery integrity findings; INCOMPLETE/FAIL outcome"),
        t("Campaign completion 與 campaign health 必須分開閱讀；recovery 完成不會洗掉 validation failure。", "Campaign completion and campaign health must be read separately; recovery completion does not wash away a validation failure."),
    ),
]


FLOW = [
    ("pre", t("PRE-CHECK", "PRE-CHECK"), t("前置驗證", "Pre-check")),
    ("clean-start", t("CLEAN-START PREPARATION", "CLEAN-START PREPARATION"), t("清理與基線準備", "Clean-start and baseline")),
    ("baseline", t("BASELINE CAPTURE", "BASELINE CAPTURE"), t("基線收集", "Baseline capture")),
    ("approval", t("OPERATOR APPROVAL", "OPERATOR APPROVAL"), t("操作人員核准", "Operator approval")),
    ("cycle", t("CYCLE ACTION", "CYCLE ACTION"), t("Cycle 動作", "Cycle action")),
    ("recovery", t("BOOT / ENDPOINT RECOVERY", "BOOT / ENDPOINT RECOVERY"), t("開機與 endpoint recovery", "Boot and endpoint recovery")),
    ("post", t("POST-CHECK", "POST-CHECK"), t("後置驗證", "Post-check")),
    ("comparison", t("PRE ↔ POST COMPARISON", "PRE ↔ POST COMPARISON"), t("前後比較", "PRE to POST comparison")),
    ("classification", t("RESULT CLASSIFICATION", "RESULT CLASSIFICATION"), t("結果分類", "Result classification")),
    ("evidence", t("EVIDENCE & REPORT", "EVIDENCE & REPORT"), t("證據與報告", "Evidence and report")),
]


SECTIONS = [
    ("overview", "01", t("Overview", "Overview")),
    ("flow", "02", t("Validation Flow", "Validation Flow")),
    ("matrix", "03", t("Validation Matrix", "Validation Matrix")),
    ("pre-check", "04", t("PRE-CHECK", "PRE-CHECK")),
    ("cycle-execution", "05", t("Cycle Execution", "Cycle Execution")),
    ("post-check", "06", t("POST-CHECK", "POST-CHECK")),
    ("kernel-hardware", "07", t("Kernel & Hardware Error Detection", "Kernel & Hardware Error Detection")),
    ("bmc-logs", "08", t("BMC Log Validation", "BMC Log Validation")),
    ("project-interface", "09", t("Project Hardware Validation Interface", "Project Hardware Validation Interface")),
    ("semantics", "10", t("Result Semantics", "Result Semantics")),
    ("traceability", "11", t("Evidence Traceability", "Evidence Traceability")),
    ("integrity", "12", t("Recovery & Integrity", "Recovery & Integrity")),
]


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _pair(value: dict[str, str], cls: str = "") -> str:
    classes = f"lang {cls}".strip()
    return "".join(f'<span class="{classes} lang-{lang}">{_esc(value[lang])}</span>' for lang in LANGS)


def _pair_block(value: dict[str, str], cls: str = "") -> str:
    return _pair(value, f"lang-block {cls}".strip())


def _code_pair(value: dict[str, str]) -> str:
    return "".join(f'<code class="lang {lang} lang-{lang}">{_esc(value[lang])}</code>' for lang in LANGS)


def _field(label: dict[str, str], value: dict[str, str], code: bool = False) -> str:
    content = _code_pair(value) if code else _pair_block(value)
    return f'<div class="sop-field"><dt>{_pair(label)}</dt><dd>{content}</dd></div>'


def _section_link(section_id: str, label: dict[str, str]) -> str:
    return f'<a href="#{_esc(section_id)}">{_pair(label)}</a>'


def _item_detail(spec: dict) -> str:
    heading = t(f"{spec['number']}. {spec['name']['zh-TW']}", f"{spec['number']}. {spec['name']['en']}")
    fields = [
        (t("驗證目的", "Purpose"), spec["purpose"], False),
        (t("執行階段", "Phase"), spec["phase"], False),
        (t("指令或資料來源", "Command or Data Source"), spec["source"], False),
        (t("資料收集方式", "Collection Method"), spec["collection"], False),
        (t("判定邏輯", "Validation Logic"), spec["logic"], False),
        (t("通過條件", "PASS Criteria"), spec["passed"], False),
        (t("警告條件", "WARN Criteria"), spec["warned"], False),
        (t("失敗條件", "FAIL Criteria"), spec["failed"], False),
        (t("重試與確認機制", "Retry / Confirmation Logic"), spec["retry"], False),
        (t("前後比較方式", "PRE ↔ POST Comparison"), spec["comparison"], False),
        (t("驗證證據", "Evidence"), spec["evidence"], False),
        (t("相關 Issue Code", "Issue Code"), spec["issue_code"], True),
        (t("備註", "Notes"), spec["notes"], False),
    ]
    status_label = t("Collection / Evidence Only", "Collection / Evidence Only") if spec["kind"] == "collection" else t("Validation Item", "Validation Item")
    return f'''<article class="validation-item" id="item-{_esc(spec['key'])}">
      <div class="item-heading"><div><span class="item-number">{_esc(spec['number'])}</span><h3>{_pair(heading)}</h3></div><span class="item-kind">{_pair(status_label)}</span></div>
      <dl class="sop-fields">{''.join(_field(label, value, code) for label, value, code in fields)}</dl>
    </article>'''


def _matrix_row(spec: dict) -> str:
    summary = f'''<summary class="matrix-row"><span class="matrix-cell phase">{_pair(spec['phase'])}</span><span class="matrix-cell item"><strong>{_pair(spec['name'])}</strong><small>{_pair(t(spec['key'], spec['key']))}</small></span><span class="matrix-cell source">{_pair(spec['source'])}</span><span class="matrix-cell logic">{_pair(spec['logic'])}</span><span class="matrix-cell criteria">{_pair(spec['passed'])}</span><span class="matrix-cell criteria warn-cell">{_pair(spec['warned'])}</span><span class="matrix-cell criteria fail-cell">{_pair(spec['failed'])}</span><span class="matrix-cell evidence">{_pair(spec['evidence'])}</span></summary>'''
    return f'''<details class="matrix-entry" id="matrix-{_esc(spec['key'])}">{summary}<div class="matrix-detail"><a class="detail-link" href="#item-{_esc(spec['key'])}">{_pair(t("開啟固定 SOP 詳細欄位", "Open the fixed SOP fields"))}</a></div></details>'''


def _flow_html() -> str:
    parts = []
    for index, (anchor, title, subtitle) in enumerate(FLOW):
        arrow = '<span class="flow-arrow" aria-hidden="true">↓</span>' if index < len(FLOW) - 1 else ''
        parts.append(f'<a class="flow-stage" href="#{_esc(anchor)}"><span class="flow-index">{index + 1:02d}</span><strong>{_pair(title)}</strong><small>{_pair(subtitle)}</small></a>{arrow}')
    return '<div class="flow-list">' + ''.join(parts) + '</div>'


def _toc() -> str:
    return '<nav class="toc" aria-label="Table of contents"><div class="toc-title">' + _pair(t("文件導覽", "Contents")) + '</div>' + ''.join(
        f'<a href="#{sid}"><span>{number}</span>{_pair(title)}</a>' for sid, number, title in SECTIONS
    ) + '<a class="top-link" href="#top">↑ ' + _pair(t("回到頂端", "Back to top")) + '</a></nav>'


def _section_header(number: str, title: dict[str, str], intro: dict[str, str], section_id: str) -> str:
    return f'<section class="doc-section" id="{_esc(section_id)}"><div class="section-heading"><span class="section-number">{_esc(number)}</span><h2>{_pair(title)}</h2></div><p class="section-intro">{_pair_block(intro)}</p>'


def _item_group(keys: list[str]) -> str:
    selected = [spec for spec in ITEMS if spec["key"] in keys]
    return ''.join(_item_detail(spec) for spec in selected)


def _semantic_tables() -> str:
    return '''
      <div class="semantic-grid">
        <div class="semantic-panel"><h3>STATUS</h3><table><thead><tr><th><span class="lang lang-zh-TW">狀態</span><span class="lang lang-en">Status</span></th><th><span class="lang lang-zh-TW">意義</span><span class="lang lang-en">Meaning</span></th></tr></thead><tbody>
          <tr><td><span class="badge pass">PASS</span></td><td><span class="lang lang-zh-TW">目前實作定義的檢查通過，或 collection 明確完成且沒有更高嚴重度 finding。</span><span class="lang lang-en">The implemented check passes, or collection completed without a higher-severity finding.</span></td></tr>
          <tr><td><span class="badge warn">WARN</span></td><td><span class="lang lang-zh-TW">有需要 review 的非致命 finding；不等於 PASS，也不會自動變成 FAIL。</span><span class="lang lang-en">A non-fatal finding requires review; it is not PASS and does not automatically become FAIL.</span></td></tr>
          <tr><td><span class="badge fail">FAIL</span></td><td><span class="lang lang-zh-TW">目前實作明確判定 validation failure 或 collection 無法安全判定。</span><span class="lang lang-en">The implementation explicitly detects a validation failure or cannot safely validate the collection.</span></td></tr>
        </tbody></table></div>
        <div class="semantic-panel"><h3>CLASSIFICATION</h3><table><thead><tr><th><span class="lang lang-zh-TW">分類</span><span class="lang lang-en">Classification</span></th><th><span class="lang lang-zh-TW">意義</span><span class="lang lang-en">Meaning</span></th></tr></thead><tbody>
          <tr><td><span class="badge known">KNOWN</span></td><td><span class="lang lang-zh-TW">相同 issue identity 已存在於 immutable PRE baseline。</span><span class="lang lang-en">The same issue identity existed in the immutable PRE baseline.</span></td></tr>
          <tr><td><span class="badge new">NEW</span></td><td><span class="lang lang-zh-TW">issue identity 不在 PRE baseline。</span><span class="lang lang-en">The issue identity was not in the PRE baseline.</span></td></tr>
          <tr><td><span class="badge worsened">WORSENED</span></td><td><span class="lang lang-zh-TW">相對 PRE 的 count、native severity、native error count 或 severity 變差。</span><span class="lang lang-en">Count, native severity, native error count, or severity increased relative to PRE.</span></td></tr>
        </tbody></table><p class="callout"><span class="lang lang-zh-TW"><strong>KNOWN FAIL 仍然是 FAIL。</strong> Classification 不會改變 severity，也不代表忽略錯誤。</span><span class="lang lang-en"><strong>KNOWN FAIL is still FAIL.</strong> Classification does not change severity and does not mean the error is ignored.</span></p></div>
      </div>
      <div class="semantic-panel separation-panel"><h3><span class="lang lang-zh-TW">Campaign Completion 與 Campaign Health</span><span class="lang lang-en">Campaign Completion and Campaign Health</span></h3><table><thead><tr><th><span class="lang lang-zh-TW">維度</span><span class="lang lang-en">Dimension</span></th><th><span class="lang lang-zh-TW">值</span><span class="lang lang-en">Values</span></th><th><span class="lang lang-zh-TW">判定</span><span class="lang lang-en">Interpretation</span></th></tr></thead><tbody>
        <tr><td><span class="lang lang-zh-TW">Campaign Completion</span><span class="lang lang-en">Campaign Completion</span></td><td><span class="badge complete">COMPLETE</span> / <span class="badge incomplete">INCOMPLETE</span></td><td><span class="lang lang-zh-TW">requested execution limit 是否完成，與 health 不同。</span><span class="lang lang-en">Whether the requested execution limit completed; separate from health.</span></td></tr>
        <tr><td><span class="lang lang-zh-TW">Campaign Health</span><span class="lang lang-en">Campaign Health</span></td><td><span class="badge pass">PASS</span> / <span class="badge warn">WARN</span> / <span class="badge fail">FAIL</span></td><td><span class="lang lang-zh-TW">所有 campaign findings 的最壞 health；與 completion 不同。</span><span class="lang lang-en">The worst health across campaign findings; separate from completion.</span></td></tr>
        <tr><td><span class="lang lang-zh-TW">有效組合</span><span class="lang lang-en">Valid combination</span></td><td><span class="badge complete">COMPLETE</span> + <span class="badge fail">FAIL</span></td><td><span class="lang lang-zh-TW">requested execution 已完成，但 validation 發現 failure。</span><span class="lang lang-en">Requested execution completed, but validation found a failure.</span></td></tr>
      </tbody></table></div>'''


def render_specification(generated_time: str | None = None) -> str:
    generated_time = generated_time or now()
    tool_version = (BASE / "VERSION").read_text(encoding="utf-8").strip()
    title = t("Vera Cycle 驗證規範", "Vera Cycle Validation Specification")
    subtitle = t("驗證方法、執行流程、通過／失敗判定準則與證據定義", "Validation Methodology, Execution Flow, Pass/Fail Criteria and Evidence Definition")
    logo = _wistron_logo()
    toc = _toc()
    overview = _section_header("01", t("Overview", "Overview"), t("本文件定義 Vera Cycle Validation Framework 已實作的共通驗證方法、判定語意與證據契約。它是 project-independent 的正式 validation specification，不是某一次 campaign 的結果，也不包含任何 project hardware expected quantity。", "This document defines the shared validation methods, result semantics, and evidence contracts implemented by the Vera Cycle Validation Framework. It is a project-independent validation specification, not a campaign result, and contains no project hardware expected quantities."), "overview")
    overview += f'''<div class="overview-grid"><div class="overview-lead"><h3>{_pair(t("文件用途", "Document purpose"))}</h3><p>{_pair_block(t("讓 reviewer 不需閱讀 Python 或 shell source，即可回答 PRE 做什麼、Cycle 如何確認完成、POST 如何比較，以及什麼情況會被判定為 PASS、WARN 或 FAIL。", "Enable a reviewer to understand PRE checks, cycle completion, POST comparison, and PASS/WARN/FAIL criteria without reading Python or shell source."))}</p></div><div class="overview-facts"><div><dt>{_pair(t("文件類型", "Document type"))}</dt><dd>{_pair(t("Validation Specification", "Validation Specification"))}</dd></div><div><dt>{_pair(t("Framework", "Framework"))}</dt><dd>{_pair(t("Vera Cycle Validation Framework", "Vera Cycle Validation Framework"))}</dd></div><div><dt>{_pair(t("文件範圍", "Document scope"))}</dt><dd>{_pair(t("Generic / Project Independent", "Generic / Project Independent"))}</dd></div><div><dt>{_pair(t("產生來源", "Generated from"))}</dt><dd>{_pair(t("Actual Cycle Framework Implementation", "Actual Cycle Framework Implementation"))}</dd></div><div><dt>{_pair(t("工具版本", "Tool version"))}</dt><dd>{_esc(tool_version)}</dd></div><div><dt>{_pair(t("產生時間", "Generated time"))}</dt><dd>{_esc(generated_time)}</dd></div></div></div><div class="principles"><div><span class="principle-mark">01</span><span>{_pair_block(t("實作優先：文件只承諾目前 main implementation 真正執行的行為。", "Implementation first: the document promises only behaviour actually implemented on main."))}</span></div><div><span class="principle-mark">02</span><span>{_pair_block(t("證據可追溯：每個 finding 都回到 command、raw evidence 與 record。", "Traceable evidence: every finding points to a command, raw evidence, and record."))}</span></div><div><span class="principle-mark">03</span><span>{_pair_block(t("維度分離：Status、Classification、Completion 與 Health 各自表達不同事實。", "Separate dimensions: Status, Classification, Completion, and Health express different facts."))}</span></div></div></section>'''

    flow = _section_header("02", t("Validation Flow", "Validation Flow"), t("以下流程是正式 campaign 的共通骨架。每個 stage 可跳到對應 validation item 或結果語意。", "The following flow is the shared skeleton of a formal campaign. Each stage links to its related validation items or result semantics."), "flow")
    flow += _flow_html() + '<div class="flow-note"><span class="lang lang-zh-TW"><strong>操作人員核准：</strong>PRE evidence 與 exclusions 顯示後，只有明確確認才會把 staged evidence promote 成正式 campaign bundle。</span><span class="lang lang-en"><strong>Operator approval:</strong> only an explicit confirmation after PRE evidence and exclusions are shown promotes staged evidence into the campaign bundle.</span></div></section>'

    matrix = _section_header("03", t("Validation Matrix", "Validation Matrix"), t("矩陣先回答每個 validation item 使用什麼 source、怎樣判定、什麼會 FAIL，以及 evidence 在哪裡。展開列可跳到固定 SOP 欄位。", "The matrix answers which source each validation item uses, how it is judged, what fails, and where evidence lives. Expand a row to jump to the fixed SOP fields."), "matrix")
    headers = [t("階段", "Phase"), t("驗證項目", "Validation Item"), t("指令／資料來源", "Command / Source"), t("驗證方式", "Validation Method"), t("通過條件", "PASS Criteria"), t("警告條件", "WARN Criteria"), t("失敗條件", "FAIL Criteria"), t("驗證證據", "Evidence")]
    matrix += '<div class="matrix-wrap"><div class="matrix-head">' + ''.join(f'<div>{_pair(h)}</div>' for h in headers) + '</div>' + ''.join(_matrix_row(spec) for spec in ITEMS) + '</div></section>'

    pre_keys = ["endpoint-identity", "connectivity-auth", "root-dependencies", "clean-start", "pci-inventory", "pci-topology", "pci-link", "block-devices", "nvme", "usb", "memory", "network", "firmware", "system-info", "sensors", "dmesg", "ipmi-sel", "redfish-eventlog", "redfish-sel", "bmc-firmware", "chassis-power", "host-power", "project-hardware"]
    cycle_keys = ["cycle-command", "boot-transition", "endpoint-recovery", "unexpected-boot"]
    post_keys = ["pci-inventory", "pci-topology", "pci-link", "block-devices", "nvme", "usb", "memory", "network", "firmware", "system-info", "sensors", "dmesg", "ipmi-sel", "redfish-eventlog", "redfish-sel", "bmc-firmware", "chassis-power", "host-power", "project-hardware"]
    kernel_keys = ["sensors", "dmesg", "pci-link", "nvme"]
    bmc_keys = ["ipmi-sel", "redfish-eventlog", "redfish-sel", "bmc-firmware", "chassis-power", "host-power"]

    pre = _section_header("04", t("PRE-CHECK", "PRE-CHECK"), t("PRE 以 identity、readiness、clean-start 與 baseline capture 建立 immutable reference。Hardware/sensor finding 會顯示給 operator；只有 inventory/identity safety block 才會阻止該 target 進入 approved scope。", "PRE establishes the immutable reference through identity, readiness, clean-start, and baseline capture. Hardware and sensor findings are shown to the operator; inventory and identity-safety blocks prevent a target from entering the approved scope."), "pre-check") + _item_group(pre_keys) + '</section>'
    cycle = _section_header("05", t("Cycle Execution", "Cycle Execution"), t("每個 loop 先重新驗證 endpoint、保存 action 前 evidence，再 dispatch action、等待 boot transition，最後進入 POST。", "Each loop re-verifies endpoints, retains before-action evidence, dispatches the action, waits for boot transition, and then enters POST."), "cycle-execution") + _item_group(cycle_keys) + '</section>'
    post = _section_header("06", t("POST-CHECK", "POST-CHECK"), t("POST 以 original PRE baseline 為比較來源，並在 recovery 後執行相同的共通 capture 與 selected project check。", "POST uses the original PRE baseline for comparison and runs the same shared captures and selected project check after recovery."), "post-check") + _item_group(post_keys) + '</section>'
    kernel = _section_header("07", t("Kernel & Hardware Error Detection", "Kernel & Hardware Error Detection"), t("此章只描述 parser 與目前 evaluator 真正識別的 sensor/dmesg/link/NVMe 行為；不以一般常識擴大 coverage。", "This section describes only the sensor, dmesg, link, and NVMe behaviour actually recognised by the parser and evaluator; coverage is not expanded by general assumptions."), "kernel-hardware") + _item_group(kernel_keys) + '</section>'
    bmc = _section_header("08", t("BMC Log Validation", "BMC Log Validation"), t("BMC log collection 使用 dynamic discovery 與 worst-severity semantics。EventLog/SEL service absent 與 service unavailable 必須分開。", "BMC log collection uses dynamic discovery and worst-severity semantics. A service absent is distinct from a service unavailable."), "bmc-logs") + _item_group(bmc_keys) + '</section>'

    project_spec = next(spec for spec in ITEMS if spec["key"] == "project-hardware")
    project = _section_header("09", t("Project Hardware Validation Interface", "Project Hardware Validation Interface"), t("Framework 執行 selected project configuration，但共用 specification 只定義 interface、parsing 與 propagation，不列出任何 platform-specific expected quantity。", "The framework executes the selected project configuration, while this shared specification defines only the interface, parsing, and propagation—not platform-specific expected quantities."), "project-interface")
    project += _item_detail(project_spec) + '''<div class="contract-panel"><h3><span class="lang lang-zh-TW">Structured Contract</span><span class="lang lang-en">Structured Contract</span></h3><table><thead><tr><th><span class="lang lang-zh-TW">行型態</span><span class="lang lang-en">Line type</span></th><th><span class="lang lang-zh-TW">Framework 意義</span><span class="lang lang-en">Framework meaning</span></th></tr></thead><tbody><tr><td><code>CHECK|...</code></td><td><span class="lang lang-zh-TW">回報檢查結果與量測資訊；framework 保留 raw line 並建立 check detail。</span><span class="lang lang-en">Reports the check result and measurement information; the framework retains the raw line and creates check detail.</span></td></tr><tr><td><code>ISSUE|code|component|reason</code></td><td><span class="lang lang-zh-TW">回報 validation finding；framework 轉成 record issue 並連回 hardware evidence。</span><span class="lang lang-en">Reports a validation finding; the framework creates a record issue linked to hardware evidence.</span></td></tr><tr><td><code>RESULT|PASS</code></td><td><span class="lang lang-zh-TW">所有 selected checks 完成且沒有 failure；只有 return 0、final PASS 且沒有 findings 才是 hardware PASS。</span><span class="lang lang-en">All selected checks completed without failure; hardware is PASS only with return 0, final PASS, and no findings.</span></td></tr><tr><td><code>RESULT|FAIL</code></td><td><span class="lang lang-zh-TW">至少一個 project validation failure；return 1 且 final FAIL 仍可算 hardware execution complete，但 record/campaign health 為 FAIL。</span><span class="lang lang-en">At least one project validation failure; return 1 with final FAIL can still be execution-complete, but record/campaign health is FAIL.</span></td></tr></tbody></table></div></section>'''

    semantics = _section_header("10", t("Result Semantics", "Result Semantics"), t("Status 與 Classification、Campaign Completion 與 Campaign Health 是不同維度，必須同時閱讀而不可互相替代。", "Status and Classification, and Campaign Completion and Campaign Health, are separate dimensions and must be read together."), "semantics") + _semantic_tables() + '</section>'
    trace = _section_header("11", t("Evidence Traceability", "Evidence Traceability"), t("每個 finding 應能沿著同一條 trace 回到 raw command output，再回到 record 與 campaign health。", "Every finding should follow one trace back to raw command output, then to the record and campaign health."), "traceability")
    trace += '''<div class="trace-flow"><div><span>01</span><strong><span class="lang lang-zh-TW">Validation Item</span><span class="lang lang-en">Validation Item</span></strong><small><span class="lang lang-zh-TW">驗證項目</span><span class="lang lang-en">What is being checked</span></small></div><i>→</i><div><span>02</span><strong><span class="lang lang-zh-TW">Command / Source</span><span class="lang lang-en">Command / Source</span></strong><small><span class="lang lang-zh-TW">實際執行的 command 或 structured source</span><span class="lang lang-en">Actual command or structured source</span></small></div><i>→</i><div><span>03</span><strong><span class="lang lang-zh-TW">Raw Evidence</span><span class="lang lang-en">Raw Evidence</span></strong><small><span class="lang lang-zh-TW">phase text、delta、metadata</span><span class="lang lang-en">Phase text, delta, metadata</span></small></div><i>→</i><div><span>04</span><strong><span class="lang lang-zh-TW">Structured Finding</span><span class="lang lang-en">Structured Finding</span></strong><small><span class="lang lang-zh-TW">Issue code、severity、snippet</span><span class="lang lang-en">Issue code, severity, snippet</span></small></div><i>→</i><div><span>05</span><strong><span class="lang lang-zh-TW">Record Status</span><span class="lang lang-en">Record Status</span></strong><small><span class="lang lang-zh-TW">PRE / LOOP / status</span><span class="lang lang-en">PRE / LOOP / status</span></small></div><i>→</i><div><span>06</span><strong><span class="lang lang-zh-TW">Campaign Health</span><span class="lang lang-en">Campaign Health</span></strong><small><span class="lang lang-zh-TW">最壞 health 與 completion 分開</span><span class="lang lang-en">Worst health, separate from completion</span></small></div></div><div class="evidence-map"><div><h3><span class="lang lang-zh-TW">PRE evidence</span><span class="lang lang-en">PRE evidence</span></h3><p><span class="lang lang-zh-TW">identity、clean-start、baseline collections 與 original issue set。</span><span class="lang lang-en">Identity, clean-start, baseline collections, and the original issue set.</span></p></div><div><h3><span class="lang lang-zh-TW">Loop evidence</span><span class="lang lang-en">Loop evidence</span></h3><p><span class="lang lang-zh-TW">before-action、cycle command、recovery、POST collection。</span><span class="lang lang-en">Before-action, cycle command, recovery, and POST collections.</span></p></div><div><h3><span class="lang lang-zh-TW">Delta evidence</span><span class="lang lang-en">Delta evidence</span></h3><p><span class="lang lang-zh-TW">SEL delta、Redfish content delta、PRE issue classification。</span><span class="lang lang-en">SEL delta, Redfish content delta, and PRE issue classification.</span></p></div><div><h3><span class="lang lang-zh-TW">Recovery metadata</span><span class="lang lang-en">Recovery metadata</span></h3><p><span class="lang lang-zh-TW">boot IDs、attempts、power state、valid cycle flags。</span><span class="lang lang-en">Boot IDs, attempts, power state, and valid-cycle flags.</span></p></div><div><h3><span class="lang lang-zh-TW">Report</span><span class="lang lang-en">Report</span></h3><p><span class="lang lang-zh-TW">CYCLE_REVIEW_REPORT.html 以 relative evidence links 呈現完整 review context。</span><span class="lang lang-en">CYCLE_REVIEW_REPORT.html presents the complete review context with relative evidence links.</span></p></div></div></section>'''

    integrity = _section_header("12", t("Recovery & Integrity", "Recovery & Integrity"), t("Recovery 的目標是保留真實歷史，不是把 incomplete execution 重寫成 PASS。", "Recovery preserves factual history; it does not rewrite incomplete execution as PASS."), "integrity")
    integrity += _item_group(["recovery-integrity", "evidence-generation"]) + '<div class="final-links"><a href="CYCLE_REVIEW_REPORT.html" class="primary-link">{}</a><span>{}</span></div></section>'.format(_pair(t("Validation Result　→　CYCLE_REVIEW_REPORT.html", "Validation Result　→　CYCLE_REVIEW_REPORT.html")), _pair(t("相對連結，與 campaign bundle 一起搬移仍有效。", "Relative link; remains valid when moved with the campaign bundle.")))

    css = (_CSS
           .replace('h1{font-size:34px;line-height:1.18', 'h1{font-size:30px;line-height:1.3')
           .replace('border-top:4px solid var(--blue)', 'box-shadow:inset 0 4px 0 var(--blue)')
           .replace('border-top:3px solid var(--blue)', 'box-shadow:inset 0 3px 0 var(--blue)')
           .replace('border-top:2pt solid #005f91', 'box-shadow:inset 0 2pt 0 #005f91')
           .replace('border-top:1.5pt solid #005f91', 'box-shadow:inset 0 1.5pt 0 #005f91')
           .replace('font:10px/1.35 Consolas', 'font:11px/1.4 Consolas')
           .replace('font:700 11px/1 Consolas', 'font:700 11px/1.35 Consolas')
           .replace('font:700 12px/1 Consolas', 'font:700 12px/1.3 Consolas')
           .replace('.flow-stage strong{font-size:12px;line-height:1.25', '.flow-stage strong{font-size:12px;line-height:1.35')
           .replace('.flow-stage small{color:var(--muted);line-height:1.25', '.flow-stage small{color:var(--muted);line-height:1.35')
           .replace('.item-heading h3{font-size:18px;line-height:1.25', '.item-heading h3{font-size:18px;line-height:1.35')
           .replace('.matrix-wrap{overflow-x:auto;border:1px solid var(--line);background:var(--paper);border-radius:var(--radius)}', '.matrix-wrap{overflow-x:auto;border:1px solid var(--line);background:var(--paper);border-radius:var(--radius);padding:4px}')
           .replace('.matrix-wrap{overflow:visible;border:.5pt solid #ccd8de}', '.matrix-wrap{overflow:visible;border:.5pt solid #ccd8de;padding:0}'))
    js = _JS
    return f'''<!doctype html><html lang="zh-TW" data-lang="zh-TW"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Vera Cycle 驗證規範 | Vera Cycle Validation Specification</title><style>{css}</style></head><body data-lang="zh-TW" id="top">
      <header class="masthead"><div class="masthead-inner"><div class="brand-lockup">{logo}<div class="brand-rule"></div><div class="brand-meta"><span>{_pair(t("工程驗證文件", "Engineering Validation Document"))}</span><small>{_pair(t("正式文件", "Controlled document"))}</small></div></div><div class="title-lockup"><div class="utility"><span class="document-type">{_pair(t("Validation Specification", "Validation Specification"))}</span><span class="language-switch" role="group" aria-label="Language"><button type="button" data-lang-button="zh-TW" aria-pressed="true">繁體中文</button><span>|</span><button type="button" data-lang-button="en" aria-pressed="false">English</button></span><button type="button" class="print-control" data-print>Print / PDF</button></div><h1>{_pair(title)}</h1><p>{_pair(subtitle)}</p></div></div></header>
      <div class="page-shell"><aside>{toc}</aside><main id="main">{overview}{flow}{matrix}{pre}{cycle}{post}{kernel}{bmc}{project}{semantics}{trace}{integrity}<footer><div class="footer-brand">{logo}</div><p>{_pair(t("Vera Cycle 驗證規範 · Generic / Project Independent · Generated from Actual Cycle Framework Implementation", "Vera Cycle Validation Specification · Generic / Project Independent · Generated from Actual Cycle Framework Implementation"))}</p><p>{_pair(t("Validation Result", "Validation Result"))} <a href="CYCLE_REVIEW_REPORT.html">CYCLE_REVIEW_REPORT.html</a></p></footer></main></div><script>{js}</script></body></html>'''


_CSS = r'''
:root{color-scheme:light;--navy:#123b59;--blue:#005f91;--blue-2:#016c8c;--mint:#9acd66;--ink:#152b3d;--muted:#506476;--line:#d4e0e7;--paper:#fff;--canvas:#eef3f6;--soft:#f5f8fa;--soft-blue:#eaf3f7;--pass:#285f43;--pass-bg:#e5f2e9;--warn:#795300;--warn-bg:#fff4d4;--fail:#9b2c2c;--fail-bg:#fff0ee;--known:#39546e;--known-bg:#e7eef6;--new:#8c382f;--new-bg:#fff0ec;--radius:5px}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.6 "Segoe UI",Arial,sans-serif;font-variant-numeric:tabular-nums}body:before{content:"";display:block;height:5px;background:linear-gradient(90deg,var(--blue) 0 74%,var(--mint) 74% 100%)}a{color:var(--blue);text-underline-offset:3px;overflow-wrap:anywhere}a:hover{color:var(--navy)}button{font:inherit;color:inherit;cursor:pointer}.lang-en{display:none}body[data-lang=en] .lang-zh-TW{display:none}body[data-lang=en] .lang-en{display:inline}.lang-block{display:block}body[data-lang=en] .lang-block.lang-en{display:block}::selection{background:#bfe1ea;color:var(--navy)}:focus-visible{outline:3px solid #007aa5;outline-offset:3px}code,pre{font-family:Consolas,"Liberation Mono",monospace}code{font-size:.92em;overflow-wrap:anywhere}
.masthead{background:var(--paper);border-bottom:1px solid var(--line)}.masthead-inner{max-width:1480px;margin:auto;padding:23px 30px 22px;display:flex;justify-content:space-between;gap:38px;align-items:flex-start}.brand-lockup{display:flex;align-items:center;gap:18px;min-width:268px}.brand-mark{display:block;width:178px;line-height:0}.brand-mark svg{display:block;width:100%;height:auto}.brand-rule{height:40px;width:1px;background:var(--line)}.brand-meta{display:grid;gap:2px;color:var(--navy);font-weight:650;letter-spacing:.02em}.brand-meta small{font-weight:400;color:var(--muted);font-size:12px}.title-lockup{max-width:850px;flex:1;text-align:right}.utility{display:flex;justify-content:flex-end;align-items:center;gap:15px;color:var(--muted);font-size:12px;margin-bottom:12px}.document-type{font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--blue)}.language-switch{display:flex;align-items:center;gap:7px}.language-switch button{border:0;background:transparent;color:var(--muted);padding:3px 0;text-decoration:underline;text-underline-offset:3px}.language-switch button[aria-pressed=true]{color:var(--navy);font-weight:700;text-decoration-thickness:2px}.print-control{border:1px solid var(--line);background:var(--soft);padding:5px 10px;border-radius:4px;color:var(--navy)}.print-control:hover{background:var(--soft-blue)}h1,h2,h3,p{margin-top:0}h1{font-size:34px;line-height:1.18;letter-spacing:-.025em;margin-bottom:8px;color:var(--navy)}.title-lockup p{margin:0;color:var(--muted);font-size:15px}.page-shell{max-width:1480px;margin:auto;padding:28px 30px 50px;display:grid;grid-template-columns:220px minmax(0,1fr);gap:34px}.page-shell>aside{min-width:0}.toc{position:sticky;top:18px;border:1px solid var(--line);background:var(--paper);border-radius:var(--radius);padding:14px 0;box-shadow:0 2px 12px rgba(18,59,89,.06)}.toc-title{padding:0 15px 10px;font-weight:700;color:var(--navy);border-bottom:1px solid var(--line)}.toc a{display:grid;grid-template-columns:29px 1fr;gap:5px;padding:7px 15px;color:var(--muted);text-decoration:none;font-size:12px;line-height:1.35}.toc a span:first-child{font:700 11px/1.4 Consolas,"Liberation Mono",monospace;color:var(--blue)}.toc a:hover{background:var(--soft-blue);color:var(--navy)}.toc .top-link{border-top:1px solid var(--line);margin-top:8px;padding-top:11px}.doc-section{scroll-margin-top:18px;margin:0 0 34px}.section-heading{display:flex;gap:14px;align-items:baseline;border-bottom:2px solid var(--navy);padding-bottom:10px;margin-bottom:11px}.section-number{font:700 13px/1 Consolas,"Liberation Mono",monospace;color:var(--blue)}h2{font-size:25px;line-height:1.25;letter-spacing:-.02em;color:var(--navy);margin:0}.section-intro{max-width:78ch;color:var(--muted);margin:0 0 18px}.overview-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(370px,.95fr);gap:16px;margin-bottom:16px}.overview-lead,.overview-facts,.principles,.flow-note,.semantic-panel,.contract-panel,.final-links{border:1px solid var(--line);background:var(--paper);border-radius:var(--radius)}.overview-lead{padding:23px 25px;border-top:4px solid var(--blue)}.overview-lead h3{color:var(--navy);margin-bottom:10px;font-size:17px}.overview-lead p{max-width:64ch;margin:0;font-size:16px}.overview-facts{display:grid;grid-template-columns:1fr 1fr;gap:0;padding:7px 20px}.overview-facts>div{padding:12px 9px;border-bottom:1px solid var(--line)}.overview-facts>div:nth-last-child(-n+2){border-bottom:0}.overview-facts dt{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}.overview-facts dd{margin:3px 0 0;color:var(--navy);font-weight:650;font-size:13px}.principles{display:grid;grid-template-columns:repeat(3,1fr);padding:0}.principles>div{display:flex;gap:10px;padding:16px 18px;align-items:flex-start}.principles>div+div{border-left:1px solid var(--line)}.principle-mark{font:700 11px/1 Consolas,"Liberation Mono",monospace;color:var(--blue);padding-top:3px}.principles span:last-child{font-size:13px}.flow-list{display:flex;align-items:stretch;gap:8px;overflow-x:auto;padding:6px 0 12px}.flow-stage{min-width:150px;flex:1;border:1px solid var(--line);border-top:3px solid var(--blue);background:var(--paper);padding:12px 13px;text-decoration:none;color:var(--navy);display:flex;flex-direction:column;gap:3px;border-radius:var(--radius);transition:background .16s,border-color .16s}.flow-stage:hover{background:var(--soft-blue);border-color:var(--blue)}.flow-index{font:700 11px/1 Consolas,"Liberation Mono",monospace;color:var(--blue)}.flow-stage strong{font-size:12px;line-height:1.25}.flow-stage small{color:var(--muted);line-height:1.25}.flow-arrow{align-self:center;color:var(--blue);font-size:18px}.flow-note{padding:13px 16px;color:var(--muted);font-size:13px}.flow-note strong{color:var(--navy)}
.matrix-wrap{overflow-x:auto;border:1px solid var(--line);background:var(--paper);border-radius:var(--radius)}.matrix-head,.matrix-row{display:grid;grid-template-columns:1.25fr 1.55fr 1.75fr 1.9fr 1.85fr 1.55fr 2.2fr 1.75fr;min-width:1370px}.matrix-head{background:var(--navy);color:#fff;font-size:11px;font-weight:700;letter-spacing:.025em}.matrix-head>div{padding:11px 10px;border-right:1px solid rgba(255,255,255,.16)}.matrix-entry{border-top:1px solid var(--line)}.matrix-entry:first-of-type{border-top:0}.matrix-row{cursor:pointer;list-style:none}.matrix-row::-webkit-details-marker{display:none}.matrix-row:before{content:"+";position:absolute;visibility:hidden}.matrix-cell{padding:12px 10px;display:block;border-right:1px solid var(--line);overflow-wrap:anywhere}.matrix-cell.phase{font-weight:650;color:var(--blue);font-size:12px}.matrix-cell.item{color:var(--navy)}.matrix-cell.item small{display:block;color:var(--muted);font:10px/1.35 Consolas,"Liberation Mono",monospace;margin-top:3px}.matrix-cell.source,.matrix-cell.evidence{font:11px/1.45 Consolas,"Liberation Mono",monospace;color:#324b5e}.matrix-cell.criteria{font-size:12px}.warn-cell{color:var(--warn)}.fail-cell{color:var(--fail)}.matrix-entry[open] .matrix-row{background:var(--soft-blue)}.matrix-detail{padding:7px 14px 10px 18px;border-top:1px dashed var(--line);background:#fbfdfe;text-align:right}.detail-link{font-size:12px;font-weight:650}.validation-item{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);margin:0 0 15px;padding:19px 21px;break-inside:avoid;scroll-margin-top:18px}.item-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:12px}.item-heading>div{display:flex;gap:10px;align-items:baseline}.item-number{font:700 12px/1 Consolas,"Liberation Mono",monospace;color:var(--blue)}.item-heading h3{font-size:18px;line-height:1.25;color:var(--navy);margin:0}.item-kind{font-size:11px;color:var(--muted);border:1px solid var(--line);padding:4px 8px;border-radius:3px;white-space:nowrap}.sop-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 24px;margin:0}.sop-field{padding:10px 0 11px;border-bottom:1px solid #e6edf1}.sop-field:nth-last-child(-n+2){border-bottom:0}.sop-field dt{color:var(--blue);font-size:11px;font-weight:700;letter-spacing:.045em;text-transform:uppercase}.sop-field dd{margin:4px 0 0;color:#233e50}.sop-field dd code{display:block;white-space:pre-wrap;color:var(--navy);background:var(--soft);padding:7px 9px;border:1px solid var(--line);border-radius:3px}.semantic-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.semantic-panel{padding:19px 20px}.semantic-panel h3,.contract-panel h3{font-size:14px;letter-spacing:.08em;color:var(--navy);margin-bottom:12px}.semantic-panel table,.contract-panel table{width:100%;border-collapse:collapse;text-align:left}.semantic-panel th,.contract-panel th{font-size:11px;text-transform:uppercase;color:var(--muted);background:var(--soft);letter-spacing:.04em}.semantic-panel th,.semantic-panel td,.contract-panel th,.contract-panel td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}.semantic-panel tr:last-child td,.contract-panel tr:last-child td{border-bottom:0}.callout{background:var(--warn-bg);color:var(--warn);padding:12px 14px;margin:15px 0 0;font-size:13px}.callout strong{color:#5f4100}.separation-panel{margin-top:16px}.badge{display:inline-block;border-radius:4px;padding:2px 7px;font-size:11px;line-height:1.6;font-weight:750;letter-spacing:.035em;white-space:nowrap}.badge.pass,.badge.complete{background:var(--pass-bg);color:var(--pass)}.badge.warn{background:var(--warn-bg);color:var(--warn)}.badge.fail,.badge.incomplete{background:var(--fail-bg);color:var(--fail)}.badge.known{background:var(--known-bg);color:var(--known)}.badge.new{background:var(--new-bg);color:var(--new)}.badge.worsened{background:#f2e9d9;color:#7b4d18}.contract-panel{padding:19px 20px;margin-top:16px}.trace-flow{display:flex;align-items:stretch;gap:9px;overflow-x:auto;padding:6px 0 17px}.trace-flow>div{min-width:145px;flex:1;background:var(--paper);border:1px solid var(--line);padding:13px 12px;display:flex;flex-direction:column;gap:3px;border-radius:var(--radius)}.trace-flow>div>span{font:700 11px/1 Consolas,"Liberation Mono",monospace;color:var(--blue)}.trace-flow strong{font-size:12px;color:var(--navy)}.trace-flow small{font-size:11px;color:var(--muted);line-height:1.35}.trace-flow i{align-self:center;color:var(--blue);font-style:normal;font-size:18px}.evidence-map{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.evidence-map>div{border-top:3px solid var(--blue);background:var(--paper);padding:14px 14px;border-left:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.evidence-map h3{font-size:13px;color:var(--navy);margin-bottom:7px}.evidence-map p{color:var(--muted);font-size:12px;margin:0}.final-links{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:15px 17px;margin-top:17px;color:var(--muted);font-size:13px}.primary-link{font-weight:700;color:var(--blue)}footer{border-top:1px solid var(--line);padding-top:20px;color:var(--muted);font-size:12px}footer .brand-mark{width:120px;margin-bottom:10px}footer p{margin:5px 0}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
@media(max-width:1100px){.masthead-inner{display:block}.title-lockup{text-align:left;max-width:none;margin-top:23px}.utility{justify-content:flex-start}.page-shell{grid-template-columns:190px minmax(0,1fr);gap:22px}.overview-grid{grid-template-columns:1fr}.principles{grid-template-columns:1fr}.principles>div+div{border-left:0;border-top:1px solid var(--line)}.evidence-map{grid-template-columns:repeat(2,1fr)}}
@media(max-width:720px){body{font-size:13px}.masthead-inner{padding:18px 16px}.brand-lockup{min-width:0;gap:12px}.brand-mark{width:152px}.brand-rule{height:30px}.brand-meta{font-size:12px}.brand-meta small{font-size:10px}.page-shell{display:block;padding:17px 16px 35px}.page-shell>aside{margin-bottom:18px}.toc{position:static}.toc a{display:inline-flex;gap:6px;margin:2px 0;padding:6px 10px}.toc-title{padding-bottom:10px}.toc .top-link{display:flex;margin-top:6px}.title-lockup h1{font-size:27px}.title-lockup p{font-size:13px}.utility{flex-wrap:wrap;gap:10px}.section-heading{gap:9px}.section-number{font-size:11px}h2{font-size:22px}.overview-facts{grid-template-columns:1fr}.overview-facts>div:nth-last-child(-n+2){border-bottom:1px solid var(--line)}.overview-facts>div:last-child{border-bottom:0}.overview-lead{padding:18px}.overview-lead p{font-size:15px}.sop-fields{grid-template-columns:1fr}.sop-field:nth-last-child(-n+2){border-bottom:1px solid #e6edf1}.sop-field:last-child{border-bottom:0}.item-heading{display:block}.item-kind{display:inline-block;margin-top:9px}.validation-item{padding:16px}.evidence-map,.semantic-grid{grid-template-columns:1fr}.trace-flow{display:grid;grid-template-columns:1fr}.trace-flow>i{transform:rotate(90deg);justify-self:center}.final-links{display:block}.final-links span{margin-top:5px}}
@media print{@page{size:A4 portrait;margin:14mm 13mm}body{background:#fff;color:#111;font-size:9.2pt;line-height:1.4}body:before,.utility,.toc,aside,.print-control,.language-switch{display:none!important}.masthead{border-bottom:1.5pt solid #123b59}.masthead-inner{padding:0 0 8mm;display:flex}.brand-mark{width:38mm}.brand-rule{height:15mm}.brand-meta{font-size:8.5pt}.brand-meta small{font-size:7.5pt}.title-lockup{text-align:right;margin:0}.title-lockup h1{font-size:19pt}.title-lockup p{font-size:9pt}.page-shell{display:block;padding:7mm 0 0}.doc-section{margin-bottom:8mm;break-before:auto}.doc-section~.doc-section{break-before:page}.section-heading{border-bottom:1pt solid #123b59;padding-bottom:3mm;margin-bottom:3mm}.section-number{font-size:8pt}h2{font-size:15pt}h3{font-size:10.5pt}.section-intro{margin-bottom:4mm}.overview-grid{grid-template-columns:1fr 1fr;gap:4mm}.overview-lead,.overview-facts,.principles,.flow-note,.semantic-panel,.contract-panel,.final-links,.validation-item{border:0;border-radius:0;box-shadow:none}.overview-lead{border-top:2pt solid #005f91;padding:4mm}.overview-facts{padding:0}.overview-facts>div{padding:2.5mm;border-bottom:.5pt solid #ccd8de}.principles{grid-template-columns:repeat(3,1fr);border-top:.5pt solid #ccd8de;border-bottom:.5pt solid #ccd8de}.principles>div{padding:3mm}.principles>div+div{border-left:.5pt solid #ccd8de}.flow-list{display:grid;grid-template-columns:repeat(5,1fr);gap:2mm}.flow-stage{min-width:0;padding:2.5mm;border-top:1.5pt solid #005f91}.flow-arrow{display:none}.flow-note{padding:3mm;background:#f5f8fa}.matrix-wrap{overflow:visible;border:.5pt solid #ccd8de}.matrix-head,.matrix-row{min-width:0;grid-template-columns:1fr 1.2fr 1.35fr 1.5fr 1.4fr 1.1fr 1.65fr 1.35fr}.matrix-head>div,.matrix-cell{padding:2mm 1.5mm;font-size:7.2pt}.matrix-cell.source,.matrix-cell.evidence{font-size:6.8pt}.matrix-detail{display:none}.matrix-entry{break-inside:avoid}.validation-item{padding:4mm 0;margin-bottom:4mm;border-bottom:.5pt solid #ccd8de}.item-heading{padding-bottom:2mm;margin-bottom:2mm}.sop-fields{gap:0 5mm}.sop-field{padding:2mm 0;border-bottom:.5pt solid #e6edf1}.sop-field dt{font-size:7.2pt}.sop-field dd{font-size:8pt}.semantic-grid{grid-template-columns:1fr 1fr;gap:4mm}.semantic-panel{padding:0}.separation-panel{margin-top:4mm}.semantic-panel th,.semantic-panel td,.contract-panel th,.contract-panel td{padding:1.7mm}.trace-flow{gap:2mm}.trace-flow>div{min-width:0;padding:2mm}.trace-flow>i{font-size:10pt}.evidence-map{grid-template-columns:repeat(5,1fr);gap:2mm}.evidence-map>div{padding:2mm}.evidence-map p{font-size:7.5pt}footer{padding-top:4mm}.final-links{padding:3mm 0}.lang-en{display:none!important}body[data-lang=en] .lang-zh-TW{display:none!important}body[data-lang=en] .lang-en{display:inline!important}body[data-lang=en] .lang-block.lang-en{display:block!important}}
'''


_JS = r'''
(()=>{'use strict';
const body=document.body;
const titleByLang={'zh-TW':'Vera Cycle 驗證規範 | Vera Cycle Validation Specification','en':'Vera Cycle Validation Specification | Vera Cycle 驗證規範'};
function setLanguage(lang){body.dataset.lang=lang;document.documentElement.lang=lang;document.title=titleByLang[lang];document.querySelectorAll('[data-lang-button]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.langButton===lang)));}
document.querySelectorAll('[data-lang-button]').forEach(button=>button.addEventListener('click',()=>setLanguage(button.dataset.langButton)));
document.querySelector('[data-print]')?.addEventListener('click',()=>window.print());
let printState=[];window.addEventListener('beforeprint',()=>{printState=[...document.querySelectorAll('details')].map(item=>[item,item.open]);document.querySelectorAll('details').forEach(item=>item.open=true);});window.addEventListener('afterprint',()=>{printState.forEach(([item,open])=>item.open=open);});
document.querySelectorAll('.matrix-entry').forEach(row=>row.addEventListener('toggle',()=>{if(row.open){document.querySelectorAll('.matrix-entry[open]').forEach(other=>{if(other!==row)other.open=false;});}}));
setLanguage('zh-TW');
})();
'''


def write_specification(root: str | Path) -> Path:
    """Write the self-contained specification into a campaign or repository root."""
    root = Path(root)
    path = root / "CYCLE_VALIDATION_SPECIFICATION.html"
    atomic_write(path, render_specification())
    return path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=BASE)
    args = parser.parse_args()
    print(write_specification(args.output))
