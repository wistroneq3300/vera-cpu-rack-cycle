# Vera CPU Rack Cycle：259a80f 完整 code review 與 SIT coverage 複核

審查日期：2026-09-30（Asia/Taipei）
最後核對 main：2026-09-30 21:19:54 +08:00
Repository：https://github.com/wistroneq3300/vera-cpu-rack-cycle
固定版本：259a80fa7579ef459ab0922ae4b877f56391870b
Commit：Fix dmesg/sensor false positives
Commit 時間：2026-09-30 20:36:40 +08:00
前版：585fd4756284d25019c2902531ae9b35a782b8e0

## 一、結論

目前已有實用的 cycle 控制、PRE/POST 裝置比較、部分健康判斷和證據保存架構。以 Server SIT 工具來看，下一步最需要提升的是「判定與證據是否可信」，以及「開機後功能是否正常」。目前結果仍不足以單獨證明完整 CPU server、四節點 server 或 rack 已通過 SIT。

本次發現數個可重現的問題：新版 GHES/APEI parser 漏掉 Linux 原生 recoverable、相鄰事件被合併、不同 dmesg 錯誤被當成同一 KNOWN、採集空窗會遺失本來抓得到的錯誤、PRE script 驗證失敗仍嘗試執行、POST 重傳與既有檔案衝突且缺少新 SHA 驗證。Sensor 亂碼名修復只涵蓋一部分輸入。

不能用「93 個 tests」或「跑完很多輪」換算 coverage 百分比。還需要正式 test plan、BOM、每個 testcase 的 acceptance criteria，才能判斷分母和通過率。以下 P1/P2 是本 review 的修復優先順序，並非 CVSS 或產品嚴重度認證。

## 二、這次實際做了什麼

1. 以 GitHub API 核對 default branch=main 與完整 commit，取得該 tree 全部 42 個檔案；每檔 Git blob SHA 都匹配。這是固定版本副本，不冒稱對使用者 checkout 做過 git status。
2. 讀取上一輪 VERA_CYCLE_REVIEW_HANDOFF.md，保留 F01–F05 的對照編號；審查主要 Python 模組、兩支 shell、CLI/report/runtime、tests 與 legacy dryrun。
3. 執行既有 Python tests：原 discovery 為 93 項，92 通過，1 項 cross-UID 因容器 namespace 限制失敗。明確標記該環境限制後重跑：92 PASS / 1 SKIP。
4. 分別對 neutrino_config.sh、naboo_config.sh、stop_cycle.sh 執行 bash -n，三者通過。
5. 正式函式離線觀察：dmesg/sensor 34 個情境（含下項 3 份 fixture 重播）；engine/transport 14 個情境；runtime/report 4 個情境。兩支未修改 config 各 10 組 PATH stub 輸入，共 20 次執行。另有 discrete/PCI 純函式觀察。
6. 重播 repo 內三份既有 sensor fixtures，各 240 列，各為 WARN、4 個 SENSOR_DUPLICATE。
7. 對 Linux CPER/AER、pciutils link annotation、NVIDIA GPU/Fabric/counter/diagnostic 的相關語意核對官方來源。

以上觀察和 assertions 用來證明目前行為，包含缺陷；不能把「重現腳本 exit 0」寫成「產品通過」。本次沒有執行真機 SSH/SFTP/IPMI/Redfish、電源切換、安裝、清 logs 或實際 GPU/Storage workloads。原 repository source 沒有修改。未執行 legacy dryrun_sim.py，也沒有把上午舊 commit 的 campaign logs 當作此版驗收。

## 三、上一輪與這次修正狀態

| 項目 | 259a80f 狀態 | 本次證據 |
| --- | --- | --- |
| 單一全 info APEI 每行報 FAIL | 指定案例已修 | 全 info block 回 0 findings。 |
| 單一多行 fatal/corrected APEI 過度拆分 | 指定案例已修 | 各回 1 finding；多事件邊界另有問題。 |
| 一般亂碼名 + na 被白名單放行 | 指定案例已修，整體部分修復 | 一般亂碼/na 會 FAIL；數值/ok、CorUti+亂碼仍 PASS。 |
| F01 不同 dmesg 共用 KNOWN key | 仍存在 | 真 parser → classify → aggregate → console 已重現。 |
| F02 dmesg 格式/嚴重度涵蓋 | 仍存在，新 grouping 另有缺陷 | recoverable 漏抓，相鄰 events 合併，原生 AER/NVMe 等漏抓。 |
| F03 採集時間窗與原始證據 | 仍存在 | 兩輪 stateful ring buffer 與 read→clear 案例重現遺失。 |
| F04 PRE script 驗證 gate | 仍存在 | 五種失敗均到達一次 bash 呼叫（sudo=True）。 |
| F05 POST script 重傳/校驗 | 仍存在 | 真 Transport.upload + 記憶體 SFTP 重現 wx collision；POST 沒再驗 SHA。 |
| 舊 outband soft/off/on 執行批評 | 不適用於此版 | 此版正式發 power reset；README 尚未更新。 |
| PRE timing 被確認等待拉長 | 已修 | preserve_timing=True；實測 finished/duration 保留。 |
| PRE 內容 immutable | 尚未達成 | start() 仍改寫已確認 PRE，與 timing 是兩件事。 |
| n2 BMC hostname 必須改成 n2 | 撤回，不應再用此理由修改 | 需以實體 pairing/FRU/SN 證據確認，不能由標籤推斷。 |
| BF4_EXPECTED=0 一定是 bug | 未定義語意，不列 confirmed bug | 0 可能是期望零張，也可能想代表 disabled，需規格。 |

## 四、應優先修正的問題

### F04 / P1：PRE 上傳或 SHA 驗證失敗，仍走到 privileged script execution

位置：cycle_engine.py 247–255、185–189；cycle_transport.py 128–142。
舊問題狀態：仍存在。證據：engine/engine_probe_results.json 的 pre_sha_mismatch、pre_sha_command_failed、pre_sha_empty、pre_upload_failed、pre_partial_upload_failed。

precheck() catch 失敗後加 SCRIPT_UPLOAD_FAILED 和 blocked，卻繼續 self.capture(record)。capture() 無條件發 bash remote，sudo=True。

五種離線失敗：實際 stored bytes 與預期不同、SHA command 非零、SHA output 空、upload 失敗無檔、部分寫入後失敗。每種都記錄一次遠端 bash 嘗試。沒有檔案的情境不代表成功執行了檔案；有 mismatch/partial bytes 的情境顯示 gate 沒擋住這個呼叫。

PRE 仍會 FAIL/blocked，並非靜默 PASS。問題是擋在後續 campaign 太晚，PRE 裡已走到執行路徑。

修正：將「成功驗證待執行檔案」作為 hardware invocation 的必要條件。失敗時可保留其他獨立採集，hardware 明確標 SKIPPED/BLOCKED。必要 regression 是所有失敗情境的 script execution calls=0。

### F05 / P1：POST 既有檔案衝突，且新上傳沒有重新驗 SHA

位置：cycle_engine.py 51、185–188、414–418；cycle_transport.py 136–139。
舊問題狀態：仍存在。

PRE/POST 使用同一路徑，但正式 SFTP 使用合法的 wx exclusive create。POST 每次直接再 upload，沒有 ensure/reuse 流程。當 OS reboot 後 /tmp 保留，或 command 被拒絕因此沒有 reboot、PRE 檔仍在，第二次建立會失敗。已用正式 Transport.upload + 記憶體 SFTP 重現：NODE_UNAVAILABLE、active=False、post_complete=False。這是檔案衝突，不是 OS/BMC 真失聯。

wx 本身不是非法 mode；不要盲改 w 或無條件覆寫。安全修法：
- 不存在：exclusive upload、permissions、SHA verify，再 execute。
- 存在且是允許型態、內容 SHA 相符：reuse。
- 存在但內容或型態不安全：fail closed。
- 競態失敗不能改成無條件 overwrite。

另一次 POST corruption fixture 中，上傳 2 次但整場 sha256sum 只有 PRE 的 1 次，第二次 bytes 已不同仍到達 bash。PRE SHA 不保證下一次 transfer 的內容。每次新上傳都需校驗，錯誤內容不得 execute。

證據：post_file_survives_successful_boot、post_file_survives_rejected_action、post_uploaded_bytes_not_reverified。/tmp 是否保留依 OS 實際行為，不能宣稱每次 reboot 都一定失敗。

### F02 / P1：dmesg parser 仍會漏事件，而且這次 grouping 有新問題

位置：cycle_core.py 348–397。拆成三個可交付子項，避免只加一條 regex 就宣稱完成。

F02-A — 原生 severity 漏判。
目前只接受 fatal/corrected/uncorrected；Linux CPER 正式 enum 輸出包括 recoverable/fatal/corrected/info，未知為 unknown。event/type=recoverable 的 APEI block 回 []；event=info、section=recoverable 同樣沒有 finding。這不是說 recoverable 一律要判硬體 FAIL，而是 parser 沒建立可供報表判定的事件，無從套用客規；一般 dmesg 採集原文仍可能保留此訊息。

F02-B — 事件邊界錯誤。
用「連續 [Hardware Error] 行」一直吃下去，不在新的 event header 停。合成例：
- 8194/info + 8195/fatal：只剩 APEI 8194: fatal，source 錯。
- 8194/corrected + 8195/fatal：只剩 APEI 8194: corrected，第 2 event/原生嚴重度被吞。
- Header 與 severity 間有普通 printk：fatal block 可變成 []。
上述 corrected→fatal 仍保留一筆 FAIL，不能誤述成全部 PASS。

F02-C — 常見其他格式。
無 AER: 前綴的 PCIe Bus Error: severity=Uncorrectable (Fatal)、EDAC UE、ARM SError、I/O error, dev nvme...、mlx5 fatal 都能在單筆輸入下回 []。GPU Xid 是可選 GPU profile；x86 MCE 是通用 server profile，不能拿來強制 CPU Vera 做 x86 測項。真實完整 log 可能還有其他能命中的行，本次沒有斷言整份真機 log 必定全部漏掉。

修正：先解析事件 family、裝置/locator、event/section native severity、事件邊界及原文位置，再套 disposition policy。未知/截斷事件要可見。不要改成廣泛 error|fail|fatal，避免再次誤報。

必要 regression：severity enum 全套、event vs section 不同、info→fatal/CE→fatal 相鄰、同 source 不同 event、交錯/截斷、原生 AER 格式、NVMe 字序及正常初始化反例。

### F01 / P1：PRE 有任何 dmesg finding，POST 新 panic 可被標 KNOWN

位置：cycle_core.py 142–150、377–378、395–396、413–431；neutrin_cycle.py 117–124。

正式 dmesg parser 把偵測到的事件全部建成 DMESG_HARDWARE/dmesg。classification 與 aggregation 只比較 code/component，所以 PRE AER 和 POST Kernel panic 是同一個 key。

真 parser→分類→正式 console 離線輸出只有：
tray1_n1 | LOOP 1 | FAIL
  Known issues unchanged: 1 finding(s); see PRE and HTML for details

新 panic 詳情不顯示；聚合主項仍是 PRE AER、classification KNOWN。occurrences 與原始 evidence 尚可保留 panic，severity 仍 FAIL。本 finding 是分類/聚合/展示問題，不是 FAIL 被清成 PASS。PRE 1 次、POST 3 次也仍印 unchanged。

修正：fingerprint 至少保留事件類型、裝置 identity、subtype；不可刪掉有意義的 BDF/Xid/DIMM/port 數字。同 key 但嚴重度/次數增加需 WORSENED。KNOWN 只表示 PRE 曾觀察，不能推論與 cycle 無關；NEW 也不是 cycle 因果證明。

### F03 / P1：採集空窗與 read→clear 去重會丟掉原始證據

位置：cycle_engine.py 166–188、190–230、359–386、178–184、296–300。

三種已重現：
1. POST dmesg/clear 之後才跑 hardware/sensor/SEL；下一輪 action 前只取 identity/SEL，沒有再取 dmesg。在 hardware 階段注入目前 parser 能識別的 AER，下一次 reboot 清空 ring 後，兩輪 record/evidence 都找不到它。
2. 初次 dmesg 與 dmesg -c 之間出現事件時，只存 parser finding，沒有保存 clear 的完整原文/context；finding 還可能連到不含該事件的第一份 dmesg 檔。
3. read→clear 新增同 Source/severity、不同 BDF 的 APEI。單獨 parser 能回 2 筆，但 engine 依 code/detail 去重後只有 1 筆；第 2 筆原文也不見。

修正順序：完整保存每次採集 raw，finding 正確指向包含事件的 raw；補 BEFORE_ACTION、AFTER_BOOT_READY、AFTER_CHECKS/END 採集；使用 boot-aware cursor/position/event identity 去重。若採 journal 必須確認 persistence，不能假設上一輪 log 永久存在。最後一輪也需尾端採集。

### F06 / P2：要求「亂碼名一律 FAIL」，目前只有 na 案例修好

位置：cycle_core.py 175–186、211–231；需求：docs/TODO_updates.md 30–34。

以下正式 sensor evaluator 全回 []：
CPU0_�Temp | 30 | degrees C | ok
NVMe_�STS | 0x1 | discrete | 0x0100
PrMo0CP1CorUti� | na | percent | na

程式只是移除一個舊白名單，並未真正檢查 sensor name 的 U+FFFD。應在 health shortcut/CorUti 白名單前驗證名稱完整性，獨立回報 malformed/identity unreadable，保留 raw。合法 CorUti 例外仍需保留，使用正式 profile 精確比對。

### F07 / P1：必要 PCIe link 沒讀到，也可能當成 PASS

位置：neutrino_config.sh 與 naboo_config.sh 104–121，兩檔行號相同。

只在找到 Endpoint 且真的看到 LnkSta 時才判定。因此 Capabilities: <access denied>，或 Endpoint 只有 LnkCap 而缺 LnkSta，兩支正式腳本皆 RESULT|PASS。雖然整個 campaign 可能另有 collector 報錯，這個 link check 已無法區分「驗完正常」與「根本沒驗到」。

修正：依 profile 建 required endpoint/link 集合，逐個輸出 evaluated/unsupported/unreadable/missing；required 項不可用未評估狀態冒充正常。必要上游/root/switch link 要依 topology 另外納入；不能把未使用 port 一律判 fail。

PCIe wiring 的另一層政策：lspci 的 downgraded annotation 是由 sta/cap 比較產生，不是已查核 slot 實際配線。核准 x2 wiring 配 x4-capable SSD 可能合理，也可能是真降寬；需比較「設計期望、PRE、POST」三者，不能 blanket whitelist 所有 NVMe x2，也不能 PRE 有就算正常。

### F12 / P1（legacy 工具）：dryrun_sim.py 不是純離線唯讀

位置：dev/dryrun_sim.py 2–6、37–45、114、184、224；README.md 149。

檔頭稱 read-only/no config change，實際讀現場 inventory、透過真實 SSH 發 mst start 及 ipmitool sel clear；沒有主 runner 的鎖與確認流程。此檔本次完全沒有執行。

應移除預設 mutation，或明確隔離/重新命名 live legacy 工具，避免工程師把 dryrun 當成不會影響現場證據的 simulator。這與目前主 runner 的 transport 安全設計分開，不能把 legacy 的弱點誤套到新版 runner。

## 五、其他已確認項目與語意改善

| ID / 優先 | 證據與觸發 | 影響與修正 |
| --- | --- | --- |
| F08 / P2 零輪 COMPLETE/PASS | neutrin_cycle.py 258–271。合法正數 hours limit 在 start clearing 用盡；1秒limit/2秒虛擬準備時間，0 action、0 completed、exit0、COMPLETE/PASS。 | 計時在準備後開始，另明確表示 no cycles exercised；不能只靠 PRE health當cycle完成。不是把一般 COMPLETE/health分開的設計一概判錯。 |
| F09 / P2 SEL delta空不等於SEL空 | engine213–221取delta；report53–61把[]寫成 BMC SEL EMPTY / BMC returned no SEL records。前後都含同筆PSU事件即可重現。 | raw cumulative SEL仍保存，這是HTML誤導；改成0 new events，cumulative count另存。 |
| F10 / P2 PRE內容被改寫 | engine287–302在確認後start()把新dmesg finding加進原PRE與pre_issue_keys，再覆寫pre_report.json。 | reviewed PRE保持不變；新增START/BEFORE_ACTION record。時間保留已修，別再次報timing bug。該新事件在第一次power前發生，不能判為cycle造成。 |
| F11 / P2 額外二次boot未被識別 | wait_boot記boot1，下一次os_after_cycle回boot2；engine304–327、395–413未比一致性，乾淨fixture單一LOOP仍PASS。 | pin recovered boot ID至POST完成、尾端再核對，額外transition與資料不穩定需可見；不是本次真機或整場PASS證據。 |
| F13 / P2 計數語意需拆開 | engine412–413無條件按POST完成加1。rejected action、no boot change，在POST可完成的條件下completed仍加1。 | 保留attempts、POST completed、boot confirmed、valid cycles；Health仍FAIL。真wx既有檔案可能先擋住POST，不能聲稱所有reject必然completed。 |
| F14 / P2 PCI文字描述造成drift | core263–282比較包含raw的dict。同BDF/numericID只改description，PCI_DRIFT仍FAIL。 | structured identity/state判定，raw留證據。實際名稱資料更新是否會發生需現場條件，不是已證明裝置更換。 |
| F15 / P2 MST數row未保證唯一 | 兩config61、65。相同BDF重複22次，NIC actual22/PASS；既有test fixture也如此。 | normalized full-BDF唯一性、duplicate檢查；MST/PCI function/card/physical port分開，不直接改硬體expectation。這是合成異常輸入。 |
| F16 / P2 BF4 identities只比數量 | 兩config69、77–92。簡略枚舉A/B、verbose身份C/D，數量/serial足夠仍PASS。 | 對BDF集合與每function→board serial，快照不一致標inventory unstable，不拿數量相等當完整配對。 |

## 六、Server SIT coverage 矩陣

現有數量參數：CPU_MIN=2、DIMM_EXPECTED=16、NVMe_MIN=2、NIC_MIN=22、BF4_EXPECTED=1、PCIEFAB_MIN=20、USB_MIN=1、BMC_MIN=1。這是當前腳本設定，不代表本次已以平台BOM核可每個數量。

| 項目 | 現在可證明的範圍 | 尚不能證明／建議 |
| --- | --- | --- |
| CPU | SMBIOS Populated至少2；lscpu raw保存 | 一顆Disabled By BIOS仍可count2。需enabled/OS online core/thread/NUMA、型號與受控運算正確性。 |
| SOCAMM/Memory | Size>0裝置恰好16 | 16×128GB→16×64GB的合成變更仍PASS。需每slot容量/型號/速率、總量/OS可見合理差、NUMA分布、RAS。 |
| PCIe | PRE/POST BDF/ID/raw比較；部分Endpoint降速降寬 | required link已評估集合、driver binding、必要upstream、平台wiring期望與實際傳輸。 |
| NVMe | namespace路徑去重成controller後至少2 | SN/model/FW、namespace size/identity、SMART/media/error counters、指定測試資料的read/checksum。 |
| MST/NIC/BF4 | table列數、部分VPD board serial/count | 22列不等於22外部port。需function→driver→netdev/RDMA→physical port映射、link/speed/counters、指定peer傳輸。 |
| Sensors | threshold status、malformed/unreadable、PRE缺列和reread | 正式required sensors、穩定ID、亂碼、離散解碼、thermal/power時序。所有合法hex直接略過不能證明健康。 |
| BMC/SEL | identity、mc info/power、SEL讀取及delta，事件人工review | 不等於BMC全功能通過。需區分讀取成功、事件解碼/判定、人工review完成，及PSU/fan/cooling需求。 |
| BIOS/FW/OS | BIOS/BMC/kernel/OS部分raw | Version:Unknown仍可PASS，因未做版本verdict。需核准FW/driver/config manifest。 |
| Power | dispatch狀態、OS boot ID變化、power-on | 不直接證明DC/AC物理效果、off dwell、電源域、只重開一次。 |
| Functional | 目前主要是列舉與狀態 | 尚未見CPU/Memory/NVMe/Network短資料正確性工作負載，不能把裝置存在當資料路徑正常。 |
| Four-node/rack | 多target並行、各node結果及排除狀態 | 尚需整台/整櫃inventory、shared-resource影響、同步/錯峰、跨node傳輸與power-domain驗證。 |

CPU disabled、Memory容量和FW Unknown案例是「現有只做count/collection的coverage缺口」，不冒稱原本的count契約都寫錯。

離散sensor也不能反過來規定所有非零hex都FAIL：同樣0x0100在不同sensor/event type語意不同。應依SDR/OEM定義解碼，未解碼顯示未評估。PRE比較與golden required list要分開：PRE原本少裝置，不代表設計允許缺少。

## 七、dmesg 的具體加強方式

建議事件資料至少保留：
family、code/subtype、device/locator、native_severity、disposition、first/last time、boot_id、phase、occurrence_count、raw起訖/證據檔、PRE comparison。

可用分層範圍：
- ARM/Vera CPU：GHES/APEI/CPER、SError、對應平台的memory/PCIe/RAS。
- PCIe：AER correctable/nonfatal/fatal、DPC/recovery與相關裝置。
- Storage：NVMe timeout/reset/controller、block I/O、必要filesystem狀態。
- NIC：driver/FW health、port/link與error counters。
- Kernel：panic/oops/BUG/lockup/hung-task；與硬體根因分類分開。
- 可選GPU：Xid、ECC、fabric管理與generation適用的事件路徑。

Corrected要保留數量/頻率及變化；有no-CE客規可以FAIL，沒有客規不應自行固定改WARN或忽略。INFO可以降噪，但未知vendor section不能僅因沒decoder就宣稱已驗證正常。單一Call Trace可支持kernel/driver異常的finding，不能單獨證明硬體損壞。

最低 regression 集合：原生severity全套；相鄰events；交錯/截斷；同類不同BDF；同device不同subtype；same fingerprint頻率/嚴重度增加；PRE AER→POST panic；POST之後下一action前事件；read→clear新事件與原文正確歸屬；正常初始化反例。

## 八、每輪、四節點與rack怎麼補

每輪可分：BEFORE_ACTION收尾證據 → action → boot transition/readiness → inventory/health → 受控短功能驗證 → AFTER_CHECKS證據。最後一輪也要收尾。各phase保留時間與boot identity，以免把跨boot或已清除資料當同一窗。

短功能驗證可優先做CPU受控運算與結果、Memory小範圍pattern、NVMe指定資料read/checksum、NIC/RDMA對核准peer傳輸與結果檢查。每N輪或收尾做較深壓力/性能；N、時間、允許負載與門檻由test plan決定，不在review任意塞固定值。每輪完整MLPerf通常不適合作為輕量cycle sanity的唯一方案。

對使用者一台4node、每node2 CPU的情境：
1. 建立node↔board/FRU/SN↔OS/BMC↔tray↔power domain映射，不要求所有hostname文字必相同。
2. 單node測試：其餘三node的連線、工作負載、boot ID與共享資源影響是否符合設計。
3. 四node同步與錯峰pattern：判定同輪完成、recovery時差、共享power/cooling/network趨勢。
4. Rack層：完整expected inventory、分批與同時pattern、boot分布、跨node資料路徑、異常隔離。
5. Endpoint lock能保護同controller程序共用endpoint，不能由此自動推出所有不同IP的node沒有共用電源域。擴充power-domain lock/barrier需平台圖與操作需求。

以上是後續test plan建議，本次未執行現場動作。

## 九、GPU Server 要作可選profile

本案是Vera CPU專案，不能因為缺GPU就FAIL。擴充GPU Server時再按SKU啟用：

| 層 | 建議 |
| --- | --- |
| Inventory/readiness | GPU數、UUID/BDF/model、driver/GSP/FW與所需服務，明確unsupported/NA/failure。 |
| Health | ECC、retirement/row-remapping、temperature/power/clock/throttling，依實際支援能力。 |
| Function | CUDA init、可驗結果的短compute、HBM與host/device搬移。 |
| Fabric | 實際NVLink/NVSwitch topology、ready狀態、port/ASIC counters；按世代與管理stack。 |
| Cross-node | P2P/NCCL correctness/performance與所選IB/RoCE路徑，記錄拓樸和門檻。 |

NVIDIA官方說明Xid可能來自硬體、驅動/NVIDIA軟體或應用，不能看到Xid就直接定性GPU壞。DGX/HGX B200/B300的NVSwitch不使用舊SXid方式，官方指向DCGM經NVSDM取得port/ASIC counters；Hopper與較早世代不可與Blackwell一概而論。

Counter需記reset scope。nvidia-smi官方說volatile ECC從driver load起算，aggregate是長期累積；跨reboot/driver reload不可直接相減再把負數歸零當正常。DCGM官方表中r1只有software，不能以r1通過宣稱GPU memory、PCIe/NVLink深診斷都完成。依現場版本選測項，並與既有核准NV工具整合。

## 十、測試品質：為什麼現有綠燈仍可能漏掉

- FakeTransport對未知命令回成功；會掩蓋命令拼錯與流程缺失。
- Fake upload直接覆寫dict；SHA又從同dict算，缺少正式exclusive/create/partial-write/mismatch契約。
- KNOWN測試自己指定不同component BDF，但真dmesg parser全部用dmesg；沒測真正全鏈。
- 六種mode/channel測試的OS/BMC共用一個boot counter、power固定On，不能證明實際AC/DC/Off dwell或獨立恢復。
- 三份現有真實sensor fixtures沒有被unittest自動讀入。
- 原README的 bash -n a.sh b.sh c.sh只解析第一份、其餘當參數；應各檔個別執行。
- README仍寫outband soft/off/on，並保留本commit已移除的亂碼na白名單文字。

Cross-UID未驗證說明：目前容器UID/GID map只映射0；test_runtime_process.py的setgid(65534)回EINVAL。原始run exit1、log有child例外導致重複輸出；這不是production lock壞的證據。附原log與明確skip重跑，不隱藏失敗。真Paramiko端到端沒有執行，現場ARM/MFT/BMC行為及全rack併發亦尚未驗證。

建議把tests重點放在 production parse→classify→report、transport contract及真實sanitized transcripts；不以新增大量happy-path tests膨脹數量。

## 十一、給Codex的實作順序與驗收

第一批（結果可信度）：
- F04/F05：統一ensure_verified_script，驗證失敗絕不execute；existing good檔可安全reuse；保留wx防覆寫。
- F02/F01：事件parser與fingerprint，保留native severity/未知事件；新事件和惡化不能被KNOWN藏掉。
- F03：採集邊界、raw durability、dedup與finding evidence連結。

第二批（現有功能完整性）：
- F06/F07：亂碼名稱/required link不可因shortcut PASS；修F08/F09/F10/F11/F13與文件語意。
- F12：隔離會變更現場的legacy dryrun。
- F14–F16：結構化identity與唯一性/對應。

第三批（正式SIT coverage）：
- Golden profile、CPU/Memory/NUMA、required sensors/離散解碼、FW。
- Short functional checks與四node/rack矩陣。
- 需要時加GPU profile與NV工具。

保留既有wizard、PRE後明確確認、selected channel、不自動fallback、不盲目重送模糊power命令、endpoint locks、owner-only graceful stop、硬體finding keep-going但FAIL不可隱藏。不要為修review大規模重寫整個架構，也不要依猜測修改inventory/BF4或PCIe正常值。每項最小patch需有專對該風險的regression和清楚diff。

本交付是review 與重現證據，沒有包含正式patch。後續依使用者的實作任務與既有授權處理；不能將本報告解讀成真機power/log-clear/FW操作或直接push的指令。

## 十二、附件與來源

配套zip包含：
- 本報告、CODEX_HANDOFF.txt、findings.json。
- source_manifest.json（42檔Git blob identity）、review_metadata.json。
- dmesg/、engine/、runtime/、coverage/、test_audit/ 的探針、觀察結果和執行證據。
- 不重複包入GitHub原始repository；用固定commit重新取得source。

原碼固定URL prefix：
https://github.com/wistroneq3300/vera-cpu-rack-cycle/blob/259a80fa7579ef459ab0922ae4b877f56391870b/
主要引用檔：cycle_core.py、cycle_engine.py、cycle_transport.py、cycle_runtime.py、cycle_report.py、neutrin_cycle.py、neutrino_config.sh、naboo_config.sh、dev/dryrun_sim.py、dev/tests/test_cycle.py、dev/tests/test_hardware_script.py、dev/tests/test_runtime_process.py、README.md、docs/TODO_updates.md。

官方語意：
[O1] Linux CPER：https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/cper.c
[O2] Linux AER：https://docs.kernel.org/PCI/pcieaer-howto.html
[O3] pciutils link_compare：https://github.com/pciutils/pciutils/blob/master/ls-caps.c
[O4] Paramiko SFTP：https://docs.paramiko.org/en/stable/api/sftp.html
[O5] NVIDIA Fabric Manager：https://docs.nvidia.com/datacenter/tesla/fabric-manager-user-guide/index.html
[O6] NVIDIA SMI：https://docs.nvidia.com/deploy/nvidia-smi/index.html
[O7] DCGM diagnostics：https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/dcgm-diagnostics.html

來源與判定對應：F02原生格式見O1/O2；F07 annotation見O3；F05 wx語意見O4；GPU Xid/Blackwell fabric見O5；ECC reset lifetime見O6；r1範圍見O7。其他結論直接來自固定原碼和附件的離線實際輸出。官方文件版本只作格式/能力參照，不冒稱已核對使用者真機kernel、driver、firmware全部版本。


# FINAL USER DECISIONS

See the conversation-approved implementation policy: script SHA gate; single campaign upload; dmesg -c at end of every POST; corrected/recoverable WARN, fatal/uncorrected FAIL; detailed dmesg event classes and per-loop deltas; garbled sensor names FAIL; CPU lscpu/online cross-check without fixed SKU; memory dmidecode vs MemTotal with configurable 90% threshold; missing PCIe LnkSta FAIL; downgrade FAIL; duplicate full BDF FAIL; BF4 identity from lspci only; no NVMe SMART; no golden FW manifest; SEL unchanged; development-stage hardware FAIL keep-going; collection failures FAIL but continue except untrustworthy validation/script/identity/boot; historical FAIL remains campaign FAIL; multi-node isolation; graceful stop retained; per-loop check summary; concise stage/exception-oriented console UX; mandatory regression tests.
