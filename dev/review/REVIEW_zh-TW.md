# vera-cpu-rack-cycle 完整原始碼審查

此文件保留重構前的審查結果；目前實作與驗證請見專案根目錄的 README.md 與 VERIFICATION.md。

審查日期：2026-09-29

版本：main / f18de4a85d66974242fc88af8e91f4bfc5394a57

範圍：8 個 tracked files 全部讀取；2 支 Python、2 支 Shell、README、2 份 inventory、.gitignore。

方法：逐段靜態審查、Python 編譯、Bash 語法檢查、25 個離線重現情境，包含 mock 完整 cycle_one 流程。

未連線實機、未發送電源指令、未修改原始程式、未推送 GitHub。僅新增 review/ 審查附件。

**結論：已有可用的資料蒐集骨架，但目前不能單靠 PASS/FAIL 或健康報告認定機器健康。既有誤判失敗，也有漏判硬體異常；dry-run 與電源控制還有行為和文件不一致的問題。**

以下「重現」指合成資料或 mock，不表示真實機櫃已發生相同故障。P1 為建議正式長跑前處理；P2 為可靠性與擴充改善。編號是議題數，與離線重現情境數不同。

## 優先修正：P1

### R01. dry-run 會刪除 SEL，與「唯讀」承諾相反【重現】

- 位置：dryrun_sim.py:179–185、114；README.md:14。
- run_node 一開始就送出 ipmitool sel clear，沒有先備份原 SEL，也沒有獨立開關。
- snapshot 還會執行 mst start；這也是改變系統狀態的動作。
- 影響：使用者為了「先看看」執行 dry-run，可能失去原始故障事件證據。
- 建議：dry-run 僅讀取，保留 baseline 做事件差集；清 SEL 與準備 MST 拆成明確的 setup 操作。

### R02. 正式循環也在備份與身份核對前清除證據【靜態確認】

- 位置：neutrino_cycle.py:715–731。
- 先執行 sel clear 與 dmesg -c 丟棄輸出，之後才 identity/check_mac 與 pre_dmesg_all。
- 影響：pre_dmesg_all 並非清除前資料；既有 SEL 無備份。若 inventory 指錯可登入的設備，身份檢查發現前就已清除其 log。
- 建議：身份及設備配對核對 → 原始證據存檔 → 確認收集成功 → 必要時清除；優先以時間戳/record ID 做差集，避免清除。

### R03. BF4 存在且其他盤點正常，config 仍然無法通過【重現】

- 位置：vera_rack.sh:119–145、480–484；neutrino_cycle.py:474–484。
- BF4_fun 無條件設 BF4_ERROR_TAG=1；Sum_fun 必須等於 0 才輸出成功文字，而 config_ok 又要求此文字。
- 影響：正常完整盤點也回傳 config=False；預設 keep_going=False 時第一輪結束便停止該節點。
- 建議：依實際結果設定 flag，盤點輸出結構化結果與正確 exit code；是否需要 BF4 應由 inventory/profile 決定。
- 額外確認：config_ok 的 exit_code 參數完全沒使用，exit 2 配成功字串也會通過。

### R04. 健康報告會隱藏真正 config 失敗，甚至把開機逾時寫成 PASS【重現】

- 位置：neutrino_cycle.py:1099–1109、1128–1144、1209–1212、1263、1425–1431。
- _row_real_issues 直接排除所有 step=config；detail 含 BF4 的 issue 也被廣泛排除，沒有驗證真的是「此節點不需 BF4」。
- FAIL_KINDS 未包含 TIMEOUT/NO_VALUE，overall_fail 也不看 result.error 或必需步驟是否完成。
- 已重現：NVMe config loss、boot TimeoutError、worker FileExistsError，都能產生健康報告 PASS。
- 影響：最容易被拿來交付的 HARDWARE_HEALTH_REPORT.md 可能提供相反結論。
- 建議：同一份結構化評估結果生成所有報表；區分 PASS/WARN/FAIL/INCOMPLETE/BLOCKED。僅豁免明確設備代碼及指定節點，不以字串或整個 config 類別排除。

### R05. WARN 在執行器被視為失敗，摘要卻可能顯示 OK【重現】

- 位置：neutrino_cycle.py:879–885、1055–1073、1104–1133、1439–1445。
- evaluate_result 把未豁免的所有 issue 都當 fatal，包含 sensor_diff WARN。
- 單節點摘要又把 WARN 排除，沒有 real issue 就寫 OK。
- 影響：一次已恢復的感測器瞬斷足以停止節點；runtime FAILED、node summary OK、health report PASS 可同時出現。
- 建議：以 severity 判斷是否失敗；WARN 可繼續且必須在所有摘要保留。

### R06. 感測器 critical/non-recoverable 判斷不相容於標準 ipmitool 輸出【重現＋上游核對】

- 位置：neutrino_cycle.py:419–420、950–975。
- 程式只接受 critical / non-recoverable 長字串；標準 sensor list 通常使用 cr / nr。
- 已重現：ok → cr、ok → nr 都得到 sensor_diff=True。
- ok → na/ns（讀值不可用）也會通過；原本就異常、或不是從 ok 開始的惡化也不在檢查範圍。
- 建議：建立狀態正規化表，區分健康、警告、嚴重、未知；分開評估「當下健康」與「相較 baseline 的變化」。
- 上游依據：[ipmi_sensor.c](https://github.com/ipmitool/ipmitool/blob/master/lib/ipmi_sensor.c)、[ipmi_sdr_get_thresh_status](https://github.com/ipmitool/ipmitool/blob/master/lib/ipmi_sdr.c#L826)。現場若有客製 ipmitool，仍需保留實際輸出 fixture 驗證。

### R07. 同名感測器後一筆正常值會覆蓋前一筆異常【重現】

- 位置：neutrino_cycle.py:372–390、398–416。
- 使用 name set 及 name→status dict；重複名稱採 last occurrence wins。
- 已重現：同名 Temp 第一筆 critical、第二筆 ok，最後只留下 ok。
- 影響：多個不同实体或重複 SDR 記錄若共用顯示名稱，部分故障或部分消失可被隱藏。
- 建議：先用現場 SDR 驗證重複名稱的意義；以 sensor number/entity/owner 等穩定身份辨識。無法辨識時至少保留所有狀態、採最嚴重值，不直接覆蓋。

### R08. sensor 命令失敗被 || true 改為成功，讀不到與掉 sensor 混在一起【重現＋靜態確認】

- 位置：neutrino_cycle.py:423–444、797–802、832–888。
- capture_sensor_list 的 shell 指令有 2>&1 || true，命令失敗常回 code=0；呼叫端依賴 code 判定是否讀取成功。
- 只特別辨識 Get SDR ... command failed，其他裝置不存在/權限/通訊失敗可能被當空表。
- 影響：既可能將採集故障誤報 SENSOR_LOST，也可能在 baseline 空/不足時跳過檢查；「ipmi0 不在就 skip」註解與實作不一致。
- 建議：保留真 exit code，將 stdout/stderr 分開，驗證可解析表格完整性；區分 collection error、sensor loss、status fault。

### R09. DIMM 計算的是 SMBIOS 插槽數，空插槽也算已安裝【重現】

- 位置：vera_rack.sh:176–184、214–217、465。
- 每個 Memory Device 都加一，DIMM_Qty=$No；Size: No Module Installed 並非空字串。
- 已重現：16 個全部空插槽仍得到 DIMM_Qty=16，Lost_fun 不報少 DIMM。
- CPU 同樣只數 Socket Designation，沒有驗證處理器 populated/status（148–164）。
- 建議：解析 populated、size、enabled/status，檢查總容量與預期模組身份，最好使用結構化輸入。

### R10. outband reboot 實際送軟關機，沒有重新開機步驟【靜態確認＋上游核對】

- 位置：neutrino_cycle.py:606–609、779–780；README.md:62。
- power soft 是 ACPI soft shutdown，並非一般 reboot；程式後面只等待 boot_id 改變，沒有等 off 再 power on。
- 影響：支援 ACPI 的機器可能關機後一直等到 timeout。
- 建議：先定義測試需要 graceful reboot、hard reset 或 power off/on；選定相符指令與完整狀態流程，文件清楚區分。
- 上游依據：[ipmitool power 命令文件](https://github.com/ipmitool/ipmitool/blob/master/doc/ipmitool.1.in#L2193)。

### R11. auto 沒有 fallback；outband 也要求 OS 在 PRE 已可登入【重現＋靜態確認】

- 位置：neutrino_cycle.py:715–716、767–780、1703–1705；README.md:66–67。
- auto 在 main 被改成 inband；issue_cycle/wait_for_os 無 outband fallback 路徑。
- 預檢固定先 SSH OS，OS 原本不在線時 outband 操作也無法走到 issue_cycle。
- 建議：明確規範 fallback 的條件與次數，先查證前一次動作是否已生效，避免重複下電。若測試設計要求 baseline，應將「恢復已關機 OS」與「循環測試」分開，而非宣稱 outband 任意可用。

### R12. 密碼會出現在 OOB 逾時例外與命令參數；dry-run 有 shell 注入問題【重現＋靜態確認】

- 位置：neutrino_cycle.py:581–589、637–640、916–917；dryrun_sim.py:37–45。
- OOB 使用 -P password；TimeoutExpired 的字串包含完整 argv，issue_cycle 將其寫入 note/issues，後續落盤。
- 已用合成密碼重現例外文字洩漏；程式雖將正常顯示的 command 遮罩，例外路徑未遮罩。
- dry-run 直接把密碼及 IP 插入 shell=True 字串，密碼未 quote；空格、$、分號等會被 shell 解讀，cmd!r 也不是 shell escaping。
- 建議：使用參數陣列與適當的受控 credential 傳遞（ipmitool -E/env 或受限憑證來源），例外統一去敏；dry-run 改用共用 SSH 層，避免 shell=True。若既有 log 曾遇此逾時情境，需檢查其是否含明文密碼。

### R13. PRE 已失敗仍執行電源循環，POST 還會覆蓋 PRE 結果【完整 mock cycle 重現】

- 位置：neutrino_cycle.py:737–741、767–774、889–892、905–906。
- pre root/config/power 為 False 不阻擋 issue_cycle；keep_going 僅在整輪結束才生效。
- pre/post 共用 root/config/power key，post 正常就把 pre 失敗覆蓋。
- 已重現：pre config=False → 照樣發送 cycle → post config=True → 最終 PASS。
- 建議：拆開 pre/post 步驟；身份不符、必要工具缺失、基準不完整不得開始；既存硬體異常是否允許測試，應採明確 policy。

### R14. 嚴重 dmesg 與部分 SEL 事件未進入判定【完整 mock cycle 重現】

- 位置：neutrino_cycle.py:520–524、893–896、1163–1175、1204–1212、1322–1328。
- dmesg 是 record-only，且先將 post_dmesg_ok 設 True；health report 雖掃出 fatal AER，overall_fail 不使用該結果。
- 已重現：含 AER: Uncorrected (Fatal) 的完整 mock loop 回 PASS，健康報告列 1 matches 仍 PASS。
- SEL 主要依一般 error/fail 字詞掃描與「是否空」，沒有事件型別/嚴重性判定；有事件不代表必須 FAIL，但不能等同完整健康檢查。
- 建議：定義平台可接受噪音與硬體故障規則，輸出分類、severity、原始事件引用，讓所有報告使用相同評估結果。

## 可靠性與擴充：P2

### R15. 電源指令是否成功與 RESPONSE_LOST 處理不一致【靜態確認】

- 位置：neutrino_cycle.py:617–662、922–928。
- inband exec_command 後不讀 stdout/stderr/exit status，直接等 2 秒後記 OK；command not found 也可能被記為已接受，直到等開機逾時。
- aux_cycle 走 log_command，回應斷線例外直接跳出整輪，沒有 OOB/inband 的 RESPONSE_LOST 對帳流程。
- 對帳一律要求 bmc_boot_changed，但一般 host reboot/power cycle 不需要 BMC 重啟；即使對帳成功，原 issue 仍在，evaluate_result 仍可能 FAILED。
- 建議：每種 mode 專屬 postcondition；明確區分未送出、已送出未確認、已確認、失敗，對帳後更新 issue disposition。

### R16. inventory 節點身份、輸出路徑與選取規則不一致【重現＋靜態確認】

- 位置：neutrino_cycle.py:119–120、228–260、695–696、1118–1120、1359–1366、1696–1701。
- inventory 允許不同 tray 的同名 n1，但目錄与報告只用 node，兩者都寫 node1/loop1；已重現目錄名稱碰撞。
- 未禁止多行指到同 BMC/OS，可能對同設備併發送電源命令。
- CLI --node n1 --node n99 會默默丟掉 n99，只要 n1 有效就照跑；已重現。
- node label 不限制格式，含路徑分隔符可能逸出預期節點目录；空必要 IP 也通過 loader。這需要控制輸入來源，非宣稱存在遠端攻擊入口。
- 建議：不可變 target_id=(project,tray,node)，驗證必要 IP、端點唯一性、label 格式；任何未知選取都回報錯誤。

### R17. 所謂 CLI preflight 幾乎沒有檢查【重現】

- 位置：neutrino_cycle.py:1528、1707–1712。
- 沒有 --cycle 時只處理參數/載入 inventory，直接 return 0；不驗證 SSH、BMC 指令、必要套件、config 檔案、基準可取得。
- wizard 有 ping，但 ping 也不能證明 SSH 權限或工具完整。
- 建議：新增真正無寫入 preflight，產生每個節點的 ready/blocked 與原因，明列將執行的模式與目標。

### R18. dry-run 把「一直都讀不到」描述成穩定【重現】

- 位置：dryrun_sim.py:102–148、175–177、197–214。
- snapshot 丟棄大多數 command return code；比的是解析後的集合。
- 完全讀不到時 baseline/current 都空，差異=0；已重現 loop FAIL，但結論仍寫「穩定」。
- 最後 exit code 也沒有隨 failed snapshot/loop 變成非零。
- 建議：先證明採集有效、基準有效，再比較；穩定與健康分開，但任何 UNKNOWN/FAIL 都不能在結論中省略。

### R19. baseline 完整性與整場 campaign 比較不足【靜態確認】

- 位置：neutrino_cycle.py:743–765、431–444、814–828；dryrun_sim.py:64–77。
- sensor 三次讀取只取最多 unique names，不要求達到已驗證的完整基準；240 rows 只是提前結束條件。
- 每轮重抓基準；前一輪掉的硬體若一直沒回來，在 keep-going 後續輪可能成為新基準。前一輪故障仍留著，但後續 loop 的單獨 PASS 容易被誤解。
- PCIe 使用整行文字作身份，名稱資料庫/輸出变化也会像掉卡；dry-run 要求 BDF 有 domain，標準 01:00.0 行直接忽略，已重現。
- 建議：保留驗證過的 campaign baseline 加每輪 pre baseline；使用 lspci -Dnn 和穩定結構化 ID；缺乏有效 baseline 回 INCOMPLETE。

### R20. host key 信任策略不足、DPU 獨立憑證未接線【靜態確認】

- 位置：neutrino_cycle.py:276–289、531–565、1388–1392、1693–1711；dryrun_sim.py:42。
- 主程式強制 trust_first_use=True，新 host key 寫入每次 PID 專用暫存檔；既有 system known_hosts 仍会使用，但新設備無持久信任。
- dry-run 完全關閉 host key 檢查。
- 文件宣稱 NEUTRINO_* / LILY_* 密碼，但 main 僅讀 BMC_PASSWORD/OS_PASSWORD，Lily 強制共用兩組密碼。
- 建議：持久 known_hosts，首次註冊與正式執行分開；每個 role 的 user/password/key 可設定且確實使用。

### R21. stop/lock 不足以保證單一擁有者與安全收尾【靜態確認】

- 位置：stop_cycle.sh:5–15；neutrino_cycle.py:1453–1483。
- pkill -9 -f 以名稱廣泛殺程序，可能殺到其他 campaign 或相關程序；SIGKILL 不執行收尾，報告可能停在半寫入狀態。
- stop 只檢查 neutrino_cycle，沒有驗證 dryrun 已停。
- /var/run lock 若無法開就改用 /tmp，不同權限使用者可能取得不同 lock；兩處都不可寫仍允許繼續。
- dry-run 無 lock，另一台 orchestrator 也不受本機 flock 保護。
- 建議：PID/target/run ID 精確停止，SIGTERM 優雅停止於安全邊界，超時才強殺；統一鎖定路徑，鎖失敗應中止；多控制端使用共享租約或操作規範。

### R22. timeout 不是整段流程的實際時間上限【靜態風險，未實機計時】

- 位置：neutrino_cycle.py:292–305、315–324、561–575、665–689、1408–1418。
- boot deadline 裡嵌套 SSH retry/sleep/identity retry，單次內層操作可能超過剩餘時間。
- Lily 註解約 5 分鐘，但 40 輪內每次 connect 也多次重試，時間可能遠超註解。
- hours 只在每輪開始檢查，最後一輪可以超出指定時數。
- run 順序讀 stdout 再 stderr，大量 stderr 時有流控阻塞風險；此為實作風險，未使用真 SSH 重現。
- 建議：共用 monotonic deadline、每次操作傳剩餘時間、同時 drain stdout/stderr；文件說清楚 hours 是「停止開始新輪」還是硬上限。

### R23. config 來源與執行版本不確定，clone 後不能直接依 README 跑【靜態確認】

- 位置：neutrino_cycle.py:1040–1052、1494–1498；dryrun_sim.py:221–224；README.md:18–23。
- 路徑寫死 /root/rackctl。未在該目錄安裝時 README 指令找不到 inventory。
- local config 缺失仍執行遠端舊 ~/vera_rack.sh；存在時又直接覆寫遠端同名檔，未記錄 hash、版本或備份。
- requirements 未完整列出 Linux/fcntl、orchestrator ipmitool、node nvme-cli/mft/dmidecode/net-tools/sudo 等環境要求；naboo inventory 只有表頭。
- 建議：預設路徑相對 repo；preflight 驗證，使用每次 run 專屬遠端檔名與 hash；記錄 Python/工具/BMC/BIOS/config 版本；未配置專案不要顯示為可用。

### R24. 硬體盤點存在身份誤認與檢查深度不足【部分重現】

- 位置：vera_rack.sh:25–36、71–89、124–137、229–250、404–431、450–458。
- 任意非 Vera MST device type 都算 BF4；已用 ConnectX7 fixture 重現 BF4_Qty=1。
- NIC 計算所有 /dev/mst/ 行，沒有驗證是否為指定型號或重複 endpoint。
- NVMe 以 list 的 namespace 行數計數，不必然等於實體磁碟數；容量、序號、FW 與鏈路速度主要是顯示，未加入 pass/fail。
- 通用 Device 陣列在不同裝置種類間未清空，Device_fun 又固定掃 32 筆，摘要數量有殘留/上限風險。
- 建議：用 BOM/profile 定義每節點預期項目，區分實體裝置、function、namespace，檢查 ID/SN/容量/速率；重新初始化各類型容器。
- 是否應把鏈路降速、corrected AER、FW 差異列 FAIL，需要測試規格決定，不能從目前 repo 推定。

### R25. 報告完整性、耐久性及長跑成本仍需加強【靜態確認】

- 位置：neutrino_cycle.py:127–129、709–711、1196–1205、1358–1383、1434–1448。
- save 直接覆寫，程序中止/空間不足可能留下截斷 JSON；缺少原子替換與磁碟空間檢查。
- 每輪從頭重寫/掃描所有歷史報告及 dmesg，總成本隨輪數接近平方增加。
- health report 的 loops_total=max 已存在 loop，沒有區分 requested/completed/failed/aborted；工作失敗或節點停止後標題可讓人误认完整測試完成。
- 建議：append-only 事件與原子 summary、獨立 campaign manifest/狀態、增量索引、適當間隔生成完整報告；記錄停止原因。

### R26. 缺少測試及 CI，規則散落造成文件與行為逐漸不一致【倉庫檢查】

- 初始倉庫沒有自動測試、CI workflow、依賴版本約束。
- 判斷規則分散在 output_issues/evaluate_result/_row_real_issues/health report/dryrun，導致本次多個互相矛盾的結果。
- 建議：先建立純函式 parser/evaluator，再以匿名化真機 fixture 做回歸；測試至少涵蓋健康/掉卡/空輸出/錯誤碼/timeout/重複 sensor/命令回應丟失/部分 campaign/報表一致性。硬體操作層與評估層分離。

## 建議分階段處理

1. **可信結果與資料保全**：R01–R09、R12–R14。先移除隱藏故障與毀損證據的路徑，讓報告可以被信任。
2. **電源狀態機與可控執行**：R10–R11、R15–R17、R20–R23。確定目標正確、動作明確、單次命令可對帳、可停止。
3. **平台化與長跑**：R18–R19、R24–R26。統一 profile、基準、依賴與回歸，補上完整性及效能。

需要討論的規格決策：

- BF4 是所有節點必備，還是依 node/BOM 可選？目前程式「必備」與報告「預期不存在」互相矛盾。
- WARN、不可讀、INCOMPLETE 如何影響繼續測試與最終結果？
- auto fallback 是否允許第二次電源動作？什麼證據證明第一次未成功？
- SEL/dmesg 是否可清除？若允許，備份與保留政策為何？
- aux_cycle 要證明哪個 power domain 確實切換？僅 OS boot_id 改變不足以證明實際電源軌行為；需平台規格或 BMC 電源證據確認。

## 驗證附件

- offline_review.py：可重跑的離線 defect probes；Bash 的設備命令均由函式 mock，Python 網路與電源相關呼叫被替換。
- offline_observations.json：25 個確認情境的輸出；所有密碼/位址都是合成測試資料。
- Python py_compile 與兩個 Shell bash -n：皆通過。這代表語法可解析，不代表上述功能正確。
- 未執行真機 reset/reboot/aux_cycle、SSH/IPMI 互通或現場長跑；BOM、SDR 重複名稱意義、BMC 腳本電源域、客製工具輸出仍需實機資料核對。
