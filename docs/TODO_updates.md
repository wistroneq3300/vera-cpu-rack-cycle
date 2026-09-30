# Cycle 腳本 — 待更新清單 (2026-09-30)

> 使用者口述想改的點,逐條記錄。**尚未動 code**,確認後才實作。

## 1. BF4_EXPECTED 設 0 的行為(討論中)
- 現況:`neutrino_config.sh` / `naboo_config.sh` 的 `BF4_EXPECTED=1`
- 路 A(`bf4_ports==0`)有 `BF4_EXPECTED != 0` 保護 → 設 0 不 FAIL
- 但 `BF4_IDENTITY_UNAVAILABLE`(line 88-89)**沒有同樣保護** → 設 0 仍可能 FAIL(不一致)
- 待決定:是否修此不一致 / 是否把預設改 0

## 2. dmesg `Hardware Error` 誤報 + 過度拆分 ✅ 已完成 (2026-09-30)
- 位置:`cycle_core.py` `dmesg_issues()`(已重寫)
- 問題一(pattern太寬):`Hardware Error` 連 `event severity: info` 的 APEI
  純通知事件也抓 → 誤報 FAIL
  - 實例:L105-21R_n1 loop0054 / loop0021 `[Hardware Error]: Hardware error from
    APEI Generic Hardware Error Source: 8194` + `severity: info` + `type: info`
- 問題二(沒去重):一個 Hardware Error 事件的多行
  (severity/type/section/length/hex dump)各自算一條 issue
  → 1 事件 = 19 findings,太吵
- **修法(已完成)**:
  - (a) APEI block 只在含 `severity/type: (fatal|corrected|uncorrected)` 才報;
        整塊 `info` → 放行(不報)。
  - (b) 整個 block 收斂成**一條** issue(不再每行一條)。
  - 單行錯誤(AER Uncorrected/Fatal、MCE、nvme error、Memory failure、
    panic/BUG/Call Trace)維持逐行比對。
- **驗證**:126 個真實 dmesg 檔,舊 72 findings → 新 **0**(全為 info 誤報);
  新增測試 `test_apei_info_block_is_benign_and_collapses`、
  `test_apei_severe_block_reports_once`。**93 測試全綠**。

## 3. sensor 亂碼名一律 FAIL ✅ 已完成 (2026-09-30)
- 使用者要求:亂碼名(U+FFFD `�`)不可放行 → 一律 FAIL。
- `cycle_core.py` `_known_no_reading()`:移除「名字含 `�` 且 unit 空」分支,
  白名單只剩 `coruti`。
- 測試更新:亂碼行(有/無 unit)→ 期望 FAIL。91 測試全綠。

## 待補(使用者還會繼續講其他點)

