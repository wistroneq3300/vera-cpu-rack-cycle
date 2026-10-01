# Vera CPU Rack / neutrino cycle tool — 完整 code review

日期：2026-09-29
對象：`wistroneq3300/vera-cpu-rack-cycle` @ `85d04ac`（origin/main）
方法：逐模組閱讀 2,384 行 + 用真機資料（`cycle_test0929_080551`、`fixtures/real-hardware/`）與 stub 實測
**未做**：真機端到端執行（硬體斷電中）

---

## 0. 結論（TL;DR）

**這是一個設計相當成熟、注重證據保存與「不確定就說不確定」的系統。** 核心哲學正確：
- PRE 不可變、POST 才對比
- 無 reply ≠ 成功，一律走 `RESPONSE_LOST` → 需 boot ID + power 證據才 reconcile
- 抓不到資料 = FAIL，不靜默通過
- 報告與 journal 分離、可 rebuild

但**它不是「已驗證可用」**。我找到 **2 個真 bug、若干次要問題**；其中 2 個真 bug 都已處理（BUG-1 依政策刪 rule、BUG-2 已修），BUG-3 撤回（非 bug）。以下按嚴重度排列。

---

## 1. 真 bug（建議修）

### ✅ BUG-1（已依政策解決）：`BF4_MISSING` 被列為 KNOWN 但仍讓 campaign 永遠 FAIL

**現象**：`issue_policy.md` 原本把 `BF4_MISSING` 標成 `KNOWN`，但 `health()` 只看 severity（KNOWN 不降 severity）。所以 n2/n3/n4 每個 loop 都是 **FAIL**，整個 campaign 健康度**永遠 FAIL**。

**使用者決策**：BF4 **是必要的**——有 → PASS、沒有 → FAIL。
**處理**：**刪除該 KNOWN rule**。`vera_rack.sh` 底層邏輯本來就正確（無 BF4 → `BF4_MISSING` → FAIL），刪 rule 後回歸純 FAIL。

**驗證**：有 BF4 → 無 issue → PASS；無 BF4 → `BF4_MISSING` = NEW/FAIL。

---

### ✅ BUG-2（已修）：`parse_sensors` 靜默丟棄不含 `|` 的行

**位置**：`cycle_core.py:138-157`

原本 `if "|" not in line: continue` 會把**非空、無 `|` 的行整行丟掉**，與 docstring 宣稱「保留不完整行避免靜默通過」矛盾。

**實際風險**：`ipmitool sensor list` 可能 **rc=0 但 stdout 混入診斷行**（例如 `Error: Unable to establish IPMI v2 / RMCP+ session`）。該行無 `|` → 被靜默丟棄 → sensor 清單悄悄變短 → 可能誤觸 `SENSOR_MISSING`。

**修法**：非空無 `|` 的行 → 記為 malformed row → `SENSOR_MALFORMED`（FAIL）。空行仍忽略。
**驗證**：真機 n1/n2/n3 fixture 不變（240 rows / WARN）；新增測試；**51 tests OK**。

---

### ⚪ BUG-3（撤回，非 bug）：`sel_delta` 用整行比對

原本我列為 bug，**重新檢視後撤回**。`sel_delta` 以「整行文字（含 record ID + timestamp）」做 Counter diff，是**刻意的設計**：
- BMC SEL **record ID 會循環重用**
- 「同 ID、不同 timestamp」**確實是新事件**，必須保留

程式有註解（`cycle_core.py:253`）與專門測試（`test_sel_reused_id_with_new_timestamp`）證明這是**有意為之**。若改成以 ID 為 key，反而會**漏掉**重用 ID 的新事件。**維持原狀。**

---

## 2. 次要問題

| # | 位置 | 問題 | 影響 |
|---|---|---|---|
| M-1 | `vera_rack.sh:87` | `pci_count PCIeFAB 'NVIDIA.*bridge\|bridge.*NVIDIA'` 用 `grep -Eic`，「NVIDIA ... bridge」跨詞比對；真機實測 21（≥20 ✓），但若 lspci 描述順序改變（class 在前 vendor 在後）可能漏算 | 真機目前 OK |
| M-2 | `vera_rack.sh:58` | BF4 偵測把 `$PCI`（全域）也算進去，但 `-F` 模式下 `$PCI` 為空；`all` 模式順序上 `collect PCI` 先於 `nic_bf4_check`，OK。但變數依賴隱晦 | 可維護性 |
| M-3 | ~~`cycle_engine.py:237`~~ | ✅ **已修**：巢狀三元改為 if/elif，`inband` 抽變數 | 可讀性 |
| M-4 | `neutrino_cycle.py` `campaign()` | 116 語句巨型函式 | 可維護性 |
| M-5 | 全域 | 多處 `except Exception` 過寬（8 處，**防禦性設計**，不建議動） | 有意的取捨 |
| M-6 | ~~`cycle_report.py:76`~~ | ✅ **已修**：改抓尾端數字，取不到就退回 PRE 錨點（原本空 phase 會 IndexError） | 脆 → 已強化 |
| M-7 | `sensor_issues` | `unreadable` 含空字串 `""`，所以「status 空 + reading 空」的健康 sensor 會被判 `SENSOR_UNREADABLE`；`_known_no_reading` 只豁免 coruti/亂碼。真機 240 行無此情況，但邊界脆 | 真機 OK |

---

## 3. 設計問題（已決策）

### ✅ D-1（已決策）：BF4 缺席算 FAIL
使用者政策：**BF4 是必要的，有 → PASS、沒有 → FAIL**。做法：刪除 KNOWN rule（已完成）。

### ⚪ D-2（撤回）：`sel_delta` 改成以 ID 為 key？
**不改**。原判斷有誤——現行「整行比對」是刻意處理 SEL record ID 循環重用，改成 ID-key 反而會漏事件。見 BUG-3 說明。

### ✅ D-3（已決策）：不加自動停止，跑到底
使用者決定：**FAIL 不中止，照樣跑完 N 輪**。理由：這是壓測，要觀察故障的時間分布（偶發 vs 持續惡化）。硬體真的掛掉時節點通常會失聯，現有機制已會停該節點；想停手動用 `--stop`。
**不需新功能。**

---

## 4. 已驗證正確的部分（可放心）

| 模組 | 驗證方式 | 結果 |
|---|---|---|
| `parse_sensors` | 三台真機 240 行 | ✅ 全解析，unique 232 名（4 個已知重複） |
| `sensor_issues` | 真機 3 台 + 30 loop 重播 | ✅ WARN，假 FAIL 全清 |
| `parse_pci` | 真機 `lspci -Dnn` | ✅ 16 BDF 正確解析（含 multi-domain `0002:` 等） |
| `config_issues` | 真機條件 stub 跑新版 `vera_rack.sh` | ✅ 只出 `BF4_MISSING`，格式正確 |
| `classify` + `aggregate_issues` | 端到端 | ✅ KNOWN 標記、occurrence 累計正確 |
| `vera_rack.sh` 門檻 | 真機 lspci/mst | ✅ PCIeFAB 21/USB 1/BMC 1/NIC 22/DIMM 16 |
| 測試套件 | Linux | ✅ 51 tests OK |
| `TemporaryDirectory` rename | 實測 | ✅ 成功路徑不會因 cleanup 崩潰 |
| stub shell 相容 | dash/bash/sh | ✅ 三 shell 通過 |

---

## 5. 尚未驗證（無法在斷電期做）

- ❌ 真機端到端一輪（BMC/OS SSH、ipmitool power cycle、boot 偵測、dmesg/SEL 實抓）
- ❌ 破壞性情境：中途斷網、Ctrl-C、BMC 掛、雙節點併發鎖
- ❌ HTML 報告在瀏覽器的實際渲染/無障礙
- ❌ `--stop` / `stop_cycle.sh` 實跑
- ❌ 多 target 平行（目前只有 node4 有效真機 log）

---

## 6. 建議行動順序

1. ~~決策 D-1（BF4 政策）~~ ✅ 已完成——刪 rule
2. ~~修 BUG-2（parse_sensors 壞行）~~ ✅ 已完成——malformed 化
3. ~~修 BUG-3（sel_delta）~~ ⚪ 撤回——非 bug
4. **等客人走後**做真機端到端 1 輪驗證——無法省
5. 次要問題：~~M-3/M-6~~ ✅ 已修；M-1/M-2/M-4/M-5/M-7 建議**不動**（防禦性設計或真機無害）
6. ~~決策 D-3「一有 FAIL 就停」~~ ✅ 已決策——**不停，跑到底**

---

## 附：實測指令與原始數據

```bash
# sensor 判定（真機 fixture）
python3 -c "
import sys; sys.path.insert(0,'.')
from cycle_core import parse_sensors, sensor_issues, health
for n in ('n1','n2','n3'):
    print(n, health(sensor_issues(parse_sensors(open(f'fixtures/real-hardware/{n}_sensor_list.txt').read()))))
"
# -> n1 WARN  n2 WARN  n3 WARN

# BF4 政策
python3 -c "
import sys; sys.path.insert(0,'.')
from cycle_core import config_issues, classify, parse_policy, health
iss=config_issues(open('/tmp/vera_out.txt').read(),1)
classify(iss,'neutrino',parse_policy(open('issue_policy.md').read()))
print(health(iss))  # -> FAIL（KNOWN 不降 severity）
"
```
