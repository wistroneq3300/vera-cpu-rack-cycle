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

但**它不是「已驗證可用」**。我找到 **2 個真 bug、3 個需決策的設計問題、若干次要問題**。以下按嚴重度排列。

---

## 1. 真 bug（建議修）

### 🔴 BUG-1：`BF4_MISSING` 被列為 KNOWN 但仍讓 campaign 永遠 FAIL

**現象**：`issue_policy.md` 把 `BF4_MISSING` 標成 `KNOWN`，但 `health()` 只看 severity（KNOWN 不降 severity）。所以 n2/n3/n4 每個 loop 都是 **FAIL**，整個 campaign 健康度**永遠 FAIL**。

實測：
```
BF4_MISSING classify -> KNOWN, severity 仍 FAIL
campaign health = FAIL   # 永遠
```

**與你的預期不符**：專案記憶寫「BF4 config 失敗…報告會自動排除」。實際上報告**不會排除**，只是標 KNOWN 讓你人工過濾；健康度仍是 FAIL。

**這是設計還是 bug？** `issue_policy.md` 明寫「Classification never changes severity or health」——所以是**有意設計**。但它讓「campaign 結論」失去意義（永遠 FAIL）。**需要你決策**（見第 3 節）。

---

### 🟠 BUG-2：`parse_sensors` 靜默丟棄不含 `|` 的壞行

**位置**：`cycle_core.py:141-143`

```python
for line in text.splitlines():
    if "|" not in line:
        continue          # ← 整行直接丟掉，不記錄
```

docstring 宣稱「Keep incomplete table rows so the evaluator cannot silently pass them」，但**不含 `|` 的行會被靜默丟棄**。

**風險**：BMC 用 `ipmitool sensor list` 回傳時，若某行因傳輸問題損壞成純文字（無 `|`），該 sensor 就**從 current 消失** → 觸發 `SENSOR_MISSING` FAIL。**方向是安全的（會 FAIL 不會靜默 PASS）**，但：
1. 註解與行為不符（誤導維護者）
2. `SENSOR_MALFORMED` 永遠不會對「無 `|`」的行觸發
3. 可能產生**假 FAIL**（其實是傳輸雜訊，不是 sensor 真的消失）

**建議**：非空、非標題、無 `|` 的行應記為 `SENSOR_MALFORMED` 的 candidate，或至少在 docstring 說清楚。

---

### 🟠 BUG-3：`sel_delta` 用整行文字比對，同事件 ID 不同時間戳會誤判為新事件

**位置**：`cycle_core.py:252-264`

用完整行（含 timestamp）做 Counter diff。BMC SEL 的同一筆記錄若 timestamp 有微小差異（或重讀時間不同），會被當成**新事件**。反之，若真事件 ID 重複但內容相同則仍可見（這部分是對的）。

實測：
```
prev="1 | 00:01:00 | Power off"
cur ="1 | 00:02:00 | Power off"   -> delta=1（誤報新事件）
```

**風險**：SEL delta 會有多餘雜訊。**但影響有限**——SEL 在系統裡明訂「REVIEW REQUIRED: 僅供人工複核，不自動判定」，不會直接造成 FAIL。屬**低嚴重度噪音**。

**建議**：以 record ID（SEL 第一欄）為 key 做 diff，而非整行。

---

## 2. 次要問題

| # | 位置 | 問題 | 影響 |
|---|---|---|---|
| M-1 | `vera_rack.sh:87` | `pci_count PCIeFAB 'NVIDIA.*bridge\|bridge.*NVIDIA'` 用 `grep -Eic`，「NVIDIA ... bridge」跨詞比對；真機實測 21（≥20 ✓），但若 lspci 描述順序改變（class 在前 vendor 在後）可能漏算 | 真機目前 OK |
| M-2 | `vera_rack.sh:58` | BF4 偵測把 `$PCI`（全域）也算進去，但 `-F` 模式下 `$PCI` 為空；`all` 模式順序上 `collect PCI` 先於 `nic_bf4_check`，OK。但變數依賴隱晦 | 可維護性 |
| M-3 | `cycle_engine.py:237` | `command = "reboot" if mode=="reboot" else "ipmitool power cycle" if channel=="inband" else "power cycle"` 巢狀三元過長 | 可讀性 |
| M-4 | `neutrin_cycle.py` `campaign()` | 116 語句巨型函式 | 可維護性 |
| M-5 | 全域 | 多處 `except Exception` 過寬（ruff 會警告） | 可能吞掉 bug |
| M-6 | `cycle_report.py:76` | `phase.split()[-1]` 假設 phase 格式為 `LOOP <n>`；若格式變動會 KeyError/IndexError | 脆 |
| M-7 | `sensor_issues` | `unreadable` 含空字串 `""`，所以「status 空 + reading 空」的健康 sensor 會被判 `SENSOR_UNREADABLE`；`_known_no_reading` 只豁免 coruti/亂碼。真機 240 行無此情況，但邊界脆 | 真機 OK |

---

## 3. 需你決策的設計問題

### D-1：BF4 缺席到底算不算 FAIL？（最重要）

三個選項：
- **(a) 維持現狀**：標 KNOWN，健康度仍 FAIL。你每次要人工忽略。✅ 最保守
- **(b) 讓 KNOWN 不影響 campaign health**：`status()` 只對 `NEW` 的 FAIL 算 FAIL。⚠️ 改了語意，需同步報告文案
- **(c) BF4 到貨後刪掉那條 policy rule**：回到乾淨 FAIL。✅ 業界標準做法

**我的建議**：**(a) + (c)**。不要改 KNOWN 的語意（會掩蓋未來真問題），而是在 BF4 到貨後刪 rule。若你現在就想讓 campaign「看起來 PASS」，只能改 (b)，但那削弱了工具的核心價值。

### D-2：`sel_delta` 是否要改成以 ID 為 key？
建議改（見 BUG-3），但優先度低。

### D-3：是否加 `--loops` 之外的「自動停止於第一個 FAIL」？
目前任何 FAIL 都不會自動中止（設計上是「跑完 N 輪」）。若你要「一有硬體 FAIL 就停」，需新功能。

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
| 測試套件 | Linux | ✅ 50 tests OK |
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

1. **決策 D-1**（BF4 政策）—— 影響你怎麼解讀每份報告
2. 修 **BUG-2**（parse_sensors 註解/壞行處理）—— 小改、降假 FAIL 風險
3. 修 **BUG-3**（sel_delta 以 ID 為 key）—— 小改、降噪音
4. **等客人走後**做真機端到端 1 輪驗證——無法省
5. 次要問題（M-1..M-7）可延後

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
