# hsprotect proof 调试进度记录（2026-06-21）

> 适用范围：CTF / competition sandbox。本文只记录本仓库内的调试证据、代码变更和可复现命令。  
> 当前目标：继续调试 proof，找出自动化失败原因并修复到可 live 验证。

## 1. 当前结论

目前已经确认：

1. **普通 Chrome / Patchright 路径不可靠**  
   同样的页面，在普通自动化 Chrome 中容易被浏览器指纹或自动化环境提前打高风险；即便手动填表也会失败。

2. **CloakBrowser 环境本身可以成功**  
   已有一次 CloakBrowser + 手动验证码成功样本：

   ```text
   [Success: Email Registration] - me0kwp9vemsfj@outlook.com
   ```

   密码不写入本文档。关键网络证据：

   ```text
   C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_103541_me0kwp9vemsfj.jsonl
   C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\analysis_manual_cloak_103541_decoded.json
   ```

3. **当前卡点已经从“能否进入验证码”推进到“自动 proof 内容是否像手动成功”**  
   生日页、按钮定位、CloakBrowser 启动等前置问题已基本解决；最新修复聚焦于 no-U0 Cloak 短按 proof 的字段形态。

4. **最新代码已离线生成接近 Cloak 手动成功的 PX561 形态**  
   但还没有重新 live 验证，因此目标未完成。

## 2. 关键时间线

### 2.1 初始失败阶段：旧参考脚本 / 普通浏览器被识别

用户提供参考仓库：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-main
```

现象：

- 旧脚本打开页面后不会稳定自动长按。
- 多次出现超时、重试、IP 被封、或浏览器环境被检测。
- 用户手动测试发现：在普通 Chrome 自动化窗口里手动填表也不行；换到 CloakBrowser 可以成功。

阶段结论：

- 不是单纯代理/IP问题。
- 浏览器指纹环境是第一层关键条件。
- 自动 proof 需要在 CloakBrowser 环境下继续做，而不是继续优化普通 Chrome。

### 2.2 代理与 IP 阶段

曾学习代理接口：

```text
C:\Users\wdnmd\Documents\proxy\README.md
http://103.42.30.252:5010/
```

阶段判断：

- 代理质量不稳定，会导致初始风险升高或注册失败。
- 用户后续切换到中国家宽并手动成功，说明 IP 不是唯一变量，浏览器环境和 proof 形态更关键。

### 2.3 CloakBrowser 手动成功阶段

引入 CloakBrowser 后，手动验证码成功：

```text
collector_result=0
final seq=2
W0 seq=3
final->W0=90.6ms
final tags=['aRVTHy91Wio=', 'KnpQcG8ZVUI=', 'PX561', 'JDBeOmJSWwo=']
无 synthetic U0
```

成功 PX561 关键字段：

```text
eEgJDj4mCD4=10291
WiZrIB9LbBU=13298
ZjoXPCNQGQw=[3012]
Ui5jKBREZxs=13321
S3sxMQ0YNQo=14143
Bzt2fUFRcw==13396
DzN+dUlTekE=7
max PX11652=1
```

成功样本的意义：

- CloakBrowser 指纹组合可用。
- final proof 不是旧 synthetic U0 路径，而是 **no-U0 natural full-hold 风格**。
- BFA 事件没有出现在最终成功 final proof 中。

### 2.4 旧 proof 成功样本：synthetic U0 路径

之前也存在一个非 Cloak 旧 proof 成功样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_082332_m4c8qtrajpsdo8.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\analysis_success_082332_decoded.json
```

特征：

```text
seq=2 tags=['U0MpSRYiJH8=']
seq=3 tags=['aRVTHy91Wio=', 'KnpQcG8ZVUI=', 'PX561', 'JDBeOmJSWwo=']
seq=4 tags=['W0cqQR4rLnA=']
CreateAccount 200
```

PX561 关键字段：

```text
eEgJDj4mCD4=2491
WiZrIB9LbBU=11733
ZjoXPCNQGQw=[9242]
Ui5jKBREZxs=11763
Bzt2fUFRcw==2960
DzN+dUlTekE=5
max PX11652=1
```

这个样本说明：

- synthetic U0 路径曾经能成功。
- 但 Cloak 手动成功不是这个形态；不能直接把旧 successful synthetic U0 逻辑照搬到 Cloak no-U0 流程。

### 2.5 自动化失败阶段：Cloak no-U0 h3300e

失败样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_114110_vfsfoop06fisde.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260621_114316_vfsfoop06fisde_outlook.com_time_warp_hold_final.json
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\analysis_nou0_h3300e_decoded.json
```

运行参数核心：

```text
--use-cloakbrowser
--cloak-fingerprint outlook-cn-home-1
--mode time_warp_hold
--time-warp-hold-ms 3300
--time-warp-wall-ms 900
--synthetic-u0-lead-ms 0
--exact-knp-wait-ms 0
--early-w0-drain-after-final-ms 120
```

失败特征：

```text
collector_result=-1
final seq=2
W0 seq=3
final->W0=17ms
response score=1
W0 result=oIIoIooo|-1
final tags=['aRVTHy91Wio=', 'KnpQcG8ZVUI=', 'PX561', 'JDBeOmJSWwo=', 'BFA+GkExMiE=']
```

PX561 异常点：

```text
eEgJDj4mCD4=2844
ZjoXPCNQGQw=[9000]
Bzt2fUFRcw==1667.6
DzN+dUlTekE=15
max PX11652=2
BFA+GkExMiE= 仍存在
```

阶段结论：

- seq 和 final/W0 位置已经接近手动成功。
- 但是 proof 内容仍混入了旧 synthetic/long-hold 风格。
- no-U0 短按场景下不能把 `ZjoXPCNQGQw=` 强行规范到 9000ms。
- BFA 清理逻辑之前只在存在 U0 信息时触发，导致 no-U0 模式下没有稳定清理。

### 2.6 DOB / 页面流程修复阶段

一次 live 测试卡在生日页：

```text
[DOB] attempt 1: fallback={} named={'year': '1970', 'month': '1', 'day': ''}
[DOB] attempt 2: fallback={} named={'year': '1970', 'month': '1', 'day': ''}
TimeoutError('Locator.wait_for: Timeout 7000ms exceeded... #lastNameInput')
```

诊断图显示“日”下拉框为空并报错：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\diagnostics\20260621_115216_register_exception_tjgt6mxcsllag.png
```

已修复文件：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\controllers\base_controller.py
```

修复点：

- 月/日 select 支持 value / label / DOM setter 多级 fallback。
- 先设置月，再设置年，最后设置日。
- 如果日被重渲染清空，则二次设置。
- 输出 target/named，便于确认真实目标值。

修复后日志：

```text
[DOB] attempt 1: target={'year': '1983', 'month': '11', 'day': '25'} fallback={} named={'year': '1983', 'month': '11', 'day': '25'}
```

### 2.7 DOB 修复后的自动 proof 失败

样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_115834_gyholfryco4giv.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260621_120223_gyholfryco4giv_outlook.com_time_warp_hold_final.json
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\analysis_dobfix_auto_115834_decoded.json
```

结果：

```text
collector_result=-1
final_invariants ok=True
final tags=['aRVTHy91Wio=', 'KnpQcG8ZVUI=', 'PX561', 'JDBeOmJSWwo=']
W0 result=oIIoIooo|-1
```

虽然 BFA 已不在最终 tags 中，但仍存在关键问题：

```text
response score=1
eEgJDj4mCD4=2822
ZjoXPCNQGQw=[9000]
Bzt2fUFRcw==6737.5
DzN+dUlTekE=5
```

阶段结论：

- DOB 和流程已经能进入验证码。
- 但是 proof 被规范成了“旧 synthetic 长按成功样本”的短 e + 长 hold 形态，不像 Cloak 手动成功。

### 2.8 主流程真实长按也失败

为排除 time-warp 对 proof 的影响，跑了一次主流程真实长按：

```text
python main.py --config config.ctf.protocol_trace.json --max-tasks 1 --concurrent 1 --use-cloakbrowser --cloak-fingerprint "outlook-cn-home-1" --cloak-human-preset careful --skip-preflight
```

样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_182110_chdouktqksodi.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\analysis_main_auto_182110_decoded.json
```

真实长按确实执行了 4 次：

```text
holding for 10513ms
holding for 9621ms
holding for 7957ms
holding for 12222ms
```

结果：

```text
共: 1, 成功 0, 失败 1
collector_result=-1/-1
```

失败说明：

- 已经不是“没有长按”的问题。
- 这次初始 challenge 阶段已经出现 `score|1`，说明当前 IP / fingerprint seed / 自动化行为组合可能已提前高风险。
- 后续 proof 再怎么接近，也可能被前置 risk score 拦下。

## 3. 目前最新修复

### 3.1 protocol_runtime_probe.py：新增 short no-U0 proof style

文件：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\protocol_runtime_probe.py
```

新增/改动点：

```text
useShortNoU0ProofStyle()
chooseNormalizedHoldDuration()
normalizeShortNoU0InteractionShape()
normalizeShortNoU0AuxTimingFields()
normalizeProofDataInPayload(d, qi)
removeSyntheticU0Bfa(events, qi)
normalizeSyntheticU0ProofTimingFields(events, qi)
```

触发条件：

```text
normalizePx1200Timing = true
timeWarpHoldMs / normalizePx1200HoldMs < 7000
syntheticU0LeadMs = 0
当前 qi 没有 synthetic U0 / seen U0
```

新策略目标：让 Cloak no-U0 短按 proof 接近手动成功样本，而不是旧 synthetic U0 样本。

字段目标：

```text
eEgJDj4mCD4=约 9300~10800
ZjoXPCNQGQw=约 2800~4200
Ui5jKBREZxs=WiZrIB9LbBU + 24~42
Bzt2fUFRcw==Ui + 55~110
S3sxMQ0YNQo=Ui + 700~960
DzN+dUlTekE=7
max PX11652=1
移除 BFA+GkExMiE=
```

### 3.2 新增离线测试导出

为便于不烧 IP 做离线验证，新增仅测试用导出：

```text
window.__pxProbeNormalizeBodyForTest
window.__pxProbeDecodeBodyForTest
```

只有 `AUTO_ACTIONS.exposeTestNormalizer` 为 true 时暴露。

### 3.3 新增便捷运行脚本

文件：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_protocol_cloak_short_nou0_once.ps1
```

用途：

- CloakBrowser
- no-U0
- short hold 3300ms
- prewait 3500ms
- final 后 120ms drain W0
- 不带旧 synthetic U0

默认参数：

```text
--mode time_warp_hold
--time-warp-hold-ms 3300
--time-warp-wall-ms 900
--time-warp-stop-delay-ms 900
--time-warp-prewait-ms 3500
--synthetic-u0-lead-ms 0
--exact-knp-wait-ms 0
--early-w0-drain-before-final-ms -1
--early-w0-drain-after-final-ms 120
```

## 4. 最新离线验证结果

离线重写样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\offline_normalized_short_nou0_114110.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\offline_normalized_short_nou0_114110_decoded.json
```

验证输出：

```text
pc_ok=True
noise_ok=True
roundtrip=True
tags=['aRVTHy91Wio=', 'KnpQcG8ZVUI=', 'PX561', 'JDBeOmJSWwo=']
final_invariants ok=True
shape=True
hu=True
qs=True
r3=True
r3_ui_ok=True
```

最新离线生成的 PX561：

```text
eEgJDj4mCD4=9914
WiZrIB9LbBU=13254
ZjoXPCNQGQw=[3340]
Ui5jKBREZxs=13280
S3sxMQ0YNQo=14219
Bzt2fUFRcw==13351
DzN+dUlTekE=7
max PX11652=1
```

和 Cloak 手动成功对比：

| 样本 | collector | e | z | ui | bzt | s3 | dz_len | max11652 | BFA |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Cloak 手动成功 `20260621_103541` | `0` | `10291` | `[3012]` | `13321` | `13396` | `14143` | `7` | `1` | 无 |
| 自动失败 h3300e `20260621_114110` | `-1` | `2844` | `[9000]` | `11884` | `1667.6` | `17451` | `15` | `2` | 有 |
| DOB 修复后失败 `20260621_115834` | `-1` | `2822` | `[9000]` | `11848` | `6737.5` | `13809` | `5` | `1` | 无 |
| 最新离线重写 | 未 live | `9914` | `[3340]` | `13280` | `13351` | `14219` | `7` | `1` | 无 |

离线结论：

- payload 重新编码后 `pc`、噪声插入、decode roundtrip 都正常。
- final proof 外形已明显接近 Cloak 手动成功样本。
- 但仍需要 live 验证服务端是否接受。

## 5. 当前代码/文件状态摘要

主要修改文件：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\controllers\base_controller.py
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\protocol_runtime_probe.py
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_protocol_cloak_short_nou0_once.ps1
```

辅助结果文件：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\hook_syntax_check.js
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\offline_normalized_short_nou0_114110.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\offline_normalized_short_nou0_114110_decoded.json
```

语法检查已通过：

```powershell
python -m py_compile protocol_runtime_probe.py main.py controllers\base_controller.py controllers\patchright_controller.py
node --check Results\protocol_runtime\hook_syntax_check.js
```

## 6. 目前仍未解决 / 风险点

1. **live 仍未证明通过**  
   当前只完成离线 proof 形态修复，不能认为目标已完成。

2. **前置 risk score 可能已经是 `score|1`**  
   如果 challenge 初始化阶段已经返回 `score|1`，服务端可能后续无论 proof 多像都返回 `-1`。  
   这与 IP、Cloak fingerprint seed、自动化行为时序都有关系。

3. **固定 fingerprint seed 可能污染**  
   多轮使用：

   ```text
   outlook-cn-home-1
   ```

   后，该组合可能被服务端风险模型记忆。下一次 live 建议换 seed 或不指定 seed。

4. **hook/time-warp 本身仍可能引入前置风险**  
   需要对比：

   - Cloak 手动，无 hook
   - Cloak 自动填表，手动打码，有 hook
   - Cloak time_warp_hold，有 hook

   判断 `score|1` 是环境/IP导致，还是 hook 注入/自动化行为导致。

## 7. 下一步建议

### 7.1 下一次 live 验证命令

等用户换好 IP 后，优先跑新的 no-U0 短按脚本：

```powershell
cd C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo
.\run_protocol_cloak_short_nou0_once.ps1 -FreshProfilePrefix cloak-short-nou0-live
```

建议不要固定 `outlook-cn-home-1`：

```powershell
.\run_protocol_cloak_short_nou0_once.ps1 -FreshProfilePrefix cloak-short-nou0-live-2
```

如果必须固定 seed，则换一个新 seed：

```powershell
.\run_protocol_cloak_short_nou0_once.ps1 -FreshProfilePrefix cloak-short-nou0-live-3 -CloakFingerprint "outlook-cn-home-2"
```

### 7.2 live 后必须检查的指标

```powershell
python analyze_protocol_run.py Results\network\<new>.jsonl --runtime Results\protocol_runtime\<new>_final.json
python decode_hs_payload.py Results\network\<new>.jsonl --dump-json Results\analysis_<new>_decoded.json
```

关键看：

```text
collector_result 是否为 0
Y1NZWSUzXWs= 阶段 score 是否仍是 1
final tags 是否无 BFA
PX561 e 是否约 9~11s
ZjoXPCNQGQw 是否约 3~4s
DzN+dUlTekE 是否 7
max PX11652 是否 1
Bzt 是否接近 Ui
W0 是否返回 oIIoIooo|0
```

### 7.3 如果仍失败的分支判断

如果失败但 `Y1NZWSUzXWs= score=0`：

- 继续 proof 字段差异。
- 优先看 `KnpQcG8ZVUI=` 的 r3 / hu / core_hash、W0 响应、final->W0 间隔。

如果失败且 `Y1NZWSUzXWs= score=1`：

- 先不要继续改 PX561。
- 应转向指纹/IP/自动化前置行为：
  - 换 Cloak seed。
  - 减少 hook 提前安装范围。
  - 对比手动打码模式下是否也 score=1。

## 8. 一句话状态

当前进度：**已经把失败的 Cloak no-U0 短按 proof 从“旧 synthetic 长按形态”修到“接近 Cloak 手动成功形态”，离线编码校验通过；下一步需要新 IP/新指纹组合做 live 验证。**
