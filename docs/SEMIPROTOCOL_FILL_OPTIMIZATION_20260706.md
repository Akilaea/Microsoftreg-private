# 半协议填表加速记录（2026-07-06）

## 本轮目标

在不改动 5s proof / W0 成功路径的前提下，继续压缩注册前半段 UI 填表耗时，并处理慢节点上“只看到 layout 文本框、真实 hsprotect 按钮尚未挂载”导致的 no_result0。

## 已改动

### 1. 填表等待参数化

文件：

```text
controllers/base_controller.py
run_semiprotocol_5s_once.ps1
run_mihomo_semiprotocol_5s_batch.ps1
```

新增环境变量 / 脚本参数，默认值保持旧稳定版不变：

```text
OUTLOOK_SIGNUP_FAST_POST_EMAIL_WAIT_MS
OUTLOOK_SIGNUP_FAST_PRE_PASSWORD_SUBMIT_WAIT_MS
OUTLOOK_SIGNUP_FAST_POST_PASSWORD_WAIT_MS
OUTLOOK_SIGNUP_FAST_BIRTH_INPUT_SETTLE_MS
OUTLOOK_SIGNUP_FAST_BIRTH_SELECT_SETTLE_MS
OUTLOOK_SIGNUP_FAST_DOB_READY_WAIT_MS
OUTLOOK_SIGNUP_FAST_NAME_READY_WAIT_MS
OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_WAIT_MS
OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_POLL_MS
OUTLOOK_SIGNUP_FAST_LEFT_NAME_PAGE_MS
OUTLOOK_SIGNUP_FAST_POST_NAME_SUBMIT_BUFFER_MS
```

### 2. DOB ready gate

新增 `FastDobReadyWaitMs`：在 DOB 页先等 BirthYear/BirthMonth/BirthDay 控件真实可见，再走快速设置。这样避免过早调用 DOB fallback 后退到较慢的 Playwright 控件路径。

### 3. 真实验证码按钮等待参数化

文件：

```text
protocol_runtime_probe.py
run_1s_protocol_restart_once.ps1
run_mihomo_protocol1s_batch.ps1
run_semiprotocol_5s_once.ps1
run_mihomo_semiprotocol_5s_batch.ps1
```

新增：

```text
-RealTargetWaitMs / --real-target-wait-ms
```

用途：慢节点上 instruction text/layout 框先出现，但 nested `role=button` 还没挂载。旧逻辑固定等 12s，遇到 captcha.js 慢加载会直接 abort，形成 `no_result0`。现在可提高到 20s 做慢节点容错。

### 4. timing 汇总工具

新增：

```text
summarize_semiprotocol_fill_timing.py
```

用于从 `*_live_probe.log` 聚合：entry、email、password、DOB、name、captcha 各阶段耗时。

## 本轮 live 结果

### A. fast waits 小批量

命令核心参数：

```powershell
-FastPostEmailWaitMs 120
-FastPrePasswordSubmitWaitMs 80
-FastPostPasswordWaitMs 120
-FastBirthInputSettleMs 80
-FastBirthSelectSettleMs 60
-FastNameReadyWaitMs 60
-FastNameSubmitWaitMs 6500
-FastNameSubmitPollMs 120
-FastPostNameSubmitBufferMs 120
```

结果文件：

```text
Results/protocol_runtime/mihomo_protocol1s_batch_20260706_051259.json
Results/protocol_runtime/semiprotocol_fill_fastwait_analysis_20260706_051259.json
```

结果：

```text
create_account_200: 2
no_result0: 1
trace_fail: 1
```

观察：

- `email_ready -> email_submitted` 从旧约 280ms 降到约 150ms。
- `password_ready -> password_submitted` 从旧约 360ms 降到约 150ms。
- `names_ready` 固定缓冲从旧约 145ms 降到约 80ms。
- DOB 仍主要受页面控件出现时间影响，单纯缩短 settle 不稳定，收益有限。

### B. DOB ready + 20s real target wait

命令核心新增：

```powershell
-FastDobReadyWaitMs 5000
-RealTargetWaitMs 20000
```

结果文件：

```text
Results/protocol_runtime/mihomo_protocol1s_batch_20260706_052255.json
Results/protocol_runtime/semiprotocol_fill_fastwait_dobready_analysis_20260706_052255.json
Results/protocol_runtime/mihomo_protocol1s_batch_20260706_053206.json
Results/protocol_runtime/semiprotocol_fill_fastwait_realtarget_analysis_20260706_053206.json
```

结果：

```text
052255 batch: create_account_200=1, no_result0=3, trace_fail=1
053206 batch: create_account_200=1, trace_fail=1
```

关键样本：

```text
20260706_052603_live_probe.log
  total=84454ms
  password_submitted->dob_submitted=2281ms
  names_ready->name_submitted=2442ms
  human_loaded=2 / human_success=2

20260706_053217_live_probe.log
  total=87832ms
  password_submitted->dob_submitted=2956ms
  names_ready->name_submitted=3051ms
  human_loaded=2 / human_success=2
```

20s real target wait没有破坏成功路径；慢按钮样本能正常升级到真实按钮：

```text
[Probe] time_warp_hold: upgraded to real target box=...
```

但它只能解决“按钮慢挂载”，不能解决 IP/节点导致的 no_result0 或 fresh re-challenge。

## 当前结论

- 填表固定等待已压掉约 `0.4s - 0.7s`。
- DOB 阶段有时可压到约 `2.3s`，但主要瓶颈仍是 DOB 页控件实际渲染时间。
- 总耗时仍主要由验证码阶段决定：单轮约 40s 左右，二次 challenge 会到 80s+。
- 当前最有效的稳定改动不是继续砍 UI 等待，而是：
  1. 保留 fast waits；
  2. 开 `FastDobReadyWaitMs 5000`；
  3. 开 `RealTargetWaitMs 20000`；
  4. 继续减少 fresh re-challenge。

## 推荐实验命令

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 8 `
  -RunsPerNode 1 `
  -TargetSuccessCount 2 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 4 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native `
  -FastPostEmailWaitMs 120 `
  -FastPrePasswordSubmitWaitMs 80 `
  -FastPostPasswordWaitMs 120 `
  -FastBirthInputSettleMs 80 `
  -FastBirthSelectSettleMs 60 `
  -FastDobReadyWaitMs 5000 `
  -FastNameReadyWaitMs 60 `
  -FastNameSubmitWaitMs 6500 `
  -FastNameSubmitPollMs 120 `
  -FastPostNameSubmitBufferMs 120 `
  -RealTargetWaitMs 20000
```

## 下一步

1. 分离“填表耗时”和“验证码耗时”：后续统计只看单 challenge 样本，否则二次 challenge 会淹没填表收益。
2. 继续分析 fresh re-challenge：目前多个 80s+ 成功都是 `human_loaded=2 / human_success=2`，真正耗时来自第一轮 result0 后 host 再发 HumanCaptcha。
3. 如果要继续压总时间，优先做 `result0 -> risk/verify -> fresh challenge` 的判定与规避，而不是继续砍 100ms 级 UI 等待。
