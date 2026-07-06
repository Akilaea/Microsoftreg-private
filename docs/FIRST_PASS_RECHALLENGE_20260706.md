# First-pass 二次验证码修复记录（2026-07-06）

## 当前判断

二次验证码不是 `collector` proof 直接失败。

失败样本第一轮的共同点是：

```text
PX561 final / W0 已经给到 result|0
post-captcha risk/verify 仍返回 riskChallengeRequired
随后 host 重新加载 HumanCaptcha
第二轮同样 result|0 后才 state=continue
```

所以问题在 `HumanCaptcha solution -> host risk/verify` 的提交时机/落地顺序，而不是单纯 `final` shape。

## 关键差异

旧 gate 只保证：

```text
W0 result|0 后等待约 1450ms
```

但从失败样本看，`risk/verify` 被放行时，`HumanCaptcha_Success` telemetry 通常还没发出或刚刚发出。也就是：

```text
W0 result|0
-> risk/verify 被放行
-> HumanCaptcha_Success telemetry
-> risk/verify response = riskChallengeRequired
```

一次通过需要更保守地序列化为：

```text
W0 result|0
-> HumanCaptcha_Success telemetry 已出现并稳定一小段时间
-> post-captcha risk/verify
```

## 本次代码改动

新增 first-pass 专用 gate：

```text
--risk-verify-human-success-age-ms
--risk-verify-human-success-timeout-ms
```

逻辑：

1. 只处理携带 `HumanCaptcha challengeSolution` 的第二次 `risk/verify`；
2. 仍然等待 `collector/W0 result|0`；
3. 额外等待当前 result 之后的新鲜 `HumanCaptcha_Success` telemetry；
4. 要求该 telemetry 至少达到指定 age 后再放行 `risk/verify`；
5. 使用 `result_at` 作为 freshness anchor，避免上一轮失败后的旧 success 信号污染下一轮。

默认半协议 5s 当前参数：

```text
RiskVerifyGateMs=1450
RiskVerifyGateTimeoutMs=9000
RiskVerifyHumanSuccessAgeMs=650
RiskVerifyHumanSuccessTimeoutMs=3000
RealTargetWaitMs=20000
Attempts=1
```

`run_mihomo_semiprotocol_5s_batch.ps1` 也不再默认传 `-AllowSecondAttempt`。如果后续要跑“保底注册成功率”，需要显式加：

```powershell
-AllowSecondAttempt
```

## 验证方式

先跑 first-pass 目标，不允许第二轮兜底：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 8 `
  -RunsPerNode 1 `
  -TargetSuccessCount 3 `
  -TargetFirstPass `
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
  -FastPostNameSubmitBufferMs 120
```

观察 route log 中的 gate 记录：

```text
event=risk_verify_gate
last_result=0
human_success_seen=true
human_success_age_ms >= 650
```

如果仍出现第一轮 `riskChallengeRequired`，下一步矩阵：

```text
RiskVerifyHumanSuccessAgeMs = 900 / 1200 / 1600
RiskVerifyGateMs            = 1450 / 2500 / 3500
```

优先调 `HumanSuccessAge`，因为它直接对应二次验证码的 race。
