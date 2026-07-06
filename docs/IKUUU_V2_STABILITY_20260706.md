# iKuuu_V2 节点池与稳定路线记录（2026-07-06）

## 节点池

新订阅：

```text
C:\Users\wdnmd\Downloads\iKuuu_V2.yaml
```

已合并到隔离 mihomo：

```text
.mihomo-isolated\config.yaml
.mihomo-isolated\iKuuu_V2_20260706_090334.yaml
.mihomo-isolated\config.before_ikuuu_v2_20260706_090334.yaml
.mihomo-isolated\ikuuu_v2_merge_20260706_090334.json
```

合并后总数：`304`，本批新增 `46`，新节点测活 `40/46` 可用。

## V1 protocol_takeover 观察

V1 在新节点上主要失败点仍是验证码前的 host risk：

```text
pre-captcha risk/verify status=403 riskBlock
```

已做一处贴近自然流的修正：

```text
controllers\base_controller.py
signup_protocol_takeover_preverify_transport=page_fetch
```

也就是把 V1 第一次 `risk/verify` 默认改成页面内 `fetch`，不再默认走 `APIRequestContext`。不过实测 `iKuuu_V2 香港S10` 仍然在 pre-captcha `risk/verify` 返回 403，说明这类失败更偏 IP/前置风险，不是验证码 proof 阶段。

验证日志：

```text
Results\protocol_runtime\ikuuu_v2_preverify_pagefetch_probe_20260706_091354.console.log
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_091354.json
```

## 当前稳定成功路线

切回已验证的 5s 半协议路线：

```text
SignupFillMode=protocol_assist
WallMs=5000
W0ResponseMode=real_final_neutral_w0_success
AllowSecondAttempt=true
```

本轮 iKuuu_V2 live：

```text
Results\protocol_runtime\ikuuu_v2_semiprotocol5s_stability_20260706_091459.console.log
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_091500.json
```

结果：

```text
2/2 strict CreateAccount=200
2/2 captcha_protocol_ok
1/2 firstpass_ok
0/2 riskblock
```

成功节点：

```text
HK 43.243.192.91   iKuuu_V2 🇭🇰 香港S06 | x0.8
HK 103.151.172.93  iKuuu_V2 🇭🇰 香港S09 | IEPL
```

结论：当前“稳定成功”应以 `5s protocol_assist + neutral final + W0 result0 + 自动换节点隔离 riskblock/no_result0` 作为基线；V1 protocol_takeover 继续作为后续优化路线，不要用它做成功率基线。

## 推荐继续跑法

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -AliveFile .\.mihomo-isolated\alive_20260706_090454.json `
  -Filter "iKuuu_V2" `
  -ExcludeFilter "" `
  -MaxNodes 20 `
  -RunsPerNode 1 `
  -TargetSuccessCount 5 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 3 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native `
  -AllowSecondAttempt
```

## 扩大验证：TargetSuccessCount=5

命令同上，`MaxNodes=20`，`TargetSuccessCount=5`，成功后继续换节点。

结果文件：

```text
Results\protocol_runtime\ikuuu_v2_semiprotocol5s_target5_20260706_091852.console.log
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_091853.json
```

结果：

```text
total: 8
strict CreateAccount=200: 5
firstpass_ok: 5
captcha_protocol_ok: 5
pre/IP/prefill failures: 3
```

成功节点：

```text
HK 103.151.172.31   iKuuu_V2 🇭🇰 香港S04 | IEPL
HK 103.151.172.89   iKuuu_V2 🇭🇰 香港S11 | IEPL
HK 103.151.172.84   iKuuu_V2 🇭🇰 香港S05 | IEPL
JP 13.158.67.53     iKuuu_V2 🇯🇵 免费-日本2-Ver.8
JP 103.151.173.203  iKuuu_V2 🇯🇵 日本S07 | IEPL
```

失败/隔离节点：

```text
HK 43.243.192.92    iKuuu_V2 🇭🇰 香港S07 | x0.8          real_w0_no_create
HK 43.243.192.97    iKuuu_V2 🇭🇰 香港S08 | x0.8          no_result0
HK 103.151.172.34   iKuuu_V2 🇭🇰 香港S02 | IEPL          riskblock
```

本批口径：只要进入有效验证码并打出 `W0 oIIoIooo|0` 的样本，均进入 `CreateAccount 200`；失败主要仍在 IP/前置/host 层。当前稳定成功方案已经可以自动跳过坏节点直到拿够目标成功数。
