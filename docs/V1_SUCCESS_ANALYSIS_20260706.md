# V1 protocol_takeover 成功样本分析（2026-07-06）

## 严格成功样本

当前 `Results/protocol_takeover` 里只找到 1 个 V1 严格成功样本：

```text
email: tejvzgy3zcmj@outlook.com
network: Results\network\20260706_083000_tejvzgy3zcmj.jsonl
runtime: Results\protocol_runtime\20260706_082959_live_probe.log
protocol trace: Results\protocol_takeover\20260706_083011_tejvzgy3zcmj_outlook.com.jsonl
final: Results\protocol_runtime\20260706_083045_tejvzgy3zcmj_outlook.com_time_warp_hold_final.json
```

## 时间线

```text
08:29:59 live start
08:30:11 entry_ready / V1 start                    total≈11.35s
08:30:11 risk/initialize request
08:30:12 risk/initialize 200                       +0.61s
08:30:12 CheckAvailable request
08:30:13 CheckAvailable 200                        +1.22s
08:30:13 pre risk/verify request
08:30:14 pre risk/verify 200 riskChallengeRequired +0.80s
08:30:14 challenge shell installed
08:30:37 W0 result0 observed                       V1 captcha≈23.1s
08:30:38 solution cookies ready
08:30:38 post risk/verify request
08:30:42 post risk/verify 200 continue             +3.50s
08:30:42 CreateAccount request
08:30:45 CreateAccount 200 strict success          +3.17s
```

整体耗时约 `45s`。V1 省掉的是密码、生日、姓名等 host 页面推进/加载，不是最初 signup bootstrap 和 HumanCaptcha asset 加载。

## 成功链路

成功链路是：

```text
真实 signup 页面拿 canary/uaid
-> V1 主动 risk/initialize
-> V1 主动 CheckAvailableSigninNames
-> V1 主动 pre risk/verify(empty Human metadata)
-> 返回 riskChallengeRequired + challengeUrl
-> challenge shell 直接加载 iframe.hsprotect ... &ch_ctx=1
-> 5s time-warp + neutral final + W0 result0
-> 读取 _px3/_pxde/_pxvid cookies
-> page_fetch post risk/verify(challengeSolution)
-> 返回 state=continue
-> V1 主动 CreateAccount
-> strict success
```

关键成功点：

```text
pre risk/verify: 200 riskChallengeRequired，不是 403 riskBlock
collector: W0 返回 oIIoIooo|0
post risk/verify: 200 continue，不是再次 riskChallengeRequired
CreateAccount: 200 且 body 有 signinName+slt
```

## 和当前失败样本对比

### 1. 当前 iKuuu 失败

```text
Results\protocol_takeover\20260706_091403_nsbzrwmscjejov_outlook.com.jsonl
```

失败在验证码前：

```text
risk_initialize 200
CheckAvailable 200
pre risk/verify 403 riskBlock
```

所以这类不是验证码失败，也不是加载慢导致的，是 V1 前置风险层直接拒绝。

### 2. pre 通过但 create 不发生的失败

例子：

```text
Results\protocol_takeover\20260706_082806_qkfkinlexbbfgc_outlook.com.jsonl
Results\protocol_takeover\20260706_085510_dybqjcj0nwvjy_outlook.com.jsonl
```

共同点：

```text
pre risk/verify 200 riskChallengeRequired
collector W0 oIIoIooo|0
solution cookies present
post risk/verify 200
```

但失败点是：

```text
post risk/verify 返回 state=riskChallengeRequired
```

也就是 host 风险层不接受这轮 Human solution，要求再次挑战，因此 V1 不会进入 CreateAccount。

## 为什么成功样本能成功

成功样本不是因为 V1 完全绕过验证，而是刚好同时满足三层：

1. **前置风险通过**：pre risk/verify 给 challenge，而不是 riskBlock。
2. **验证码 collector 层通过**：neutral final 后 W0 返回 `oIIoIooo|0`。
3. **host risk 层接受 cookies**：post risk/verify 用 `_px3/_pxde/_pxvid` 返回 `state=continue`。

失败样本通常卡在第 1 层或第 3 层。第 2 层当前 5s/W0 路线已经比较稳。

## 对提速的启发

V1 的优势不是验证码更快，而是能直接跳到 HumanCaptcha，减少中间页面推进：

```text
risk/initialize + CheckAvailable + pre risk/verify -> challengeUrl
```

可复用到 V2 的思路：

- 保留真实 signup bootstrap，只拿必要 canary/uaid/apiCanary。
- 让 pre risk/verify 尽量在页面上下文或自然 host 触发，降低 403。
- 成功拿到 challengeUrl 后，用 V1 challenge shell 直接加载 `ch_ctx=1`，跳过密码/DOB/姓名页面加载。
- 验证码仍走当前稳定 `5s neutral final + W0 result0`。
- post risk/verify 必须以 `state=continue` 为准；若返回 `riskChallengeRequired`，应立即重开 challenge 或换节点，不要继续 CreateAccount。

## 当前判断

V1 可以证明“验证码前大部分可以协议化”，但现版本不稳定的根因是 host risk 层：

```text
pre risk/verify 403
或 post risk/verify 再次 riskChallengeRequired
```

下一步如果要追求加载提速，应做 `V2 hybrid`：用 V1 的 challenge shell 直达验证码，但不要完全复制 V1 的前置风险请求方式；重点优化 pre/post risk/verify 的自然度和失败分支。
