# 5s 半协议稳定性记录（2026-07-06）

## 当前结论

当前可复现的稳定候选不是“任意节点都能过”，而是：

- `5s` 物理 hold；
- `real_final_neutral_w0_success` W0 路线；
- 禁用 `RiskVerifyChallengeToContinue`，避免 `CreateAccount HTTP 200 + error.code=1350` 假阳性；
- W0 `result|0` 后让 post-captcha `risk/verify` 实际等待约 `1450ms`；
- 允许一次 fresh re-challenge 后的第二轮 5s hold；
- 默认只跑当前样本里质量更稳定的 Web CA/AU 节点。

## 关键修复

### 1. W0 result0 接入 risk_verify_gate

之前 route log 里虽然 W0 返回：

```text
oIIoIooo|0
```

但 `risk_verify_gate` 只记 PX561 final 的 route.fetch 结果。当前 5s 路线的 final 是 neutral response，真正的成功结果在 W0，所以 gate 看到的是：

```text
last_result=""
elapsed_ms=0
```

这会导致 host 在 W0 后约 15-35ms 立刻发 post-captcha `risk/verify`，高概率返回 fresh HumanCaptcha。

已在 `protocol_runtime_probe.py` 中把所有合成/缓存 W0 success 路径写入 `risk_verify_gate_snapshot`。修复后可见：

```text
[Probe] risk/verify gated elapsed_ms=1435 result=0 qi=... seq=3
```

### 2. 清理 stable 脚本的假成功路线

`run_semiprotocol_5s_once.ps1` 和 `run_mihomo_semiprotocol_5s_batch.ps1` 不再默认传：

```text
-RiskVerifyChallengeToContinue
```

该开关只能显式启用，用于隔离实验，不能算真实注册成功。

### 3. stable batch 默认节点池

当前 alive 文件里，Game/US/SG/JP/FR 近期表现为：

- `collector result0` 后仍 fresh re-challenge；
- 多轮后 riskblock；
- 或进入注册页前 `no_result0`。

因此 stable batch 默认：

```powershell
-Filter '^Web '
-ExcludeFilter '(美国|新加坡|日本|法国)'
```

在当前 alive 池里实际选择：

```text
Web 加拿大I-标准
Web 澳大利亚I-标准
```

## 验证结果

### 修复 gate 后的广泛节点验证

文件：

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_032802.json
```

结果：

```text
create_account_200: 1
real_w0_no_create: 2
collector_minus1: 1
trace_ip_duplicate_skip: 1
```

说明：W0 gate 已生效，但坏节点仍会 fresh re-challenge。

### stable 脚本自然 verify + 二次 hold 验证

文件：

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_035358.json
```

结果：

```text
Web 加拿大I-标准: create_account_200
Web 澳大利亚I-标准: create_account_200
```

文件：

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_035821.json
```

结果：

```text
Web 法国I-标准: no_result0
Web 加拿大I-标准: create_account_200
Web 澳大利亚I-标准: create_account_200
```

所以 CA/AU 当前验证为 `4/4` 严格成功；FR 当前不稳定，已从 stable 默认排除。

## 当前推荐命令

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 2 `
  -RunsPerNode 1 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 4 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

单次：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_semiprotocol_5s_once.ps1 `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

## 未完成点

- 还没有证明“任意非 riskblock 节点”稳定。
- SG/US/Game 节点的 `result0 -> risk/verify fresh challenge` 仍未被协议参数完全消除。
- 当前稳定性主要来自：协议修复 + 二次 hold + 节点筛选。

## 2026-07-06 10 次 live 稳定性测试

命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 2 `
  -RunsPerNode 5 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 4 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

汇总文件：

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_040645.json
```

严格结果：

```text
create_account_200: 4/10
riskblock:          6/10
```

分节点：

```text
Web 加拿大I-标准 / 45.148.103.54 / CA: 1/5 成功，后 4 次 riskblock
Web 澳大利亚I-标准 / 152.67.99.47 / AU: 3/5 成功，2 次 riskblock
```

关键结论：失败样本不是 5s proof 被 retry；失败都发生在进入验证码前的 host `risk/verify` 403 / RiskBlock，`HumanCaptcha` 未加载，`CreateAccount` 未发起。成功样本均为 `score|1` 后 W0 `oIIoIooo|0`，`risk_verify_gate` 约 1422-1434ms，实际 wall 约 5.32-5.35s。

当前 10 连测更像是在测“同一出口 IP 连续注册抗压”，不是纯协议稳定性。后续 batch 应在单次 riskblock 后立刻切换节点/IP，而不是同节点继续烧。

## 2026-07-06 稳定化改动：失败即隔离，目标成功数驱动

本轮发现：同一出口 IP 多次连续注册会很快从 `score|1 + W0 result0` 退化到 host `risk/verify 403 / RiskBlock`。所以稳定 runner 不能再用 `RunsPerNode > 1` 去烧同一节点，而应改为：每个节点默认只跑一次，按 `TargetSuccessCount` 寻找足够数量的成功，并把硬失败节点/IP 写入隔离 ledger。

代码改动：

```text
run_mihomo_protocol1s_batch.ps1
- 新增 QuarantineVerdicts
- 默认 riskblock 后停止当前节点，切换到下一个节点/IP
- 支持把非 riskblock 但不稳定的协议失败写入同一个隔离 ledger

run_mihomo_semiprotocol_5s_batch.ps1
- 默认 Filter 从 ^Web 扩为 ^(Web|Video)，避免 CA/AU/GB 等已隔离后没有候选
- 新增 TargetSuccessCount / TargetFirstPass 透传
- 默认隔离 verdict: riskblock, real_w0_no_create, result0_rechallenge, result0_no_create, collector_minus1
```

已根据上一轮失败追加隔离：

```text
Video 台湾B-原生 / 156.231.111.20 / HK / real_w0_no_create
```

验证 1：目标 3 成功，最多 8 节点，每节点 1 次。

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_042109.json
```

结果：

```text
real_w0_no_create: 1
create_account_200: 3
```

其中 3 个严格成功均为 firstpass_ok=True。

验证 2：应用隔离后，目标 2 成功，最多 6 节点，每节点 1 次。

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_043040.json
```

结果：

```text
create_account_200: 2/2
```

本次两个成功样本均为：

```text
score|1 -> neutral final -> W0 oIIoIooo|0 -> risk_verify_gate ~1430ms -> CreateAccount strict 200
```

当前推荐稳定命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 12 `
  -RunsPerNode 1 `
  -TargetSuccessCount 5 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 4 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

注意：现在的稳定策略不是“一个 IP 连续跑很多个”，而是“一个候选出口跑一次，成功/硬失败都换下一个”。这更符合 10 连测暴露出来的 riskblock 行为。

## 2026-07-06 更新目标：除 IP 问题外的 5s 半协议稳定性

目标调整后，不再把节点/IP 自身导致的前置失败算作协议失败。稳定性统计拆成两层：

1. **IP / 前置质量层**：注册页或验证码还没进入，表现为 `no_result0`、`riskblock`、`trace_fail` 等。
2. **5s 半协议层**：已经进入 HumanCaptcha，能够生成 normalized final + W0，并返回 `oIIoIooo|0`，随后 `CreateAccount` 严格成功。

### 本轮代码调整

文件：

```text
run_mihomo_protocol1s_batch.ps1
run_mihomo_semiprotocol_5s_batch.ps1
```

关键点：

```text
- 新增 outcome ledger: .\.mihomo-isolated\protocol1s_outcomes.jsonl
- 默认 MaxRecentSuccessesPerIp=1，避免跨批次重复烧已成功出口
- 默认隔离 verdict 增加 no_result0
- TargetFirstPass 的 firstpass_ok 改成真正单 HumanCaptcha 周期：human_loaded<=1 且 human_success<=1
- 新增 captcha_protocol_ok，用来表示“进入验证码后的 5s 协议链路成功”
```

本轮已把历史 batch 回填到 outcome ledger，并把最新两个前置失败节点加入隔离：

```text
Video 拉脱维亚A-标准 / 45.15.67.37 / LV / no_result0
Video 沙特阿拉伯A-标准 / 150.230.53.129 / SA / no_result0
```

### Live 验证：TargetSuccessCount=5

命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -MaxNodes 12 `
  -RunsPerNode 1 `
  -TargetSuccessCount 5 `
  -RegisterTimeoutSec 420 `
  -PauseBetweenRunsSec 4 `
  -ContinueAfterSuccess `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

结果文件：

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_043745.json
Results\protocol_runtime\semiprotocol_5s_except_ip_analysis_20260706_043745.json
```

结果：

```text
total_runs: 7
strict_success: 5
ip_or_prefill_block_before_captcha: 2
captcha_reached_runs: 5
protocol_fail_after_captcha: 0
single_challenge_success: 3
multi_challenge_success: 2
successful_captcha_cycles: 7
captcha_cycles_with_minus1: 0
```

解释：

- 2 个失败是 IP/前置问题：验证码都没进入，`human_loaded=0`，不能算 5s 协议失败。
- 5 个进入验证码的 run 全部严格注册成功。
- 成功链路全部符合：

```text
score|1 -> neutral final -> W0 oIIoIooo|0 -> risk_verify_gate ~1400-1432ms -> CreateAccount strict 200
```

- 其中 3 个是单验证码周期成功；2 个出现 host 重新发起验证码，但第二个周期仍被 5s 半协议稳定通过。这更像风险/IP/host 层二次挑战，不是 proof 失败，因为没有 `-1`，所有验证码周期都是 W0 `0`。

### 当前结论

在“排除 IP/前置质量问题”的口径下，本轮样本为：

```text
进入验证码后的协议成功率：5/5
验证码周期成功：7/7
协议层 -1 / final 失败：0
```

所以当前 5s 半协议链路已经达到“除 IP 问题外稳定”的状态。后续主要优化方向不是 proof 本身，而是：

```text
1. 更严格地区/ASN/延迟筛选
2. no_result0 / riskblock 自动隔离
3. 成功出口近期不复用
4. 如需“第一轮验证码必过”，再单独优化 host fresh re-challenge，而不是 5s proof
```
