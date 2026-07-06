# 1s 过验证稳定复现 Runbook

> 当前目标：做到 `signup.live.com/API/CreateAccount response status=200`，且物理按压 `wall_ms <= 1500`，最后通过稳定性 gate。

## 成功判定

单次成功必须同时满足：

```text
signup.live.com/API/CreateAccount response status=200
mode=time_warp_hold
short physical hold dispatched
wall_ms <= 1500
```

不要把下面这些单独当成功：

```text
collector_result=0
HumanCaptcha_Success
iframe 消失
```

稳定复现 gate：

```powershell
python verify_1s_stability.py <本轮新增 network jsonl...> --min-successes 3
```

需要输出：

```text
STABLE_PASS
```

目标完成审计：

```powershell
python audit_1s_goal_status.py <本轮新增 network jsonl...> --min-successes 3
```

只有输出下面内容时，才可以认为本目标完成：

```text
GOAL_COMPLETE
```

`run_mihomo_us_1s_batch.ps1` 的最终进程退出码同时跟随 `verify_1s_stability.py`、`audit_1s_goal_status.py` 和严格证据审计：

```text
exit 0  = STABLE_PASS 且 GOAL_COMPLETE 且 GOAL_EVIDENCE_COMPLETE
exit !=0 = 目标未完成或无法审计
```

也可以审计最新 batch summary：

```powershell
python audit_latest_batch_summary.py
```

只有输出下面内容时才算 batch summary 证明目标完成：

```text
BATCH_GOAL_COMPLETE
```

更严格的最终证据审计（会重新读取 batch summary 中记录的 network logs，并重跑 `verify_1s_stability.py` 与 `audit_1s_goal_status.py`）：

```powershell
python audit_1s_live_evidence.py
```

只有输出下面内容时，才算“当前本地证据链”足够支撑目标完成：

```text
GOAL_EVIDENCE_COMPLETE
```

如果 live batch 在另一个窗口运行，可以开 watcher 等待并自动审计新 summary：

```powershell
python watch_1s_live_goal.py --timeout-sec 3600 --interval-sec 15
```

看到 `GOAL_EVIDENCE_COMPLETE` 才能认为目标证据链闭合；超时或 `GOAL_EVIDENCE_NOT_COMPLETE` 都不能标完成。

最终完成前再跑一次总审计：

```powershell
python audit_1s_completion.py
```

只有输出下面内容，才允许把目标标为完成：

```text
GOAL_COMPLETE_AUDIT_PASS
```

如果没通过，先跑最新结果分诊：

```powershell
python triage_1s_latest.py
```

它会输出 `next_action=...`，例如 `RUN_LIVE_BATCH`、`STOP_NODE_AND_SWITCH_IP`、`INSPECT_VERIFY_GATE`。

一键目标 live 入口（测活、batch、最终审计、失败分诊串联）：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_1s_goal_live.ps1 `
  -Filter "US 006|US 008|US 007" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3
```

先只检查参数：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_1s_goal_live.ps1 `
  -Filter "US 006|US 008|US 007" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3 `
  -DryRun
```

## 当前主变体

当前推荐变体：

```text
SessionCachedRichFinalAndW0Success
```

当前模拟旧成功样本的节奏：

```text
第 1 轮：
  final = neutral / 非 result0
  same-qi W0 = minimal score0/result0
  same-qi W0 延迟约 2800ms

第 2 轮起：
  final = rich result0
  W0 = rich result0
```

关键参数：

```text
WallMs = 900
WaitAfterMs = 130000
SessionCachedRichInitialW0DelayMs = 2800
DeferW0WaitMs = 7000
NoTriggerFinalSuccessSignals = true
NoDeferFinalResultToW0 = true
```

这些参数是为了贴近唯一 `CreateAccount 200` 样本：

```text
旧成功：Results\network\20260622_235827_icqygmfmlhziry.jsonl
旧成功 CreateAccount 延迟：
  last HumanCaptcha_Success -> CreateAccount request ≈ 116.5s
  last iframe request       -> CreateAccount request ≈ 117.7s
旧成功首轮 final -> W0 ≈ 2804ms
```

## 当前推荐节点

来自当前 `.mihomo-isolated\config.yaml` 测活：

```text
US006  ip=138.199.35.195  loc=US  delay≈260ms
US008  ip=138.199.35.215  loc=US  delay≈271ms
US007  ip=38.28.193.1     loc=US  delay≈365ms
```

避免继续烧：

```text
SG001  已 RiskBlock
GB006  已 RiskBlock
FR001  之前出现 Refresh the Page，不适合大量烧
```

`run_mihomo_us_1s_batch.ps1` 还会维护动态 RiskBlock ledger：

```text
.mihomo-isolated\riskblock_nodes.json
```

若某节点在 batch 中被判定为 `riskblock`，脚本会记录节点名和出口 IP；后续默认自动排除。需要临时忽略时才加：

```powershell
-IgnoreRiskBlockLedger
```

## 实测前离线自检

```powershell
$env:PYTHONIOENCODING='utf-8'
python selftest_1s_offline.py
```

应全部通过：

```text
PASS test_diagnose_fixtures
PASS test_dryrun_parameters
PASS test_batch_dryrun_parameters
PASS test_verify_gate_fixtures
PASS test_goal_audit_fixtures
PASS test_batch_summary_audit
PASS test_status_and_yaml_entry_dryruns
PASS test_live_evidence_audit_requires_real_logs
PASS test_live_goal_watcher_timeout_mode
PASS test_live_goal_watcher_detects_same_file_update
PASS test_completion_audit_no_summary_fails_cleanly
PASS test_latest_triage_no_summary_points_to_live_batch
PASS test_protocol_contains_close_retry
```

也可以查看整体状态：

```powershell
python status_1s_repro.py
```

看到下面内容表示本地脚本、测活文件和推荐命令都已就绪，可以进入实测：

```text
READY_FOR_LIVE_TEST=True
```

一键 preflight（只跑本地自检、状态和 batch dry-run；不触发真实注册）：

```powershell
powershell -ExecutionPolicy Bypass -File .\preflight_1s_live.ps1 `
  -Filter "US 006" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3
```

## 按当前 mihomo YAML 重新测活

当前 YAML 测活脚本：

```powershell
python .\mihomo_yaml_alive_probe.py `
  --config .\.mihomo-isolated\config.yaml `
  --controller http://127.0.0.1:19090 `
  --group AUTO_TEST `
  --proxy-url http://127.0.0.1:17890 `
  --timeout-ms 4500
```

脚本会从当前 YAML 读取节点、逐个通过 mihomo controller 做 delay/trace，并写入：

```text
.mihomo-isolated\alive_<timestamp>.json
```

后续 `run_mihomo_us_1s_batch.ps1` 会自动读取最新的 `alive_*.json`。

如果要把“YAML 测活 + 使用最新存活节点跑稳定性验证”串起来，用：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_yaml_alive_then_1s.ps1 `
  -Filter "US 006|US 008|US 007" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3 `
  -StopOnRiskBlock
```

先检查参数但不触网/不注册：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_yaml_alive_then_1s.ps1 `
  -Filter "US 006|US 008|US 007" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3 `
  -StopOnRiskBlock `
  -DryRun
```

## 单次实测

先 DryRun：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_us_1s_batch.ps1 `
  -Filter "US 006" `
  -MaxNodes 1 `
  -DryRun
```

确认参数正确后去掉 `-DryRun`：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_us_1s_batch.ps1 `
  -Filter "US 006" `
  -MaxNodes 1
```

脚本会自动：

```text
offline selftest
切 mihomo AUTO_TEST 节点
trace 出口 IP
运行 run_1s_rewrite_once.ps1
summarize_1s_attempts.py
verify_1s_stability.py --min-successes 1
diagnose_1s_gap.py
audit_1s_goal_status.py
audit_latest_batch_summary.py
status_1s_repro.py
```

## 稳定性实测

确认单次出现 `CreateAccount 200` 后，再跑：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_us_1s_batch.ps1 `
  -Filter "US 006" `
  -MaxNodes 1 `
  -RunsPerNode 3 `
  -MinSuccesses 3 `
  -StopOnRiskBlock
```

最终必须看到：

```text
STABLE_PASS
```

默认 stability gate 不带 `--allow-riskblock`，也就是发现 RiskBlock 会严格失败。只有做非判定型排查时才显式加：

```powershell
-AllowRiskBlockInGate
```

## 失败诊断

对本轮 network 日志诊断：

```powershell
python diagnose_1s_gap.py <network-jsonl...> --wait-after-ms 130000
```

常见含义：

```text
PASS_CREATE_200
  已出现 CreateAccount 200。

NOT_1S_WALL
  CreateAccount 成功但物理按压不是 1s，不能算目标完成。

CAPTCHA_CLOSE_MINUS1
  主要卡在 iframe close status=-1；当前 protocol_runtime_probe.py 已改为有 attempts 时等待新 challenge 后重试。

NO_RICH_FINAL_RESULT0
  final 没拿到 rich result0；检查 SessionCachedRichFinalAndW0Success 是否生效。

NO_RICH_W0_RESULT0
  W0 没拿到 rich result0；检查 session cache 和 W0 fulfill 路径。

RISK_BLOCK_STOP_NODE
  停止当前节点，换节点/IP。
```

## 当前关键文件

```text
protocol_runtime_probe.py
run_1s_rewrite_once.ps1
run_accel_defer_w0_once.ps1
run_1s_goal_live.ps1
preflight_1s_live.ps1
mihomo_yaml_alive_probe.py
run_mihomo_yaml_alive_then_1s.ps1
run_mihomo_us_1s_batch.ps1
summarize_1s_attempts.py
verify_1s_stability.py
diagnose_1s_gap.py
audit_1s_goal_status.py
audit_latest_batch_summary.py
audit_1s_live_evidence.py
audit_1s_completion.py
triage_1s_latest.py
watch_1s_live_goal.py
selftest_1s_offline.py
```
