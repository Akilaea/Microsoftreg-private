# OutlookRegister CTF Protocol Harness

> 适用范围：CTF / competition sandbox / 内网高仿真靶场。请只在授权的比赛环境、靶场容器、靶场代理节点和允许的测试账号范围内使用。

这个仓库是当前 `protocol_takeover_thin + 5s wall hold` 版本的打包基线。它保留了完整的运行脚本、协议探针、Cloak/Patchright 控制器、节点批量调度和分析工具；默认不会依赖历史 `Results/` 或 `profiles/`。

## 当前版本状态

当前主线：

```text
run_mihomo_protocol_takeover_thin_batch.ps1
  -> run_mihomo_protocol1s_batch.ps1
     -> run_1s_protocol_restart_once.ps1
        -> protocol_runtime_probe.py
```

默认策略：

```text
SignupFillMode=protocol_takeover_thin
SignupEntryMode=msal_authorize
WallMs=5000
HoldMs=13000
PreverifyTransport=page_fetch
ThinGotoWaitUntil=commit
PreverifyMinTotalMs=12000
W0ResponseMode=real_final_neutral_w0_success
RiskVerifyHumanSuccessAgeMs=650
RiskVerifyHumanSuccessTimeoutMs=3000
```

最近验证要点：

- `riskblock` 会自动写入 ledger，后续节点如果命中相同出口 IP 会跳过。
- 已修复一类非 IP 的 `no_result0`：慢节点上 iframe/captcha.js/真实按钮尚未 ready 时，旧逻辑过早放弃。
- 当前版本把 hold 按钮定位预算和 `RealTargetWaitMs` 对齐，并给 KNP prestart guard 增加短重试。
- 最新节点池测试中，修复后小批量结果从大量 `no_result0` 改善为“成功或 riskblock”为主。

## 目录说明

核心文件：

```text
controllers/
  base_controller.py              # 注册流程、协议接管、risk/initialize / risk/verify / CreateAccount 编排
  patchright_controller.py        # Cloak/Patchright 浏览器控制、验证码按钮定位、鼠标行为

protocol_runtime_probe.py         # 运行时 hook、time-warp hold、collector 捕获/归一化、final/W0 处理
run_1s_protocol_restart_once.ps1  # 单次 live 运行包装器
run_mihomo_protocol1s_batch.ps1   # mihomo 节点切换 + 批量运行 + ledger 记录
run_mihomo_protocol_takeover_thin_batch.ps1  # 当前推荐批量入口

config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json
                                  # 当前 5s baseline 配置
ads_like_cloak_profile_generator.py
                                  # 从 AdsPower 元数据/离线模板生成 Cloak 风格 profile 配置

analyze_*.py / audit_*.py / compare_*.py
                                  # trace、collector、proof shape、batch summary 分析工具

docs/
                                  # 当前路线、稳定性、thin bootstrap、first-pass 等记录
```

默认不打包的运行状态：

```text
Results/             # network/runtime/protocol_takeover trace，体积大，含历史账号和响应体
profiles/            # 浏览器 profile，体积大且本地相关
.mihomo-isolated/    # 本地节点池、订阅、riskblock/outcome ledger
.release/            # 历史 release 包
__pycache__/         # Python 缓存
```

## 环境要求

建议环境：

- Windows 10/11
- PowerShell 5+ 或 PowerShell 7+
- Python 3.10+
- 可用的 CloakBrowser / Patchright 环境
- 可用 mihomo mixed proxy 和 controller

默认端口约定：

```text
mihomo mixed proxy: http://127.0.0.1:17890
mihomo controller:  http://127.0.0.1:19090
proxy group:        AUTO_TEST
```

如果你的端口不同，运行时用参数覆盖，不需要改代码。

## 快速开始

### 1. 检查 Python 语法

```powershell
python -m py_compile `
  .\protocol_runtime_probe.py `
  .\controllers\base_controller.py `
  .\controllers\patchright_controller.py
```

### 2. 准备 mihomo

需要有一个可用的 mihomo controller 和 mixed proxy。当前脚本默认：

```text
Controller = http://127.0.0.1:19090
ProxyUrl   = http://127.0.0.1:17890
Group      = AUTO_TEST
```

如果你已经有 alive 节点文件，可以直接指定：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_protocol_takeover_thin_batch.ps1 `
  -AliveFile .\.mihomo-isolated\alive_unseen_strict_YYYYMMDD_HHMMSS.json `
  -Filter "." `
  -MaxNodes 5 `
  -RunsPerNode 1 `
  -TargetSuccessCount 1 `
  -RegisterTimeoutSec 260 `
  -WallMs 5000
```

如果 controller / proxy / group 不同：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_protocol_takeover_thin_batch.ps1 `
  -Controller "http://127.0.0.1:19090" `
  -ProxyUrl "http://127.0.0.1:17890" `
  -Group "AUTO_TEST" `
  -AliveFile .\.mihomo-isolated\alive_latest.json `
  -Filter "." `
  -MaxNodes 5 `
  -RunsPerNode 1 `
  -TargetSuccessCount 1
```

### 3. 单次运行

如果只想验证当前本机代理，不切 mihomo 节点：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_1s_protocol_restart_once.ps1 `
  -WallMs 5000 `
  -HoldMs 13000 `
  -StopDelayMs 900 `
  -PreDownDwellMs 900 `
  -FinalProofNormalizer ads_safe `
  -W0Policy after160 `
  -NoSyntheticU0 `
  -HybridLegacyDownCdpMoveUp `
  -LegacyShortHoldSteps 24 `
  -RequireChctxRuntimeReady `
  -MinRuntimeHookReadyFrames 6 `
  -MinKnpPrestartOk 5 `
  -PreholdHookGuardRetries 2 `
  -PreholdReadinessGateMs 1800 `
  -RealTargetWaitMs 20000 `
  -RetryAfterMs 7000 `
  -SignupEntryMode msal_authorize `
  -SignupFillMode protocol_takeover_thin `
  -W0ResponseMode real_final_neutral_w0_success `
  -W0ResponseWaitMs 3500 `
  -DelayCaptchaCloseMs 8000 `
  -CaptchaCloseGraceMs 3000 `
  -RiskVerifyGateMs 1450 `
  -RiskVerifyGateTimeoutMs 9000 `
  -RiskVerifyHumanSuccessAgeMs 650 `
  -RiskVerifyHumanSuccessTimeoutMs 3000 `
  -PreserveFinalBfa `
  -Config .\config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json
```

## 节点池和 ledger

批量脚本会读取 alive 文件，按延迟排序，逐个切换节点并运行 live。

常见文件：

```text
.mihomo-isolated\alive_latest.json
.mihomo-isolated\alive_unseen_strict_*.json
.mihomo-isolated\riskblock_protocol1s.json
.mihomo-isolated\protocol1s_outcomes.jsonl
```

结果分类：

```text
create_account_200
  CreateAccount 严格成功，账号注册完成。

riskblock
  实际跑了该节点，risk/verify 返回 403 / riskBlock，脚本会记录到 riskblock ledger。

riskblock_ledger_skip
  没有跑注册流程；切节点后 trace 出口 IP，发现该节点名或实际出口 IP 已在 riskblock ledger 中，直接跳过。

no_result0
  没观察到 collector result|0。通常是验证码 iframe / captcha.js / hold button / runtime hook 未完整 ready，或节点加载质量太差。

result0_no_create
  collector 已有 result|0，但 host 后续没完成 CreateAccount。需要看 post-captcha risk/verify 和 CreateAccount 细节。

real_w0_no_create
  W0 result|0 出现但 CreateAccount 未成功。重点看 solution candidate 和 post risk/verify。

collector_minus1
  collector 返回失败结果，通常是 proof shape / timing / 顺序问题。

browser_launch_error
  浏览器或 CDP 启动失败。
```

## 当前成功路径

理想顺序：

```text
risk/initialize 200
pre-captcha risk/verify 200 -> HumanCaptcha
hsprotect iframe + captcha.js loaded
collector bootstrap / Y1NZ / KNP
PX561 final neutral
W0 result|0
post-captcha risk/verify accepted
CreateAccount 200
```

关键日志片段：

```text
[Probe] real/session-final fulfilled W0 success ...
[Probe] collector response ... results=['oIIoIooo|0']
[ProtocolTakeoverV1] post-captcha risk/verify accepted solution_idx=...
[ProtocolTakeoverV1] CreateAccount strict success source=post_verify_continue signin=...
[Success: Email Registration] - ...@outlook.com: ...
```

## 最近关键修复

### 1. Solution candidate 多源尝试

`controllers/base_controller.py` 中增加了 `read_hsprotect_solution_candidates()`，post-captcha `risk/verify` 不再只用 cookie jar，而是按顺序尝试：

1. collector 同一 qi 的 `PX561` / preproof `_px3/_pxde`
2. 相邻 qi 的可用解
3. cookie jar fallback

这主要用于处理：

```text
W0 result|0 已出现，但 post risk/verify 仍返回 HumanCaptcha / riskBlock / no continue token
```

### 2. Thin bootstrap 使用 page_fetch

`risk/initialize` / `pre risk/verify` 在 thin V2 路线下优先使用页面上下文发起，减少 isolated APIRequestContext 和页面状态不一致。

相关环境变量：

```text
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_TRANSPORT=page_fetch
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_MIN_TOTAL_MS=12000
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_GOTO_WAIT_UNTIL=commit
```

### 3. 慢节点 no_result0 修复

`protocol_runtime_probe.py` 中：

- hold button 定位预算现在会参考 `RealTargetWaitMs`，避免 slow node 上 iframe/captcha.js 稍晚 ready 时直接失败。
- KNP prestart guard 增加短重试，避免 ch_ctx frame 刚挂载但 hook 尚未 ready 时误判。

这类失败之前通常长这样：

```text
unable to locate hold button
prehold hook guard: aborting before mouse input because ch_ctx KNP prestart coverage is too low
no_result0
```

修复后这类非 IP 失败显著减少。

## 常用分析命令

分析最新 network/protocol run：

```powershell
python .\analyze_latest_protocol_run.py --no-decode-dump
```

分析 batch summary：

```powershell
python .\audit_latest_batch_summary.py
```

对比 proof shape：

```powershell
python .\compare_protocol_1s_shapes.py
```

快速分类某个 network trace：

```powershell
python .\classify_protocol_run.py .\Results\network\YYYYMMDD_HHMMSS_email.jsonl
```

## 排错手册

### 大量 riskblock

表现：

```text
pre-captcha risk/verify riskblock status=403
post-captcha risk/verify did not continue status=403 innerError riskBlock
```

处理：

- 这是节点/IP 质量问题优先，不先改协议。
- 使用新的 alive_unseen_strict 池继续跑。
- 同出口 IP 会被 ledger 跳过，避免重复消耗。

### 大量 no_result0

优先看日志是否包含：

```text
unable to locate hold button
loaded_seen=false
y1nz_ready=false
KNP prestart coverage is too low
```

处理：

- 保持当前修复后的版本。
- 可适当增大：
  ```text
  -RealTargetWaitMs 24000
  -RegisterTimeoutSec 300
  ```
- 如果仍然集中出现，说明节点加载验证码资源质量差，换池更有效。

### result0 但没 CreateAccount

重点看：

```text
Results\protocol_takeover\*.jsonl
solution_candidates
solution_candidate_attempt
solution_candidate_response
solution_accepted
```

如果 solution candidate 都不被接受，再比较同一 qi 的 `_px3/_pxde`、W0、final 包顺序。

### 浏览器启动失败

检查：

```text
config.*.json -> patchright.browser_path
CloakBrowser 是否存在
profile 目录是否可写
是否有残留 chrome/cloak 进程占用 profile
```

## 输出和隐私

运行后会生成：

```text
Results\network\*.jsonl
Results\protocol_runtime\*.json
Results\protocol_takeover\*.jsonl
profiles\...
```

这些文件可能包含：

- 注册邮箱前缀
- 响应体 / continuation token
- collector proof 片段
- 本地 profile 状态

发布或发给别人前，建议只分享 clean package，不分享 `Results/`、`profiles/` 和 `.mihomo-isolated/`。

## 打包说明

推荐 clean package 排除：

```text
.git/
Results/
profiles/
.mihomo-isolated/
.release/
__pycache__/
*.pyc
*.log
```

当前包保留 source、docs、默认配置和运行脚本。拿到包后如果没有 `.mihomo-isolated`，需要自己重新准备 mihomo config / alive 文件。

## 当前建议使用命令

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_protocol_takeover_thin_batch.ps1 `
  -AliveFile .\.mihomo-isolated\alive_unseen_strict_YYYYMMDD_HHMMSS.json `
  -Filter "." `
  -MaxNodes 5 `
  -RunsPerNode 1 `
  -TargetSuccessCount 1 `
  -RegisterTimeoutSec 260 `
  -PauseBetweenRunsSec 4 `
  -WallMs 5000
```

如果 `riskblock`，脚本会记录并切换下一个节点；如果 `riskblock_ledger_skip`，说明该实际出口 IP 已经在 ledger 中，不会消耗一次注册尝试。

## Maintenance Index

Non-runtime organization helpers were added without changing the current command
surface:

```text
docs/PROJECT_ORGANIZATION.md
docs/RUNTIME_STATE_CONTRACT.md
docs/FILE_INDEX.md
tools/config_explain.py
tools/check_package.py
tools/check_encoding.py
```

Useful read-only checks:

```powershell
python .\tools\config_explain.py
python .\tools\check_package.py --compile
python .\tools\check_encoding.py
python .\selftest_1s_offline.py
```
