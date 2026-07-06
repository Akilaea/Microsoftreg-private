# 半协议填表推进记录（2026-07-05）

目标：先固定 `5s` 验证码基线，把验证码前的表单阶段从保守 UI 输入切到“半协议填表”。

## 当前实现边界

本轮先落地 **阶段 A：浏览器会话内半协议填表**：

```text
msal_authorize 直接入口
→ live signup 页面正常 mint cookie/canary/uaid
→ email/password/DOB/name 通过 DOM state setter 写入 React 控件
→ 仍由真实 signup 前端触发 risk/verify 和 hsprotect iframe
→ 验证码继续复用当前 ads_safe + 5s time-warp 基线
```

也就是说：当前不是纯 requests 全协议；它保留真实浏览器 profile、真实 signup 前端和真实 hsprotect worker，只把最容易拖慢/卡 UI 的输入动作改成直接状态写入。

这样做的原因：

- 验证码 proof 仍依赖当前浏览器/profile/iframe 上下文；
- 直接 requests 到 `risk/verify/CreateAccount` 还需要稳定抽取 canary、uaid、continuationToken、px3/pxde/pxvid；
- 先把 UI 输入时间压下来，后续再把 `risk/initialize / CheckAvailable / risk/verify / CreateAccount` 分段协议化。

## 新增开关

### `protocol_runtime_probe.py`

新增：

```text
--signup-fill-mode ui|fast_dom|semi_protocol|protocol_assist
```

`ui` 是原保守路径。

- `semi_protocol`：阶段 A，浏览器会话内 DOM state 快速填表；
- `protocol_assist`：阶段 B，在阶段 A 基础上，对 `CheckAvailableSigninNames` 做 in-page fetch 预取，并用 route cache 快速 fulfill UI 后续同名请求。

### `run_1s_protocol_restart_once.ps1`

新增：

```powershell
-SignupFillMode ui|fast_dom|semi_protocol|protocol_assist
```

### `run_mihomo_protocol1s_batch.ps1`

新增同名参数，方便批量节点测试。

### 新 runner

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_semiprotocol_5s_once.ps1
```

默认参数：

```text
WallMs=5000
HoldMs=13000
SignupEntryMode=msal_authorize
SignupFillMode=protocol_assist
BotProtectionWaitSec=0
FinalProofNormalizer=ads_safe
NoSyntheticU0
HybridLegacyDownCdpMoveUp
LegacyShortHoldSteps=24
DelayCaptchaCloseMs=8000
RiskVerifyGateMs=1450 / timeout=8000
RiskVerifyChallengeToContinue enabled by default in the wrapper
```

## 验证命令

单次：

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_semiprotocol_5s_once.ps1
```

只看命令不跑 live：

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_semiprotocol_5s_once.ps1 -DryRun
```

批量节点：

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_mihomo_protocol1s_batch.ps1 `
  -AliveFile C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\.mihomo-isolated\alive_20260705_184555.json `
  -Filter "Video 香港B|Game 新加坡02|Game 美国05|Web 法国I|Web 英国I|Web 加拿大I" `
  -MaxNodes 3 `
  -RunsPerNode 1 `
  -ContinueAfterSuccess `
  -RegisterTimeoutSec 330 `
  -WallMs 5000 `
  -HoldMs 13000 `
  -StopDelayMs 900 `
  -PreDownDwellMs 900 `
  -BotProtectionWaitSec 0 `
  -SignupEntryMode msal_authorize `
  -SignupFillMode protocol_assist `
  -DelayCaptchaCloseMs 8000 `
  -RiskVerifyGateMs 1450 `
  -RiskVerifyGateTimeoutMs 8000 `
  -RiskVerifyChallengeToContinue
```

## 下一阶段

如果阶段 A 能稳定进验证码并 CreateAccount：

1. 抽取 live signup 参数：`sru / uaid / canary / hpgid / scid / apiCanary`。
2. 把 `CheckAvailableSigninNames` 改成 in-page fetch 协议调用。
3. 把 `risk/initialize` 和首次 `risk/verify` 改成协议调用，只把 hsprotect iframe 保留在浏览器。
4. 从 collector final response 抽取 `_px3/_pxde/pxvid`，再协议提交二次 `risk/verify` 和 `CreateAccount`。

## Live 记录

### 2026-07-05 22:45 首测

命令：`run_mihomo_protocol1s_batch.ps1`，`WallMs=5000`、`SignupEntryMode=msal_authorize`、`SignupFillMode=semi_protocol`。

结果：

```text
verdict=no_result0
network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_224527_kbynvxqe4myfuj.jsonl
```

原因：fast DOB 第一版只依赖 DOM setter，遇到英文 Fluent custom combobox 时没有稳定设置 `BirthMonth/BirthDay/BirthYear`。

修正：半协议模式下仍保留原来的 `set_birth_select / set_birth_combo` 兜底，只减少 retry/wait，不再跳过 custom combobox 路径。

### 2026-07-05 22:46 修正后 live 成功

同节点 `Game 新加坡02-标准`，同参数重跑成功：

```text
[Success: Email Registration] - pszimqhkjibwll@outlook.com: aPhu!8oL5a6#rL
verdict=create_account_200
actual_wall_ms≈5277
collector final: score|1 + score|0 + result|0
```

证据：

```text
summary:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260705_224620.json

network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_224624_pszimqhkjibwll.jsonl

runtime:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_224718_pszimqhkjibwll_outlook.com_time_warp_hold_final.json
```

关键时间线（以首个 authorize 请求为 0）：

```text
signup page 200        +6.99s
risk/initialize req    +9.69s
CheckAvailable req     +10.72s
pre-captcha risk/verify +19.74s
captcha iframe ch_ctx=1 +23.98s
HumanCaptcha_Loaded    +28.87s
post-captcha risk/verify +44.13s
CreateAccount req      +45.92s
CreateAccount 200      +48.81s
```

相比之前 `outlook entry + 保守填表` 约 `58s` 的成功样本，本次约 `49s` 完成；真正省掉的是 OWA shell 与 UI typing/dwell，后续主要瓶颈变成 signup 前端加载、captcha asset 加载和 5s hold 本身。

### 2026-07-05 22:53 阶段 B：CheckAvailable 协议预取接入

新增 `protocol_assist`：

```text
1. route("**/API/CheckAvailableSigninNames*") 安装缓存处理器；
2. email DOM 写入后，在 signup 页面内直接 fetch CheckAvailableSigninNames；
3. fetch 使用 live 页面 canary / cookies / uaid / client-request-id；
4. UI 后续点击“下一步”时，同名请求由 route cache 立即 fulfill；
5. 如果 canary 提取或预取失败，自动回退原 UI 网络请求。
```

验证样本：

```text
network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_225341_pvfvtvxfxqtn.jsonl

live log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_225339_live_probe.log
```

关键日志：

```text
CheckAvailable protocol cache route installed
CheckAvailable prefetch result={'ok': True, 'status': 200, 'ms': 579, ...}
CheckAvailable fulfill from protocol cache status=200 used=1
```

该样本进入验证码并产 final，但 collector 返回 `result|-1`，判定为验证码 proof 层失败，不是半协议 CheckAvailable 失败。

### 2026-07-05 22:57 阶段 B live 成功

`protocol_assist + 5s ads_safe` 成功：

```text
[Success: Email Registration] - agwevqkfg8wxdy@outlook.com: kiEouJKd7%E%
verdict=create_account_200
actual_wall_ms≈5314
collector final: score|1 + score|0 + result|0
```

证据：

```text
summary:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260705_225733.json

network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_225737_agwevqkfg8wxdy.jsonl

live log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_225736_live_probe.log

route:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_225737_route_normalizer.jsonl
```

关键日志确认：

```text
CheckAvailable prefetch ok=True status=200 ms=1454.9
CheckAvailable fulfill from protocol cache status=200 used=1
password result={'ok': True}
names result={'ok': True}
CreateAccount=200
```

结论：阶段 B 已跑通。`CheckAvailableSigninNames` 可以从 UI 请求切到 in-page 协议预取，不破坏后续 risk/verify、HsProtect 和 CreateAccount。

### 2026-07-05 23:20 阶段 C 调整：risk/initialize 改成安全观察模式

前一版尝试在 signup 页面里直接 `fetch("https://login.microsoftonline.com/.../risk/initialize")`：

```text
risk/initialize prefetch result={ok: False, reason: "TypeError: Failed to fetch"}
```

网络侧能看到额外的 `risk/initialize` request，但页面 JS 因跨域/CORS 无法读取响应体。这个做法会多打一笔初始化请求，不稳定，也没有真正节省时间。

现在改成更保守的阶段 C：

```text
page.on("response")
→ 不主动预取、不复制请求
→ 不拦截/fulfill risk/initialize
→ 只在真实前端收到 risk/initialize 响应后读取并缓存 continuationToken / humanSensorUrl / providers
```

预期日志：

```text
risk/initialize observed via response listener status=200 read_ms=...
risk/initialize route snapshot status=200 summary={... continuationLen ..., providers:['Human'], hasHumanSensorUrl:true}
```

边界：

- 这一步目前主要是 **捕获/抽参**，不是加速；
- 好处是没有额外 cross-origin prefetch，也不会让失败的 `Failed to fetch` 污染现场；
- 当前版本不再使用 `route.fetch` 拦截 risk/initialize，避免观测逻辑改变前置时序；
- 下一步才能基于缓存到的 `continuationToken + humanSensorUrl` 继续拆首次 `risk/verify`。

新增只读分析脚本：

```powershell
python C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\analyze_semiprotocol_flow.py `
  C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\<run>.jsonl
```

它会输出关键状态机时间线，例如：

```text
authorize.request
signup.response
risk_initialize.request/response
check_available.request/response
risk_verify.challenge
captcha_js
risk_verify.continue
create_account.response
```

验证记录：

```text
2026-07-05 23:24 response-listener 版本成功：

network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_232416_dpcxz8lw4ouz.jsonl

live log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_232415_live_probe.log

关键日志：
risk/initialize observed via response listener status=200 read_ms=3.8
CheckAvailable prefetch ok=True
CheckAvailable fulfill from protocol cache used=1
collector final: score|1 + score|0 + result|0
CreateAccount=200
```

### 2026-07-05 23:39 5s 稳定化加固

目标不是把 IP/RiskBlock 也算进验证码稳定性，而是先把可控的 `collector result|-1` retry 处理掉。

改动：

```text
1. route normalizer 将 final collector 响应结果发布到进程内 FINAL_FETCH_GUARD_STATE；
2. time_warp_hold 等待阶段如果观察到当前尝试的 collector result|-1：
   - 有 retry budget：不再等到 UI timeout，立即重开一轮 fresh 5s hold；
   - 无 retry budget：立即按 proof retry 失败返回，避免 130s 空等；
3. run_semiprotocol_5s_once 默认 Attempts=2、RetryAfterMs=7000、CaptchaCloseGraceMs=3000；
4. network state 增加 risk_verify 403/429 检测，把 RiskBlock 从验证码失败里拆出来。
```

验证：

```text
成功样本：
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_233906_ole2vihenlcrd.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260705_233903_live_probe.log

结果：
collector final: score|1 + score|0 + result|0
CreateAccount=200
actual_wall_ms≈5251
```

随后一跑失败在前置 `risk/verify 403 riskBlock`，还没进入验证码，不计入 5s proof retry：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260705_234020_hwlrwxksoakm.jsonl
risk/verify response=403
RiskBlock
```

### 2026-07-06 00:04 retry 稳定化修正

发现一个导致“第一轮 result|-1 后第二轮不稳定”的细节：

```text
失败样本：
Results\network\20260705_234720_qi9oahbewwbd.jsonl
Results\protocol_runtime\20260705_234720_route_normalizer.jsonl

形态：
first final = result|-1
页面显示英文 Please try again
旧状态机只识别中文“请再试一次”，因此没有按 retry 状态处理
```

本次修正：

```text
1. controllers\patchright_controller.py
   - retry 检测补充 Please try again / Try again / 日文/繁体等 marker。

2. protocol_runtime_probe.py
   - collector passive response capture 增加 seen_at。
   - time_warp_hold 在共享 FINAL_FETCH_GUARD_STATE 未及时可见时，
     从 passive collector responses 里兜底识别 oIIoIooo|-1，
     这样后续可以更快进入 fresh retry。

3. protocol_runtime_probe.py
   - ads_safe normalizer 新增窄修正：
     aRV(2), Knp(4), PX(6), JDBe(7), BFA(8)
     → aRV(2), Knp(3), BFA(4), PX(6), JDBe(7)
   - 目标是对齐已有成功 shifted/natural-U0 样本，避免 stray-U0 把 Knp/BFA counter 推高。

4. run_semiprotocol_5s_once.ps1
   - 状态抽取时按 network 时间戳匹配同名 route log，避免 RiskBlock 样本误配上一轮 route。
```

验证：

```text
节点：Game 日本08-标准（mihomo AUTO_TEST）
network:
Results\network\20260706_000253_jahzfzxndsnk.jsonl
route:
Results\protocol_runtime\20260706_000253_route_normalizer.jsonl
state:
Results\protocol_runtime\semiprotocol_state_20260706_000253_jahzfzxndsnk.json

结果：
first final:  result|-1
fresh retry:  new qi=1783267416146, final result|0
risk/verify: 200 → continue
CreateAccount: 200
```

这一跑证明：半协议填表 + 5s hold 在遇到一次 proof retry 后，仍能在同 profile / 同 IP 下续跑成功。当前主要不可控失败仍是前置 `risk/verify 403 RiskBlock`，应单独归类为节点/IP问题。

### 2026-07-06 00:31 prehold readiness gate 第一轮稳定性验证

继续分析首轮 `result|-1` 的失败簇后，新增了一个 bounded warm-up gate：不是无限等待，而是在真实按钮定位、late runtime hook 安装完成后，最多等待 `PreholdReadinessGateMs=1800`，直到 captcha 侧初始化状态更完整再按下。

当前 gate 条件：

```text
elapsed >= min_elapsed
current_qi 非空且 qi_stable_ms >= 550
collector_pending == 0
scoped_frames >= 6
chctx_frames >= 1
y1nz_ready == true
captcha_js_ok 或 HumanCaptcha_Loaded
failure_seen == false
```

这次重点修正：`chctx_frames` 的可观测 frame URL 统计经常只有 1，但 runtime hook 日志能看到多个 challenge context，所以从 `>=4` 改为 `>=1`，避免 gate 总是超时后才继续。

先做语法和 dry-run：

```text
python -m py_compile .\protocol_runtime_probe.py .\controllers\patchright_controller.py .\extract_semiprotocol_state.py
powershell -ExecutionPolicy Bypass -File .\run_semiprotocol_5s_once.ps1 -DryRun
```

结果均通过。

随后 live 验证：

```text
预热后 3 个有效 live 样本：3/3 首轮 result|0 + CreateAccount 200

1) Game 新加坡02-标准
network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_002748_rolwrj0ashbso.jsonl
route:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_002748_route_normalizer.jsonl
log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_002747_live_probe.log

2) Game 新加坡02-标准
network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_002901_krqkotjvfuqtx.jsonl
route:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_002901_route_normalizer.jsonl
log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_002900_live_probe.log

3) Game 美国05-标准
network:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_003022_wfyyh1hnpc7ngt.jsonl
route:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_003022_route_normalizer.jsonl
log:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_003021_live_probe.log
```

共同特征：

```text
prehold readiness ready=True
qi_stable_ms≈911-1036
collector_pending=0
scoped_frames=7
chctx_frames=1
loaded_seen=True
y1nz_ready=True

final:
score|1 + score|0
result|0
hu_seq = aRV(2), Knp(3), PX561(5), JDBe(6), BFA(7)
CreateAccount=200
```

另外一条无效样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_002508_wukfuoj9aocxa.jsonl

节点：Game 日本08-标准
结果：验证码前 risk/verify 403 RiskBlock；没有进入 final proof。
这个样本继续按节点/IP问题归类，不计入 5s proof 稳定性。

为了避免以后手动忘参数，补了一个批量包装脚本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_mihomo_semiprotocol_5s_batch.ps1
```

它固定传入当前 5s 半协议稳定参数：

```text
WallMs=5000
HoldMs=13000
SignupEntryMode=msal_authorize
SignupFillMode=protocol_assist
FinalProofNormalizer=ads_safe
PreholdReadinessGateMs=1800
DelayCaptchaCloseMs=8000
CaptchaCloseGraceMs=3000
RiskVerifyGateMs=1450
RiskVerifyGateTimeoutMs=8000
RiskVerifyChallengeToContinue=true
AllowSecondAttempt=true
```

用法：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 -MaxNodes 3 -RunsPerNode 1 -ContinueAfterSuccess
```

dry-run 已通过：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 -DryRun -MaxNodes 1
```
```

## 2026-07-06 半协议填表继续推进

### 改动

1. 给 `controllers/base_controller.py` 加了表单阶段计时：

```text
[SemiProtocolFillTiming] entry_ready / email_ready / email_submitted / password_ready / password_submitted / dob_submitted / names_ready / name_submitted / captcha_phase_done
```

2. 增加快速提交模式：

```text
OUTLOOK_SIGNUP_SUBMIT_MODE=dom_fast      # 默认，email/password/DOB 用 DOM click 快速推进
OUTLOOK_SIGNUP_NAME_SUBMIT_MODE=native   # 默认，姓名页保持更保守，避免过早进入 hsprotect 时 real button 未挂载
```

3. `CheckAvailableSigninNames` 预取增加可切换模式：

```text
OUTLOOK_SIGNUP_CHECK_AVAILABLE_PREFETCH_MODE=sync   # 默认，沿用协议预取 + route fulfill
OUTLOOK_SIGNUP_CHECK_AVAILABLE_PREFETCH_MODE=off    # 不预取，走自然 UI 请求；用于对比是否省时/减少额外请求
```

对应 runner 已支持参数：

```powershell
run_semiprotocol_5s_firstpass_once.ps1 `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native

run_mihomo_semiprotocol_5s_firstpass_batch.ps1 `
  -CheckAvailablePrefetchMode off `
  -SubmitMode dom_fast `
  -NameSubmitMode native
```

### Live 结果

#### 基线：旧半协议 5s first-pass

样本：

```text
Results\protocol_runtime\20260706_021713_live_probe.log
Results\network\20260706_021715_nptxezbe2qm1cq.jsonl
```

关键计时：

```text
entry_ready       7120ms
name_submitted   17812ms
entry 后到验证码  10692ms
captcha_phase_done 57683ms
result: success / CreateAccount=200
```

#### 新 dom_fast 提交，CheckAvailable=sync

样本：

```text
Results\protocol_runtime\20260706_022433_live_probe.log
Results\network\20260706_022434_make4bgbcyoq.jsonl
```

关键计时：

```text
entry_ready       13529ms   # 节点/页面加载偏慢，单独看
name_submitted   20456ms
entry 后到验证码  6927ms
captcha_phase_done 57039ms
result: success / CreateAccount=200
```

结论：排除入口波动后，表单阶段从约 `10.7s` 压到约 `6.9s`，主要收益来自按钮提交不再走 Cloak/Playwright 慢点击。

#### 新 dom_fast 提交，CheckAvailable=off

样本：

```text
Results\protocol_runtime\20260706_022610_live_probe.log
Results\network\20260706_022612_sqebefw1hyadn.jsonl
```

关键计时：

```text
entry_ready       6418ms
name_submitted   14162ms
entry 后到验证码  7744ms
captcha_phase_done 48506ms
result: success / CreateAccount=200
```

`off` 模式没有额外预取请求，email_ready 几乎不等待；但自然 CheckAvailable 会转移到 password_ready 阶段，所以表单总时长和 `sync` 接近。当前建议：

- 要最小协议扰动/减少额外请求：用 `-CheckAvailablePrefetchMode off`；
- 要保留 Phase-B 协议预取验证：用默认 `sync`。

### 目前结论

- 半协议填表可稳定保留验证码主线 `final neutral + W0 success`。
- 表单阶段已经从约 `10~11s` 压到 `7s` 左右。
- 总耗时仍主要被入口加载、captcha.js/hsprotect 加载、5s hold、post-hold risk/verify/CreateAccount 吃掉。
- 下一步如果继续压总耗时，优先看：
  1. 入口/Signup 页面复用或预热；
  2. captcha.js 与 real nested button readiness 的等待逻辑；
  3. post-captcha `risk/verify -> CreateAccount` 的协议化。

## 2026-07-06 暂停：CreateAccount 200 假阳性修正

发现问题：部分账号登录提示不存在。复查网络日志后确认：之前的成功判定把 `CreateAccount HTTP 200` 当成创建成功，但该接口会返回：

```json
{"error":{"code":"1350", ...}}
```

这类也是 HTTP 200，但不是注册成功。真正成功响应体应包含类似：

```text
telemetryContext, encPuid, redirectUrl, signinName, slt
```

已确认两个样本是假阳性：

```text
ihgvfnexmurtyj@outlook.com -> CreateAccount error code=1350
sqebefw1hyadn@outlook.com -> CreateAccount error code=1350
```

对应证据：

```text
Results\network\20260706_014954_ihgvfnexmurtyj.jsonl
Results\network\20260706_022612_sqebefw1hyadn.jsonl
```

已修正：

1. `controllers/base_controller.py`
   - `wait_for_create_account_success()` 不再以 HTTP 200 为成功；
   - 必须看到成功响应体字段：`signinName + slt + (redirectUrl 或 encPuid)`；
   - `error.code=1350/1058/...` 会立即判失败，不再写入成功账号文件。

2. `summarize_1s_attempts.py` / `classify_protocol_run.py`
   - `create_200` 改为严格成功响应体；
   - 新增 `create_http_200`、`create_error_code`、`create_body_keys`，保留排错信息。

3. `run_mihomo_protocol1s_batch.ps1`
   - 成功计数现在只在最终 strict verdict 为 `create_account_200` 时增加；
   - 不再因为输出里有 `response POST status=200` 就计为成功。

本地历史审计产物：

```text
Results\protocol_runtime\createaccount_audit_20260706.json
Results\unlogged_email.valid_audit_20260706.txt
Results\unlogged_email.false_positive_20260706.txt
Results\unlogged_email.unknown_audit_20260706.txt
```

历史 `Results\unlogged_email.txt` 未自动覆盖，避免误删；后续以 audit 文件为准。

## 2026-07-06 1350 假阳性根因

结论：`CreateAccount HTTP 200 + error.code=1350` 不是账号创建成功，而是我们之前的 `RiskVerifyChallengeToContinue` 实验开关把第二次 `risk/verify` 的重新挑战响应强行改成了 `state=continue`，导致前端拿着未被服务端认可的 continuationToken 去调用 `CreateAccount`。

关键差异：

```text
成功样本：post-captcha risk/verify 自然返回 state=continue，响应体约 789 bytes，ContinuationToken 长度约 746。
失败1350：post-captcha risk/verify 实际仍返回 riskChallengeRequired，响应体约 1236 bytes；rewriter 把它改成 state=continue，ContinuationToken 长度仍约 767。
```

证据：

```text
false: Results\protocol_runtime\20260706_014954_risk_verify_rewriter.jsonl
idx=2 old_len=1236 rewritten=true state=riskChallengeRequired new_len=810
CreateAccount -> error.code=1350

false: Results\protocol_runtime\20260706_022612_risk_verify_rewriter.jsonl
idx=2 old_len=1236 rewritten=true state=riskChallengeRequired new_len=810
CreateAccount -> error.code=1350

success: Results\protocol_runtime\20260706_022434_risk_verify_rewriter.jsonl
idx=2 old_len=789 rewritten=false state=continue
CreateAccount -> keys: telemetryContext, encPuid, redirectUrl, signinName, slt
```

聚合审计：

```text
29/29 个 error.code=1350 样本都命中 idx=2 rewritten=true
严格成功样本没有这个 rewritten=true 特征
```

因此 `RiskVerifyChallengeToContinue` 不能作为成功路径，它只会制造 CreateAccount 200 假象。已把半协议 5s wrapper 默认改为不启用该开关；如需做隔离实验才显式加：

```powershell
-RiskVerifyChallengeToContinue
```

后续成功必须同时满足：

```text
collector result|0
post-captcha risk/verify 自然 state=continue，不 rewritten
CreateAccount 响应体包含 signinName + slt + redirectUrl/encPuid
```
