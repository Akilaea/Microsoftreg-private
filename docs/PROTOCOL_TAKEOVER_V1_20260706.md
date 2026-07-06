# Protocol Takeover V1（2026-07-06）

目标：在真实浏览器/profile/验证码环境保留的前提下，把验证码前后注册链路尽量协议化；HumanCaptcha 仍由当前 5s/first-pass 验证码路径处理。

## V1 边界

当前实现新增 `signup_fill_mode=protocol_takeover`：

1. 打开真实 signup/MSAL 入口，保留当前浏览器指纹、cookie、localStorage、页面 canary。
2. Python/Playwright `context.request` 按真实顺序发协议请求：
   - `risk/initialize`：使用页面初始 canary；
   - `CheckAvailableSigninNames`：拿 `apiCanary` / `telemetryContext` / `isAvailable`；
   - pre-captcha `risk/verify`：提交姓名、生日、国家、memberName，获取 HumanCaptcha challenge。
3. 在真实 signup 页面内注入可见 iframe shell，加载返回的 `challengeUrl`。
4. 复用现有 `handle_captcha`（5s/first-pass 路线）完成 HumanCaptcha。
5. 从 hsprotect cookie 中读取 `_px3/_pxde/_pxvid`，等待短 settle 后协议提交：
   - post-captcha `risk/verify`；
   - `CreateAccount`。
6. `CreateAccount` 仍使用严格成功判定：必须有 `signinName + slt`，且有 `redirectUrl/encPuid` 等成功体；不会把 HTTP 200 + `error.code=1350` 当成功。

## 使用方式

单次 dry-run：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_semiprotocol_5s_once.ps1 `
  -SignupFillMode protocol_takeover `
  -DryRun -NoExtractState
```

live 单次（沿用 5s 稳定参数）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_semiprotocol_5s_once.ps1 `
  -SignupFillMode protocol_takeover `
  -NoExtractState
```

批量节点：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_batch.ps1 `
  -SignupFillMode protocol_takeover `
  -MaxNodes 3 -RunsPerNode 1
```

## 新增文件/参数

代码入口：

- `controllers\base_controller.py`
- `protocol_runtime_probe.py`
- `run_1s_protocol_restart_once.ps1`
- `run_mihomo_protocol1s_batch.ps1`
- `run_semiprotocol_5s_once.ps1`
- `run_semiprotocol_5s_firstpass_once.ps1`
- `run_mihomo_semiprotocol_5s_batch.ps1`
- `run_mihomo_semiprotocol_5s_firstpass_batch.ps1`

可调环境变量：

- `OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_COOKIE_TIMEOUT_MS`，默认 `9000`：验证码后等待 `_px3/_pxde` cookie 的时间。
- `OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_POST_SUCCESS_SETTLE_MS`，默认 `650`：拿到 solution cookie 后再提交 post-captcha `risk/verify` 的 settle 时间。
- `OUTLOOK_SIGNUP_COUNTRY_CODE`，默认 `LK`：V1 协议体里的 country code。

V1 trace 输出：

```text
Results\protocol_takeover\<timestamp>_<email>.jsonl
```

## 已验证

- `python -m py_compile controllers\base_controller.py protocol_runtime_probe.py`
- `run_semiprotocol_5s_once.ps1 -SignupFillMode protocol_takeover -DryRun -NoExtractState`

## 预期风险

- 如果 hsprotect iframe 只通知真实 host state 而不落 `_px3/_pxde` cookie，V1 会停在 `solution cookies missing`。
- 如果注入 iframe 后父页面不自动关闭 shell，当前 message hook 会根据 success/postMessage 尝试移除；若仍卡住，下一步应把 captcha handler 改成“result0/cookie 可用即返回”的 V1 专用 handler。
- `context.request` 不触发页面 XHR 事件，因此 V1 单独写 `Results\protocol_takeover` 证据；最终仍以 CreateAccount strict body 为准。
