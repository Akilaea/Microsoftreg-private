# CTF 注册测试用法

当前结论：

- 旧版自动点击人机验证会触发 `账户创建已被阻止`。
- `manual_captcha=true` 时，脚本自动填表，浏览器进入验证阶段后由人手动完成验证，已验证可成功注册。
- 后续要做“协议注册”，先用 trace 配置抓完整请求顺序，再用 `analyze_network_trace.py` 汇总关键 POST。

## 1. 可用的模拟填表注册

```powershell
cd C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-main
python main.py --config config.ctf.manual.json --max-tasks 1 --concurrent 1
```

流程：

1. 脚本自动打开 Chrome 并填写邮箱、密码、生日、姓名。
2. 进入人机验证后，控制台出现 `[Manual]`。
3. 手动在浏览器里完成验证。
4. 成功账号写入 `Results\unlogged_email.txt`。

可指定账号名/密码，仅限单任务：

```powershell
python main.py --config config.ctf.manual.json --max-tasks 1 --concurrent 1 --email testname123 --password "Aa123456!x"
```

## 2. 带协议 trace 的模拟填表注册

```powershell
powershell -ExecutionPolicy Bypass -File .\run_manual_trace.ps1
```

或指定账号：

```powershell
powershell -ExecutionPolicy Bypass -File .\run_manual_trace.ps1 -Email testname123 -Password "Aa123456!x"
```

输出：

- 注册结果：`Results\unlogged_email.txt`
- 失败截图/文本：`Results\diagnostics\`
- 网络请求日志：`Results\network\*.jsonl`

`config.ctf.trace.json` 默认：

- 记录关键域名请求/响应顺序。
- 记录 POST body，便于协议复现。
- 请求/响应 headers 会记录，但 Cookie/Authorization 默认脱敏。

## 3. 分析最近一次协议 trace

```powershell
python analyze_network_trace.py
```

显示：

- 关键请求顺序
- POST 目标
- POST body 长度和 SHA256 摘要
- URL query 参数名

如需看 POST body 预览：

```powershell
python analyze_network_trace.py --show-post-preview
```

## 4. 下一步协议注册方向

拿到成功 trace 后，优先关注：

1. `signup.live.com` 上的 POST 顺序。
2. 注册提交前后的 `uaid / opid / contextid / client_id / cobrandId` 变化。
3. 人机验证通过后页面提交的最终创建账号请求。
4. 哪些字段来自初始 HTML，哪些字段来自 JS/XHR。

如果最终创建账号请求只依赖可复现 token 和浏览器 cookies，可以再写 `protocol_register.py` 用 `requests.Session` 复现。
如果最终请求依赖新版人机验证的动态 proof，则协议注册仍需浏览器或人工验证阶段产出的 proof。
