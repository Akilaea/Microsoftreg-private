# AdsPower / SunBrowser CDP 接入

当前可用 profile：

```text
name=test1
user_id=1782906748604
profile_dir=C:\.ADSPOWER_GLOBAL\cache\1782906748604_LOCALCTF
```

## 发现当前 CDP endpoint

SunBrowser 使用 `--remote-debugging-port=0` 启动时，真实端口会写入 profile 目录下的
`DevToolsActivePort`。端口可能随重启变化，不要写死。

```powershell
python .\adspower_cdp_endpoint.py --user-id 1782906748604
```

需要查看标签页时：

```powershell
python .\adspower_cdp_endpoint.py --user-id 1782906748604 --list-targets
```

当前验证到的 endpoint：

```text
cdp_endpoint=http://127.0.0.1:10093
browser_ws=ws://127.0.0.1:10093/devtools/browser/3e9863f1-a197-4ba0-976b-869bc9b88d8b
```

## 连接方式

Playwright 可直接 attach：

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://127.0.0.1:10093")
    context = browser.contexts[0]
    page = context.pages[0]
    print(page.title(), page.url)
```

只 attach 时不要调用 `page.close()` / `context.close()`，避免误关 AdsPower 里的页面。

现有 browser-level observer 也可复用：

```powershell
python .\manual_browser_cdp_observer.py --cdp-endpoint http://127.0.0.1:10093 --timeout-seconds 900 --out Results\network\adspower_manual.jsonl
```

注意：`websocket-client` 默认会发送 `Origin` 头，SunBrowser 会返回 `403 remote-allow-origins`。仓库里的
`manual_browser_cdp_observer.py` 和 `manual_raw_cdp_observer.py` 已改为 `suppress_origin=True`。

## 已验证

```text
profile_active=true
devtools_port=10093
/json/version=ok
/json/list=ok
browser_level_cdp_attach=ok
playwright_connect_over_cdp=ok
```

## 半自动实验 runner

新建 AdsPower profile 并打开窗口后，先 dry-run 确认 endpoint 和标签页：

```powershell
python .\adspower_manual_runner.py --user-id <user_id> --label test3 --dry-run
```

正式挂 observer 并等待手动流程：

```powershell
python .\adspower_manual_runner.py --user-id <user_id> --label test3 --timeout-seconds 900 --append-notes
```

runner 会自动完成：

```text
1. 读取 DevToolsActivePort，发现当前 CDP endpoint
2. 查询 AdsPower active 状态
3. 启动 manual_browser_cdp_observer.py
4. 实时打印 risk/verify 和 hsprotect collector 信号
5. 命中 state=continue / riskBlock / collector score=1 后停止 observer
6. 运行 summarize_score1_rootcause.py
7. 可选追加 Results\score1_rootcause_notes.md
```

runner 不负责表单输入；注册流程仍由用户在 SunBrowser 中手动完成。这样可以保持成功样本的人机链路，同时让证据采集和归档自动化。

## 协议状态机抽取

把一次 CDP trace 转成脱敏、机器可读的协议状态：

```powershell
python .\protocol_from_adspower_trace.py Results\network\adspower_test2_live.browser_cdp.jsonl
```

输出默认写到：

```text
Results\protocol_runtime\<trace>.protocol_state.json
```

状态文件包含：

```text
risk/initialize 与 risk/verify 状态序列
HumanCaptcha telemetry
hsprotect collector seq/rsc/tags/score/results
Y1NZ 指纹摘要
关键请求 header 形状
最终 verdict
纯协议复用候选 / 必须浏览器实时生成的边界
```

默认会脱敏账号和 token-like 字段，只保留存在性、长度和短 hash。

多个状态文件对比：

```powershell
python .\compare_protocol_states.py Results\protocol_runtime\success.protocol_state.json Results\protocol_runtime\retry.protocol_state.json
```

对比器会输出每份 trace 的 final class、risk state 序列、collector score 序列、HumanCaptcha 指标，并列出相对第一份 state 的差异。
