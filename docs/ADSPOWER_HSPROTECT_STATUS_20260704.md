# AdsPower / HsProtect 当前状态与推进思路（2026-07-04）

本文记录当前 AdsPower/SunBrowser 线在 Outlook 注册验证码加速上的实验状态、关键证据、失败原因判断，以及下一步建议。

## 1. 当前目标

目标不是单纯“注册成功一次”，而是：

```text
AdsPower profile 下
自动填表到 HsProtect 验证码
真实视觉上约 1s～1.5s 完成按住验证
最终触发 PX561 / result=0 / CreateAccount 200
并尽量稳定复现
```

当前已确认：

- AdsPower 手动/正常长按在好 IP 下可以成功。
- AdsPower `page.mouse` 路径可以触发 HsProtect final proof，但会同步阻塞，视觉上仍然接近原始长按速度。
- 快速 raw CDP / OOPIF CDP / native SendInput 目前都没有触发 final `PX561`。

## 2. AdsPower 当前运行方式

AdsPower 由用户手动创建/重建 profile，例如：

```text
outlook测试25
outlook测试26
```

每次重建后 `user_id` 会变化，需要重新读取：

```powershell
python .\adspower_cdp_endpoint.py --user-id <user_id> --list-targets --json
```

当前 AdsPower 接入方式是：

```text
protocol_runtime_probe.py
  -> connect_over_cdp
  -> http://127.0.0.1:<AdsPower profile CDP port>
  -> SunBrowser / AdsPower 已启动窗口
```

这和 CloakBrowser 的方式不同：

```text
CloakBrowser:
  protocol_runtime_probe.py
    -> cloakbrowser.launch / launch_persistent_context
    -> fresh profile
    -> 直接控制 Cloak Chromium

AdsPower:
  protocol_runtime_probe.py
    -> connect_over_cdp
    -> 接管已存在的 SunBrowser / AdsPower profile
```

这个差异是当前问题的核心之一。

## 3. 当前验证码链路理解

正常成功链路大致为：

```text
填表
  ↓
risk/initialize
  ↓
CheckAvailableSigninNames
  ↓
risk/verify
  ↓
HumanCaptcha iframe / captcha.js
  ↓
collector / KNP / score
  ↓
按住按钮
  ↓
final proof: PX561
  ↓
HsProtect 返回 result=0
  ↓
宿主页继续 CreateAccount
  ↓
注册成功
```

所以判断一次输入路径是否有效，至少要看：

```text
risk/verify = 200
HumanCaptcha_Loaded 出现
按压后是否出现 PX561
PX561 response 是否 result=0
之后是否 CreateAccount 200
```

如果没有 `PX561`，说明还没进入 HsProtect final proof 生成路径，不能归因到 proof 字段失败。

## 4. 已验证的输入路径

### 4.1 AdsPower `page.mouse.forClick`

代表样本：

```text
Results\network\20260704_065255_uikjxzgmyobxcv.jsonl
Results\protocol_runtime\20260704_065255_uikjxzgmyobxcv.protocol_state.json
```

结果：

```text
backend=page.mouse.forClick
mouseMoved dt_ms≈11391
actual_wall_ms≈12952
PX561 result=0
CreateAccount 200
```

结论：

- 这条路可以触发 `PX561`，甚至可以成功。
- 但是 `mouseMoved` 同步阻塞约 11 秒。
- 用户看到的视觉效果仍然是正常慢速验证码，不符合 1s 目标。

### 4.2 raw CDP + force=0.5

代表样本：

```text
Results\network\20260704_064415_xwaxizoevytloy.jsonl
```

结果：

```text
actual_wall_ms≈1672
input_total_ms≈169
无 PX561
verdict=challenge_pending
```

结论：

- 速度达标。
- 但 HsProtect 不认这条 raw CDP 输入，没有生成 final proof。

### 4.3 fire-and-forget `send_no_reply` + raw release

代表样本：

```text
Results\network\20260704_070524_pgjmnprthilgv.jsonl
```

结果：

```text
input_total_ms≈9
actual_wall_ms≈420
async_raw_cdp_release sent
无 PX561
verdict=challenge_pending
```

结论：

- 程序层阻塞可以绕过。
- 但事件没有被 HsProtect 当成有效完成。

### 4.4 OOPIF direct input

代表样本：

```text
Results\network\20260704_082806_vpjqnlgtpzzp9t.jsonl
```

结果：

```text
已 attach 到 iframe.hsprotect.net ch_ctx=1 OOPIF target
actual_wall_ms≈1514
无 PX561
verdict=challenge_pending
```

结论：

- 目标 iframe/OOPIF 找到了。
- 但直接向 OOPIF target 发 raw CDP mouse event 仍然不触发 final proof。

### 4.5 Windows native SendInput

第一次有效验证码样本：

```text
Results\network\20260704_084601_zpvjocdidbkykc.jsonl
Results\protocol_runtime\20260704_084601_zpvjocdidbkykc.protocol_state.json
Results\protocol_runtime\20260704_084746_zpvjocdidbkykc_outlook.com_time_warp_hold_final.json
```

结果：

```text
risk/verify 200
HumanCaptcha_Loaded 出现
native input_total_ms≈10
actual_wall_ms≈1515
无 PX561
verdict=challenge_pending
```

这轮发现 OS 前台窗口不是 SunBrowser，而是 Edge，因此补了焦点逻辑。

第二次焦点补丁后样本：

```text
Results\network\20260704_090526_ojyctgqlmtps.jsonl
Results\protocol_runtime\20260704_090526_ojyctgqlmtps.protocol_state.json
Results\protocol_runtime\20260704_090711_ojyctgqlmtps_outlook.com_time_warp_hold_final.json
```

关键日志：

```text
focus_ok=True
fg_before=SunBrowser
fg_after=SunBrowser
native_sendinput down page=(496.1,644.6) screen=(503,766)
native_sendinput up page=(496.3,644.5) screen=(503,766)
actual_wall_ms=1508
```

结果：

```text
无 PX561
verdict=challenge_pending
```

用户视觉观察：

```text
进度条走了一部分又停了
```

结论：

- native SendInput 已确认按到 SunBrowser，不是单纯焦点问题。
- 1.5 秒释放时，HsProtect 认为长按未完成，因此不生成 `PX561`。
- 这更像是“真实短按不足以完成当前 AdsPower/HsProtect 分支”，而不是坐标偏移。

## 5. 当前核心矛盾

当前 AdsPower 下形成了一个很明确的二选一问题：

```text
page.mouse / page.mouse.forClick:
  能触发 PX561
  但同步阻塞 10s+

raw CDP / OOPIF CDP / native SendInput:
  真实 1s～1.5s
  但不触发 PX561
```

也就是说，问题不是“怎么把鼠标放到按钮上”，而是：

```text
如何让 HsProtect 在 AdsPower 环境中，
在短真实按压时间内进入 final proof 生成路径。
```

## 6. 为什么 Cloak 不等价于 AdsPower

CloakBrowser 之前的成功/接近成功路线主要特点：

```text
fresh profile
CloakBrowser launch / launch_persistent_context
no Playwright-emulated viewport
短真实按压
time-warp clock
KNP / W0 / PX561 时序修正
```

AdsPower 当前则是：

```text
用户手动创建 profile
SunBrowser / AdsPower 反指纹壳
connect_over_cdp 接管已开窗口
page.mouse.move 在 pressed 状态会被 HsProtect/renderer 同步阻塞
```

因此：

- Cloak 的上层协议参数可以参考。
- Cloak 的底层浏览器/input path 不能直接套到 AdsPower。
- AdsPower profile 目录也不建议直接给 Cloak 当 `user_data_dir`。
- 可行的是提取 AdsPower 的指纹参数，迁移到 Cloak fresh profile 做对照。

## 7. AdsPower profile 能否迁到 Cloak

不建议直接迁目录：

```text
C:\.ADSPOWER_GLOBAL\cache\<user_id>_LOCALCTF
```

原因：

- AdsPower/SunBrowser 有自己的扩展、配置、锁文件、指纹注入状态。
- CloakBrowser 有自己的 fingerprint/humanize 逻辑。
- 两套反指纹壳混用会污染 profile。
- Chromium 版本、Local State、storage/cookie 加密状态也可能不兼容。

但可以迁移参数：

```text
AdsPower profile
  -> 提取 UA / language / timezone / screen / WebGL / platform / proxy
  -> 生成 Cloak runtime config
  -> Cloak fresh profile 启动
  -> 对比 score / PX561 / CreateAccount
```

这个方向的意义是：

```text
Ads 的指纹参数
+
Cloak 更干净的输入链路
```

## 8. 当前代码改动

主要改动文件：

```text
protocol_runtime_probe.py
```

已新增/使用的实验参数：

```text
--hybrid-page-move-for-click
--hybrid-page-move-no-reply
--async-raw-cdp-release-ms
--async-raw-cdp-release-no-wait
--oopif-cdp-hold-input
--oopif-cdp-no-wait
--native-sendinput-hold-input
```

native SendInput 已补充：

```text
EnumWindows 查找 SunBrowser
SetForegroundWindow / BringWindowToTop
记录 fg_before / fg_after
记录 down/up 屏幕坐标
记录 GetCursorPos
```

语法检查通过：

```powershell
python -m py_compile .\protocol_runtime_probe.py
```

## 9. 下一步建议

### 方向 A：Ads-CloakStyle 对照跑法

目的：

```text
尽量复制 Cloak openstyle 的上层参数，
但底层仍使用 AdsPower CDP endpoint，
看是否能生成 PX561。
```

判断：

```text
如果没有 PX561：
  Ads 输入路径仍是瓶颈。

如果有 PX561 但 result=-1/retry：
  进入 proof 字段/时序优化阶段。

如果 PX561 result=0：
  继续优化 CreateAccount/risk 后段。
```

### 方向 B：非点击回调验证

目的：

```text
填表到验证码后，不模拟点击，
hook 宿主页 postMessage / message handler / fetch/XHR，
注入 HsProtect 成功回调，
看宿主页是否会发 CreateAccount。
```

判断：

```text
如果不发 CreateAccount：
  单纯前端成功事件不够，必须真实/伪造 final proof。

如果发 CreateAccount 但后端拒绝：
  Microsoft 后端仍校验 HS token/proof。

如果 CreateAccount 200：
  可以转向纯协议/回调版。
```

### 方向 C：Ads 指纹参数迁移到 Cloak

目的：

```text
从 AdsPower local API / profile 配置中提取指纹参数，
生成 Cloak fresh profile 配置，
利用 Cloak 输入链路继续做 1s proof。
```

这条路可能比继续在 AdsPower 内部硬绕输入阻塞更有性价比。

### 方向 D：继续拆 HsProtect final proof 生成条件

目的：

```text
找到为什么 page.mouse.forClick 能触发 PX561，
而 raw CDP/native 短按不能触发 PX561。
```

重点比较：

```text
event.isTrusted
pointer/mouse event 序列
buttons/button/detail
movementX/movementY
timestamp / performance.now
frame target / OOPIF target
mousemove handler 内部状态机
progress bar 完成条件
```

## 10. 当前推荐优先级

建议优先级：

```text
1. Ads-CloakStyle 对照跑法
2. 非点击成功回调验证
3. Ads 参数迁移到 Cloak fresh profile
4. 深拆 HsProtect final proof 生成条件
```

原因：

- native 已经确认能按到，但短按不完成，继续在 OS 鼠标上消耗收益不高。
- raw CDP/OOPIF 已证明快但不触发 PX561。
- page.mouse.forClick 是唯一已知 Ads 下能触发 PX561 的自动输入路径，但阻塞严重。
- 下一步应先确认是否存在“不依赖 Ads 输入链路”的成功路径。

## 11. 常用命令

查询 AdsPower profile：

```powershell
$env:PYTHONIOENCODING='utf-8'
@'
import json, urllib.request, urllib.parse
q=urllib.parse.urlencode({'page':1,'page_size':300,'search':'outlook'})
data=json.load(urllib.request.urlopen('http://127.0.0.1:50326/api/v1/user/list?'+q))
for p in data.get('data',{}).get('list',[]):
    if p.get('name') == 'outlook测试26':
        print(json.dumps(p, ensure_ascii=False, indent=2))
'@ | python -
```

获取 CDP endpoint：

```powershell
python .\adspower_cdp_endpoint.py --user-id <user_id> --list-targets --json
```

解析 trace：

```powershell
python .\analyze_protocol_run.py Results\network\<trace>.jsonl
python .\protocol_from_adspower_trace.py Results\network\<trace>.jsonl --out-dir Results\protocol_runtime
```

语法检查：

```powershell
python -m py_compile .\protocol_runtime_probe.py
```

