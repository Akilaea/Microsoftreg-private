# HsProtect proof 调试记录（2026-06-22）

## 当前结论

- `Y1NZWSUzXWs=` 前置风险包的 `score|1` 阻断已经能在 Python route 层稳定修到 `score|0`。
- 失败点已从“是否能产生 proof”下沉到 final proof 形态与发送顺序：
  - 自然长按可以产生 `PX561/JDBe/W0`，但原始 proof 带有 `BFA`、`click=True`、`PX11652=2`、超长 `Dz/GU/JNP`，服务端返回 `oIIoIooo|-1`。
  - 旧的静态 template normalizer 能把形态改成手动成功样式，但 live 仍返回 `-1`，说明静态移植过度，和当前运行的坐标/时序/指纹不一致。
- 用户判断“不是按的位置不对，而是加速失败、需要明显超过 1s”与日志一致：短 wall time 不稳定；`wall≈3300ms` 可产 proof，但仍有 final/W0 时序和 proof 噪声问题。

## 关键样本

```text
手动成功:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_103541_me0kwp9vemsfj.jsonl

time_warp 成功案例:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260621_082332_m4c8qtrajpsdo8.jsonl

自然长按失败（用于离线修 proof）:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260622_024529_lvaibkfdlc2qxk.jsonl

静态 template normalizer live 失败:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260622_031841_lcshoq24ibjmbt.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260622_031841_route_normalizer.jsonl

当前 IP blocked:
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260622_035341_hs1p6hi8veq0.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\diagnostics\20260622_035654_registration_not_completed_hs1p6hi8veq0.png
```

## 本次代码改动

- `C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\protocol_runtime_probe.py`
  - 新增 `--final-proof-normalizer {minimal,template,off}`。
  - `minimal` 模式不再整包套用旧成功模板，而是保留当前运行的坐标/时序，只做窄修复：
    - 删除 `BFA+GkExMiE=`；
    - 去掉 dirty fallback 产生的 `pointerdown/mousedown/mouseup/click`；
    - 将最终 active group 的 `PX11652` 压到 `0/1`；
    - 对超长 `GU/JNP` 做当前坐标的确定性采样；
    - 修正异常 `PX561/JDBe R3` 差值。
  - `template` 保留旧行为，便于回放对比。
  - `off` 只修 Y1NZ，不修 final proof。
- `C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\controllers\patchright_controller.py`
  - 新增 `captcha.allow_visible_iframe_fallback=false` 支持。
  - CLI 新增 `--disable-visible-iframe-fallback`，避免先点 outer iframe，减少脏点击污染 final `Dz`。
- `C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\summarize_route_normalizer.py`
  - 摘要里显示 final proof normalizer 模式。

## 已验证

```powershell
python -m py_compile protocol_runtime_probe.py controllers\patchright_controller.py summarize_route_normalizer.py
```

离线对 `20260622_031841_lcshoq24ibjmbt` 的第一个失败 final proof 应用 `minimal` 后：

```text
tags: [aRV, Knp, PX561, JDBe]
BFA: removed
PX561: e=41304 z=[9114] wi=50418 ui=50435 r3=51688
Dz: 25 -> 5
click: True -> False
max PX11652: 2 -> 1
GU/JNP: 150/600 -> 28/56
final_invariants.ok=True
pc_ok=True noise_ok=True payload_roundtrip=True
```

## 当前 live 状态

最后一次 live 没有进入验证码，直接显示日文 blocked 页面：

```text
账号创建被阻止
通常とは異なるアクティビティが検出され、このアカウントの作成がブロックされました。
```

因此本次代码修复还没有拿到有效 live proof 验证。需要新 IP 后继续。

## 下次新 IP 后建议命令

优先验证“不加速 + minimal final + 禁 outer fallback”：

```powershell
cd C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo
python protocol_runtime_probe.py --config config.ctf.protocol_trace.jp.json --fresh-profile-prefix cloak-jpctx-natural-minfinal-jp --use-cloakbrowser --cloak-human-preset careful --mode observe_hold --route-only-hook --defer-route-hook-until-proof --normalize-y1nz-preproof --final-proof-normalizer minimal --disable-visible-iframe-fallback --wait-before-ms 32000 --wait-after-ms 32000
```

如果能进入验证码但自然长按仍失败，再测“长 wall time 的加速路径”：

```powershell
python protocol_runtime_probe.py --config config.ctf.protocol_trace.jp.json --fresh-profile-prefix cloak-jpctx-wall6500-minfinal-jp --use-cloakbrowser --cloak-human-preset careful --mode time_warp_hold --route-only-hook --defer-route-hook-until-proof --normalize-y1nz-preproof --final-proof-normalizer minimal --disable-visible-iframe-fallback --time-warp-hold-ms 9200 --time-warp-wall-ms 6500 --time-warp-stop-delay-ms 300 --time-warp-clock-mode full --normalize-px1200-timing on --align-px561-timing-from-px1200 --inject-knp-sandbox-event --wait-before-ms 32000 --wait-after-ms 26000 --skip-mid-snapshots
```

复测后必须看：

```powershell
python summarize_route_normalizer.py Results\protocol_runtime\<最新>_route_normalizer.jsonl
python analyze_protocol_run.py Results\network\<最新>.jsonl --runtime Results\protocol_runtime\<最新>_final.json
```

成功判定仍然是：

```text
signup.live.com/API/CreateAccount 200
```

