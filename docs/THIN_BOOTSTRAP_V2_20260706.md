# Thin Bootstrap V2 进展记录（2026-07-06）

## 当前结论

`protocol_takeover_thin` 的方向是有效的：真实页面只加载到 canary/uaid 可用，`entry_ready` 从完整页面路径的约 11s 降到约 2.4–5.1s（个别慢节点 10s）。

但 thin 太早进入 `risk/verify` 会明显触发 pre-captcha `riskBlock`。当前最佳组合是：

```text
SignupFillMode=protocol_takeover_thin
ThinGotoWaitUntil=commit
PreverifyMinTotalMs=12000
PreverifyTransport=page_fetch
WallMs=5000
W0ResponseMode=real_final_neutral_w0_success
```

已固化到：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\run_mihomo_protocol_takeover_thin_batch.ps1
```

默认会设置：

```text
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_MIN_TOTAL_MS=12000
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_TRANSPORT=page_fetch
OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_GOTO_WAIT_UNTIL=commit
```

## A/B 结果

| 批次 | 配置 | 结果 | 结论 |
|---|---|---:|---|
| `20260706_095804` | 12s + api | 1/1 成功 | 证明 pacing 可以让 thin 成功 |
| `20260706_100028` | 12s + api | 0/5 成功 | 4 个 pre-riskblock，1 个 post rechallenge |
| `20260706_100300` | 14s + api | 0/8 成功 | 单纯加长到 14s 没改善 |
| `20260706_100654` | 12s + page_fetch | 3/6 成功 | 当前最佳，preverify transport 是关键变量 |

`page_fetch + 12s` 成功节点：

```text
3.114.209.170     JP  iKuuu_V2 免费-日本1-Ver.7
103.151.173.208   JP  iKuuu_V2 日本S03 | IEPL
103.151.173.91    JP  iKuuu_V2 日本S10 | IEPL
```

## 关键证据

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260706_095804.json
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260706_100028.json
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260706_100300.json
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260706_100654.json
```

成功样本：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_100717_q4slabajahka.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_100757_q4slabajahka_outlook.com_time_warp_hold_final.json

C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\network\20260706_100952_jxcocsnmuhvs.jsonl
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\20260706_101032_jxcocsnmuhvs_outlook.com_time_warp_hold_final.json
```

## 失败分类

1. `pre risk/verify 403 riskBlock`
   - thin bootstrap 本身快，但 preverify 仍会被节点/IP/上下文质量放大。
   - `api` transport 比 `page_fetch` 更容易出现。

2. `real_w0_no_create`
   - collector 已有 `W0 result0`，但 post `risk/verify` 返回 `riskChallengeRequired`。
   - 这类不是验证码 final 完全失败，而是 post verify 没接受当前 cookie/source。

3. `no_result0`
   - 进入挑战后没有稳定拿到 W0 `result0`。

## 下一步

优先沿着当前最佳组合继续做两件事：

1. **稳定性**：继续用 `page_fetch + 12s` 跑更多节点，单独统计 `pre-riskblock` 和 `post rechallenge`。
2. **速度**：在成功节点上小步降低 `PreverifyMinTotalMs`：`11000 -> 10000 -> 9000`，看 pre-riskblock 是否回升。

如果 `post rechallenge` 仍高，下一步重点对比成功/失败的 post verify source：

```text
pxvid 来源
_px3/_pxde 使用 collector response 还是尾部 cookie
challenge uuid/vid 是否和当前 iframe 精确一致
post risk/verify 发送时机与 W0 result0 age
```

## 11s 下探结果

后续用同一 wrapper 参数只把 `PreverifyMinTotalMs` 降到 `11000`：

```text
C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\protocol_runtime\mihomo_protocol1s_batch_20260706_101303.json
```

结果：

```text
1/8 CreateAccount 200
1/8 no_result0（入口/IP质量问题）
6/8 real_w0_no_create 或 no_result0
```

关键对照：`103.151.173.208` 在 12s/page_fetch 批次里成功，在 11s/page_fetch 批次里变成 `real_w0_no_create`。这说明下探到 11s 后，失败不一定表现为 pre-403，而会变成 post `risk/verify` 不接受当前 `W0 result0`，重新返回 `riskChallengeRequired`。

暂定结论：`12000ms` 是当前 thin V2 比较安全的下限；继续降到 11s 得不偿失，除非先解决 post verify source/cookie 绑定问题。
