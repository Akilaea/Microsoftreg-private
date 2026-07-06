# Semiprotocol 5s First-Pass Route - 2026-07-06

## Goal

Push the 5s semiprotocol path toward "first round 100%": one visible HumanCaptcha challenge, no fresh retry/re-challenge, and account creation proceeds from the same challenge.

## Current best route

Use `real_final_neutral_w0_success` instead of trying to force the final PX561 response itself to carry `result|0`.

Observed protocol shape:

```text
seq=2 PX561 final  -> response: score|1, no result exposed to host
seq=3 W0          -> response: score|0 + result|0
host              -> HumanCaptcha_Success + CreateAccount 200
```

This matters because some live runs show the real internal final response would still be `result|-1`, but exposing that `-1` makes the host immediately retry. The first-pass route hides the final result and lets the same challenge complete on the following W0 packet.

## Scripts added/updated

- `run_semiprotocol_5s_firstpass_once.ps1`
  - single live run, fixed `Attempts=1`
  - fixed `W0ResponseMode=real_final_neutral_w0_success`
  - fixed `W0ResponseWaitMs=3500`

- `run_mihomo_semiprotocol_5s_firstpass_batch.ps1`
  - mihomo node batch wrapper for first-pass route
  - uses `SignupEntryMode=msal_authorize`, `SignupFillMode=protocol_assist`
  - uses `WallMs=5000`, `HoldMs=13000`, `PreholdReadinessGateMs=1800`
  - does not pass `AllowSecondAttempt`

- `run_mihomo_protocol1s_batch.ps1`
  - added explicit `-W0ResponseWaitMs` pass-through.

- `summarize_1s_attempts.py` / `classify_protocol_run.py`
  - added evidence fields:
    - `route_merged_results`
    - `real_final_internal_results`
    - `real_final_neutral_w0`

## Validation commands

```powershell
python -m py_compile .\protocol_runtime_probe.py .\controllers\patchright_controller.py .\extract_semiprotocol_state.py .\classify_protocol_run.py .\summarize_1s_attempts.py
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_firstpass_batch.ps1 -MaxNodes 5 -RunsPerNode 1 -ContinueAfterSuccess
```

## Live evidence

### Batch 1

Summary:

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_011648.json
```

Result:

```text
5/5 CreateAccount=200
5/5 entered HumanCaptcha final proof
5/5 first-pass OK via neutral final + W0 result0
0/5 visible retry/re-challenge
0/5 riskblock
```

Nodes:

```text
SG 142.91.102.236     Game 新加坡02-标准
US 150.230.38.62      Game 美国02-原生
US 104.238.222.30     Game 美国05-标准
US 138.2.234.245      Web 美国I-标准
FR 89.168.62.71       Web 法国I-标准
```

Representative logs:

```text
Results\network\20260706_011652_hnpyqk880hldl.jsonl
Results\network\20260706_011751_eej4bsiuc4cy.jsonl
Results\network\20260706_011850_zxlaphvfteoiu.jsonl
Results\network\20260706_011946_uyunrelnsdqd.jsonl
Results\network\20260706_012049_ommoolhqpq6i.jsonl
```

### Batch 2

Summary:

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_012235.json
```

Result:

```text
3/5 CreateAccount=200
3/3 entered HumanCaptcha final proof and first-pass OK
1/5 riskblock before final proof
1/5 no_result0 / IP quality, did not reach final proof
```

Successful nodes:

```text
SG 168.138.178.199    Web 新加坡I-标准
US 129.213.39.184     Game 美国03-标准
CA 45.148.103.54      Web 加拿大I-标准
```

Non-proof failures:

```text
GB 141.147.66.196     Web 英国I-标准      risk/verify 403 RiskBlock before final proof
US 104.238.222.30     Game 美国01-原生    IP quality / did not enter registration final proof
```

## Combined current score

For runs that actually reached the captcha final-proof stage:

```text
8/8 first-pass success
8/8 CreateAccount=200
0/8 visible retry
0/8 fresh qi retry needed
```

Across selected nodes including IP-quality failures:

```text
8/10 CreateAccount=200
1/10 riskblock before captcha proof
1/10 no_result0 before captcha proof
```

## Important nuance

This is first-pass at the host/challenge level, not "final packet itself always returns result0".

In some successful samples, the debug-only real final response still had `result|-1` internally:

```text
final internal: result|-1
host-visible final: score|1 only, no result
W0 visible merged: score|0 + result|0
```

That is exactly why the route improves over the old 5s path: the host never consumes the final `-1`, so it does not enter retry.

## Next work

1. Keep this as current stable 5s first-pass baseline.
2. Increase sample size with only nodes that pass pre-captcha risk/verify.
3. Add a batch mode that targets N valid captcha-final samples, skipping riskblock/no_result0 nodes automatically.
4. Once the 5s first-pass path is stable on larger samples, start lowering `WallMs` again while preserving the neutral-final + W0-success ordering.

## Batch helper improvement

`run_mihomo_protocol1s_batch.ps1` and `run_mihomo_semiprotocol_5s_firstpass_batch.ps1` now support:

```powershell
-TargetSuccessCount N
```

Use it with a larger `-MaxNodes` to keep moving past riskblock / no_result0 nodes until N successful first-pass samples are collected:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_firstpass_batch.ps1 `
  -MaxNodes 20 -TargetSuccessCount 5 -ContinueAfterSuccess
```

## Additional validation - target 10 first-pass samples

Command:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_mihomo_semiprotocol_5s_firstpass_batch.ps1 `
  -MaxNodes 30 -TargetSuccessCount 10 -ContinueAfterSuccess -Filter '^(Game|Web|Video) '
```

Summary:

```text
Results\protocol_runtime\mihomo_protocol1s_batch_20260706_014039.json
```

Result:

```text
10/11 CreateAccount=200
10/10 entered HumanCaptcha final proof and first-pass OK
0/10 visible retry/re-challenge among valid final-proof samples
1/11 no_result0 before captcha final proof (Video 巴林A-标准, ip=38.54.2.135)
```

Successful first-pass nodes:

```text
HK 45.207.40.31       Video 台湾B-原生
HK 156.231.111.45     Video 香港A-解锁
HK 156.231.111.52     Video 香港C-标准
SG 142.91.102.236     Game 新加坡02-标准
TW 114.42.200.155     Video 台湾D-标准
PH 104.28.194.103     Video 菲律宾A-原生
US 104.238.222.108    Video 美国D-原生
US 150.230.38.62      Game 美国02-原生
US 104.238.222.30     Game 美国05-标准
US 138.2.234.245      Web 美国I-标准
```

Representative evidence:

```text
Results\network\20260706_014045_bmzkoqgy1q8wh.jsonl
Results\network\20260706_014134_wvxylnadonynqg.jsonl
Results\network\20260706_014236_ksyvhoi8ebzfqp.jsonl
Results\network\20260706_014326_oyqptyicnstjpx.jsonl
Results\network\20260706_014423_bqffjdjzeemr.jsonl
Results\network\20260706_014523_h6kmgpxrwng3a.jsonl
Results\network\20260706_014619_tshyci2iegb2r.jsonl
Results\network\20260706_014749_tivnycfawyri.jsonl
Results\network\20260706_014954_ihgvfnexmurtyj.jsonl
Results\network\20260706_015111_pakhwctdnlges.jsonl
```

Across recent first-pass batches, valid captcha-final samples are now:

```text
25/25 first-pass OK
25/25 CreateAccount=200
0/25 visible retry/re-challenge
```

Non-proof failures remain outside the captcha proof path:

```text
risk/verify 403 RiskBlock before final proof
IP / node quality no_result0 before final proof
```

## Batch target semantics tightened

`run_mihomo_protocol1s_batch.ps1` now has `-TargetFirstPass`. The first-pass wrapper always passes it, so `-TargetSuccessCount N` means N verified first-pass samples, not merely N `CreateAccount=200` samples.
