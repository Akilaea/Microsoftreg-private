# File Index

This index groups the clean package without changing file locations.  Use
`PACKAGE_MANIFEST.json` as the authoritative machine-readable file list.

## Current Runtime Path

```text
run_mihomo_protocol_takeover_thin_batch.ps1
run_mihomo_protocol1s_batch.ps1
run_1s_protocol_restart_once.ps1
protocol_runtime_probe.py
controllers/base_controller.py
controllers/patchright_controller.py
controllers/playwright_controller.py
```

## Primary Configs

```text
config.ctf.json
config.ctf.json.example
config.ctf.protocol_trace.json.example
config.ctf.cloak_manual_profile.json
config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json
config.json.example
requirements.txt
settings.py
```

## Batch And Single-Run Scripts

```text
preflight_1s_live.ps1
run_1s_goal_live.ps1
run_1s_original_cdp_once.ps1
run_1s_rewrite_once.ps1
run_1s_stability_batch.ps1
run_1s_variant_matrix.ps1
run_1s_w0_defer_once.ps1
run_accel_defer_w0_once.ps1
run_accel_late_only_once.ps1
run_manual_captcha_clean_once.ps1
run_manual_captcha_once.ps1
run_manual_trace.ps1
run_mihomo_openstyle_systemproxy_batch.ps1
run_mihomo_semiprotocol_5s_batch.ps1
run_mihomo_semiprotocol_5s_firstpass_batch.ps1
run_mihomo_us_1s_batch.ps1
run_mihomo_yaml_alive_then_1s.ps1
run_natural_hold_once.ps1
run_protocol_cloak_once.ps1
run_protocol_cloak_openstyle_once.ps1
run_protocol_cloak_short_nou0_once.ps1
run_protocol_narrow_once.ps1
run_rewrite_final_once.ps1
run_semiprotocol_5s_firstpass_once.ps1
run_semiprotocol_5s_once.ps1
```

## Analysis And Evidence Gates

```text
analyze_captcha_events.py
analyze_latest_protocol_run.py
analyze_network_trace.py
analyze_protocol_proof.py
analyze_protocol_run.py
analyze_semiprotocol_flow.py
audit_1s_completion.py
audit_1s_goal_status.py
audit_1s_live_evidence.py
audit_latest_batch_summary.py
classify_protocol_run.py
compare_host_flow.py
compare_protocol_1s_shapes.py
compare_protocol_states.py
diagnose_1s_gap.py
diff_hs_final_fields.py
extract_semiprotocol_state.py
parse_netlog_success.py
status_1s_repro.py
summarize_1s_attempts.py
summarize_risk_capture.py
summarize_route_normalizer.py
summarize_score1_rootcause.py
summarize_semiprotocol_fill_timing.py
summarize_success_invariants.py
triage_1s_latest.py
verify_1s_stability.py
watch_1s_live_goal.py
```

## Protocol And Payload Helpers

```text
decode_hs_payload.py
fetch_hs_assets.py
project_knp_scope.py
rewrite_hs_payload.py
synthesize_protocol_final_body.py
protocol_from_adspower_trace.py
```

## Browser, AdsPower, And Proxy Helpers

```text
adspower_autofill_runner.py
adspower_auto_profile.py
adspower_cdp_endpoint.py
adspower_createaccount_takeover.py
adspower_manual_runner.py
ads_like_cloak_profile_generator.py
build_mihomo_from_subscriptions.py
launch_clean_outlook_proxy.py
launch_cloak_cdp.py
launch_open_outlook_netlog.py
launch_open_outlook_risk_capture.py
launch_open_outlook_risk_cdp_only.py
manual_browser_cdp_observer.py
manual_cdp_observer.py
manual_raw_cdp_observer.py
mihomo_auto_proxy_test.py
mihomo_yaml_alive_probe.py
setup_mihomo_isolated.py
start_mihomo_isolated.ps1
stop_mihomo_isolated.ps1
```

## Static Assets And Historical Artifacts

```text
crcldu_auditor_1781995800000.js
crcldu_sync_1781998200000.html
current_success_diff.txt
diff_w0_px.txt
controllers/base_controller.py.bak_adspower_dob_20260702_052423
controllers/base_controller.py.bak_signup_fields_20260702_053411
```

## Maintenance Tools

```text
tools/check_encoding.py
tools/check_package.py
tools/config_explain.py
```
