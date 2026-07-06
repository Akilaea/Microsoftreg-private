import argparse
import json
from pathlib import Path

from summarize_1s_attempts import (
    live_summary,
    matching_runtime_logs,
    network_summary,
    route_summary,
    verdict,
)


VERDICT_MAP = {
    "CREATE_200": "create_account_200",
    "RISK_BLOCK": "riskblock",
    "CREATE_REQUEST_NO_200": "create_request_no200",
    "COLLECTOR_-1": "collector_minus1",
    "CAPTCHA_CLOSE_-1": "collector_minus1",
    "RESULT0_NO_CREATE": "result0_no_create",
    "RESULT0_RECHALLENGE": "result0_rechallenge",
    "NO_RESULT0": "no_result0",
    "W0_DEFER_NO_CREATE": "w0_defer_no_create",
    "CACHED_W0_NO_CREATE": "cached_w0_no_create",
    "RICH_FINAL_AND_W0_NO_CREATE": "rich_final_and_w0_no_create",
    "MERGED_W0_NO_CREATE": "merged_w0_no_create",
    "REAL_W0_NO_CREATE": "real_w0_no_create",
}


def classify(path: Path) -> dict:
    net = network_summary(path)
    route = route_summary(matching_runtime_logs(net["stamp"], "*_route_normalizer.jsonl"))
    live = live_summary(matching_runtime_logs(net["stamp"], "*_live_probe.log"))
    raw = verdict(net, route, live)
    return {
        "network": str(path),
        "verdict": VERDICT_MAP.get(raw, raw.lower()),
        "raw_verdict": raw,
        "create_200": net.get("create_200"),
        "create_http_200": net.get("create_http_200"),
        "create_error_code": net.get("create_error_code"),
        "create_body_keys": net.get("create_body_keys"),
        "create_request": net.get("create_request"),
        "riskblock": net.get("riskblock") or live.get("riskblock"),
        "captcha_close_minus1": net.get("captcha_close_minus1") or live.get("captcha_close_minus1"),
        "human_loaded": net.get("human_loaded"),
        "human_success": net.get("human_success"),
        "iframe_loads": net.get("iframe_loads"),
        "network_collector_results": net.get("collector_results"),
        "route_collector_results": route.get("collector_results"),
        "route_merged_results": route.get("route_merged_results"),
        "real_final_internal_results": route.get("real_final_internal_results"),
        "route_collector_scores": route.get("collector_scores"),
        "real_final_neutral_w0": route.get("real_final_neutral_w0"),
        "final_shapes": route.get("final_shapes"),
        "risk_verify_gate": route.get("risk_verify_gate"),
        "risk_verify_gate_elapsed_ms": route.get("risk_verify_gate_elapsed_ms"),
        "captcha_close_delayed": route.get("captcha_close_delayed"),
        "captcha_close_suppressed": route.get("captcha_close_suppressed"),
        "captcha_close_delay_elapsed_ms": route.get("captcha_close_delay_elapsed_ms"),
        "actual_wall_ms_values": live.get("actual_wall_ms_values"),
        "route_logs": route.get("route_logs"),
        "live_logs": live.get("live_logs"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Machine-readable classifier for one protocol live run.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    rows = [classify(p) for p in args.paths]
    payload = rows[0] if len(rows) == 1 else rows
    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
