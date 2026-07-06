import argparse
import json
from datetime import datetime
from pathlib import Path

from analyze_protocol_run import analyze_network
from summarize_1s_attempts import (
    matching_runtime_logs,
    network_summary,
    read_jsonl,
    route_summary,
    live_summary,
    verdict,
)


def _parse_ts(value):
    if not value:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _network_timeline(path: Path) -> dict:
    out = {
        "human_success_ts": [],
        "iframe_ts": [],
        "create_req_ts": None,
        "create_200_ts": None,
        "close_minus1_ts": [],
    }
    for _idx, ev in read_jsonl(path):
        ts = _parse_ts(ev.get("ts") or ev.get("timestamp") or ev.get("time"))
        url = ev.get("url") or ""
        text = "\n".join(str(ev.get(k) or "") for k in ("url", "post_data", "body"))
        if "HumanCaptcha_Success" in text and ts:
            out["human_success_ts"].append(ts)
        if ev.get("event") == "request" and "iframe.hsprotect.net/index.html" in url and "ch_ctx=1" in url and ts:
            out["iframe_ts"].append(ts)
        if "captcha_close?status=-1" in url and ts:
            out["close_minus1_ts"].append(ts)
        if ev.get("method") == "POST" and "signup.live.com/API/CreateAccount" in url:
            if ev.get("event") == "request" and ts and out["create_req_ts"] is None:
                out["create_req_ts"] = ts
            if ev.get("event") == "response" and int(ev.get("status") or 0) == 200 and ts:
                out["create_200_ts"] = ts
    cr = out["create_req_ts"]
    out["create_after_last_human_success_s"] = None
    out["create_after_last_iframe_s"] = None
    if cr and out["human_success_ts"]:
        prev = [x for x in out["human_success_ts"] if x <= cr]
        if prev:
            out["create_after_last_human_success_s"] = round((cr - max(prev)).total_seconds(), 3)
    if cr and out["iframe_ts"]:
        prev = [x for x in out["iframe_ts"] if x <= cr]
        if prev:
            out["create_after_last_iframe_s"] = round((cr - max(prev)).total_seconds(), 3)
    return out


def _route_details(paths: list[Path]) -> dict:
    out = {
        "minimal_w0_result0": 0,
        "rich_w0_result0": 0,
        "rich_final_result0": 0,
        "neutral_final": 0,
        "same_qi_minimal_w0": 0,
        "initial_w0_delay_ms": [],
        "final_and_w0_variant_events": 0,
        "final_result_sequence": [],
        "w0_result_sequence": [],
    }

    def classify(tags, parts):
        parts = [str(x) for x in (parts or [])]
        results = [x for x in parts if x.startswith("oIIoIooo|")]
        scores = [x for x in parts if x.startswith("IoIoIo|score|")]
        has_result0 = "oIIoIooo|0" in results
        is_rich = (
            any(x.startswith("IoIIIo|cu") for x in parts)
            and any(x.startswith("oIIoIIoo|_pxde|") for x in parts)
            and any(x.startswith("IoooII|_px3|") for x in parts)
        )
        if "PX561" in tags:
            if has_result0 and is_rich:
                out["rich_final_result0"] += 1
                out["final_result_sequence"].append("rich_result0")
            elif not has_result0:
                out["neutral_final"] += 1
                out["final_result_sequence"].append("neutral")
            elif has_result0:
                out["final_result_sequence"].append("minimal_result0")
        if tags == ["W0cqQR4rLnA="]:
            if has_result0 and is_rich:
                out["rich_w0_result0"] += 1
                out["w0_result_sequence"].append("rich_result0")
            elif has_result0:
                out["minimal_w0_result0"] += 1
                out["w0_result_sequence"].append("minimal_result0")
            else:
                out["w0_result_sequence"].append("neutral")

    for p in paths:
        for _idx, ev in read_jsonl(p):
            tags = ((ev.get("before") or {}).get("tags") or [])
            resp = ev.get("response_decoded_merged") or ev.get("response_decoded") or {}
            parts = [str(x) for x in (resp.get("parts") or [])]
            if ev.get("session_cached_rich_same_qi_minimal_w0"):
                out["same_qi_minimal_w0"] += 1
            if ev.get("session_cached_rich_initial_w0_delay_ms") is not None:
                try:
                    out["initial_w0_delay_ms"].append(int(ev.get("session_cached_rich_initial_w0_delay_ms") or 0))
                except Exception:
                    pass
            if ev.get("session_cached_rich_final_and_w0_success"):
                out["final_and_w0_variant_events"] += 1
            classify(tags, parts)
    return out


def _network_collector_details(path: Path) -> dict:
    out = {
        "minimal_w0_result0": 0,
        "rich_w0_result0": 0,
        "rich_final_result0": 0,
        "neutral_final": 0,
        "final_result_sequence": [],
        "w0_result_sequence": [],
    }

    def classify(tags, parts):
        parts = [str(x) for x in (parts or [])]
        results = [x for x in parts if x.startswith("oIIoIooo|")]
        has_result0 = "oIIoIooo|0" in results
        is_rich = (
            any(x.startswith("IoIIIo|cu") for x in parts)
            and any(x.startswith("oIIoIIoo|_pxde|") for x in parts)
            and any(x.startswith("IoooII|_px3|") for x in parts)
        )
        if "PX561" in tags:
            if has_result0 and is_rich:
                out["rich_final_result0"] += 1
                out["final_result_sequence"].append("rich_result0")
            elif not has_result0:
                out["neutral_final"] += 1
                out["final_result_sequence"].append("neutral")
            else:
                out["final_result_sequence"].append("minimal_result0")
        if tags == ["W0cqQR4rLnA="]:
            if has_result0 and is_rich:
                out["rich_w0_result0"] += 1
                out["w0_result_sequence"].append("rich_result0")
            elif has_result0:
                out["minimal_w0_result0"] += 1
                out["w0_result_sequence"].append("minimal_result0")
            else:
                out["w0_result_sequence"].append("neutral")

    posts, _results = analyze_network(path)
    for post in posts:
        classify(post.get("tags") or [], (post.get("response") or {}).get("parts") or [])
    return out


def _combined_details(route_details: dict, network_details: dict) -> dict:
    out = dict(route_details)
    for key in ("minimal_w0_result0", "rich_w0_result0", "rich_final_result0", "neutral_final"):
        out[key] = max(int(route_details.get(key) or 0), int(network_details.get(key) or 0))
    out["network_minimal_w0_result0"] = network_details.get("minimal_w0_result0", 0)
    out["network_rich_w0_result0"] = network_details.get("rich_w0_result0", 0)
    out["network_rich_final_result0"] = network_details.get("rich_final_result0", 0)
    out["network_final_result_sequence"] = network_details.get("final_result_sequence", [])
    out["network_w0_result_sequence"] = network_details.get("w0_result_sequence", [])
    return out


def diagnose(path: Path, wait_after_ms: int = 130000) -> dict:
    net = network_summary(path)
    route_paths = matching_runtime_logs(net["stamp"], "*_route_normalizer.jsonl")
    live_paths = matching_runtime_logs(net["stamp"], "*_live_probe.log")
    route = route_summary(route_paths)
    live = live_summary(live_paths)
    timeline = _network_timeline(path)
    route_details = _route_details(route_paths)
    network_details = _network_collector_details(path)
    details = _combined_details(route_details, network_details)

    issues = []
    if net["create_200"]:
        issues.append("PASS_CREATE_200")
    if net["riskblock"] or live["riskblock"]:
        issues.append("RISK_BLOCK_STOP_NODE")
    if net["captcha_close_minus1"] or live["captcha_close_minus1"]:
        issues.append("CAPTCHA_CLOSE_MINUS1")
    if live.get("max_wall_ms") and int(live["max_wall_ms"]) > 1500:
        issues.append("NOT_1S_WALL")
    # Do not mark missing route-shape counters against an already accepted
    # CreateAccount run: older route logs can omit W0 fulfill records even
    # though the network analyzer saw the collector result.
    if not net["create_200"]:
        if details["rich_final_result0"] == 0:
            issues.append("NO_RICH_FINAL_RESULT0")
        if details["rich_w0_result0"] == 0:
            issues.append("NO_RICH_W0_RESULT0")
        if details["minimal_w0_result0"] == 0:
            issues.append("NO_INITIAL_MINIMAL_W0_RESULT0")
    if live.get("timeout") and int(wait_after_ms) < 120000:
        issues.append("WAIT_AFTER_TOO_SHORT_FOR_OLD_SUCCESS_DELAY")

    return {
        "path": str(path),
        "verdict": verdict(net, route, live),
        "create_200": net["create_200"],
        "create_request": net["create_request"],
        "riskblock": bool(net["riskblock"] or live["riskblock"]),
        "captcha_close_minus1": bool(net["captcha_close_minus1"] or live["captcha_close_minus1"]),
        "human_success": net["human_success"],
        "iframe_loads": net["iframe_loads"],
        "wall_ms_values": live.get("wall_ms_values") or [],
        "route_logs": [str(x) for x in route_paths],
        "live_logs": [str(x) for x in live_paths],
        "timeline": {
            "create_after_last_human_success_s": timeline["create_after_last_human_success_s"],
            "create_after_last_iframe_s": timeline["create_after_last_iframe_s"],
            "close_minus1_count": len(timeline["close_minus1_ts"]),
        },
        "route_details": details,
        "network_collector_details": network_details,
        "issues": issues,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose why a 1s hsprotect run did or did not reach CreateAccount.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--wait-after-ms", type=int, default=130000)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rows = [diagnose(p, wait_after_ms=args.wait_after_ms) for p in args.paths]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    for row in rows:
        print(f"=== {Path(row['path']).name} :: {row['verdict']} ===")
        print(
            f"create200={row['create_200']} create_req={row['create_request']} "
            f"risk={row['riskblock']} close-1={row['captcha_close_minus1']} "
            f"human_success={row['human_success']} iframe_loads={row['iframe_loads']} "
            f"wall_ms={','.join(map(str,row['wall_ms_values'])) or '-'}"
        )
        print(
            "route_shape="
            f"initial_min_w0={row['route_details']['minimal_w0_result0']} "
            f"rich_final={row['route_details']['rich_final_result0']} "
            f"rich_w0={row['route_details']['rich_w0_result0']} "
            f"net_rich_final={row['route_details']['network_rich_final_result0']} "
            f"net_rich_w0={row['route_details']['network_rich_w0_result0']} "
            f"same_qi_min_w0={row['route_details']['same_qi_minimal_w0']} "
            f"initial_w0_delay_ms={','.join(map(str,row['route_details']['initial_w0_delay_ms'])) or '-'} "
            f"variant_events={row['route_details']['final_and_w0_variant_events']}"
        )
        print(
            "delay="
            f"create_after_human_success_s={row['timeline']['create_after_last_human_success_s']} "
            f"create_after_iframe_s={row['timeline']['create_after_last_iframe_s']} "
            f"close_minus1_count={row['timeline']['close_minus1_count']}"
        )
        print("issues=" + ",".join(row["issues"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
