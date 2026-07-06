import argparse
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

from analyze_protocol_run import analyze_network


ROOT = Path(__file__).resolve().parent
NETWORK_DIR = ROOT / "Results" / "network"
RUNTIME_DIR = ROOT / "Results" / "protocol_runtime"


def parse_stamp_from_name(path: Path) -> datetime | None:
    m = re.match(r"(\d{8})_(\d{6})", path.name)
    if not m:
        return None
    try:
        return datetime.strptime("".join(m.groups()), "%Y%m%d%H%M%S")
    except Exception:
        return None


def ts_ms(value) -> float | None:
    if not value:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp() * 1000.0
    except Exception:
        return None


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                yield idx, json.loads(line)
            except Exception:
                continue


def network_summary(path: Path) -> dict:
    posts, results = analyze_network(path)
    out = {
        "network": str(path),
        "stamp": parse_stamp_from_name(path),
        "collector_results": results,
        "collector_posts": len(posts),
        "create_request": False,
        "create_200": False,
        "create_http_200": False,
        "create_error_code": "",
        "create_body_keys": [],
        "riskblock": False,
        "captcha_close_minus1": False,
        "human_success": 0,
        "human_loaded": 0,
        "iframe_loads": 0,
        "rounds": [],
    }
    first_iframe_ms = None
    for idx, ev in read_jsonl(path):
        text = "\n".join(str(x or "") for x in (ev.get("url"), ev.get("post_data"), ev.get("body")))
        url = ev.get("url") or ""
        if ev.get("method") == "POST" and "signup.live.com/API/CreateAccount" in url:
            if ev.get("event") == "request":
                out["create_request"] = True
            if ev.get("event") == "response" and int(ev.get("status") or 0) == 200:
                out["create_http_200"] = True
                body = str(ev.get("body") or "").strip()
                try:
                    parsed = json.loads(body) if body else {}
                except Exception:
                    parsed = {}
                if isinstance(parsed, dict):
                    out["create_body_keys"] = sorted(str(k) for k in parsed.keys())
                    err = parsed.get("error")
                    if isinstance(err, dict):
                        out["create_error_code"] = str(err.get("code") or "")
                    if (
                        parsed.get("signinName")
                        and parsed.get("slt")
                        and (parsed.get("redirectUrl") or parsed.get("encPuid"))
                    ):
                        out["create_200"] = True
        if "RiskBlock" in text or "Abuse" in text or "Enforcement" in text or "异常活动" in text:
            out["riskblock"] = True
        if "captcha_close?status=-1" in url:
            out["captcha_close_minus1"] = True
        if "HumanCaptcha_Success" in text:
            out["human_success"] += 1
        if "HumanCaptcha_Loaded" in text:
            out["human_loaded"] += 1
        if ev.get("event") == "request" and "iframe.hsprotect.net/index.html" in url and "ch_ctx=1" in url:
            out["iframe_loads"] += 1
            if first_iframe_ms is None:
                first_iframe_ms = ts_ms(ev.get("ts") or ev.get("timestamp") or ev.get("time"))
    by_qi = {}
    for p in posts:
        qi = str(p.get("qi") or "")
        if not qi or qi == "1604064986000":
            continue
        tags = p.get("tags") or []
        item = by_qi.setdefault(qi, {"qi": qi, "u0": None, "w0": None, "final": None, "results": []})
        kind = None
        if "U0MpSRYiJH8=" in tags:
            kind = "u0"
        if "W0cqQR4rLnA=" in tags:
            kind = "w0"
        if "PX561" in tags:
            kind = "final"
        if kind:
            item[kind] = p.get("ts_ms")
        resp = p.get("response") or {}
        item["results"].extend(resp.get("results") or [])
    for item in by_qi.values():
        u0, w0, final = item.get("u0"), item.get("w0"), item.get("final")
        item["u0_to_final_ms"] = round(final - u0, 1) if u0 and final else None
        item["final_to_w0_ms"] = round(w0 - final, 1) if w0 and final else None
        out["rounds"].append(item)
    return out


def matching_runtime_logs(
    stamp: datetime | None,
    pattern: str,
    tolerance_seconds: int = 20,
    limit: int | None = 1,
):
    """Return runtime logs nearest to a network capture timestamp.

    Batch runs can start attempts close together.  Returning every file inside
    a broad time window lets a neighboring attempt's route/live log pollute the
    current network verdict.  Keep the default window intentionally narrow and
    return only the nearest match; callers can pass limit=None when they
    intentionally want all matches.
    """
    if not stamp:
        return []
    logs = []
    for p in RUNTIME_DIR.glob(pattern):
        s = parse_stamp_from_name(p)
        if not s:
            continue
        delta = abs((s - stamp).total_seconds())
        if delta <= tolerance_seconds:
            logs.append((delta, p))
    logs = sorted(logs, key=lambda x: (x[0], x[1].stat().st_mtime))
    if limit is not None:
        logs = logs[: max(0, int(limit))]
    return [p for _, p in logs]


def route_summary(paths: list[Path]) -> dict:
    out = {
        "route_logs": [str(p) for p in paths],
        "collector_results": [],
        "collector_scores": [],
        "final_shapes": [],
        "optimistic_final": 0,
        "optimistic_final_deferred_to_w0": 0,
        "deferred_w0": 0,
        "rewrite_final": 0,
        "neutral_fetch_w0": 0,
        "neutral_merge_w0": 0,
        "neutral_cached_w0": 0,
        "real_final_neutral_w0": 0,
        "route_merged_results": [],
        "real_final_internal_results": [],
        "session_cached_rich_final_and_w0": 0,
        "fetch_errors": 0,
        "risk_verify_gate": 0,
        "risk_verify_gate_elapsed_ms": [],
        "captcha_close_delayed": 0,
        "captcha_close_suppressed": 0,
        "captcha_close_delay_elapsed_ms": [],
    }
    for p in paths:
        for _, ev in read_jsonl(p):
            if ev.get("event") == "risk_verify_gate":
                out["risk_verify_gate"] += 1
                if ev.get("elapsed_ms") is not None:
                    out["risk_verify_gate_elapsed_ms"].append(ev.get("elapsed_ms"))
            if ev.get("event") in {"captcha_close_minus1_delayed", "captcha_close_minus1_suppressed"}:
                out["captcha_close_delayed"] += 1
                if ev.get("event") == "captcha_close_minus1_suppressed":
                    out["captcha_close_suppressed"] += 1
                if ev.get("elapsed_ms") is not None:
                    out["captcha_close_delay_elapsed_ms"].append(ev.get("elapsed_ms"))
            if ev.get("optimistic_final_success"):
                out["optimistic_final"] += 1
            if ev.get("optimistic_final_deferred_to_w0"):
                out["optimistic_final_deferred_to_w0"] += 1
            if ev.get("deferred_final_result_to_w0"):
                out["deferred_w0"] += 1
            if ev.get("response_rewritten_final_success"):
                out["rewrite_final"] += 1
            if ev.get("neutral_final_fetch_w0"):
                out["neutral_fetch_w0"] += 1
            if ev.get("neutral_final_merge_w0_success"):
                out["neutral_merge_w0"] += 1
            if ev.get("neutral_final_cached_w0_success"):
                out["neutral_cached_w0"] += 1
            if ev.get("real_final_neutral_w0_success"):
                out["real_final_neutral_w0"] += 1
            if ev.get("session_cached_rich_final_and_w0_success"):
                out["session_cached_rich_final_and_w0"] += 1
            if ev.get("route_fetch_error"):
                out["fetch_errors"] += 1
            decoded = ev.get("response_decoded") or {}
            for result in decoded.get("results") or []:
                out["collector_results"].append(str(result))
            for score in decoded.get("scores") or []:
                out["collector_scores"].append(str(score))
            merged_decoded = ev.get("response_decoded_merged") or {}
            for result in merged_decoded.get("results") or []:
                out["route_merged_results"].append(str(result))
            real_final_decoded = ev.get("real_final_response_decoded") or {}
            for result in real_final_decoded.get("results") or []:
                out["real_final_internal_results"].append(str(result))
            final_inv = ((ev.get("after") or {}).get("final_invariants") or
                         (ev.get("before") or {}).get("final_invariants"))
            if final_inv:
                out["final_shapes"].append({
                    "ok": final_inv.get("ok"),
                    "shape_ok": final_inv.get("shape_ok"),
                    "hu_ok": final_inv.get("hu_ok"),
                    "r3_ui_ok": final_inv.get("r3_ui_ok"),
                    "r3_ui_delta": final_inv.get("r3_ui_delta"),
                    "hu": final_inv.get("hu"),
                })
    return out


def live_summary(paths: list[Path]) -> dict:
    out = {
        "live_logs": [str(p) for p in paths],
        "riskblock": False,
        "create_success": False,
        "create_observed": False,
        "timeout": False,
        "captcha_close_minus1": False,
        "mode_time_warp": False,
        "short_hold_count": 0,
        "wall_ms_values": [],
        "actual_wall_ms_values": [],
        "fake_hold_ms_values": [],
        "max_wall_ms": None,
        "min_wall_ms": None,
        "max_actual_wall_ms": None,
        "min_actual_wall_ms": None,
    }
    needles_risk = [
        "Error: Rate limit",
        "RiskBlock",
        "state=blocked",
        "status=403",
        "riskblock status=403",
        "异常活动",
        "闃绘柇",
    ]
    for p in paths:
        text = p.read_text(encoding="utf-8", errors="replace")
        if any(x in text for x in needles_risk):
            out["riskblock"] = True
        if "[Success: Email Registration]" in text or "CreateAccount strict success" in text:
            out["create_success"] = True
        if "CreateAccount observed" in text or "signup.live.com/API/CreateAccount" in text:
            out["create_observed"] = True
        if "timed out waiting after short hold" in text or "TimeoutError" in text:
            out["timeout"] = True
        if "captcha close status=-1" in text or "captcha_close?status=-1" in text:
            out["captcha_close_minus1"] = True
        if "mode=time_warp_hold" in text:
            out["mode_time_warp"] = True
        out["short_hold_count"] += len(re.findall(r"short physical hold dispatched", text))
        for m in re.finditer(r"fake_hold_ms=(\d+)\s+wall_ms=(\d+)", text):
            try:
                out["fake_hold_ms_values"].append(int(m.group(1)))
                out["wall_ms_values"].append(int(m.group(2)))
            except Exception:
                pass
        for m in re.finditer(r"actual_wall_ms=(\d+)", text):
            try:
                out["actual_wall_ms_values"].append(int(m.group(1)))
            except Exception:
                pass
    if out["wall_ms_values"]:
        out["max_wall_ms"] = max(out["wall_ms_values"])
        out["min_wall_ms"] = min(out["wall_ms_values"])
    if out["actual_wall_ms_values"]:
        out["max_actual_wall_ms"] = max(out["actual_wall_ms_values"])
        out["min_actual_wall_ms"] = min(out["actual_wall_ms_values"])
    return out


def verdict(net: dict, route: dict, live: dict) -> str:
    if net["create_200"] or live.get("create_success"):
        return "CREATE_200"
    if net["riskblock"] or live["riskblock"]:
        return "RISK_BLOCK"
    if net["create_request"]:
        return "CREATE_REQUEST_NO_200"
    route_results = ",".join(route.get("collector_results") or [])
    has_route_result0 = "oIIoIooo|0" in route_results or "|0" in route_results
    has_route_result_neg = "oIIoIooo|-1" in route_results or "|-1" in route_results
    if has_route_result0 and not net["create_200"]:
        if (net.get("iframe_loads") or 0) > max(1, net.get("human_success") or 0):
            return "RESULT0_RECHALLENGE"
        return "RESULT0_NO_CREATE"
    if has_route_result_neg:
        return "COLLECTOR_-1"
    if net["captcha_close_minus1"] or live["captcha_close_minus1"]:
        return "CAPTCHA_CLOSE_-1"
    if route["deferred_w0"] or route["optimistic_final_deferred_to_w0"]:
        return "W0_DEFER_NO_CREATE"
    if route["neutral_cached_w0"]:
        return "CACHED_W0_NO_CREATE"
    if route["session_cached_rich_final_and_w0"]:
        return "RICH_FINAL_AND_W0_NO_CREATE"
    if route["neutral_merge_w0"]:
        return "MERGED_W0_NO_CREATE"
    if route["neutral_fetch_w0"]:
        return "REAL_W0_NO_CREATE"
    if net["collector_results"] or has_route_result0:
        return "RESULT0_NO_CREATE"
    return "NO_RESULT0"


def print_summary(net: dict, route: dict, live: dict):
    v = verdict(net, route, live)
    print(f"=== {Path(net['network']).name} :: {v} ===")
    print(
        "create200={create_200} create_req={create_request} risk={riskblock} "
        "close-1={captcha_close_minus1} iframe_loads={iframe_loads} "
        "HumanLoaded={human_loaded} HumanSuccess={human_success} "
        "collector_results={results}".format(
            **net,
            results=",".join(net["collector_results"]) if net["collector_results"] else "-",
        )
    )
    print(
        "route: optimistic_final={optimistic_final} opt_final_to_w0={optimistic_final_deferred_to_w0} "
        "deferred_w0={deferred_w0} rewrite_final={rewrite_final} "
        "neutral_fetch={neutral_fetch_w0} neutral_merge={neutral_merge_w0} "
        "neutral_cached={neutral_cached_w0} rich_final_and_w0={session_cached_rich_final_and_w0} "
        "fetch_errors={fetch_errors} risk_gate={risk_verify_gate} risk_gate_ms={risk_gate_ms} "
        "close_delay={captcha_close_delayed} close_suppress={captcha_close_suppressed} close_delay_ms={close_delay_ms}".format(
            **route,
            risk_gate_ms=",".join(str(x) for x in route.get("risk_verify_gate_elapsed_ms") or []) or "-",
            close_delay_ms=",".join(str(x) for x in route.get("captcha_close_delay_elapsed_ms") or []) or "-",
        )
    )
    print(
        "live: risk={riskblock} create_observed={create_observed} timeout={timeout} close-1={captcha_close_minus1} "
        "time_warp={mode_time_warp} short_holds={short_hold_count} wall_ms={wall} actual_wall_ms={actual_wall}".format(
            **live,
            wall=",".join(str(x) for x in live.get("wall_ms_values") or []) or "-",
            actual_wall=",".join(str(x) for x in live.get("actual_wall_ms_values") or []) or "-",
        )
    )
    for r in net["rounds"][-4:]:
        print(
            f"  qi={r['qi']} u0->final={r['u0_to_final_ms']}ms "
            f"final->w0={r['final_to_w0_ms']}ms results={','.join(r['results']) or '-'}"
        )
    if route["route_logs"]:
        print("  routes=" + ", ".join(Path(x).name for x in route["route_logs"]))
    if live["live_logs"]:
        print("  live=" + ", ".join(Path(x).name for x in live["live_logs"]))


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize recent 1s hsprotect attempts.")
    ap.add_argument("paths", nargs="*", type=Path, help="Network jsonl paths. Defaults to latest --limit files.")
    ap.add_argument("--limit", type=int, default=6)
    args = ap.parse_args()

    paths = args.paths
    if not paths:
        paths = sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[: args.limit]
    for p in paths:
        net = network_summary(p)
        route = route_summary(matching_runtime_logs(net["stamp"], "*_route_normalizer.jsonl"))
        live = live_summary(matching_runtime_logs(net["stamp"], "*_live_probe.log"))
        print_summary(net, route, live)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
