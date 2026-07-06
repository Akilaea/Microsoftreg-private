import argparse
from pathlib import Path

from summarize_1s_attempts import (
    NETWORK_DIR,
    matching_runtime_logs,
    network_summary,
    route_summary,
    live_summary,
    verdict,
)


def latest_networks(limit: int) -> list[Path]:
    return sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]


def classify(path: Path, max_wall_ms: int) -> dict:
    net = network_summary(path)
    route = route_summary(matching_runtime_logs(net["stamp"], "*_route_normalizer.jsonl"))
    live = live_summary(matching_runtime_logs(net["stamp"], "*_live_probe.log"))
    one_s_ok = bool(
        live.get("mode_time_warp")
        and int(live.get("short_hold_count") or 0) > 0
        and (
            live.get("max_actual_wall_ms")
            if live.get("max_actual_wall_ms") is not None
            else live.get("max_wall_ms")
        )
        is not None
        and int(
            live.get("max_actual_wall_ms")
            if live.get("max_actual_wall_ms") is not None
            else live.get("max_wall_ms")
            or 0
        )
        <= int(max_wall_ms)
    )
    return {
        "path": path,
        "net": net,
        "route": route,
        "live": live,
        "verdict": verdict(net, route, live),
        "one_s_ok": one_s_ok,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Verify whether recent 1s hsprotect attempts satisfy a stability gate. "
            "Default gate is strict: latest N attempts must all have CreateAccount 200."
        )
    )
    ap.add_argument("paths", nargs="*", type=Path, help="Network jsonl paths. Defaults to latest --attempts files.")
    ap.add_argument("--attempts", type=int, default=3, help="How many latest network logs to evaluate when paths are omitted.")
    ap.add_argument("--min-successes", type=int, default=None, help="Required CreateAccount 200 count. Default: attempts.")
    ap.add_argument("--allow-riskblock", action="store_true", help="Do not fail specially on RiskBlock; still counts as non-success.")
    ap.add_argument(
        "--max-wall-ms",
        type=int,
        default=1500,
        help="Maximum allowed real physical hold wall_ms for a success to count as 1s. Default: 1500.",
    )
    args = ap.parse_args()

    paths = args.paths or latest_networks(max(1, args.attempts))
    required = args.min_successes if args.min_successes is not None else len(paths)
    rows = [classify(p, args.max_wall_ms) for p in paths]

    raw_create_200 = sum(1 for r in rows if r["verdict"] == "CREATE_200")
    success = sum(1 for r in rows if r["verdict"] == "CREATE_200" and r["one_s_ok"])
    create_200_not_1s = raw_create_200 - success
    risk = sum(1 for r in rows if r["verdict"] == "RISK_BLOCK")
    w0_defer_no_create = sum(1 for r in rows if r["verdict"] == "W0_DEFER_NO_CREATE")
    result0_no_create = sum(1 for r in rows if r["verdict"] == "RESULT0_NO_CREATE")
    real_w0_no_create = sum(1 for r in rows if r["verdict"] == "REAL_W0_NO_CREATE")
    merged_w0_no_create = sum(1 for r in rows if r["verdict"] == "MERGED_W0_NO_CREATE")
    cached_w0_no_create = sum(1 for r in rows if r["verdict"] == "CACHED_W0_NO_CREATE")
    rich_final_and_w0_no_create = sum(1 for r in rows if r["verdict"] == "RICH_FINAL_AND_W0_NO_CREATE")
    close1 = sum(1 for r in rows if r["verdict"] == "CAPTCHA_CLOSE_-1")

    print(
        f"stability_gate attempts={len(rows)} required_successes={required} "
        f"successes={success} raw_create_200={raw_create_200} max_wall_ms={args.max_wall_ms}"
    )
    print(
        f"breakdown riskblock={risk} w0_defer_no_create={w0_defer_no_create} "
        f"result0_no_create={result0_no_create} real_w0_no_create={real_w0_no_create} "
        f"merged_w0_no_create={merged_w0_no_create} cached_w0_no_create={cached_w0_no_create} "
        f"rich_final_and_w0_no_create={rich_final_and_w0_no_create} "
        f"captcha_close_-1={close1} "
        f"create_200_not_1s={create_200_not_1s}"
    )
    for i, r in enumerate(rows, 1):
        net = r["net"]
        route = r["route"]
        rounds = net.get("rounds") or []
        last_round = rounds[-1] if rounds else {}
        print(
            f"#{i} {Path(r['path']).name} verdict={r['verdict']} "
            f"create200={net['create_200']} one_s_ok={r['one_s_ok']} "
            f"wall_ms={','.join(str(x) for x in (r['live'].get('wall_ms_values') or [])) or '-'} "
            f"actual_wall_ms={','.join(str(x) for x in (r['live'].get('actual_wall_ms_values') or [])) or '-'} "
            f"short_holds={r['live'].get('short_hold_count')} "
            f"result0={','.join(net['collector_results']) or '-'} "
            f"optFinalToW0={route['optimistic_final_deferred_to_w0']} deferredW0={route['deferred_w0']} "
            f"neutralFetch={route['neutral_fetch_w0']} neutralMerge={route['neutral_merge_w0']} "
            f"neutralCached={route['neutral_cached_w0']} richFinalAndW0={route['session_cached_rich_final_and_w0']} "
            f"final->w0={last_round.get('final_to_w0_ms')}ms"
        )

    if success >= required and len(rows) >= required:
        print("STABLE_PASS")
        return 0
    if create_200_not_1s:
        print("STABLE_FAIL_NOT_1S")
        return 3
    if risk and not args.allow_riskblock:
        print("STABLE_FAIL_RISKBLOCK")
        return 2
    print("STABLE_FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
