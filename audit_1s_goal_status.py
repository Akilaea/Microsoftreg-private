import argparse
import json
from pathlib import Path

from summarize_1s_attempts import NETWORK_DIR
from verify_1s_stability import classify


def latest_networks(limit: int) -> list[Path]:
    return sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]


def audit(paths: list[Path], *, min_successes: int = 3, max_wall_ms: int = 1500) -> dict:
    rows = [classify(p, max_wall_ms) for p in paths]
    successes = [
        r for r in rows
        if r["verdict"] == "CREATE_200" and r["one_s_ok"]
    ]
    raw_create_200 = [r for r in rows if r["verdict"] == "CREATE_200"]
    risk = [r for r in rows if r["verdict"] == "RISK_BLOCK"]
    not_1s = [r for r in raw_create_200 if not r["one_s_ok"]]
    close1 = [r for r in rows if r["verdict"] == "CAPTCHA_CLOSE_-1"]

    requirements = {
        "enough_attempts": len(rows) >= int(min_successes),
        "enough_1s_create200": len(successes) >= int(min_successes),
        "no_riskblock": len(risk) == 0,
        "no_create200_not_1s": len(not_1s) == 0,
    }
    complete = all(requirements.values())
    return {
        "complete": complete,
        "status": "GOAL_COMPLETE" if complete else "GOAL_NOT_COMPLETE",
        "attempts": len(rows),
        "required_successes": int(min_successes),
        "successes": len(successes),
        "raw_create_200": len(raw_create_200),
        "riskblock": len(risk),
        "create_200_not_1s": len(not_1s),
        "captcha_close_minus1": len(close1),
        "requirements": requirements,
        "rows": [
            {
                "path": str(r["path"]),
                "verdict": r["verdict"],
                "create_200": bool(r["net"].get("create_200")),
                "one_s_ok": bool(r["one_s_ok"]),
                "wall_ms_values": r["live"].get("wall_ms_values") or [],
                "short_holds": r["live"].get("short_hold_count"),
            }
            for r in rows
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Strict completion audit for the active goal: 1s CreateAccount stable reproduction."
    )
    ap.add_argument("paths", nargs="*", type=Path, help="Network jsonl paths. Defaults to latest --attempts logs.")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--min-successes", type=int, default=3)
    ap.add_argument("--max-wall-ms", type=int, default=1500)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    paths = args.paths or latest_networks(max(1, args.attempts))
    result = audit(paths, min_successes=args.min_successes, max_wall_ms=args.max_wall_ms)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"{result['status']} attempts={result['attempts']} "
            f"successes={result['successes']}/{result['required_successes']} "
            f"raw_create_200={result['raw_create_200']} riskblock={result['riskblock']} "
            f"create_200_not_1s={result['create_200_not_1s']} "
            f"captcha_close_minus1={result['captcha_close_minus1']}"
        )
        for key, ok in result["requirements"].items():
            print(f"  {key}={ok}")
        for idx, row in enumerate(result["rows"], 1):
            print(
                f"  #{idx} {Path(row['path']).name} verdict={row['verdict']} "
                f"create200={row['create_200']} one_s_ok={row['one_s_ok']} "
                f"wall_ms={','.join(map(str,row['wall_ms_values'])) or '-'}"
            )
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
