import argparse
import json
import time
from pathlib import Path

from audit_1s_live_evidence import evidence_status
from audit_latest_batch_summary import latest_summary


def summary_signature_key(path: Path | None) -> str:
    """Return a key that changes when the same summary file is updated."""
    if not path:
        return ""
    try:
        stat = path.stat()
        return f"{path.resolve()}|mtime_ns={stat.st_mtime_ns}|size={stat.st_size}"
    except FileNotFoundError:
        return f"{path.resolve()}|missing"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Watch for a live mihomo 1s batch summary and strictly audit it until "
            "GOAL_EVIDENCE_COMPLETE or timeout."
        )
    )
    ap.add_argument("--timeout-sec", type=int, default=3600)
    ap.add_argument("--interval-sec", type=int, default=15)
    ap.add_argument("--allow-existing", action="store_true", help="Audit the current latest summary immediately.")
    ap.add_argument("--min-successes", type=int, default=None, help="Override required success count for rerun gates.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    start = time.time()
    initial = latest_summary()
    initial_key = summary_signature_key(initial)
    last_audited_key = ""
    last_result: dict | None = None

    while True:
        path = latest_summary()
        path_key = summary_signature_key(path)
        should_audit = bool(path) and (args.allow_existing or path_key != initial_key) and path_key != last_audited_key
        if should_audit and path_key != last_audited_key:
            try:
                result = evidence_status(path, min_successes=args.min_successes, rerun=True)
            except Exception as exc:
                result = {
                    "summary_path": str(path),
                    "status": "GOAL_EVIDENCE_NOT_COMPLETE",
                    "error": repr(exc),
                }
            last_audited_key = path_key
            last_result = result
            if args.json:
                print(json.dumps(result, ensure_ascii=False), flush=True)
            else:
                print(
                    f"[watch] audited {Path(path).name} status={result.get('status')} "
                    f"elapsed={int(time.time() - start)}s",
                    flush=True,
                )
            if result.get("status") == "GOAL_EVIDENCE_COMPLETE":
                if not args.json:
                    print("GOAL_EVIDENCE_COMPLETE", flush=True)
                return 0

        elapsed = time.time() - start
        if elapsed >= max(0, args.timeout_sec):
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "GOAL_EVIDENCE_NOT_COMPLETE",
                            "reason": "timeout",
                            "elapsed_sec": int(elapsed),
                            "latest_summary": str(path) if path else None,
                            "last_result": last_result,
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            else:
                print(
                    f"GOAL_EVIDENCE_NOT_COMPLETE reason=timeout elapsed={int(elapsed)}s "
                    f"latest_summary={Path(path).name if path else '-'}",
                    flush=True,
                )
            return 1
        time.sleep(max(1, args.interval_sec))


if __name__ == "__main__":
    raise SystemExit(main())
