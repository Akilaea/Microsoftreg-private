import argparse
import json
from pathlib import Path

from audit_1s_completion import completion_audit
from audit_latest_batch_summary import latest_summary


def choose_next_action(audit: dict) -> str:
    if audit.get("status") == "GOAL_COMPLETE_AUDIT_PASS":
        return "MARK_GOAL_COMPLETE"
    if audit.get("reason") in {"no batch summary found", "batch summary path does not exist"}:
        return "RUN_LIVE_BATCH"

    evidence = audit.get("evidence") or {}
    summary = evidence.get("summary") or {}
    missing = evidence.get("missing_network_logs") or []
    requirements = audit.get("requirements") or {}
    rerun = evidence.get("rerun") or {}

    if missing:
        return "FIX_MISSING_NETWORK_LOGS_OR_RERUN_BATCH"
    if int(summary.get("riskblock_count") or 0) > 0:
        return "STOP_NODE_AND_SWITCH_IP"
    if not requirements.get("stable_pass") and int(summary.get("success_count") or 0) == 0:
        return "INSPECT_PROTOCOL_FAILURE"
    if not requirements.get("success_count_sufficient"):
        return "CONTINUE_SMALL_BATCH_UNTIL_MIN_SUCCESSES"
    if rerun.get("verify_exit") not in (0, None):
        return "INSPECT_VERIFY_GATE"
    if rerun.get("audit_exit") not in (0, None):
        return "INSPECT_GOAL_AUDIT"
    return "INSPECT_LATEST_BATCH_SUMMARY"


def triage(path: Path | None = None, min_successes: int | None = None) -> dict:
    summary_path = path or latest_summary()
    audit = completion_audit(summary_path, min_successes=min_successes)
    action = choose_next_action(audit)
    evidence = audit.get("evidence") or {}
    summary = evidence.get("summary") or {}
    return {
        "status": "TRIAGE_COMPLETE" if audit.get("status") == "GOAL_COMPLETE_AUDIT_PASS" else "TRIAGE_NOT_COMPLETE",
        "next_action": action,
        "completion_status": audit.get("status"),
        "summary_path": audit.get("summary_path"),
        "batch_status": summary.get("status"),
        "success_count": summary.get("success_count"),
        "min_successes": summary.get("min_successes"),
        "riskblock_count": summary.get("riskblock_count"),
        "network_log_count": summary.get("network_log_count"),
        "missing_network_logs": evidence.get("missing_network_logs") or [],
        "requirements": audit.get("requirements") or {},
        "rerun": evidence.get("rerun") or {},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage the latest 1s live batch result and print the next concrete action.")
    ap.add_argument("path", nargs="?", type=Path, help="Summary JSON path. Defaults to latest mihomo batch summary.")
    ap.add_argument("--min-successes", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = triage(args.path, min_successes=args.min_successes)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"{result['status']} next_action={result['next_action']} "
            f"completion={result['completion_status']} summary={Path(result['summary_path']).name if result.get('summary_path') else '-'} "
            f"successes={result.get('success_count')}/{result.get('min_successes')} "
            f"riskblock={result.get('riskblock_count')} network_logs={result.get('network_log_count')}"
        )
        missing = result.get("missing_network_logs") or []
        if missing:
            print("missing_network_logs:")
            for item in missing[:20]:
                print(f"  {item}")
        for name, ok in (result.get("requirements") or {}).items():
            print(f"  {name}={ok}")
    return 0 if result["status"] == "TRIAGE_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
