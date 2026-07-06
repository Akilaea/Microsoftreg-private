import argparse
import json
from pathlib import Path

from audit_1s_live_evidence import evidence_status
from audit_latest_batch_summary import latest_summary


def completion_audit(path: Path | None = None, min_successes: int | None = None) -> dict:
    summary_path = path or latest_summary()
    if not summary_path:
        return {
            "status": "GOAL_COMPLETE_AUDIT_FAIL",
            "reason": "no batch summary found",
            "summary_path": None,
        }
    if not summary_path.exists():
        return {
            "status": "GOAL_COMPLETE_AUDIT_FAIL",
            "reason": "batch summary path does not exist",
            "summary_path": str(summary_path),
        }
    evidence = evidence_status(summary_path, min_successes=min_successes, rerun=True)
    summary = evidence.get("summary") or {}
    requirements = {
        "stable_pass": bool(summary.get("stable_pass")),
        "goal_complete": bool(summary.get("goal_complete")),
        "evidence_complete": evidence.get("status") == "GOAL_EVIDENCE_COMPLETE",
        "success_count_sufficient": int(summary.get("success_count") or 0) >= int(evidence.get("required_successes") or 0) > 0,
        "network_logs_present": not evidence.get("missing_network_logs") and len(evidence.get("network_logs") or []) >= int(evidence.get("required_successes") or 0),
        "rerun_verify_ok": (evidence.get("rerun") or {}).get("verify_exit") == 0,
        "rerun_audit_ok": (evidence.get("rerun") or {}).get("audit_exit") == 0,
    }
    ok = all(requirements.values())
    return {
        "status": "GOAL_COMPLETE_AUDIT_PASS" if ok else "GOAL_COMPLETE_AUDIT_FAIL",
        "summary_path": str(summary_path),
        "requirements": requirements,
        "evidence": evidence,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Final completion audit for the active objective: stable 1s verification. "
            "This is the last local gate before marking the goal complete."
        )
    )
    ap.add_argument("path", nargs="?", type=Path, help="Summary JSON path. Defaults to latest mihomo batch summary.")
    ap.add_argument("--min-successes", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = completion_audit(args.path, min_successes=args.min_successes)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"{result['status']} summary={Path(result['summary_path']).name if result.get('summary_path') else '-'}")
        if result["status"] != "GOAL_COMPLETE_AUDIT_PASS":
            if result.get("reason"):
                print(f"reason={result['reason']}")
            for name, ok in (result.get("requirements") or {}).items():
                print(f"  {name}={ok}")
    return 0 if result["status"] == "GOAL_COMPLETE_AUDIT_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
