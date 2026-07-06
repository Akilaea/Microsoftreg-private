import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SUMMARY_DIR = ROOT / "Results" / "protocol_runtime"


def latest_summary() -> Path | None:
    items = sorted(
        SUMMARY_DIR.glob("mihomo_us_1s_batch_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return items[0] if items else None


def load_summary(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))


def audit_summary(path: Path) -> dict:
    data = load_summary(path)
    final_gate = data.get("final_gate") or {}
    final_evidence = data.get("final_evidence") or {}
    results = data.get("results") or []
    network_logs = data.get("network_logs") or []
    stable_pass = bool(final_gate.get("stable_pass"))
    goal_complete = bool(final_gate.get("goal_complete"))
    success_count = int(data.get("success_count") or 0)
    min_successes = int(data.get("min_successes") or 0)
    create_account_200_count = sum(1 for r in results if isinstance(r, dict) and r.get("verdict") == "create_account_200")
    verify_exit = final_gate.get("verify_exit")
    audit_exit = final_gate.get("audit_exit")
    exit_ok = (
        bool(final_gate)
        and stable_pass
        and goal_complete
        and verify_exit == 0
        and audit_exit == 0
        and min_successes > 0
        and success_count >= min_successes
        and create_account_200_count >= min_successes
        and len(network_logs) >= min_successes
    )
    return {
        "path": str(path),
        "created_at": data.get("created_at"),
        "filter": data.get("filter"),
        "exclude_filter": data.get("exclude_filter"),
        "success_count": success_count,
        "min_successes": min_successes,
        "network_log_count": len(network_logs),
        "result_count": len(results),
        "riskblock_count": sum(1 for r in results if isinstance(r, dict) and r.get("verdict") == "riskblock"),
        "create_account_200_count": create_account_200_count,
        "final_gate_present": bool(final_gate),
        "stable_pass": stable_pass,
        "goal_complete": goal_complete,
        "verify_exit": verify_exit,
        "audit_exit": audit_exit,
        "diagnose_exit": final_gate.get("diagnose_exit"),
        "evidence_exit": final_evidence.get("evidence_exit"),
        "evidence_complete": bool(final_evidence.get("evidence_complete")),
        "evidence_status": final_evidence.get("status"),
        "status": "BATCH_GOAL_COMPLETE" if exit_ok else "BATCH_GOAL_NOT_COMPLETE",
        "final_gate": final_gate,
        "final_evidence": final_evidence,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit the latest or specified mihomo 1s batch summary JSON.")
    ap.add_argument("path", nargs="?", type=Path, help="Summary JSON path. Defaults to latest Results/protocol_runtime/mihomo_us_1s_batch_*.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    path = args.path or latest_summary()
    if not path:
        print("BATCH_GOAL_NOT_COMPLETE no batch summary found")
        return 1
    result = audit_summary(path)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"{result['status']} summary={Path(result['path']).name} "
            f"success_count={result['success_count']}/{result['min_successes']} "
            f"network_logs={result['network_log_count']} riskblock={result['riskblock_count']} "
            f"stable_pass={result['stable_pass']} goal_complete={result['goal_complete']} "
            f"verify_exit={result['verify_exit']} audit_exit={result['audit_exit']} "
            f"evidence_complete={result['evidence_complete']} evidence_exit={result['evidence_exit']}"
        )
    return 0 if result["status"] == "BATCH_GOAL_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
