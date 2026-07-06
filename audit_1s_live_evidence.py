import argparse
import json
import subprocess
import sys
from pathlib import Path

from audit_latest_batch_summary import audit_summary, latest_summary


ROOT = Path(__file__).resolve().parent


def run_cmd(args: list[str], timeout: int = 120) -> dict:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    return {
        "args": args,
        "exit": proc.returncode,
        "stdout": proc.stdout,
        "tail": proc.stdout.splitlines()[-80:],
    }


def normalize_network_paths(summary_path: Path, values: list) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        if not value:
            continue
        p = Path(str(value))
        if not p.is_absolute():
            # Batch summaries normally store absolute paths, but keep relative
            # paths reproducible when a summary is moved around for debugging.
            candidate = (summary_path.parent / p)
            if candidate.exists():
                p = candidate
            else:
                p = ROOT / p
        paths.append(p)
    return paths


def evidence_status(path: Path, min_successes: int | None = None, rerun: bool = True) -> dict:
    summary = audit_summary(path)
    raw = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    required = int(min_successes if min_successes is not None else (summary.get("min_successes") or 0))
    network_paths = normalize_network_paths(path, raw.get("network_logs") or [])
    missing_network_logs = [str(p) for p in network_paths if not p.exists()]
    verify = None
    audit = None
    rerun_ok = False

    if rerun and network_paths and not missing_network_logs:
        verify = run_cmd(
            [sys.executable, "verify_1s_stability.py", *[str(p) for p in network_paths], "--min-successes", str(required)],
            timeout=180,
        )
        audit = run_cmd(
            [sys.executable, "audit_1s_goal_status.py", *[str(p) for p in network_paths], "--min-successes", str(required)],
            timeout=180,
        )
        rerun_ok = (
            verify["exit"] == 0
            and audit["exit"] == 0
            and "STABLE_PASS" in verify["stdout"]
            and "GOAL_COMPLETE" in audit["stdout"]
        )
    elif not rerun:
        rerun_ok = True

    complete = (
        summary.get("status") == "BATCH_GOAL_COMPLETE"
        and required > 0
        and not missing_network_logs
        and rerun_ok
    )
    return {
        "summary_path": str(path),
        "required_successes": required,
        "summary": summary,
        "network_logs": [str(p) for p in network_paths],
        "missing_network_logs": missing_network_logs,
        "rerun": {
            "enabled": rerun,
            "ok": rerun_ok,
            "verify_exit": None if verify is None else verify["exit"],
            "audit_exit": None if audit is None else audit["exit"],
            "verify_tail": [] if verify is None else verify["tail"],
            "audit_tail": [] if audit is None else audit["tail"],
        },
        "status": "GOAL_EVIDENCE_COMPLETE" if complete else "GOAL_EVIDENCE_NOT_COMPLETE",
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Strictly audit latest/specified live batch evidence. "
            "A complete result requires the batch summary gate plus a local rerun of verify_1s_stability.py "
            "and audit_1s_goal_status.py against the recorded network logs."
        )
    )
    ap.add_argument("path", nargs="?", type=Path, help="Summary JSON path. Defaults to latest mihomo batch summary.")
    ap.add_argument("--min-successes", type=int, default=None, help="Override required success count for rerun gates.")
    ap.add_argument("--summary-only", action="store_true", help="Do not rerun network-log gates; weaker, for debugging only.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    path = args.path or latest_summary()
    if not path:
        print("GOAL_EVIDENCE_NOT_COMPLETE no batch summary found")
        return 1
    result = evidence_status(path, min_successes=args.min_successes, rerun=not args.summary_only)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        summary = result["summary"]
        rerun = result["rerun"]
        print(
            f"{result['status']} summary={Path(result['summary_path']).name} "
            f"batch_status={summary.get('status')} successes={summary.get('success_count')}/{summary.get('min_successes')} "
            f"network_logs={summary.get('network_log_count')} missing_logs={len(result['missing_network_logs'])} "
            f"verify_exit={rerun.get('verify_exit')} audit_exit={rerun.get('audit_exit')} rerun_ok={rerun.get('ok')}"
        )
        if result["missing_network_logs"]:
            print("missing_network_logs:")
            for p in result["missing_network_logs"][:20]:
                print(f"  {p}")
        if rerun.get("verify_tail"):
            print("verify_tail:")
            for line in rerun["verify_tail"][-20:]:
                print(f"  {line}")
        if rerun.get("audit_tail"):
            print("audit_tail:")
            for line in rerun["audit_tail"][-20:]:
                print(f"  {line}")
    return 0 if result["status"] == "GOAL_EVIDENCE_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
