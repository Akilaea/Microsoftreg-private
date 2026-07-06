import argparse
import json
import subprocess
import sys
from pathlib import Path

from audit_latest_batch_summary import audit_summary, latest_summary


ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / ".mihomo-isolated" / "riskblock_nodes.json"
ALIVE_DIR = ROOT / ".mihomo-isolated"


def run_selftest() -> dict:
    proc = subprocess.run(
        [sys.executable, "selftest_1s_offline.py"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
    return {
        "ok": proc.returncode == 0,
        "exit": proc.returncode,
        "tail": proc.stdout.splitlines()[-20:],
    }


def latest_alive() -> dict:
    files = sorted(ALIVE_DIR.glob("alive_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return {"present": False}
    path = files[0]
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception as exc:
        return {"present": True, "path": str(path), "error": repr(exc)}
    alive = data.get("alive") or []
    us = [
        {
            "name": item.get("name"),
            "ip": item.get("ip"),
            "loc": item.get("loc"),
            "delay": item.get("delay"),
        }
        for item in alive
        if "US" in str(item.get("name") or "").upper() or str(item.get("loc") or "").upper() == "US"
    ]
    return {
        "present": True,
        "path": str(path),
        "total": data.get("total"),
        "alive_count": data.get("alive_count"),
        "us_alive": us,
    }


def riskblock_ledger() -> dict:
    if not LEDGER.exists():
        return {"present": False, "path": str(LEDGER), "entries": []}
    try:
        data = json.loads(LEDGER.read_text(encoding="utf-8-sig", errors="replace"))
        entries = data if isinstance(data, list) else [data]
    except Exception as exc:
        return {"present": True, "path": str(LEDGER), "error": repr(exc), "entries": []}
    return {"present": True, "path": str(LEDGER), "entries": entries, "count": len(entries)}


def required_scripts() -> dict:
    names = [
        "protocol_runtime_probe.py",
        "run_1s_rewrite_once.ps1",
        "run_mihomo_us_1s_batch.ps1",
        "run_1s_goal_live.ps1",
        "mihomo_yaml_alive_probe.py",
        "run_mihomo_yaml_alive_then_1s.ps1",
        "preflight_1s_live.ps1",
        "verify_1s_stability.py",
        "audit_1s_goal_status.py",
        "audit_1s_live_evidence.py",
        "audit_1s_completion.py",
        "triage_1s_latest.py",
        "watch_1s_live_goal.py",
    ]
    items = [{"name": name, "present": (ROOT / name).exists()} for name in names]
    return {"ok": all(item["present"] for item in items), "items": items}


def latest_batch() -> dict:
    path = latest_summary()
    if not path:
        return {"present": False}
    try:
        return {"present": True, **audit_summary(path)}
    except Exception as exc:
        return {"present": True, "path": str(path), "error": repr(exc)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline status dashboard for current 1s reproduction work.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skip-selftest", action="store_true")
    args = ap.parse_args()

    result = {
        "selftest": None if args.skip_selftest else run_selftest(),
        "latest_alive": latest_alive(),
        "riskblock_ledger": riskblock_ledger(),
        "required_scripts": required_scripts(),
        "latest_batch": latest_batch(),
        "recommended_single": (
            'powershell -ExecutionPolicy Bypass -File .\\run_mihomo_us_1s_batch.ps1 '
            '-Filter "US 006" -MaxNodes 1'
        ),
        "recommended_stability": (
            'powershell -ExecutionPolicy Bypass -File .\\run_mihomo_us_1s_batch.ps1 '
            '-Filter "US 006" -MaxNodes 1 -RunsPerNode 3 -MinSuccesses 3 -StopOnRiskBlock'
        ),
        "recommended_yaml_stability": (
            'powershell -ExecutionPolicy Bypass -File .\\run_mihomo_yaml_alive_then_1s.ps1 '
            '-Filter "US 006|US 008|US 007" -MaxNodes 1 -RunsPerNode 3 -MinSuccesses 3 -StopOnRiskBlock'
        ),
        "recommended_preflight": (
            'powershell -ExecutionPolicy Bypass -File .\\preflight_1s_live.ps1 '
            '-Filter "US 006" -MaxNodes 1 -RunsPerNode 3 -MinSuccesses 3'
        ),
        "recommended_goal_live": (
            'powershell -ExecutionPolicy Bypass -File .\\run_1s_goal_live.ps1 '
            '-Filter "US 006|US 008|US 007" -MaxNodes 1 -RunsPerNode 3 -MinSuccesses 3'
        ),
        "recommended_completion_audit": "python audit_1s_completion.py",
        "recommended_triage": "python triage_1s_latest.py",
    }
    ready = True
    if result["selftest"] is not None and not result["selftest"].get("ok"):
        ready = False
    if not result["latest_alive"].get("present"):
        ready = False
    if not result["latest_alive"].get("us_alive"):
        ready = False
    if not result["required_scripts"].get("ok"):
        ready = False
    result["ready_for_live_test"] = ready

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"READY_FOR_LIVE_TEST={ready}")
        if result["selftest"] is not None:
            print(f"selftest_ok={result['selftest']['ok']} exit={result['selftest']['exit']}")
        alive = result["latest_alive"]
        print(f"alive_present={alive.get('present')} path={alive.get('path')} alive_count={alive.get('alive_count')}")
        if alive.get("us_alive"):
            print("us_alive:")
            for item in alive["us_alive"][:8]:
                print(f"  delay={item.get('delay')} ip={item.get('ip')} loc={item.get('loc')} name={item.get('name')}")
        ledger = result["riskblock_ledger"]
        print(f"riskblock_ledger_present={ledger.get('present')} count={ledger.get('count', 0)} path={ledger.get('path')}")
        scripts = result["required_scripts"]
        print(f"required_scripts_ok={scripts.get('ok')}")
        if not scripts.get("ok"):
            for item in scripts["items"]:
                if not item.get("present"):
                    print(f"  missing={item.get('name')}")
        batch = result["latest_batch"]
        print(
            f"latest_batch_present={batch.get('present')} status={batch.get('status')} "
            f"stable_pass={batch.get('stable_pass')} goal_complete={batch.get('goal_complete')} path={batch.get('path')}"
        )
        print("recommended_preflight:")
        print("  " + result["recommended_preflight"])
        print("recommended_single:")
        print("  " + result["recommended_single"])
        print("recommended_stability:")
        print("  " + result["recommended_stability"])
        print("recommended_yaml_stability:")
        print("  " + result["recommended_yaml_stability"])
        print("recommended_goal_live:")
        print("  " + result["recommended_goal_live"])
        print("recommended_completion_audit:")
        print("  " + result["recommended_completion_audit"])
        print("recommended_triage:")
        print("  " + result["recommended_triage"])
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
