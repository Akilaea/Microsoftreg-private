import argparse
import json
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from adspower_cdp_endpoint import default_profile_dir, fetch_json, read_devtools_active_port


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


SIGNALS = {
    "risk_continue": "risk/verify state=continue",
    "success": "CreateAccount completed without known error",
    "server_error": "CreateAccount/server context error",
    "risk_block": "riskBlock",
    "collector_score1": "collector score=1",
    "hsprotect_retry": "HumanCaptcha_Failure or ch_ctx retry state",
}


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_label(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "adspower"


def discover(user_id: str, host: str, profile_dir: str | None, timeout: float):
    pdir = Path(profile_dir) if profile_dir else default_profile_dir(user_id)
    port, browser_path = read_devtools_active_port(pdir)
    endpoint = f"http://{host}:{port}"
    version = fetch_json(endpoint + "/json/version", timeout)
    targets = fetch_json(endpoint + "/json/list", timeout)
    return {
        "user_id": user_id,
        "profile_dir": str(pdir),
        "port": port,
        "cdp_endpoint": endpoint,
        "browser_ws_from_file": f"ws://{host}:{port}{browser_path}",
        "browser_ws": version.get("webSocketDebuggerUrl"),
        "browser": version.get("Browser"),
        "user_agent": version.get("User-Agent"),
        "targets": [
            {
                "type": item.get("type"),
                "title": item.get("title"),
                "url": item.get("url"),
            }
            for item in targets
        ],
    }


def active_status(user_id: str, api_key: str, helper: str, timeout: float):
    url = f"{helper.rstrip('/')}/api/v1/browser/active?api_key={api_key}&user_id={user_id}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"code": -1, "msg": str(exc)}


def start_observer(endpoint: str, out_path: Path, timeout_seconds: int):
    cmd = [
        sys.executable,
        "manual_browser_cdp_observer.py",
        "--cdp-endpoint",
        endpoint,
        "--timeout-seconds",
        str(timeout_seconds),
        "--out",
        str(out_path),
    ]
    return subprocess.Popen(
        cmd,
        cwd=Path.cwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )


def start_stdout_reader(proc: subprocess.Popen):
    lines: queue.Queue[str | None] = queue.Queue()

    def pump():
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                lines.put(line)
        finally:
            lines.put(None)

    thread = threading.Thread(target=pump, name="observer-stdout-reader", daemon=True)
    thread.start()
    return lines


def classify_line(line: str):
    if "CreateAccount" in line and "server_error=" in line and "server_error=-" not in line:
        return "server_error"
    if "CreateAccount" in line and (
        "contextID" in line
        or "matching cookie" in line
        or "status=4" in line
        or "code=server_error" in line
    ):
        return "server_error"
    if "CreateAccount" in line and "status=200" in line and "error=-" in line and "server_error=-" in line:
        return "success"
    if "risk/verify" in line and "state=continue" in line:
        return "risk_continue"
    if "risk/verify" in line and ("riskBlock" in line or "forbidden" in line):
        return "risk_block"
    if "collector" in line and "score=1" in line:
        return "collector_score1"
    return ""


def classify_snapshot(log_path: Path):
    if not log_path.exists() or log_path.stat().st_size == 0:
        return "", "trace empty"
    try:
        from protocol_from_adspower_trace import extract

        state = extract(log_path, include_sensitive=False)
    except Exception as exc:
        return "", f"snapshot pending: {exc}"

    verdict = state.get("verdict") or {}
    final_class = verdict.get("final_class") or "unknown"
    if final_class == "server_error" or verdict.get("create_account_server_error"):
        return "server_error", f"class={final_class}"
    if verdict.get("create_account_success"):
        return "success", f"class={final_class}"
    if verdict.get("risk_block"):
        return "risk_block", f"class={final_class}"
    if (
        verdict.get("hcaptcha_failure")
        or verdict.get("hcaptcha_loaded_after_success")
        or final_class in {"hsprotect_retry", "hsprotect_rechallenge"}
    ):
        return (
            "hsprotect_retry",
            f"class={final_class} chctx_score0={verdict.get('chctx_score0')} "
            f"chctx_score1={verdict.get('chctx_score1')} "
            f"loaded_after_success={verdict.get('hcaptcha_loaded_after_success')}",
        )
    if verdict.get("risk_continue"):
        return "risk_continue", f"class={final_class}"
    return "", f"class={final_class}"


def summarize(log_path: Path):
    cmd = [sys.executable, "summarize_score1_rootcause.py", str(log_path)]
    return subprocess.run(
        cmd,
        cwd=Path.cwd(),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def extract_protocol_state(log_path: Path):
    cmd = [sys.executable, "protocol_from_adspower_trace.py", str(log_path)]
    return subprocess.run(
        cmd,
        cwd=Path.cwd(),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def append_note(
    notes_path: Path,
    label: str,
    user_id: str,
    info: dict,
    log_path: Path,
    verdict: str,
    summary: str,
    protocol_output: str,
):
    excerpt = []
    for line in summary.splitlines():
        if any(
            key in line
            for key in [
                "risk_initialize",
                "risk_verify",
                "telemetry_hcaptcha",
                "collector #",
                "verdict",
            ]
        ):
            excerpt.append(line)
    block = [
        "",
        "",
        f"## {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} AdsPower runner {label}",
        "",
        "```text",
        f"profile_label={label}",
        f"user_id={user_id}",
        f"cdp_endpoint={info.get('cdp_endpoint')}",
        f"browser={info.get('browser')}",
        f"network_log={log_path}",
        f"runner_verdict={verdict or 'unknown'}",
        "```",
        "",
        "摘要：",
        "",
        "```text",
        *excerpt[:40],
        "```",
    ]
    if protocol_output.strip():
        block.extend(["", "协议状态：", "", "```text", protocol_output.strip(), "```"])
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    with notes_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(block))


def main() -> int:
    ap = argparse.ArgumentParser(description="AdsPower/SunBrowser manual-flow runner for CTF experiments.")
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--label", default=None)
    ap.add_argument("--profile-dir", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--timeout-seconds", type=int, default=900)
    ap.add_argument("--api-key", default="LOCAL_API_KEY")
    ap.add_argument("--helper", default="http://127.0.0.1:50326")
    ap.add_argument("--out-dir", default="Results/network")
    ap.add_argument("--dry-run", action="store_true", help="Only discover endpoint and targets; do not start observer.")
    ap.add_argument("--append-notes", action="store_true", help="Append a compact run entry to score1_rootcause_notes.md.")
    ap.add_argument("--notes", default="Results/score1_rootcause_notes.md")
    ap.add_argument("--snapshot-interval-seconds", type=float, default=5.0)
    ap.add_argument(
        "--failure-grace-seconds",
        type=float,
        default=0.0,
        help="Grace period before stopping on hsprotect retry/re-challenge. Default 0 stops immediately.",
    )
    ap.add_argument(
        "--risk-continue-grace-seconds",
        type=float,
        default=45.0,
        help="After risk/verify continue, keep observing for CreateAccount/server errors before declaring success.",
    )
    args = ap.parse_args()

    label = safe_label(args.label or args.user_id)
    print(f"[Runner] discovering AdsPower CDP for user_id={args.user_id}", flush=True)
    info = discover(args.user_id, args.host, args.profile_dir, 5.0)
    active = active_status(args.user_id, args.api_key, args.helper, 3.0)
    info["active_status"] = active
    print(json.dumps(info, ensure_ascii=False, indent=2), flush=True)

    if args.dry_run:
        return 0

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"adspower_{label}_{ts()}.browser_cdp.jsonl"
    print(f"[Runner] starting observer -> {log_path}", flush=True)
    proc = start_observer(info["cdp_endpoint"], log_path, args.timeout_seconds)
    lines = start_stdout_reader(proc)

    verdict = ""
    snapshot_candidate = ""
    snapshot_candidate_at = 0.0
    risk_continue_at = 0.0
    last_snapshot_at = 0.0
    stdout_done = False
    started = time.time()
    try:
        while True:
            now = time.time()
            try:
                line = lines.get(timeout=0.2)
            except queue.Empty:
                line = ""

            if line is None:
                stdout_done = True
            elif line:
                print(line, end="", flush=True)
                signal = classify_line(line)
                if signal:
                    verdict = signal
                    print(f"[Runner] signal={signal} ({SIGNALS.get(signal)})", flush=True)
                    if signal == "risk_continue":
                        risk_continue_at = now
                    elif signal in {"success", "server_error", "risk_block"}:
                        break

            if args.snapshot_interval_seconds > 0 and now - last_snapshot_at >= args.snapshot_interval_seconds:
                last_snapshot_at = now
                signal, detail = classify_snapshot(log_path)
                if signal in {"risk_block"}:
                    verdict = signal
                    print(f"[Runner] snapshot signal={signal} ({detail})", flush=True)
                    break
                if signal == "risk_continue":
                    if not risk_continue_at:
                        risk_continue_at = now
                        verdict = signal
                        print(f"[Runner] snapshot signal={signal} ({detail}); waiting for CreateAccount", flush=True)
                if signal == "hsprotect_retry":
                    if args.failure_grace_seconds <= 0:
                        verdict = signal
                        print(f"[Runner] snapshot signal={signal} ({detail})", flush=True)
                        break
                    if snapshot_candidate != signal:
                        snapshot_candidate = signal
                        snapshot_candidate_at = now
                        print(f"[Runner] snapshot candidate={signal} ({detail})", flush=True)
                    elif now - snapshot_candidate_at >= args.failure_grace_seconds:
                        verdict = signal
                        print(f"[Runner] snapshot signal={signal} ({detail})", flush=True)
                        break
                elif signal:
                    snapshot_candidate = ""
                    snapshot_candidate_at = 0.0

            if risk_continue_at and now - risk_continue_at >= args.risk_continue_grace_seconds:
                verdict = "success"
                print(
                    f"[Runner] risk_continue grace elapsed; no server_error observed "
                    f"for {args.risk_continue_grace_seconds:.1f}s",
                    flush=True,
                )
                break

            if proc.poll() is not None and stdout_done:
                break
            if now - started > args.timeout_seconds:
                verdict = "timeout"
                break
    except KeyboardInterrupt:
        verdict = "interrupted"
        print("[Runner] interrupted; stopping observer", flush=True)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    print(f"[Runner] observer stopped; verdict={verdict or 'unknown'}", flush=True)
    print(f"[Runner] log={log_path}", flush=True)
    summary = summarize(log_path)
    print(summary.stdout, flush=True)
    protocol = extract_protocol_state(log_path)
    print(protocol.stdout, flush=True)
    if args.append_notes:
        append_note(Path(args.notes), label, args.user_id, info, log_path, verdict, summary.stdout, protocol.stdout)
        print(f"[Runner] appended notes -> {args.notes}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
