import argparse
import json
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from adspower_cdp_endpoint import default_profile_dir, fetch_json, read_devtools_active_port
from adspower_manual_runner import active_status, classify_line, classify_snapshot, summarize, extract_protocol_state


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


ROOT = Path(__file__).resolve().parent


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_label(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(text or "")).strip("_") or "adspower_autofill"


def discover(user_id: str, host: str, profile_dir: str | None, timeout: float) -> dict:
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
            {"type": t.get("type"), "title": t.get("title"), "url": t.get("url")}
            for t in targets
        ],
    }


def start_observer(endpoint: str, out_path: Path, timeout_seconds: int) -> subprocess.Popen:
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
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )


def start_main(
    endpoint: str,
    config: str,
    mode: str,
    max_tasks: int,
    concurrent: int,
    email: str | None,
    password: str | None,
    manual_wait_seconds: int,
    manual_post_wait_seconds: int | None,
    skip_preflight: bool,
) -> subprocess.Popen:
    cmd = [
        sys.executable,
        "main.py",
        "--config",
        config,
        "--cdp-endpoint",
        endpoint,
        "--max-tasks",
        str(max_tasks),
        "--concurrent",
        str(concurrent),
    ]
    if skip_preflight:
        cmd.append("--skip-preflight")
    if mode == "manual-captcha":
        cmd.extend(["--manual-captcha", "--manual-captcha-wait-seconds", str(manual_wait_seconds)])
        if manual_post_wait_seconds is not None:
            cmd.extend(["--manual-post-verify-wait-seconds", str(manual_post_wait_seconds)])
    elif mode != "auto-hold":
        raise ValueError(f"unsupported mode: {mode}")
    if email:
        cmd.extend(["--email", email])
    if password:
        cmd.extend(["--password", password])

    print("[AutoFill] launching main.py:", " ".join(cmd), flush=True)
    return subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )


def pump_stdout(name: str, proc: subprocess.Popen, out_queue: queue.Queue):
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            out_queue.put((name, line))
    finally:
        out_queue.put((name, None))


def classify_main_line(line: str) -> str:
    text = line or ""
    if "[Success: Email Registration]" in text:
        return "create_success_print"
    if "[Manual]" in text:
        return "manual_challenge"
    if "未观察到 CreateAccount 200" in text:
        return "create_not_observed"
    if "账户创建已被阻止" in text or "一些异常活动" in text or "blocked" in text.lower():
        return "blocked_hint"
    return ""


def write_run_meta(path: Path, meta: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def append_note(notes_path: Path, meta: dict, summary_text: str, protocol_text: str):
    excerpt = []
    for line in summary_text.splitlines():
        if any(k in line for k in ["risk_verify", "telemetry_hcaptcha", "collector #", "verdict"]):
            excerpt.append(line)
    block = [
        "",
        "",
        f"## {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} AdsPower autofill {meta.get('label')}",
        "",
        "```text",
        f"mode={meta.get('mode')}",
        f"user_id={meta.get('user_id')}",
        f"cdp_endpoint={meta.get('cdp_endpoint')}",
        f"browser={meta.get('browser')}",
        f"network_log={meta.get('network_log')}",
        f"main_exit={meta.get('main_exit')}",
        f"observer_verdict={meta.get('observer_verdict')}",
        f"main_verdict={meta.get('main_verdict')}",
        "```",
        "",
        "摘要：",
        "",
        "```text",
        *excerpt[:50],
        "```",
    ]
    if protocol_text.strip():
        block.extend(["", "协议状态：", "", "```text", protocol_text.strip(), "```"])
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    with notes_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(block))


def protocol_verdict_class(protocol_text: str) -> str:
    m = re.search(r"verdict\s+class=([A-Za-z0-9_.-]+)", protocol_text or "")
    return m.group(1) if m else ""


def main() -> int:
    ap = argparse.ArgumentParser(description="AdsPower/SunBrowser autofill + manual captcha runner.")
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--label", default=None)
    ap.add_argument("--profile-dir", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--api-key", default="LOCAL_API_KEY")
    ap.add_argument("--helper", default="http://127.0.0.1:50326")
    ap.add_argument("--config", default="config.ctf.risk_probe.json")
    ap.add_argument("--mode", choices=["manual-captcha", "auto-hold"], default="manual-captcha")
    ap.add_argument("--timeout-seconds", type=int, default=900)
    ap.add_argument("--manual-captcha-wait-seconds", type=int, default=900)
    ap.add_argument("--manual-post-verify-wait-seconds", type=int, default=10)
    ap.add_argument("--max-tasks", type=int, default=1)
    ap.add_argument("--concurrent", type=int, default=1)
    ap.add_argument("--email", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--out-dir", default="Results/network")
    ap.add_argument("--notes", default="Results/score1_rootcause_notes.md")
    ap.add_argument("--append-notes", action="store_true")
    ap.add_argument("--no-skip-preflight", action="store_true")
    ap.add_argument(
        "--no-stop-on-retry",
        action="store_true",
        help="Keep waiting after hsprotect retry/failure. Default stops immediately to avoid burning a profile/IP.",
    )
    ap.add_argument(
        "--success-grace-seconds",
        type=float,
        default=25.0,
        help="After risk/verify continue is observed, keep main.py alive briefly so it can finish CreateAccount and persist credentials.",
    )
    ap.add_argument("--dry-run", action="store_true", help="Discover endpoint and show planned commands only.")
    args = ap.parse_args()

    label = safe_label(args.label or f"{args.user_id}_{args.mode}")
    print(f"[AutoFill] discovering AdsPower CDP for user_id={args.user_id}", flush=True)
    info = discover(args.user_id, args.host, args.profile_dir, 5.0)
    info["active_status"] = active_status(args.user_id, args.api_key, args.helper, 3.0)
    print(json.dumps(info, ensure_ascii=False, indent=2), flush=True)

    out_dir = Path(args.out_dir)
    run_stamp = ts()
    log_path = out_dir / f"adspower_autofill_{label}_{run_stamp}.browser_cdp.jsonl"
    meta_path = Path("Results/protocol_runtime") / f"adspower_autofill_{label}_{run_stamp}.meta.json"

    planned = {
        "label": label,
        "mode": args.mode,
        "user_id": args.user_id,
        "cdp_endpoint": info.get("cdp_endpoint"),
        "browser": info.get("browser"),
        "network_log": str(log_path),
        "meta": str(meta_path),
        "config": args.config,
    }
    if args.dry_run:
        print("[AutoFill] dry-run plan:")
        print(json.dumps(planned, ensure_ascii=False, indent=2))
        return 0

    print(f"[AutoFill] starting observer -> {log_path}", flush=True)
    observer = start_observer(info["cdp_endpoint"], log_path, args.timeout_seconds)
    main_proc = start_main(
        endpoint=info["cdp_endpoint"],
        config=args.config,
        mode=args.mode,
        max_tasks=args.max_tasks,
        concurrent=args.concurrent,
        email=args.email,
        password=args.password,
        manual_wait_seconds=args.manual_captcha_wait_seconds,
        manual_post_wait_seconds=args.manual_post_verify_wait_seconds,
        skip_preflight=not args.no_skip_preflight,
    )

    q: queue.Queue = queue.Queue()
    threading.Thread(target=pump_stdout, args=("observer", observer, q), daemon=True).start()
    threading.Thread(target=pump_stdout, args=("main", main_proc, q), daemon=True).start()

    observer_done = False
    main_done = False
    observer_verdict = ""
    main_verdict = ""
    success_seen_at = None
    last_snapshot_at = 0.0
    started = time.time()

    try:
        while True:
            now = time.time()
            try:
                name, line = q.get(timeout=0.2)
            except queue.Empty:
                name, line = "", ""

            if line is None:
                if name == "observer":
                    observer_done = True
                elif name == "main":
                    main_done = True
            elif line:
                prefix = "[Observer]" if name == "observer" else "[Main]"
                print(prefix, line, end="", flush=True)
                if name == "observer":
                    signal = classify_line(line)
                    if signal == "success":
                        observer_verdict = signal
                        if success_seen_at is None:
                            success_seen_at = now
                            print(
                                f"[AutoFill] observer signal=success; waiting up to "
                                f"{args.success_grace_seconds:.1f}s for main.py to persist result",
                                flush=True,
                            )
                        elif now - success_seen_at >= max(0.0, args.success_grace_seconds):
                            print("[AutoFill] success grace elapsed; stopping", flush=True)
                            break
                    elif signal in {"server_error", "risk_block"}:
                        observer_verdict = signal
                        print(f"[AutoFill] observer signal={signal}", flush=True)
                        break
                if name == "main":
                    signal = classify_main_line(line)
                    if signal:
                        main_verdict = signal

            if now - last_snapshot_at >= 5.0:
                last_snapshot_at = now
                signal, detail = classify_snapshot(log_path)
                if signal in {"success", "server_error", "risk_block", "hsprotect_retry"}:
                    observer_verdict = signal
                    print(f"[AutoFill] snapshot={signal} {detail}", flush=True)
                    if signal in {"risk_block", "server_error"}:
                        break
                    if signal == "success":
                        if success_seen_at is None:
                            success_seen_at = now
                            print(
                                f"[AutoFill] success observed; waiting up to "
                                f"{args.success_grace_seconds:.1f}s for main.py to persist result",
                                flush=True,
                            )
                        elif now - success_seen_at >= max(0.0, args.success_grace_seconds):
                            print("[AutoFill] success grace elapsed; stopping", flush=True)
                            break
                    if signal == "hsprotect_retry" and not args.no_stop_on_retry:
                        main_verdict = "hsprotect_retry"
                        print("[AutoFill] stopping on hsprotect_retry", flush=True)
                        break

            if main_done:
                break
            if now - started > args.timeout_seconds:
                main_verdict = main_verdict or "timeout"
                print("[AutoFill] timeout reached; terminating main.py", flush=True)
                break
    except KeyboardInterrupt:
        main_verdict = main_verdict or "interrupted"
        print("[AutoFill] interrupted", flush=True)
    finally:
        if main_proc.poll() is None:
            main_proc.terminate()
            try:
                main_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                main_proc.kill()
        if observer.poll() is None:
            observer.terminate()
            try:
                observer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                observer.kill()

    main_exit = main_proc.poll()
    observer_exit = observer.poll()
    print(f"[AutoFill] stopped main_exit={main_exit} observer_exit={observer_exit}", flush=True)
    print(f"[AutoFill] log={log_path}", flush=True)

    summary = summarize(log_path)
    print(summary.stdout, flush=True)
    protocol = extract_protocol_state(log_path)
    print(protocol.stdout, flush=True)
    protocol_class = protocol_verdict_class(protocol.stdout)

    meta = dict(planned)
    meta.update(
        {
            "main_exit": main_exit,
            "observer_exit": observer_exit,
            "observer_verdict": observer_verdict or "unknown",
            "main_verdict": main_verdict or "unknown",
            "protocol_class": protocol_class or "unknown",
            "finished_at": datetime.now().isoformat(),
        }
    )
    write_run_meta(meta_path, meta)
    print(f"[AutoFill] meta={meta_path}", flush=True)

    if args.append_notes:
        append_note(Path(args.notes), meta, summary.stdout, protocol.stdout)
        print(f"[AutoFill] appended notes -> {args.notes}", flush=True)

    if protocol_class and protocol_class != "success":
        return 1
    if main_exit == 0:
        return 0
    if observer_verdict == "success" and main_verdict not in {"create_not_observed", "blocked_hint", "timeout"}:
        return 0
    return int(main_exit or 1)


if __name__ == "__main__":
    raise SystemExit(main())
