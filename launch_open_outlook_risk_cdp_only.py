"""
Manual risk/verify sampler without Chrome NetLog.

This mirrors C:\\Users\\wdnmd\\ZCodeProject\\open_outlook.py as closely as
possible, but adds only a local DevTools port so manual_cdp_observer.py can
passively capture:

  - /api/v1.0/risk/initialize
  - /api/v1.0/risk/verify
  - hsprotect collector score responses
  - CreateAccount

It intentionally does NOT pass --log-net-log, because the Chrome command-line
warning for that flag was suspected to pollute the challenge.
"""

import argparse
import datetime as _dt
import json
import pathlib
import secrets
import socket
import subprocess
import sys
import time

import cloakbrowser


ROOT = pathlib.Path(__file__).resolve().parent
PROFILE_ROOT = pathlib.Path(r"C:\Users\wdnmd\ZCodeProject\profiles")
NETWORK_DIR = ROOT / "Results" / "network"
RUNTIME_DIR = ROOT / "Results" / "protocol_runtime"


def find_free_port(preferred: int) -> int:
    if preferred:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", preferred))
                return preferred
            except OSError:
                pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> int:
    ap = argparse.ArgumentParser(description="Launch original-style Cloak with CDP-only passive observer.")
    ap.add_argument("url", nargs="?", default="https://outlook.live.com/mail/0/?prompt=create_account")
    ap.add_argument("profile", nargs="?", default="")
    ap.add_argument("--port", type=int, default=19222)
    ap.add_argument("--timeout-seconds", type=int, default=600)
    ap.add_argument("--timezone", default="Asia/Shanghai")
    ap.add_argument("--locale", default="zh-CN")
    ap.add_argument("--proxy-server", default="", help="Optional Chrome proxy-server, e.g. http://127.0.0.1:17890")
    ap.add_argument("--keep-sandbox-flag", action="store_true", help="Do not filter Cloak's --no-sandbox flag.")
    ap.add_argument("--observer", choices=("raw", "patchright", "none"), default="raw")
    args_ns = ap.parse_args()

    binary = cloakbrowser.binary_info()
    if not binary.get("installed"):
        print("CloakBrowser kernel not installed; downloading...")
        cloakbrowser.ensure_binary()
        binary = cloakbrowser.binary_info()
    chrome_exe = binary["binary_path"]

    extra_args = []
    if args_ns.proxy_server:
        extra_args.append(f"--proxy-server={args_ns.proxy_server}")

    cargs = cloakbrowser.build_args(
        stealth_args=True,
        extra_args=extra_args or None,
        timezone=args_ns.timezone,
        locale=args_ns.locale,
        headless=False,
    )
    if not args_ns.keep_sandbox_flag:
        cargs = [a for a in cargs if a.lower() not in ("--no-sandbox", "--no--sandbox")]

    profile_name = args_ns.profile or ("riskcdp_" + secrets.token_hex(4))
    user_data_dir = PROFILE_ROOT / profile_name
    target_url = args_ns.url if str(args_ns.url).startswith("http") else "https://signup.live.com"

    NETWORK_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    port = find_free_port(args_ns.port)
    network_path = NETWORK_DIR / f"{stamp}_{profile_name}.manual_risk_cdp.jsonl"
    observer_log = RUNTIME_DIR / f"{stamp}_{profile_name}.manual_risk_cdp_observer.log"
    meta_path = RUNTIME_DIR / f"{stamp}_{profile_name}.manual_risk_cdp.meta.json"

    cargs += [
        f"--user-data-dir={user_data_dir}",
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",
    ]

    meta = {
        "created_at": stamp,
        "profile_name": profile_name,
        "user_data_dir": str(user_data_dir),
        "target_url": target_url,
        "network_path": str(network_path),
        "observer_log": str(observer_log),
        "cdp_endpoint": f"http://127.0.0.1:{port}",
        "chrome_exe": chrome_exe,
        "binary_version": binary.get("version"),
        "timezone": args_ns.timezone,
        "locale": args_ns.locale,
        "proxy_server": args_ns.proxy_server,
        "sandbox_flag_filtered": not args_ns.keep_sandbox_flag,
        "observer": args_ns.observer,
        "note": "CDP-only passive sampler; no --log-net-log",
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 72)
    print("CloakBrowser manual risk sampler (CDP only, no NetLog)")
    print(f"  Profile : {profile_name} ({user_data_dir})")
    print(f"  URL     : {target_url}")
    print(f"  CDP     : http://127.0.0.1:{port}")
    print(f"  Network : {network_path}")
    print(f"  Log     : {observer_log}")
    print(f"  Meta    : {meta_path}")
    if args_ns.proxy_server:
        print(f"  Proxy   : {args_ns.proxy_server}")
    print("=" * 72)

    browser_proc = subprocess.Popen([chrome_exe] + cargs + [target_url])
    print(f"[risk-cdp] browser pid={browser_proc.pid}")

    observer_proc = None
    if args_ns.observer != "none":
        time.sleep(1.5)
        observer_script = "manual_raw_cdp_observer.py" if args_ns.observer == "raw" else "manual_cdp_observer.py"
        observer_cmd = [
            sys.executable,
            str(ROOT / observer_script),
            "--cdp-endpoint",
            f"http://127.0.0.1:{port}",
            "--timeout-seconds",
            str(max(1, args_ns.timeout_seconds)),
            "--out",
            str(network_path),
        ]
        with observer_log.open("w", encoding="utf-8") as log_fh:
            observer_proc = subprocess.Popen(
                observer_cmd,
                cwd=str(ROOT),
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
            )
        print(f"[risk-cdp] observer={args_ns.observer} pid={observer_proc.pid}")
    else:
        print("[risk-cdp] observer disabled")
    print("[risk-cdp] 请在打开的 Cloak 窗口里手动走到验证码/注册结果；完成后告诉我。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
