r"""
Manual success sampler for the current CTF Outlook registration target.

Default entry intentionally matches the known successful manual NetLog sample:
bare signup.live.com.  Do not switch it to the Outlook prompt URL unless a new
successful sample proves that path is equivalent.

This intentionally mirrors C:\Users\wdnmd\ZCodeProject\open_outlook.py as
closely as possible (same cloakbrowser.build_args, same profile root, no
proxy), but adds:

  1. Chrome NetLog, for low-level timing evidence.
  2. A local DevTools port so manual_cdp_observer.py can capture response
     bodies for /api/v1.0/risk/verify and /API/CreateAccount.

Use only when we explicitly need a manual-captcha sample.  For the normal
"low pollution" manual check, launch_open_outlook_netlog.py remains closer to
the original script because it does not add a DevTools port.
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
NETLOG_DIR = ROOT / "Results" / "netlog"
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
    ap = argparse.ArgumentParser(description="Launch original-style Cloak and capture manual risk/verify response bodies.")
    ap.add_argument("url", nargs="?", default="https://signup.live.com")
    ap.add_argument("profile", nargs="?", default="")
    ap.add_argument("--port", type=int, default=19222)
    ap.add_argument("--timeout-seconds", type=int, default=600)
    args_ns = ap.parse_args()

    binary = cloakbrowser.binary_info()
    if not binary.get("installed"):
        print("CloakBrowser 内核未安装，正在下载...")
        cloakbrowser.ensure_binary()
        binary = cloakbrowser.binary_info()
    chrome_exe = binary["binary_path"]

    cargs = cloakbrowser.build_args(
        stealth_args=True,
        extra_args=None,
        timezone="Asia/Shanghai",
        locale="zh-CN",
        headless=False,
    )

    profile_name = args_ns.profile or ("riskcap_" + secrets.token_hex(4))
    user_data_dir = PROFILE_ROOT / profile_name
    target_url = args_ns.url if str(args_ns.url).startswith("http") else "https://signup.live.com"

    NETLOG_DIR.mkdir(parents=True, exist_ok=True)
    NETWORK_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    port = find_free_port(args_ns.port)
    netlog_path = NETLOG_DIR / f"{stamp}_{profile_name}.riskcap.netlog.json"
    network_path = NETWORK_DIR / f"{stamp}_{profile_name}.manual_risk_capture.jsonl"
    meta_path = NETLOG_DIR / f"{stamp}_{profile_name}.riskcap.meta.json"
    observer_log = RUNTIME_DIR / f"{stamp}_{profile_name}.manual_risk_observer.log"

    cargs += [
        f"--user-data-dir={user_data_dir}",
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",
        f"--log-net-log={netlog_path}",
        "--net-log-capture-mode=IncludeSensitive",
    ]

    meta = {
        "created_at": stamp,
        "profile_name": profile_name,
        "user_data_dir": str(user_data_dir),
        "target_url": target_url,
        "netlog_path": str(netlog_path),
        "network_path": str(network_path),
        "observer_log": str(observer_log),
        "cdp_endpoint": f"http://127.0.0.1:{port}",
        "chrome_exe": chrome_exe,
        "binary_version": binary.get("version"),
        "note": "manual risk/verify body sampler; adds remote-debugging-port, so use only when body capture is required",
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 72)
    print("CloakBrowser 手动 risk/verify 采样")
    print("  注意: 这次会加 DevTools 端口用于抓响应体；比纯 NetLog 更有污染。")
    print(f"  Profile  : {profile_name} ({user_data_dir})")
    print(f"  打开页面 : {target_url}")
    print(f"  CDP      : http://127.0.0.1:{port}")
    print(f"  Network  : {network_path}")
    print(f"  NetLog   : {netlog_path}")
    print(f"  Meta     : {meta_path}")
    print("=" * 72)

    browser_proc = subprocess.Popen([chrome_exe] + cargs + [target_url])
    print(f"[riskcap] browser pid={browser_proc.pid}")

    # Give the DevTools HTTP endpoint a short moment to bind before attaching.
    time.sleep(1.5)
    observer_cmd = [
        sys.executable,
        str(ROOT / "manual_cdp_observer.py"),
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
    print(f"[riskcap] observer pid={observer_proc.pid}")
    print("[riskcap] 请在打开的 Cloak 窗口里手动完成注册/验证码。")
    print("[riskcap] 看到注册成功后告诉我；我会读取上面的 Network/Observer 日志继续分析。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
