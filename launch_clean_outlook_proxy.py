"""
Launch a clean manual Outlook signup Cloak window through mihomo.

This is intentionally a no-observer/no-CDP control:

  - no --remote-debugging-port
  - no CDP attach
  - no NetLog
  - no Playwright/Patchright
  - filters Cloak's --no-sandbox flag to avoid Chrome warning pollution
"""

import argparse
import pathlib
import secrets
import subprocess

import cloakbrowser


PROFILE_ROOT = pathlib.Path(r"C:\Users\wdnmd\ZCodeProject\profiles")


def main() -> int:
    ap = argparse.ArgumentParser(description="Clean Cloak manual signup launcher.")
    ap.add_argument("url", nargs="?", default="https://outlook.live.com/mail/0/?prompt=create_account")
    ap.add_argument("profile", nargs="?", default="")
    ap.add_argument("--proxy-server", default="http://127.0.0.1:17890")
    ap.add_argument("--no-proxy", action="store_true", help="Do not pass an explicit browser proxy; use the system network/TUN path.")
    ap.add_argument("--timezone", default="Asia/Shanghai")
    ap.add_argument("--locale", default="zh-CN")
    ap.add_argument("--keep-sandbox-flag", action="store_true")
    args = ap.parse_args()
    if args.no_proxy:
        args.proxy_server = ""

    binary = cloakbrowser.binary_info()
    if not binary.get("installed"):
        print("CloakBrowser kernel not installed; downloading...")
        cloakbrowser.ensure_binary()
        binary = cloakbrowser.binary_info()
    chrome_exe = binary["binary_path"]

    extra_args = []
    if args.proxy_server:
        extra_args.append(f"--proxy-server={args.proxy_server}")

    cargs = cloakbrowser.build_args(
        stealth_args=True,
        extra_args=extra_args or None,
        timezone=args.timezone,
        locale=args.locale,
        headless=False,
    )
    if not args.keep_sandbox_flag:
        cargs = [a for a in cargs if a.lower() not in ("--no-sandbox", "--no--sandbox")]

    profile_name = args.profile or ("cleanproxy_" + secrets.token_hex(4))
    user_data_dir = PROFILE_ROOT / profile_name
    target_url = args.url if str(args.url).startswith("http") else "https://outlook.live.com/mail/0/?prompt=create_account"

    cargs += [f"--user-data-dir={user_data_dir}"]

    print("=" * 72)
    print("CloakBrowser clean manual signup launcher")
    print(f"  Profile : {profile_name} ({user_data_dir})")
    print(f"  URL     : {target_url}")
    print(f"  Proxy   : {args.proxy_server or '(none)'}")
    print(f"  TZ      : {args.timezone}")
    print(f"  Locale  : {args.locale}")
    print("  CDP     : disabled")
    print("  NetLog  : disabled")
    print("=" * 72)

    proc = subprocess.Popen([chrome_exe] + cargs + [target_url])
    print(f"[clean] browser pid={proc.pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
