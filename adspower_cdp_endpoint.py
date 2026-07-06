import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


def default_profile_dir(user_id: str) -> Path:
    return Path(r"C:\.ADSPOWER_GLOBAL\cache") / f"{user_id}_LOCALCTF"


def read_devtools_active_port(profile_dir: Path) -> tuple[int, str]:
    path = profile_dir / "DevToolsActivePort"
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise RuntimeError(f"{path} did not contain a port and browser websocket path")
    return int(lines[0]), lines[1].strip()


def fetch_json(url: str, timeout: float):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Discover an AdsPower/SunBrowser CDP endpoint from DevToolsActivePort.")
    ap.add_argument("--user-id", default="1782906748604", help="AdsPower user_id; used to derive the default profile dir.")
    ap.add_argument("--profile-dir", default=None, help="Explicit AdsPower profile directory.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--list-targets", action="store_true", help="Also print current DevTools targets.")
    ap.add_argument("--json", action="store_true", help="Emit one JSON object instead of key=value lines.")
    args = ap.parse_args()

    profile_dir = Path(args.profile_dir) if args.profile_dir else default_profile_dir(args.user_id)
    port, browser_path = read_devtools_active_port(profile_dir)
    endpoint = f"http://{args.host}:{port}"

    result = {
        "user_id": args.user_id,
        "profile_dir": str(profile_dir),
        "port": port,
        "cdp_endpoint": endpoint,
        "browser_ws_from_file": f"ws://{args.host}:{port}{browser_path}",
    }

    try:
        version = fetch_json(endpoint + "/json/version", args.timeout)
        result["ok"] = True
        result["browser"] = version.get("Browser")
        result["protocol_version"] = version.get("Protocol-Version")
        result["user_agent"] = version.get("User-Agent")
        result["browser_ws"] = version.get("webSocketDebuggerUrl")
        if args.list_targets:
            targets = fetch_json(endpoint + "/json/list", args.timeout)
            result["targets"] = [
                {
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "title": item.get("title"),
                    "url": item.get("url"),
                    "webSocketDebuggerUrl": item.get("webSocketDebuggerUrl"),
                }
                for item in targets
            ]
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        result["ok"] = False
        result["error"] = str(exc)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for key in ["ok", "user_id", "profile_dir", "port", "cdp_endpoint", "browser", "protocol_version", "browser_ws"]:
            if key in result:
                print(f"{key}={result[key]}")
        if "error" in result:
            print(f"error={result['error']}", file=sys.stderr)
        if args.list_targets and result.get("targets"):
            for idx, item in enumerate(result["targets"], 1):
                print(f"target[{idx}].type={item.get('type')}")
                print(f"target[{idx}].title={item.get('title')}")
                print(f"target[{idx}].url={item.get('url')}")
                print(f"target[{idx}].ws={item.get('webSocketDebuggerUrl')}")

    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
