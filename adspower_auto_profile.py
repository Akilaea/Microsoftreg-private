import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path


def request_json(url: str, method: str = "GET", data: dict | None = None, timeout: float = 15.0):
    body = None
    headers = {}
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"code": -1, "msg": text, "raw": text}


def profile_dir(user_id: str) -> Path:
    return Path(r"C:\.ADSPOWER_GLOBAL\cache") / f"{user_id}_LOCALCTF"


def read_devtools(user_id: str):
    p = profile_dir(user_id) / "DevToolsActivePort"
    lines = p.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise RuntimeError(f"{p} malformed")
    port = int(lines[0])
    browser_path = lines[1].strip()
    return port, browser_path


def wait_cdp(user_id: str, host: str, wait_sec: float):
    deadline = time.time() + wait_sec
    last_err = None
    while time.time() < deadline:
        try:
            port, browser_path = read_devtools(user_id)
            endpoint = f"http://{host}:{port}"
            version = request_json(endpoint + "/json/version", timeout=3)
            if version.get("webSocketDebuggerUrl"):
                return {
                    "profile_dir": str(profile_dir(user_id)),
                    "port": port,
                    "cdp_endpoint": endpoint,
                    "browser_ws_from_file": f"ws://{host}:{port}{browser_path}",
                    "browser_ws": version.get("webSocketDebuggerUrl"),
                    "browser": version.get("Browser"),
                    "protocol_version": version.get("Protocol-Version"),
                    "user_agent": version.get("User-Agent"),
                }
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"CDP not ready for {user_id}: {last_err}")


def main():
    ap = argparse.ArgumentParser(description="Create and start an AdsPower local CTF profile, then print its CDP endpoint.")
    ap.add_argument("--api-base", default="http://127.0.0.1:50326")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--name-prefix", default="outlook自动测试_auto")
    ap.add_argument("--remark", default="codex auto test profile")
    ap.add_argument("--wait-sec", type=float, default=30)
    ap.add_argument("--no-start", action="store_true")
    ap.add_argument("--list-targets", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = f"{args.name_prefix}_{stamp}"
    create = request_json(
        args.api_base.rstrip("/") + "/api/v1/user/create",
        method="POST",
        data={"name": name, "domain_name": "", "group_id": "0", "remark": args.remark},
        timeout=15,
    )
    if create.get("code") != 0:
        raise SystemExit(f"user/create failed: {json.dumps(create, ensure_ascii=False)}")
    data = create.get("data") or {}
    user_id = str(data.get("user_id") or data.get("id") or data.get("serial_number") or "")
    if not user_id:
        raise SystemExit(f"user/create returned no user_id: {json.dumps(create, ensure_ascii=False)}")

    result = {"name": name, "user_id": user_id, "create": create}
    if not args.no_start:
        start = request_json(args.api_base.rstrip() + f"/api/v1/browser/start?user_id={urllib.parse.quote(user_id)}", timeout=45)
        result["start"] = start
        if start.get("code") != 0:
            raise SystemExit(f"browser/start failed: {json.dumps(result, ensure_ascii=False)}")
        cdp = wait_cdp(user_id, args.host, args.wait_sec)
        result.update(cdp)
        if args.list_targets:
            try:
                result["targets"] = request_json(result["cdp_endpoint"] + "/json/list", timeout=5)
            except Exception as exc:  # noqa: BLE001
                result["targets_error"] = str(exc)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for key in ["name", "user_id", "profile_dir", "port", "cdp_endpoint", "browser", "browser_ws"]:
            if key in result:
                print(f"{key}={result[key]}")
        if args.list_targets and result.get("targets"):
            for i, t in enumerate(result["targets"], 1):
                print(f"target[{i}].type={t.get('type')}")
                print(f"target[{i}].title={t.get('title')}")
                print(f"target[{i}].url={t.get('url')}")


if __name__ == "__main__":
    main()
