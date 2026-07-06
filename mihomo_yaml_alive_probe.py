import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


DEFAULT_CONFIG = Path(".mihomo-isolated") / "config.yaml"
DEFAULT_CONTROLLER = "http://127.0.0.1:19090"
DEFAULT_PROXY = "http://127.0.0.1:17890"
DEFAULT_GROUP = "AUTO_TEST"
DEFAULT_DELAY_URL = "https://www.cloudflare.com/cdn-cgi/trace"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def http_json(method: str, url: str, body: dict | None = None, timeout: float = 8.0):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        return json.loads(text) if text else None


def load_proxy_names(config_path: Path) -> list[str]:
    with config_path.open("r", encoding="utf-8", errors="replace") as fh:
        data = yaml.safe_load(fh)
    proxies = data.get("proxies") or []
    names = []
    for item in proxies:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def switch_group(controller: str, group: str, name: str) -> None:
    quoted_group = urllib.parse.quote(group, safe="")
    http_json(
        "PUT",
        f"{controller.rstrip('/')}/proxies/{quoted_group}",
        {"name": name},
        timeout=6.0,
    )


def proxy_delay(controller: str, name: str, delay_url: str, timeout_ms: int) -> tuple[bool, int | None, str]:
    quoted_name = urllib.parse.quote(name, safe="")
    query = urllib.parse.urlencode({"timeout": str(timeout_ms), "url": delay_url})
    url = f"{controller.rstrip('/')}/proxies/{quoted_name}/delay?{query}"
    try:
        data = http_json("GET", url, timeout=max(3.0, timeout_ms / 1000.0 + 2.0))
        delay = data.get("delay") if isinstance(data, dict) else None
        if isinstance(delay, int) and delay >= 0:
            return True, delay, "delay_ok"
        return False, None, f"delay_bad:{data!r}"[:180]
    except Exception as exc:
        return False, None, repr(exc)[:180]


def trace_via_proxy(proxy_url: str, timeout: float) -> tuple[bool, str, str, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    req = urllib.request.Request(
        "https://www.cloudflare.com/cdn-cgi/trace",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read(8192).decode("utf-8", errors="replace")
        ip = re.search(r"(?m)^ip=(.+)$", text)
        loc = re.search(r"(?m)^loc=(.+)$", text)
        return True, ip.group(1) if ip else "", loc.group(1) if loc else "", "trace_ok"
    except Exception as exc:
        return False, "", "", repr(exc)[:180]


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe all nodes from the current mihomo YAML and write .mihomo-isolated/alive_*.json")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--controller", default=DEFAULT_CONTROLLER)
    ap.add_argument("--group", default=DEFAULT_GROUP)
    ap.add_argument("--proxy-url", default=DEFAULT_PROXY)
    ap.add_argument("--filter", default="", help="Optional regex for node names.")
    ap.add_argument("--max-nodes", type=int, default=0, help="0 means all matched nodes.")
    ap.add_argument("--timeout-ms", type=int, default=6500)
    ap.add_argument("--trace-timeout", type=float, default=10.0)
    ap.add_argument("--delay-url", default=DEFAULT_DELAY_URL)
    ap.add_argument("--switch-sleep-ms", type=int, default=350)
    ap.add_argument("--out-dir", type=Path, default=Path(".mihomo-isolated"))
    args = ap.parse_args()

    names = load_proxy_names(args.config)
    if args.filter:
        rx = re.compile(args.filter, re.I)
        names = [n for n in names if rx.search(n)]
    if args.max_nodes and args.max_nodes > 0:
        names = names[: args.max_nodes]
    if not names:
        raise SystemExit("no nodes matched")

    http_json("GET", f"{args.controller.rstrip('/')}/proxies", timeout=4.0)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    rows: list[dict] = []
    print(f"[alive] config={args.config} candidates={len(names)} controller={args.controller} group={args.group}")
    for idx, name in enumerate(names, 1):
        print(f"[{idx}/{len(names)}] {name}", flush=True)
        t0 = time.time()
        delay_ok, delay, delay_detail = proxy_delay(args.controller, name, args.delay_url, args.timeout_ms)
        row = {
            "idx": idx,
            "name": name,
            "alive": bool(delay_ok),
            "delay": delay,
            "delay_detail": delay_detail,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "trace_ok": False,
            "ip": "",
            "loc": "",
        }
        if delay_ok:
            try:
                switch_group(args.controller, args.group, name)
                time.sleep(max(0, args.switch_sleep_ms) / 1000.0)
                ok, ip, loc, detail = trace_via_proxy(args.proxy_url, args.trace_timeout)
                row.update({"trace_ok": ok, "ip": ip, "loc": loc, "trace_detail": detail})
                print(f"  alive delay={delay}ms trace={ok} ip={ip or '-'} loc={loc or '-'}")
            except Exception as exc:
                row.update({"trace_detail": repr(exc)[:180]})
                print(f"  alive delay={delay}ms trace=False {row['trace_detail']}")
        else:
            print(f"  dead {delay_detail}")
        rows.append(row)

    alive = sorted(
        [r for r in rows if r.get("alive") and r.get("trace_ok")],
        key=lambda r: (r.get("delay") if isinstance(r.get("delay"), int) else 10**9, r.get("elapsed_ms") or 10**9),
    )
    report = {
        "created_at": stamp,
        "config": str(args.config),
        "controller": args.controller,
        "group": args.group,
        "proxy": args.proxy_url,
        "delay_url": args.delay_url,
        "timeout_ms": args.timeout_ms,
        "total": len(names),
        "alive_count": len(alive),
        "alive": alive,
        "all": rows,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"alive_{stamp}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[alive] written={out} total={len(names)} alive={len(alive)}")
    for r in alive[:20]:
        print(f"  {r.get('delay')}ms {r.get('ip')} {r.get('loc')} {r.get('name')}")
    return 0 if alive else 1


if __name__ == "__main__":
    raise SystemExit(main())
