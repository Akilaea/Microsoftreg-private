import argparse
import base64
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


INFO_NAME_PATTERNS = [
    "剩余流量",
    "套餐到期",
    "官网",
    "无SLA",
    "过期",
    "续费",
    "traffic",
    "expire",
]


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def read_urls(path: Path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def b64decode_text(value: str) -> str:
    raw = re.sub(r"\s+", "", value)
    raw += "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8", errors="replace")


def fetch_url(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "clash-verge/v2.0 mihomo",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        },
    )
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def unique_name(base: str, seen: set[str]) -> str:
    name = re.sub(r"[\r\n\t]+", " ", str(base or "")).strip() or "node"
    if name not in seen:
        seen.add(name)
        return name
    i = 2
    while f"{name} #{i}" in seen:
        i += 1
    final = f"{name} #{i}"
    seen.add(final)
    return final


def is_info_node(node: dict) -> bool:
    name = str(node.get("name") or "")
    lowered = name.lower()
    return any(pattern.lower() in lowered for pattern in INFO_NAME_PATTERNS)


def parse_yaml_proxies(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if isinstance(data, dict):
        proxies = data.get("proxies") or []
    elif isinstance(data, list):
        proxies = data
    else:
        proxies = []
    return [
        p
        for p in proxies
        if isinstance(p, dict) and p.get("name") and p.get("server") and not is_info_node(p)
    ]


def parse_vmess(line: str) -> dict | None:
    try:
        data = json.loads(b64decode_text(line[len("vmess://") :]))
        return {
            "name": data.get("ps") or data.get("add") or "vmess",
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid") or 0),
            "cipher": data.get("scy") or "auto",
            "tls": str(data.get("tls") or "").lower() == "tls",
            "network": data.get("net") or "tcp",
            "servername": data.get("sni") or data.get("host") or data.get("add"),
        }
    except Exception:
        return None


def parse_trojan(line: str) -> dict | None:
    try:
        u = urllib.parse.urlsplit(line)
        q = urllib.parse.parse_qs(u.query)
        return {
            "name": urllib.parse.unquote(u.fragment) or u.hostname or "trojan",
            "type": "trojan",
            "server": u.hostname,
            "port": int(u.port),
            "password": urllib.parse.unquote(u.username or ""),
            "sni": (q.get("sni") or q.get("peer") or [u.hostname])[0],
            "skip-cert-verify": (q.get("allowInsecure") or q.get("skip-cert-verify") or ["0"])[0] in {"1", "true", "True"},
        }
    except Exception:
        return None


def parse_vless(line: str) -> dict | None:
    try:
        u = urllib.parse.urlsplit(line)
        q = urllib.parse.parse_qs(u.query)
        node = {
            "name": urllib.parse.unquote(u.fragment) or u.hostname or "vless",
            "type": "vless",
            "server": u.hostname,
            "port": int(u.port),
            "uuid": urllib.parse.unquote(u.username or ""),
            "tls": (q.get("security") or [""])[0] in {"tls", "reality"},
            "network": (q.get("type") or ["tcp"])[0],
            "servername": (q.get("sni") or q.get("peer") or [u.hostname])[0],
        }
        if (q.get("security") or [""])[0] == "reality":
            node["reality-opts"] = {
                "public-key": (q.get("pbk") or [""])[0],
                "short-id": (q.get("sid") or [""])[0],
            }
        return node
    except Exception:
        return None


def parse_ss(line: str) -> dict | None:
    try:
        rest = line[len("ss://") :]
        body, _, frag = rest.partition("#")
        body = body.split("?", 1)[0]
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = b64decode_text(userinfo)
        else:
            decoded = b64decode_text(body)
            userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {
            "name": urllib.parse.unquote(frag) or host or "ss",
            "type": "ss",
            "server": host.strip("[]"),
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None


def parse_link_lines(text: str) -> tuple[list[dict], dict]:
    try:
        decoded = b64decode_text(text)
        if "://" in decoded:
            text = decoded
    except Exception:
        pass

    nodes = []
    counts = {"vmess": 0, "trojan": 0, "vless": 0, "ss": 0, "unsupported": 0}
    for raw in re.split(r"[\r\n]+", text):
        line = raw.strip()
        if not line:
            continue
        parsed = None
        if line.startswith("vmess://"):
            parsed = parse_vmess(line)
            counts["vmess"] += 1
        elif line.startswith("trojan://"):
            parsed = parse_trojan(line)
            counts["trojan"] += 1
        elif line.startswith("vless://"):
            parsed = parse_vless(line)
            counts["vless"] += 1
        elif line.startswith("ss://"):
            parsed = parse_ss(line)
            counts["ss"] += 1
        elif "://" in line:
            counts["unsupported"] += 1
        if parsed and parsed.get("server") and not is_info_node(parsed):
            nodes.append(parsed)
    return nodes, counts


def render_config(proxies: list[dict], args: argparse.Namespace) -> dict:
    names = [p["name"] for p in proxies]
    return {
        "port": args.http_port,
        "socks-port": args.socks_port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "external-controller": f"127.0.0.1:{args.controller_port}",
        "secret": "",
        "mode": "rule",
        "log-level": "info",
        "tun": {"enable": False},
        "proxies": proxies,
        "proxy-groups": [{"name": "AUTO_TEST", "type": "select", "proxies": names}],
        "rules": ["MATCH,AUTO_TEST"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Build isolated mihomo config from subscription URLs.")
    ap.add_argument("--urls-file", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path(".mihomo-isolated"))
    ap.add_argument("--http-port", type=int, default=17890)
    ap.add_argument("--socks-port", type=int, default=17891)
    ap.add_argument("--controller-port", type=int, default=19090)
    ap.add_argument("--timeout", type=float, default=25.0)
    args = ap.parse_args()

    urls = read_urls(args.urls_file)
    seen_names: set[str] = set()
    proxies: list[dict] = []
    sources = []
    for idx, url in enumerate(urls, 1):
        source = {"idx": idx, "url_host": urllib.parse.urlsplit(url).netloc, "ok": False, "proxies": 0}
        try:
            body = fetch_url(url, args.timeout)
            text = body.decode("utf-8", errors="replace")
            parsed = parse_yaml_proxies(text)
            mode = "yaml"
            counts = {}
            if not parsed:
                parsed, counts = parse_link_lines(text)
                mode = "links"
            for node in parsed:
                node = dict(node)
                node["name"] = unique_name(str(node.get("name") or node.get("server") or "node"), seen_names)
                proxies.append(node)
            source.update({"ok": True, "mode": mode, "bytes": len(body), "proxies": len(parsed), "counts": counts})
        except Exception as exc:
            source.update({"error": repr(exc)[:240]})
        sources.append(source)
        print(f"[{idx}/{len(urls)}] {source['url_host']} ok={source['ok']} proxies={source['proxies']}")

    if not proxies:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "subscription_build_summary.json").write_text(
            json.dumps({"created_at": time.strftime("%Y%m%d_%H%M%S"), "sources": sources}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        raise SystemExit("no proxies parsed from subscriptions")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    config = render_config(proxies, args)
    out_config = args.out_dir / "config.yaml"
    out_config.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    meta = {
        "created_at": time.strftime("%Y%m%d_%H%M%S"),
        "source_count": len(urls),
        "proxy_count": len(proxies),
        "out_config": str(out_config),
        "http_proxy": f"http://127.0.0.1:{args.http_port}",
        "socks_proxy": f"socks5://127.0.0.1:{args.socks_port}",
        "controller": f"http://127.0.0.1:{args.controller_port}",
        "group": "AUTO_TEST",
        "sources": sources,
    }
    (args.out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out_dir / "subscription_build_summary.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: meta[k] for k in ["source_count", "proxy_count", "out_config", "controller"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
