import argparse
import json
import re
from pathlib import Path

import yaml


DEFAULT_SOURCE_DIR = Path(r"C:\Users\wdnmd\Documents\mihomo-windows-amd64-v1-go120-v1.19.27")
DEFAULT_SOURCE_CONFIG = DEFAULT_SOURCE_DIR / "nodes_20260622_075537.yaml"


def main() -> int:
    ap = argparse.ArgumentParser(description="Create an isolated mihomo config for proxy testing.")
    ap.add_argument("--source-config", type=Path, default=DEFAULT_SOURCE_CONFIG)
    ap.add_argument("--out-dir", type=Path, default=Path(".mihomo-isolated"))
    ap.add_argument("--http-port", type=int, default=17890)
    ap.add_argument("--socks-port", type=int, default=17891)
    ap.add_argument("--controller-port", type=int, default=19090)
    args = ap.parse_args()

    source_config = args.source_config.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    with source_config.open("r", encoding="utf-8", errors="replace") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise SystemExit(f"invalid mihomo yaml: {source_config}")

    proxies = data.get("proxies") or []
    names = [
        str(item.get("name"))
        for item in proxies
        if isinstance(item, dict) and item.get("name")
    ]
    if not names:
        raise SystemExit("no proxies found in source config")

    isolated = dict(data)
    isolated["port"] = int(args.http_port)
    isolated["socks-port"] = int(args.socks_port)
    isolated.pop("mixed-port", None)
    isolated["allow-lan"] = False
    isolated["bind-address"] = "127.0.0.1"
    isolated["external-controller"] = f"127.0.0.1:{int(args.controller_port)}"
    isolated["secret"] = ""
    isolated["mode"] = "rule"
    isolated["log-level"] = "info"
    isolated["tun"] = {"enable": False}
    isolated["proxy-groups"] = [
        {
            "name": "AUTO_TEST",
            "type": "select",
            "proxies": names,
        }
    ]
    isolated["rules"] = ["MATCH,AUTO_TEST"]

    out_config = out_dir / "config.yaml"
    rendered = yaml.safe_dump(isolated, allow_unicode=True, sort_keys=False)
    # Go YAML parsers may interpret unquoted values such as 473277e2 as a
    # number, which makes mihomo report "invalid REALITY short ID".  Keep all
    # short-id values explicitly string-typed.
    rendered = re.sub(r"(^\s*short-id:\s+)([^\"'\s\n#][^\n#]*?)\s*$", r'\1"\2"', rendered, flags=re.M)
    out_config.write_text(rendered, encoding="utf-8")

    meta = {
        "source_config": str(source_config),
        "out_config": str(out_config),
        "http_proxy": f"http://127.0.0.1:{int(args.http_port)}",
        "socks_proxy": f"socks5://127.0.0.1:{int(args.socks_port)}",
        "controller": f"http://127.0.0.1:{int(args.controller_port)}",
        "proxy_count": len(names),
        "group": "AUTO_TEST",
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
