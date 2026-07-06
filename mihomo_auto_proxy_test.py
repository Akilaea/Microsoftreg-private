import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


GROUP = "AUTO_TEST"
DEFAULT_CONTROLLER = "http://127.0.0.1:19090"
DEFAULT_PROXY = "http://127.0.0.1:17890"
DEFAULT_CONFIG = Path(".mihomo-isolated") / "config.yaml"


COUNTRY_HINTS = [
    ("🇺🇸", "美国"), ("美国", "美国"), ("US", "美国"), ("United States", "美国"),
    ("🇬🇧", "英国"), ("英国", "英国"), ("UK", "英国"), ("United Kingdom", "英国"),
    ("🇸🇬", "新加坡"), ("新加坡", "新加坡"), ("SG", "新加坡"),
    ("🇯🇵", "日本"), ("日本", "日本"), ("JP", "日本"),
    ("🇰🇷", "韩国"), ("韩国", "韩国"), ("KR", "韩国"),
    ("🇹🇼", "台湾",), ("台湾", "台湾"), ("TW", "台湾"), ("Taiwan", "台湾"),
    ("🇫🇷", "法国"), ("法国", "法国"), ("FR", "法国"), ("France", "法国"),
    ("🇩🇪", "德国"), ("德国", "德国"), ("DE", "德国"), ("Germany", "德国"),
    ("🇨🇦", "加拿大"), ("加拿大", "加拿大"), ("CA", "加拿大"), ("Canada", "加拿大"),
]


def load_proxy_names(config_path: Path) -> list[str]:
    with config_path.open("r", encoding="utf-8", errors="replace") as fh:
        data = yaml.safe_load(fh)
    proxies = data.get("proxies") or []
    return [
        str(item.get("name"))
        for item in proxies
        if isinstance(item, dict) and item.get("name")
    ]


def infer_country_label(name: str) -> str:
    upper = str(name or "").upper()
    for needle, label in COUNTRY_HINTS:
        if needle.upper() in upper:
            return label
    return ""


def http_json(method: str, url: str, body: dict | None = None, timeout: float = 5.0):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        return json.loads(text) if text else None


def switch_proxy(controller: str, name: str) -> None:
    group = urllib.parse.quote(GROUP, safe="")
    http_json("PUT", f"{controller.rstrip('/')}/proxies/{group}", {"name": name}, timeout=6.0)


def quick_probe(proxy_url: str, timeout: float = 8.0) -> tuple[bool, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    req = urllib.request.Request(
        "https://www.cloudflare.com/cdn-cgi/trace",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read(4096).decode("utf-8", errors="replace")
        ip = re.search(r"^ip=(.+)$", text, re.M)
        loc = re.search(r"^loc=(.+)$", text, re.M)
        return True, f"ip={ip.group(1) if ip else '?'} loc={loc.group(1) if loc else '?'}"
    except Exception as exc:
        return False, repr(exc)[:180]


def run_register(
    proxy_url: str,
    country_label: str,
    timeout: int,
    *,
    script: str = "run_accel_defer_w0_once.ps1",
    no_defer_final_result_to_w0: bool = False,
    no_synthetic_u0: bool = False,
    optimistic_w0_success: bool = False,
    optimistic_final_success: bool = False,
    rewrite_final_result_success: bool = False,
    trigger_final_success_signals: bool = False,
    no_trigger_final_success_signals: bool = False,
    defer_final_result_to_w0: bool = False,
    w0_after_final_ms: int | None = None,
    defer_w0_wait_ms: int | None = None,
    extra_script_args: list[str] | None = None,
) -> tuple[str, int]:
    cmd = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script,
        "-ProxyUrl",
        proxy_url,
    ]
    if country_label:
        cmd += ["-CountryLabel", country_label]
    if no_defer_final_result_to_w0:
        cmd += ["-NoDeferFinalResultToW0"]
    if no_synthetic_u0:
        cmd += ["-NoSyntheticU0"]
    if optimistic_w0_success:
        cmd += ["-OptimisticW0Success"]
    if optimistic_final_success:
        cmd += ["-OptimisticFinalSuccess"]
    if rewrite_final_result_success:
        cmd += ["-RewriteFinalResultSuccess"]
    if trigger_final_success_signals:
        cmd += ["-TriggerFinalSuccessSignals"]
    if no_trigger_final_success_signals:
        cmd += ["-NoTriggerFinalSuccessSignals"]
    if defer_final_result_to_w0:
        cmd += ["-DeferFinalResultToW0"]
    if w0_after_final_ms is not None:
        cmd += ["-W0AfterFinalMs", str(w0_after_final_ms)]
    if defer_w0_wait_ms is not None:
        cmd += ["-DeferW0WaitMs", str(defer_w0_wait_ms)]
    if extra_script_args:
        cmd += list(extra_script_args)
    proc = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parent,
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    return proc.stdout, proc.returncode


def classify_register_output(text: str, code: int) -> str:
    if "signup.live.com/API/CreateAccount" in text and "response POST status=200" in text:
        return "create_account_200"
    if "CreateAccount" in text and "status=200" in text:
        return "create_account_possible"
    if (
        "RiskBlock" in text
        or "state=blocked" in text
        or "Error: Rate limit" in text
        or "异常活动" in text
        or "闃绘柇" in text
    ):
        return "riskblock"
    if "HumanCaptcha iframe" in text or "PX1200 calls=" in text:
        return "captcha_or_protocol"
    if code == 0:
        return "script_success"
    return "failed"


def main() -> int:
    ap = argparse.ArgumentParser(description="Switch isolated mihomo nodes and optionally run Outlook acceleration test.")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--controller", default=DEFAULT_CONTROLLER)
    ap.add_argument("--proxy-url", default=DEFAULT_PROXY)
    ap.add_argument("--filter", default="", help="Regex filter for node names.")
    ap.add_argument("--max-nodes", type=int, default=5)
    ap.add_argument("--country-label", default="", help="Force signup country label; otherwise inferred from node name.")
    ap.add_argument("--register", action="store_true", help="Run run_accel_defer_w0_once.ps1 for each quick-probe-passing node.")
    ap.add_argument("--register-script", default="run_accel_defer_w0_once.ps1", help="PowerShell registration script to run, e.g. run_1s_rewrite_once.ps1.")
    ap.add_argument("--register-timeout", type=int, default=240)
    ap.add_argument("--continue-after-success", action="store_true", help="Keep testing remaining nodes after CreateAccount 200 instead of stopping at the first success.")
    ap.add_argument("--no-defer-final-result-to-w0", action="store_true", help="Pass -NoDeferFinalResultToW0 to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--no-synthetic-u0", action="store_true", help="Pass -NoSyntheticU0 to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--optimistic-w0-success", action="store_true", help="Pass -OptimisticW0Success to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--optimistic-final-success", action="store_true", help="Pass -OptimisticFinalSuccess to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--rewrite-final-result-success", action="store_true", help="Pass -RewriteFinalResultSuccess to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--trigger-final-success-signals", action="store_true", help="Pass -TriggerFinalSuccessSignals to run_accel_defer_w0_once.ps1.")
    ap.add_argument("--no-trigger-final-success-signals", action="store_true", help="Pass -NoTriggerFinalSuccessSignals to scripts that trigger success signals by default, e.g. run_1s_rewrite_once.ps1.")
    ap.add_argument("--defer-final-result-to-w0", action="store_true", help="Pass -DeferFinalResultToW0 to scripts that support explicitly enabling final->W0 defer, e.g. run_1s_rewrite_once.ps1.")
    ap.add_argument("--w0-after-final-ms", type=int, default=None, help="Override -W0AfterFinalMs.")
    ap.add_argument("--defer-w0-wait-ms", type=int, default=None, help="Override -DeferW0WaitMs.")
    ap.add_argument("--script-arg", action="append", default=[], help="Extra raw PowerShell script argument. May be repeated; use with known script-specific parameters only.")
    args = ap.parse_args()

    names = load_proxy_names(args.config)
    if args.filter:
        rx = re.compile(args.filter, re.I)
        names = [name for name in names if rx.search(name)]
    names = names[: max(1, int(args.max_nodes or 1))]
    if not names:
        raise SystemExit("no nodes matched")

    print(f"[mihomo-auto] candidates={len(names)} controller={args.controller} proxy={args.proxy_url}")
    try:
        http_json("GET", f"{args.controller.rstrip('/')}/proxies", timeout=3.0)
    except Exception as exc:
        raise SystemExit(f"mihomo controller not reachable: {exc!r}")

    results: list[dict] = []
    for idx, name in enumerate(names, 1):
        print(f"\n[{idx}/{len(names)}] switch {name}")
        try:
            switch_proxy(args.controller, name)
            time.sleep(0.8)
        except Exception as exc:
            print(f"  switch=fail {exc!r}")
            continue

        ok, detail = quick_probe(args.proxy_url)
        print(f"  quick={'ok' if ok else 'fail'} {detail}")
        row = {"idx": idx, "name": name, "quick": ok, "detail": detail, "verdict": "quick_fail" if not ok else "quick_ok"}
        if not ok or not args.register:
            results.append(row)
            continue

        country = args.country_label or infer_country_label(name)
        print(f"  register country={country or '(default)'}")
        out, code = run_register(
            args.proxy_url,
            country,
            args.register_timeout,
            script=args.register_script,
            no_defer_final_result_to_w0=args.no_defer_final_result_to_w0,
            no_synthetic_u0=args.no_synthetic_u0,
            optimistic_w0_success=args.optimistic_w0_success,
            optimistic_final_success=args.optimistic_final_success,
            rewrite_final_result_success=args.rewrite_final_result_success,
            trigger_final_success_signals=args.trigger_final_success_signals,
            no_trigger_final_success_signals=args.no_trigger_final_success_signals,
            defer_final_result_to_w0=args.defer_final_result_to_w0,
            w0_after_final_ms=args.w0_after_final_ms,
            defer_w0_wait_ms=args.defer_w0_wait_ms,
            extra_script_args=args.script_arg,
        )
        verdict = classify_register_output(out, code)
        row.update({"country": country, "exit": code, "verdict": verdict})
        results.append(row)
        print(f"  register_exit={code} verdict={verdict}")
        tail = "\n".join(out.splitlines()[-45:])
        print(tail)
        if verdict in {"create_account_200", "create_account_possible"} and not args.continue_after_success:
            print("\n[mihomo-auto] summary")
            for item in results:
                print(f"  #{item['idx']} {item['verdict']} {item['name']} {item.get('detail', '')}")
            return 0
    print("\n[mihomo-auto] summary")
    success = 0
    for item in results:
        if item.get("verdict") in {"create_account_200", "create_account_possible"}:
            success += 1
        print(f"  #{item['idx']} {item['verdict']} {item['name']} {item.get('detail', '')}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
