#!/usr/bin/env python
"""Print the effective high-level configuration without running a signup flow.

This is intentionally read-only.  Runtime scripts still own the actual launch
behavior; this helper only explains the config file plus important environment
overrides used by the controllers.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_CONFIG = (
    ROOT / "config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json"
)
DEFAULT_CONFIG = DEFAULT_RUNTIME_CONFIG if DEFAULT_RUNTIME_CONFIG.exists() else ROOT / "config.ctf.json"

ENV_TO_CONFIG = {
    "OUTLOOK_REGISTER_CONFIG": ("settings", "active_config_path"),
    "OUTLOOK_SIGNUP_FILL_MODE": ("signup", "signup_fill_mode"),
    "OUTLOOK_SIGNUP_ENTRY_URL": ("signup", "signup_entry_url"),
    "OUTLOOK_SIGNUP_COUNTRY_LABEL": ("signup", "signup_country_label"),
    "OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_TRANSPORT": (
        "signup",
        "signup_protocol_takeover_preverify_transport",
    ),
    "OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_MIN_TOTAL_MS": (
        "signup",
        "signup_protocol_takeover_preverify_min_total_ms",
    ),
    "OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_BOOTSTRAP_WAIT_MS": (
        "signup",
        "signup_protocol_takeover_thin_bootstrap_wait_ms",
    ),
    "OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_GOTO_WAIT_UNTIL": (
        "signup",
        "signup_protocol_takeover_thin_goto_wait_until",
    ),
    "OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_SOLUTION_CANDIDATE_LIMIT": (
        "signup",
        "signup_protocol_takeover_solution_candidate_limit",
    ),
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"config root must be an object: {path}")
    return data


def nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def build_report(config_path: Path) -> dict[str, Any]:
    config_path = config_path.resolve()
    data = load_json(config_path)
    manifest_path = ROOT / "PACKAGE_MANIFEST.json"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}

    env_overrides = {
        name: {"maps_to": ".".join(target), "value": os.environ[name]}
        for name, target in ENV_TO_CONFIG.items()
        if name in os.environ
    }

    return {
        "config_path": str(config_path),
        "current_entry": manifest.get("current_entry") or "run_mihomo_protocol_takeover_thin_batch.ps1",
        "current_config_from_manifest": manifest.get("current_config"),
        "top_level": {
            "choose_browser": data.get("choose_browser"),
            "proxy": data.get("proxy"),
            "manual_captcha": data.get("manual_captcha"),
            "capture_network": data.get("capture_network"),
            "signup_fill_mode": data.get("signup_fill_mode"),
            "signup_entry_url": data.get("signup_entry_url"),
        },
        "browser": {
            "patchright.browser_path": nested(data, "patchright", "browser_path"),
            "patchright.user_data_dir": nested(data, "patchright", "user_data_dir"),
            "patchright.use_cloakbrowser": nested(data, "patchright", "use_cloakbrowser"),
            "cloakbrowser.humanize": nested(data, "cloakbrowser", "humanize"),
            "cloakbrowser.human_preset": nested(data, "cloakbrowser", "human_preset"),
            "cloakbrowser.args": nested(data, "cloakbrowser", "args", default=[]),
        },
        "captcha": data.get("captcha", {}),
        "network_capture": {
            "capture_network_post_data": data.get("capture_network_post_data"),
            "capture_network_headers": data.get("capture_network_headers"),
            "capture_network_response_body": data.get("capture_network_response_body"),
            "redact_network_cookies": data.get("redact_network_cookies"),
            "network_url_keywords_count": len(data.get("network_url_keywords") or []),
        },
        "environment_overrides": env_overrides,
        "state_dirs": {
            "Results": str(ROOT / "Results"),
            "profiles": str(ROOT / "profiles"),
            ".mihomo-isolated": str(ROOT / ".mihomo-isolated"),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Explain the active CTF registration config.")
    ap.add_argument("--config", type=Path, default=Path(os.environ.get("OUTLOOK_REGISTER_CONFIG", DEFAULT_CONFIG)))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    report = build_report(args.config)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print(f"config_path={report['config_path']}")
    print(f"current_entry={report['current_entry']}")
    print(f"current_config_from_manifest={report['current_config_from_manifest']}")
    print("top_level:")
    for key, value in report["top_level"].items():
        print(f"  {key}={value}")
    print("browser:")
    for key, value in report["browser"].items():
        print(f"  {key}={value}")
    print("network_capture:")
    for key, value in report["network_capture"].items():
        print(f"  {key}={value}")
    print("environment_overrides:")
    if report["environment_overrides"]:
        for name, item in sorted(report["environment_overrides"].items()):
            print(f"  {name} -> {item['maps_to']} = {item['value']}")
    else:
        print("  none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
