#!/usr/bin/env python
"""
Generate CloakBrowser runtime configs that mimic an AdsPower profile's
observable fingerprint parameters.

This intentionally does NOT copy/reuse the AdsPower profile directory.  It
creates fresh Cloak profile directories and maps only the parameters that are
safe/useful for our current Outlook/HsProtect experiments:

  - User-Agent
  - Accept-Language / locale
  - optional timezone if AdsPower has one
  - stable Cloak fingerprint seed derived from the Ads profile
  - Windows fingerprint platform
  - native/no emulated viewport
  - window size close to the source Ads/SunBrowser window
  - conservative captcha hold settings

Unknown top-level keys are ignored by the existing controller, so each runtime
config also stores an ``ads_like_profile`` metadata block for later comparison.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import datetime as _dt
import hashlib
import json
import random
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_API_BASE = "http://127.0.0.1:50326"
DEFAULT_BASE_CONFIG = "config.ctf.cloak_manual_profile.json"


def request_json(url: str, timeout: float = 10.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-json response from {url}: {text[:300]!r}") from exc


def ads_list_profiles(api_base: str, search: str, page_size: int = 300) -> list[dict[str, Any]]:
    q = urllib.parse.urlencode({"page": 1, "page_size": page_size, "search": search})
    url = api_base.rstrip("/") + "/api/v1/user/list?" + q
    data = request_json(url, timeout=12)
    if data.get("code") not in (0, "0", None) and "data" not in data:
        raise RuntimeError(f"AdsPower user/list failed: {json.dumps(data, ensure_ascii=False)[:500]}")
    return list((data.get("data") or {}).get("list") or [])


def find_ads_profile(api_base: str, name: str | None, user_id: str | None) -> dict[str, Any]:
    if user_id:
        candidates = ads_list_profiles(api_base, user_id)
        for p in candidates:
            if str(p.get("user_id") or p.get("id") or "") == str(user_id):
                return p
        raise RuntimeError(f"AdsPower profile user_id={user_id!r} not found")

    if not name:
        name = "outlook测试26"
    candidates = ads_list_profiles(api_base, name)
    exact = [p for p in candidates if str(p.get("name") or "") == name]
    if exact:
        # Use the most recently opened/created one if duplicates exist.
        exact.sort(key=lambda p: (str(p.get("last_openfb_time") or ""), str(p.get("created_time") or "")), reverse=True)
        return exact[0]
    if candidates:
        candidates.sort(key=lambda p: (str(p.get("last_openfb_time") or ""), str(p.get("created_time") or "")), reverse=True)
        return candidates[0]
    raise RuntimeError(f"AdsPower profile name/search={name!r} not found")


def normalize_accept_language(language: str) -> str:
    parts = [p.strip() for p in str(language or "").split(",") if p.strip()]
    if not parts:
        return "en-US,en;q=0.9"
    out: list[str] = []
    for idx, part in enumerate(parts):
        if ";q=" in part:
            out.append(part)
        elif idx == 0:
            out.append(part)
        else:
            # Keep simple and browser-like.  HsProtect only needs a coherent
            # header; over-fitting q-values adds noise.
            q = max(0.1, 1.0 - idx * 0.1)
            out.append(f"{part};q={q:.1f}")
    return ",".join(out)


def clean_locale(language: str) -> str:
    return (str(language or "").split(",", 1)[0].strip() or "en-US")


def five_digit_seed(text: str, index: int = 0) -> str:
    digits = "".join(ch for ch in str(text or "") if ch.isdigit())
    if digits:
        base = int(digits[-5:])
    else:
        h = hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()
        base = int(h[:8], 16) % 90000 + 10000
    return f"{((base + index) % 90000) + 10000 if base < 10000 else (base + index - 10000) % 90000 + 10000:05d}"


def seed_for_profile(profile: dict[str, Any], mode: str, index: int) -> str:
    if mode == "random":
        return f"{random.randint(10000, 99999)}"
    user_id = str(profile.get("user_id") or profile.get("id") or profile.get("serial_number") or "")
    if mode == "source":
        return five_digit_seed(user_id, index)
    # deterministic: source + main visible fingerprint fields + index
    fp = profile.get("fingerprint_config") or {}
    text = json.dumps(
        {
            "user_id": user_id,
            "ua": profile.get("ua") or fp.get("ua"),
            "language": profile.get("language") or fp.get("language"),
            "webgl": profile.get("webgl_config") or fp.get("webgl_config"),
            "index": index,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return five_digit_seed(hashlib.sha256(text.encode("utf-8")).hexdigest(), 0)


def current_ads_window_size() -> str | None:
    """Return a visible SunBrowser-ish top-level window size, if present."""
    try:
        user32 = ctypes.windll.user32
        matches: list[int] = []
        cb_t = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

        def text(hwnd: int) -> str:
            buf = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buf, 512)
            return buf.value

        def cls(hwnd: int) -> str:
            buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buf, 256)
            return buf.value

        def cb(hwnd: int, _lparam: int) -> bool:
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                title = text(hwnd)
                klass = cls(hwnd)
                if klass == "Chrome_WidgetWin_1" and (
                    "SunBrowser" in title
                    or "outlook测试" in title
                    or "Let's prove" in title
                    or "Create account" in title
                    or "Microsoft account" in title
                ):
                    matches.append(hwnd)
            except Exception:
                pass
            return True

        user32.EnumWindows(cb_t(cb), 0)
        if not matches:
            return None

        class RECT(ctypes.Structure):
            _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

        rect = RECT()
        user32.GetWindowRect(matches[0], ctypes.byref(rect))
        w, h = int(rect.right - rect.left), int(rect.bottom - rect.top)
        if 600 <= w <= 2600 and 500 <= h <= 1700:
            return f"{w},{h}"
    except Exception:
        return None
    return None


def infer_window_size(profile: dict[str, Any], requested: str) -> str:
    if requested and requested != "auto":
        return requested
    live = current_ads_window_size()
    if live:
        return live

    # Ads often reports "none" when it uses the native current window.  If a
    # concrete resolution exists, keep a Chrome-like window below full screen.
    sr = str(profile.get("screen_resolution") or (profile.get("fingerprint_config") or {}).get("screen_resolution") or "")
    m = re.match(r"^\s*(\d+)[x_*](\d+)\s*$", sr)
    if m:
        sw, sh = int(m.group(1)), int(m.group(2))
        return f"{min(sw, 1365)},{min(sh, 1084)}"
    return "1010,1084"


def build_ads_like_config(
    base: dict[str, Any],
    profile: dict[str, Any],
    *,
    profile_dir: str,
    seed: str,
    window_size: str,
    hold_min_ms: int,
    hold_max_ms: int,
    hold_retries: int,
    human_preset: str,
    force_country_label: str,
    copy_timezone: bool,
    copy_proxy: bool,
) -> dict[str, Any]:
    out = json.loads(json.dumps(base, ensure_ascii=False))
    fp = profile.get("fingerprint_config") or {}

    ua = profile.get("ua") or fp.get("ua") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    language = profile.get("language") or fp.get("language") or "en-US,en"
    locale = clean_locale(language)
    timezone = (profile.get("timezone") or fp.get("timezone") or "").strip()

    out["manual_captcha"] = False
    out["max_tasks"] = 1
    out["concurrent_flows"] = 1
    out["max_captcha_retries"] = max(1, int(hold_retries))
    out["signup_country_label"] = force_country_label or ""

    cap = out.setdefault("captcha", {})
    cap["mode"] = "hold"
    cap["hold_min_ms"] = int(hold_min_ms)
    cap["hold_max_ms"] = int(hold_max_ms)
    cap["hold_retries"] = max(1, int(hold_retries))
    cap.setdefault("post_wait_ms", 18000)
    cap.setdefault("locate_timeout_ms", 22000)
    cap.setdefault("move_algorithm", "windmouse")
    cap.setdefault("move_style", "line_then_arc")
    cap["allow_visible_iframe_fallback"] = False

    out.setdefault("patchright", {})["user_data_dir"] = profile_dir
    out.setdefault("playwright", {})["user_data_dir"] = profile_dir

    ctx = out.setdefault("context", {})
    ctx["locale"] = locale
    ctx["viewport"] = None
    ctx["user_agent"] = ua
    ctx["extra_http_headers"] = {"Accept-Language": normalize_accept_language(language)}
    if copy_timezone and timezone:
        ctx["timezone_id"] = timezone
    else:
        ctx.pop("timezone_id", None)

    cloak = out.setdefault("cloakbrowser", {})
    cloak["locale"] = locale
    if copy_timezone and timezone:
        cloak["timezone"] = timezone
    else:
        cloak.pop("timezone", None)
    cloak["humanize"] = True
    cloak["human_preset"] = human_preset
    cloak["headless"] = False
    cloak["args"] = [
        f"--fingerprint={seed}",
        "--fingerprint-platform=windows",
        f"--window-size={window_size}",
    ]

    if copy_proxy:
        proxy = ads_proxy_to_url(profile.get("user_proxy_config") or {})
        if proxy:
            out["proxy"] = proxy

    out["ads_like_profile"] = {
        "source": "AdsPower local API",
        "source_name": profile.get("name"),
        "source_user_id": profile.get("user_id") or profile.get("id"),
        "seed": seed,
        "mapped": {
            "ua": ua,
            "language": language,
            "locale": locale,
            "timezone": timezone if copy_timezone else "",
            "window_size": window_size,
            "country_forced": bool(force_country_label),
        },
        "ads_fields": {
            "browser_kernel_config": profile.get("browser_kernel_config") or fp.get("browser_kernel_config"),
            "client_hints": fp.get("client_hints"),
            "webgl_config": profile.get("webgl_config") or fp.get("webgl_config"),
            "hardware_concurrency": profile.get("hardware_concurrency") or fp.get("hardware_concurrency"),
            "device_memory": profile.get("device_memory") or fp.get("device_memory"),
            "dpr": profile.get("dpr") or fp.get("dpr"),
            "webrtc": profile.get("webrtc") or fp.get("webrtc"),
            "canvas": profile.get("canvas") or fp.get("canvas"),
            "audio": profile.get("audio") or fp.get("audio"),
            "client_rects": profile.get("client_rects") or fp.get("client_rects"),
        },
        "note": "Cloak accepts only part of these fields directly; remaining Ads fields are retained as metadata for analysis.",
    }
    return out


def ads_proxy_to_url(proxy_cfg: dict[str, Any]) -> str:
    ptype = str(proxy_cfg.get("proxy_type") or proxy_cfg.get("proxy_soft") or "").lower()
    if not proxy_cfg or ptype in ("", "noproxy", "no_proxy"):
        return ""
    host = proxy_cfg.get("proxy_host") or proxy_cfg.get("host")
    port = proxy_cfg.get("proxy_port") or proxy_cfg.get("port")
    if not host or not port:
        return ""
    scheme = "socks5" if "socks" in ptype else "http"
    user = proxy_cfg.get("proxy_user") or proxy_cfg.get("username")
    pwd = proxy_cfg.get("proxy_password") or proxy_cfg.get("password")
    auth = ""
    if user:
        auth = urllib.parse.quote(str(user), safe="")
        if pwd:
            auth += ":" + urllib.parse.quote(str(pwd), safe="")
        auth += "@"
    return f"{scheme}://{auth}{host}:{port}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate AdsPower-like CloakBrowser runtime configs.")
    ap.add_argument("--api-base", default=DEFAULT_API_BASE)
    ap.add_argument("--source-name", default="outlook测试26", help="AdsPower profile name/search text.")
    ap.add_argument("--source-user-id", default="", help="AdsPower profile user_id; overrides --source-name.")
    ap.add_argument("--base-config", default=DEFAULT_BASE_CONFIG)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--profile-root", default=".\\profiles")
    ap.add_argument("--prefix", default="cloak-from-ads")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--seed-mode", choices=["source", "derived", "random"], default="source")
    ap.add_argument("--window-size", default="auto", help="'auto' uses a live Ads/SunBrowser window when available.")
    ap.add_argument("--hold-min-ms", type=int, default=9500)
    ap.add_argument("--hold-max-ms", type=int, default=12500)
    ap.add_argument("--hold-retries", type=int, default=2)
    ap.add_argument("--human-preset", choices=["default", "careful"], default="careful")
    ap.add_argument("--country-label", default="", help="Optional signup country label; empty keeps site default.")
    ap.add_argument("--copy-timezone", action="store_true", help="Copy Ads timezone if present. Default keeps Cloak/site default.")
    ap.add_argument("--copy-proxy", action="store_true", help="Copy Ads proxy config if it is explicit. Default leaves config proxy unchanged/empty.")
    ap.add_argument("--print-commands", action="store_true")
    args = ap.parse_args()

    root = Path.cwd()
    base_path = Path(args.base_config)
    if not base_path.is_absolute():
        base_path = root / base_path
    base = json.loads(base_path.read_text(encoding="utf-8"))

    profile = find_ads_profile(args.api_base, args.source_name, args.source_user_id or None)
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    window_size = infer_window_size(profile, args.window_size)

    outputs = []
    for i in range(max(1, int(args.count))):
        seed = seed_for_profile(profile, args.seed_mode, i)
        profile_dir = str(Path(args.profile_root) / f"{args.prefix}-{stamp}-{i+1:02d}-{seed}")
        cfg = build_ads_like_config(
            base,
            profile,
            profile_dir=profile_dir,
            seed=seed,
            window_size=window_size,
            hold_min_ms=args.hold_min_ms,
            hold_max_ms=args.hold_max_ms,
            hold_retries=args.hold_retries,
            human_preset=args.human_preset,
            force_country_label=args.country_label,
            copy_timezone=bool(args.copy_timezone),
            copy_proxy=bool(args.copy_proxy),
        )
        cfg_path = out_dir / f"config.ctf.runtime.{args.prefix}.{stamp}.{i+1:02d}.{seed}.json"
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        outputs.append(
            {
                "config": str(cfg_path),
                "profile_dir": profile_dir,
                "seed": seed,
                "window_size": window_size,
                "main_command": f"python .\\main.py --config .\\{cfg_path.name} --max-tasks 1 --concurrent 1 --use-cloakbrowser --cloak-human-preset {args.human_preset} --skip-preflight",
            }
        )

    manifest = {
        "generated_at": stamp,
        "source_name": profile.get("name"),
        "source_user_id": profile.get("user_id") or profile.get("id"),
        "source_ua": profile.get("ua") or (profile.get("fingerprint_config") or {}).get("ua"),
        "source_language": profile.get("language") or (profile.get("fingerprint_config") or {}).get("language"),
        "window_size": window_size,
        "count": len(outputs),
        "outputs": outputs,
    }
    manifest_path = out_dir / f"config.ctf.runtime.{args.prefix}.{stamp}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    if args.print_commands:
        print("\nCommands:")
        for item in outputs:
            print(item["main_command"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

