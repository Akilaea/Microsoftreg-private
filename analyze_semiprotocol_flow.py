#!/usr/bin/env python3
"""
Summarize a captured OutlookRegister network JSONL run.

This is intentionally read-only.  It is used by the semi-protocol workflow to
check whether an optimization changed the live state-machine order:

  authorize/signup -> risk/initialize -> CheckAvailable -> collector ->
  risk/verify -> captcha assets -> risk/verify -> CreateAccount
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
NETWORK_DIR = ROOT / "Results" / "network"


def parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return None


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            event["_dt"] = parse_ts(event.get("ts"))
            events.append(event)
    return events


def classify(record: dict[str, Any]) -> str | None:
    url = str(record.get("url") or "")
    event_name = str(record.get("event") or "")
    method = str(record.get("method") or "")
    if "consumers/oauth2/v2.0/authorize" in url and event_name == "request":
        return "authorize.request"
    if "signup.live.com/signup" in url and event_name == "response":
        return "signup.response"
    if "risk/initialize" in url and event_name == "request":
        return "risk_initialize.request"
    if "risk/initialize" in url and event_name == "response":
        return "risk_initialize.response"
    if "CheckAvailableSigninNames" in url and event_name == "request":
        return "check_available.request"
    if "CheckAvailableSigninNames" in url and event_name == "response":
        return "check_available.response"
    if "collector-" in url and "/api/v2/msft" in url and event_name == "response":
        body = str(event_body(record) or "")
        if "result|0" in body or "oIIoIooo|0" in body:
            return "collector.final_result0"
        if "score|1" in body or "_px3" in body or "_pxde" in body:
            return "collector.bootstrap"
        return "collector.response"
    if "risk/verify" in url and event_name == "request":
        return "risk_verify.request"
    if "risk/verify" in url and event_name == "response":
        body = str(event_body(record) or "")
        if "HumanCaptcha" in body:
            return "risk_verify.challenge"
        return "risk_verify.continue"
    if "captcha.hsprotect.net" in url and "captcha.js" in url and event_name == "response":
        return f"captcha_js.{method.lower()}.response"
    if "CreateAccount" in url and event_name == "request":
        return "create_account.request"
    if "CreateAccount" in url and event_name == "response":
        return "create_account.response"
    return None


def event_body(event: dict[str, Any]) -> str:
    body = event.get("body")
    if body is None:
        body = event.get("postData")
    if body is None:
        body = event.get("post_data")
    return str(body or "")


def summarize_json_body(body: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except Exception:
        return {}
    out: dict[str, Any] = {}
    if "continuationToken" in parsed:
        out["continuationLen"] = len(str(parsed.get("continuationToken") or ""))
    if "riskInitializationData" in parsed:
        providers = []
        human = ""
        for item in parsed.get("riskInitializationData") or []:
            if not isinstance(item, dict):
                continue
            if item.get("riskProvider"):
                providers.append(item.get("riskProvider"))
            if not human and item.get("humanSensorUrl"):
                human = str(item.get("humanSensorUrl") or "")
        out["providers"] = providers
        out["hasHumanSensorUrl"] = bool(human)
    if "challengeDetails" in parsed:
        details = parsed.get("challengeDetails") or {}
        meta = details.get("challengeMetadata") or {}
        out["challengeType"] = details.get("challengeType")
        out["appId"] = meta.get("appId")
        out["hasChallengeUrl"] = bool(meta.get("challengeUrl"))
    if "isAvailable" in parsed:
        out["isAvailable"] = parsed.get("isAvailable")
        out["type"] = parsed.get("type")
    if "error" in parsed or "errorCode" in parsed:
        out["error"] = parsed.get("error") or parsed.get("errorCode")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", nargs="?", help="network JSONL path; defaults to latest Results/network/*.jsonl")
    args = parser.parse_args()

    if args.jsonl:
        path = Path(args.jsonl)
    else:
        candidates = sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise SystemExit(f"no network jsonl under {NETWORK_DIR}")
        path = candidates[0]
    path = path.resolve()
    events = load_events(path)
    if not events:
        raise SystemExit(f"empty/unreadable jsonl: {path}")

    base = next((e["_dt"] for e in events if e.get("_dt")), None)
    print(f"file: {path}")
    print(f"events: {len(events)}")
    print()

    seen: set[str] = set()
    timeline: list[tuple[datetime, str, dict[str, Any]]] = []
    for event in events:
        dt = event.get("_dt")
        if not dt:
            continue
        key = classify(event)
        if not key:
            continue
        # Keep all risk_verify / collector / CreateAccount entries, but only
        # the first of noisy page-load milestones.
        if key not in {"collector.response", "collector.bootstrap", "collector.final_result0", "risk_verify.request", "risk_verify.challenge", "risk_verify.continue"}:
            if key in seen:
                continue
            seen.add(key)
        timeline.append((dt, key, event))

    for dt, key, event in timeline:
        delta = (dt - base).total_seconds() if base else 0.0
        status = event.get("status")
        status_s = f" status={status}" if status is not None else ""
        summary = summarize_json_body(event_body(event))
        summary_s = f" {summary}" if summary else ""
        print(f"+{delta:7.2f}s  {key:<28}{status_s}{summary_s}")

    create_ok = any(
        key == "create_account.response" and int(event.get("status") or 0) == 200
        for _, key, event in timeline
    )
    final_ok = any(key == "collector.final_result0" for _, key, _ in timeline)
    print()
    print(f"verdict: create_account_200={create_ok} collector_result0={final_ok}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
