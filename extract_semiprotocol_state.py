#!/usr/bin/env python3
"""
Extract a compact semi-protocol state bundle from a live network JSONL trace.

The output is designed for the next semi-automatic protocol stage: it records
the exact ordering and token shapes without dumping full tokens to console.
The JSON artifact saved under Results/protocol_runtime keeps the same bounded
summaries and can be compared between success / retry / RiskBlock runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
NETWORK_DIR = ROOT / "Results" / "network"
RUNTIME_DIR = ROOT / "Results" / "protocol_runtime"


def sha12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12] if value else ""


def token_summary(value: Any, prefix: int = 10) -> dict[str, Any]:
    s = str(value or "")
    return {
        "len": len(s),
        "sha12": sha12(s),
        "prefix": s[:prefix],
    }


def json_body(event: dict[str, Any], key: str) -> tuple[dict[str, Any], str]:
    raw = str(event.get(key) or "")
    if not raw or raw == "<redacted>":
        return {}, raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}, raw
    except Exception:
        return {}, raw


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def latest_network() -> Path:
    files = sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise SystemExit(f"no network logs under {NETWORK_DIR}")
    return files[0]


def session_id_from_url(url: str) -> str:
    try:
        qs = parse_qs(urlparse(url).query)
        return (qs.get("session_id") or [""])[0]
    except Exception:
        return ""


def summarize_risk_init_response(parsed: dict[str, Any]) -> dict[str, Any]:
    human_url = ""
    providers = []
    for item in parsed.get("riskInitializationData") or []:
        if not isinstance(item, dict):
            continue
        if item.get("riskProvider"):
            providers.append(item.get("riskProvider"))
        if not human_url and item.get("humanSensorUrl"):
            human_url = str(item.get("humanSensorUrl") or "")
    return {
        "state": parsed.get("state"),
        "continuationToken": token_summary(parsed.get("continuationToken")),
        "providers": providers,
        "humanSensorUrl": {
            "present": bool(human_url),
            "session_id": session_id_from_url(human_url),
            "prefix": human_url[:96],
        },
    }


def summarize_check_available_request(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "signInName": parsed.get("signInName"),
        "uaid": parsed.get("uaid"),
        "includeSuggestions": parsed.get("includeSuggestions"),
        "uiflvr": parsed.get("uiflvr"),
        "scid": parsed.get("scid"),
        "hpgid": parsed.get("hpgid"),
    }


def summarize_check_available_response(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "isAvailable": parsed.get("isAvailable"),
        "type": parsed.get("type"),
        "nopaAllowed": parsed.get("nopaAllowed"),
        "apiCanary": token_summary(parsed.get("apiCanary")),
        "telemetryContext": token_summary(parsed.get("telemetryContext")),
    }


def summarize_provider_metadata(items: Any) -> list[dict[str, Any]]:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        entry = {"riskProvider": item.get("riskProvider")}
        for key in ("px3", "pxde", "pxvid"):
            if key in item:
                entry[key] = token_summary(item.get(key))
        out.append(entry)
    return out


def summarize_risk_verify_request(parsed: dict[str, Any]) -> dict[str, Any]:
    sol = parsed.get("challengeSolution")
    out = {
        "continuationToken": token_summary(parsed.get("continuationToken")),
        "hasChallengeSolution": isinstance(sol, dict),
        "riskProviderMetadata": summarize_provider_metadata(parsed.get("riskProviderMetadata")),
        "msaRiskVerifySignatureKeys": sorted(list((parsed.get("msaRiskVerifySignature") or {}).keys()))
        if isinstance(parsed.get("msaRiskVerifySignature"), dict) else [],
    }
    if isinstance(sol, dict):
        out["challengeSolution"] = {
            "challengeType": sol.get("challengeType"),
            "px3": token_summary(sol.get("px3")),
            "pxde": token_summary(sol.get("pxde")),
            "pxvid": token_summary(sol.get("pxvid")),
        }
    return out


def summarize_risk_verify_response(parsed: dict[str, Any], status: int | None) -> dict[str, Any]:
    details = parsed.get("challengeDetails") if isinstance(parsed.get("challengeDetails"), dict) else {}
    meta = details.get("challengeMetadata") if isinstance(details.get("challengeMetadata"), dict) else {}
    challenge_url = str(meta.get("challengeUrl") or "")
    err = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
    return {
        "status": status,
        "state": parsed.get("state"),
        "continuationToken": token_summary(parsed.get("continuationToken")),
        "challenge": {
            "type": details.get("challengeType"),
            "appId": meta.get("appId"),
            "uuid": meta.get("uuid"),
            "vid": meta.get("vid"),
            "session_id": session_id_from_url(challenge_url),
            "hasChallengeUrl": bool(challenge_url),
        },
        "error": {
            "code": err.get("code"),
            "messagePrefix": str(err.get("message") or "")[:120],
            "innerCode": ((err.get("innerError") or {}).get("code") if isinstance(err.get("innerError"), dict) else None),
        } if err else None,
    }


def summarize_create_account_request(parsed: dict[str, Any]) -> dict[str, Any]:
    keys = sorted(parsed.keys())
    return {
        "keys": keys,
        "memberName": parsed.get("MemberName") or parsed.get("memberName") or parsed.get("signInName"),
        "hasPassword": any("pass" in k.lower() for k in keys),
        "hasRiskVerificationToken": any("risk" in k.lower() or "token" in k.lower() for k in keys),
        "uaid": parsed.get("uaid"),
    }


def parse_route_log(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    final = None
    y1nz = []
    for event in load_jsonl(path):
        decoded = event.get("response_decoded") or {}
        tags = (event.get("after") or event.get("before") or {}).get("tags") or []
        if "Y1NZWSUzXWs=" in tags:
            y1nz.append({
                "qi": event.get("qi"),
                "seq": event.get("seq"),
                "scores": decoded.get("scores") or [],
                "results": decoded.get("results") or [],
            })
        if "PX561" in tags:
            final = {
                "qi": event.get("qi"),
                "seq": event.get("seq"),
                "rsc": event.get("rsc"),
                "response_status": event.get("response_status"),
                "scores": decoded.get("scores") or [],
                "results": decoded.get("results") or [],
                "parts_count": len(decoded.get("parts") or []),
                "px561": ((event.get("after") or {}).get("px561") or {}),
                "final_invariants": ((event.get("after") or {}).get("final_invariants") or {}),
            }
    return {"route_log": str(path), "y1nz": y1nz, "final": final}


def auto_route_log(network_path: Path) -> Path | None:
    # Use the latest route log before/near this network trace.  Good enough for
    # sequential live runs; callers can pass --route for exact matching.
    candidates = sorted(RUNTIME_DIR.glob("*_route_normalizer.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def extract(path: Path, route_path: Path | None = None) -> dict[str, Any]:
    events = load_jsonl(path)
    out: dict[str, Any] = {
        "source": str(path),
        "created_at": datetime.now().isoformat(),
        "risk_initialize": {},
        "check_available": {},
        "risk_verify": [],
        "create_account": {},
    }
    pending_risk_req: dict[str, Any] | None = None
    rv_index = 0

    for event in events:
        url = str(event.get("url") or "")
        name = str(event.get("event") or "")
        method = str(event.get("method") or "")
        if method != "POST":
            continue
        if "api/v1.0/risk/initialize" in url and name == "response":
            parsed, _ = json_body(event, "body")
            out["risk_initialize"] = summarize_risk_init_response(parsed)
        elif "CheckAvailableSigninNames" in url:
            if name == "request":
                parsed, _ = json_body(event, "post_data")
                out.setdefault("check_available", {})["request"] = summarize_check_available_request(parsed)
            elif name == "response":
                parsed, _ = json_body(event, "body")
                out.setdefault("check_available", {})["response"] = summarize_check_available_response(parsed)
        elif "/api/v1.0/risk/verify" in url:
            if name == "request":
                rv_index += 1
                parsed, raw = json_body(event, "post_data")
                pending_risk_req = {
                    "index": rv_index,
                    "request_ts": event.get("ts"),
                    "request_body_len": len(raw),
                    "request": summarize_risk_verify_request(parsed),
                }
                out["risk_verify"].append(pending_risk_req)
            elif name == "response":
                parsed, raw = json_body(event, "body")
                target = pending_risk_req if pending_risk_req and "response" not in pending_risk_req else None
                if target is None:
                    target = {"index": rv_index + 1, "request": {}}
                    out["risk_verify"].append(target)
                target["response_ts"] = event.get("ts")
                target["response_body_len"] = len(raw)
                target["response"] = summarize_risk_verify_response(parsed, event.get("status"))
        elif "signup.live.com/API/CreateAccount" in url:
            if name == "request":
                parsed, raw = json_body(event, "post_data")
                out["create_account"]["request_ts"] = event.get("ts")
                out["create_account"]["request_body_len"] = len(raw)
                out["create_account"]["request"] = summarize_create_account_request(parsed)
            elif name == "response":
                parsed, raw = json_body(event, "body")
                out["create_account"]["response_ts"] = event.get("ts")
                out["create_account"]["status"] = event.get("status")
                out["create_account"]["response_body_len"] = len(raw)
                out["create_account"]["response_keys"] = sorted(parsed.keys()) if parsed else []

    out["route"] = parse_route_log(route_path or auto_route_log(path))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("network", nargs="?", help="network JSONL path, default latest")
    parser.add_argument("--route", help="matching *_route_normalizer.jsonl")
    parser.add_argument("--out", help="output JSON path")
    args = parser.parse_args()
    path = Path(args.network).resolve() if args.network else latest_network().resolve()
    route = Path(args.route).resolve() if args.route else None
    data = extract(path, route)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out).resolve() if args.out else RUNTIME_DIR / f"semiprotocol_state_{path.stem}.json"
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"source: {path}")
    print(f"state:  {out_path}")
    print("risk_initialize:", data.get("risk_initialize", {}))
    print("check_available:", data.get("check_available", {}).get("response", {}))
    for rv in data.get("risk_verify") or []:
        req = rv.get("request") or {}
        resp = rv.get("response") or {}
        print(
            f"risk_verify#{rv.get('index')}: "
            f"solution={req.get('hasChallengeSolution')} "
            f"status={resp.get('status')} state={resp.get('state')} "
            f"challenge={((resp.get('challenge') or {}).get('type'))} "
            f"err={((resp.get('error') or {}).get('innerCode') or (resp.get('error') or {}).get('code'))}"
        )
    route_final = (data.get("route") or {}).get("final") or {}
    print("collector_final:", {"scores": route_final.get("scores"), "results": route_final.get("results")})
    print("create_account:", {"status": (data.get("create_account") or {}).get("status")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
