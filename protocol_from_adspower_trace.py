import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from summarize_score1_rootcause import (
    RISK_VERIFY,
    chrome_major,
    first_header,
    load_events,
    onecollector_risk_telemetry,
    summarize_collectors,
    summarize_risk,
    y1nz_selected,
)


TOKEN_HINTS = ("px", "token", "cookie", "session", "vid", "tkt", "signature")


def sha12(value) -> str:
    if value is None:
        return ""
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]


def redacted_value(value, include_sensitive: bool):
    if include_sensitive:
        return value
    if value in (None, ""):
        return value
    return {"present": True, "len": len(str(value)), "sha256_12": sha12(value)}


def key_subset(headers: dict) -> dict:
    wanted = [
        "user-agent",
        "accept-language",
        "sec-ch-ua",
        "sec-ch-ua-platform",
        "sec-ch-ua-mobile",
        "origin",
        "referer",
        "content-type",
    ]
    out = {}
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}
    for key in wanted:
        if key in lower:
            out[key] = lower[key]
    return out


def request_header_fingerprints(events):
    rows = []
    for idx, ev in events:
        if ev.get("event") != "request":
            continue
        url = ev.get("url") or ""
        if not any(k in url for k in ["risk/", "hsprotect.net", "signup.live.com", "outlook.live.com"]):
            continue
        rows.append(
            {
                "idx": idx,
                "method": ev.get("method"),
                "url_class": classify_url(url),
                "headers": key_subset(ev.get("headers") or {}),
            }
        )
    return rows


def classify_url(url: str) -> str:
    if "api/v1.0/risk/initialize" in url:
        return "risk_initialize"
    if "api/v1.0/risk/verify" in url:
        return "risk_verify"
    if "collector-" in url and "hsprotect.net" in url:
        return "hsprotect_collector"
    if "iframe.hsprotect.net/index.html" in url:
        return "hsprotect_iframe"
    if "df.cfp.microsoft.com" in url:
        return "microsoft_dfp"
    if "browser.events.data.microsoft.com/OneCollector" in url:
        return "telemetry_onecollector"
    if "signup.live.com" in url:
        return "signup_live"
    if "outlook.live.com" in url:
        return "outlook_live"
    return "other"


def safe_risk_request(req: dict | None, include_sensitive: bool) -> dict:
    if not req:
        return {}
    return {
        "memberName": redacted_value(req.get("memberName"), include_sensitive),
        "member_domain": (str(req.get("memberName") or "").split("@", 1)[1] if "@" in str(req.get("memberName") or "") else ""),
        "countryCode": req.get("countryCode"),
        "birthdate_present": bool(req.get("birthdate")),
        "name_present": bool(req.get("firstName") or req.get("lastName")),
        "action": req.get("action"),
        "deviceDetails_present": bool(req.get("deviceDetails")),
        "has_px3": bool(req.get("has_px3")),
        "has_pxde": bool(req.get("has_pxde")),
        "pxvid": redacted_value(req.get("pxvid"), include_sensitive),
    }


def risk_timeline(events, include_sensitive: bool):
    rows = []
    for kind, idx, ev, body, req in summarize_risk(events):
        if kind == "risk_initialize":
            rows.append(
                {
                    "kind": kind,
                    "idx": idx,
                    "status": ev.get("status"),
                    "state": (body or {}).get("state") if isinstance(body, dict) else None,
                }
            )
            continue
        err = (body or {}).get("error") if isinstance(body, dict) else {}
        inner = (err or {}).get("innerError") or {}
        rows.append(
            {
                "kind": kind,
                "idx": idx,
                "status": ev.get("status"),
                "state": (body or {}).get("state") if isinstance(body, dict) else None,
                "error_code": (err or {}).get("code"),
                "inner_error_code": inner.get("code"),
                "request": safe_risk_request(req, include_sensitive),
            }
        )
    return rows


def telemetry_timeline(events):
    rows = []
    for item in onecollector_risk_telemetry(events):
        if RISK_VERIFY in (item.get("api") or ""):
            rows.append(
                {
                    "kind": "telemetry_risk_verify",
                    "idx": item.get("idx"),
                    "responseCode": item.get("responseCode"),
                    "networkDuration": item.get("networkDuration"),
                    "view": item.get("view"),
                }
            )
        elif str(item.get("metricName") or "").startswith("HumanCaptcha_"):
            rows.append(
                {
                    "kind": "telemetry_hcaptcha",
                    "idx": item.get("idx"),
                    "metricName": item.get("metricName"),
                    "metricValue": item.get("metricValue"),
                    "view": item.get("view"),
                }
            )
    return rows


def collector_timeline(path: Path, events):
    rows = []
    for item in summarize_collectors(path, events):
        rows.append(
            {
                "kind": "collector",
                "ordinal": item.get("ordinal"),
                "idx": item.get("idx"),
                "phase": item.get("phase"),
                "seq": item.get("seq"),
                "rsc": item.get("rsc"),
                "tags": item.get("tags"),
                "tag_count": len(item.get("tags") or []),
                "score": item.get("score"),
                "results": item.get("results"),
            }
        )
    return rows


def create_account_timeline(events, include_sensitive: bool):
    rows = []
    for idx, ev in events:
        url = ev.get("url") or ""
        if "signup.live.com/API/CreateAccount" not in url:
            continue
        if ev.get("event") == "request":
            body = {}
            try:
                body = json.loads(ev.get("post_data") or "{}")
            except Exception:
                body = {}
            rows.append(
                {
                    "kind": "create_account_request",
                    "idx": idx,
                    "status": None,
                    "memberName": redacted_value(body.get("MemberName"), include_sensitive),
                    "countryCode": body.get("Country"),
                    "birthdate_present": bool(body.get("BirthDate")),
                    "name_present": bool(body.get("FirstName") or body.get("LastName")),
                    "uaid": redacted_value(body.get("uaid"), include_sensitive),
                }
            )
            continue
        if ev.get("event") != "response":
            continue
        raw = ev.get("body") or ""
        body = {}
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        error_text = " ".join(
            str(x or "")
            for x in [
                body.get("error"),
                body.get("errorCode"),
                body.get("errorDescription"),
                body.get("message"),
                body.get("server_error"),
                body.get("serverError"),
                raw if ("contextID" in raw or "matching cookie" in raw or "server_error" in raw) else "",
            ]
        )
        rows.append(
            {
                "kind": "create_account_response",
                "idx": idx,
                "status": ev.get("status"),
                "has_signinName": bool(body.get("signinName")),
                "has_redirectUrl": bool(body.get("redirectUrl")),
                "has_encPuid": bool(body.get("encPuid")),
                "error_present": bool(error_text.strip()),
                "server_error": "server_error" in error_text or "serverError" in error_text,
                "context_cookie_mismatch": "contextID" in error_text or "matching cookie" in error_text,
                "signinName": redacted_value(body.get("signinName"), include_sensitive),
            }
        )
    return rows


def fingerprint_summary(path: Path, events):
    y1 = y1nz_selected(path)
    latest = y1[-1] if y1 else {}
    ua = first_header(events, "user-agent")
    return {
        "ua_chrome": chrome_major(ua),
        "ua": ua,
        "accept_language": first_header(events, "accept-language"),
        "sec_ch_ua": first_header(events, "sec-ch-ua"),
        "y1nz_latest": latest,
    }


def build_verdict(risk_rows, telemetry_rows, collector_rows, account_rows):
    states = [r.get("state") for r in risk_rows if r.get("kind") == "risk_verify"]
    errors = [r.get("inner_error_code") or r.get("error_code") for r in risk_rows]
    hcaptcha = [r.get("metricName") for r in telemetry_rows if r.get("kind") == "telemetry_hcaptcha"]
    ch_scores = [r.get("score") for r in collector_rows if r.get("phase") == "ch_ctx"]
    ch_results = [
        str(result)
        for r in collector_rows
        if r.get("phase") == "ch_ctx"
        for result in (r.get("results") or [])
    ]
    ch_result_ok = any(x.endswith("|0") for x in ch_results)
    ch_result_fail = any(x.endswith("|-1") for x in ch_results)
    create_success = any(
        r.get("kind") == "create_account_response"
        and r.get("status") == 200
        and (r.get("has_signinName") or r.get("has_redirectUrl"))
        and not r.get("error_present")
        for r in account_rows
    )
    create_server_error = any(
        r.get("kind") == "create_account_response"
        and (r.get("server_error") or r.get("context_cookie_mismatch") or r.get("error_present"))
        for r in account_rows
    )
    create_attempted = any(r.get("kind") == "create_account_request" for r in account_rows)
    seen_success = False
    loaded_after_success = False
    for metric in hcaptcha:
        if metric == "HumanCaptcha_Success":
            seen_success = True
        elif metric == "HumanCaptcha_Loaded" and seen_success:
            loaded_after_success = True
    return {
        "risk_initialization_required": any(r.get("state") == "riskInitializationRequired" for r in risk_rows),
        "risk_challenge_required": "riskChallengeRequired" in states,
        "risk_continue": "continue" in states,
        "risk_block": "riskBlock" in errors,
        "hcaptcha_loaded": "HumanCaptcha_Loaded" in hcaptcha,
        "hcaptcha_success": "HumanCaptcha_Success" in hcaptcha,
        "hcaptcha_loaded_after_success": loaded_after_success,
        "hcaptcha_failure": "HumanCaptcha_Failure" in hcaptcha,
        "chctx_score0": "0" in ch_scores,
        "chctx_score1": "1" in ch_scores,
        "chctx_result_ok": ch_result_ok,
        "chctx_result_fail": ch_result_fail,
        "create_account_attempted": create_attempted,
        "create_account_success": create_success,
        "create_account_server_error": create_server_error,
        "final_class": classify_final(
            states,
            errors,
            hcaptcha,
            ch_result_fail,
            loaded_after_success,
            create_attempted,
            create_success,
            create_server_error,
        ),
    }


def classify_final(
    states,
    errors,
    hcaptcha,
    ch_result_fail=False,
    loaded_after_success=False,
    create_attempted=False,
    create_success=False,
    create_server_error=False,
):
    if create_server_error:
        return "server_error"
    if create_success:
        return "success"
    if "riskBlock" in errors:
        return "risk_block"
    if ch_result_fail or "HumanCaptcha_Failure" in hcaptcha:
        return "hsprotect_retry"
    if loaded_after_success:
        return "hsprotect_rechallenge"
    if "continue" in states and create_attempted:
        return "create_account_pending"
    if "continue" in states:
        return "risk_continue_pending"
    if "riskChallengeRequired" in states:
        return "challenge_pending"
    return "unknown"


def replay_boundary(verdict):
    return {
        "protocol_replay_candidates": [
            "risk/initialize and risk/verify request ordering",
            "static browser request header shape",
            "OneCollector telemetry sequence shape",
        ],
        "must_generate_live_or_revalidate": [
            "hsprotect collector payload and pc",
            "px3/pxde/pxvid riskProviderMetadata",
            "iframe.hsprotect.net session_id and ch_ctx transition",
            "df.cfp.microsoft.com device fingerprint frame",
            "browser TLS/HTTP2/client-hints/runtime fingerprint",
        ],
        "current_trace_class": verdict.get("final_class"),
    }


def extract(path: Path, include_sensitive: bool):
    events = list(load_events(path))
    risk_rows = risk_timeline(events, include_sensitive)
    telemetry_rows = telemetry_timeline(events)
    collector_rows = collector_timeline(path, events)
    account_rows = create_account_timeline(events, include_sensitive)
    verdict = build_verdict(risk_rows, telemetry_rows, collector_rows, account_rows)
    return {
        "source": str(path),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "event_count": len(events),
        "fingerprint": fingerprint_summary(path, events),
        "risk": risk_rows,
        "create_account": account_rows,
        "telemetry": telemetry_rows,
        "collectors": collector_rows,
        "request_header_fingerprints": request_header_fingerprints(events),
        "verdict": verdict,
        "replay_boundary": replay_boundary(verdict),
    }


def default_out(path: Path, out_dir: Path) -> Path:
    stem = path.stem.replace(".browser_cdp", "")
    return out_dir / f"{stem}.protocol_state.json"


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract a machine-readable protocol state from AdsPower/SunBrowser CDP traces.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--out-dir", type=Path, default=Path("Results/protocol_runtime"))
    ap.add_argument("--include-sensitive", action="store_true", help="Do not redact account/token-like values.")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path in args.paths:
        state = extract(path, args.include_sensitive)
        out = default_out(path, args.out_dir)
        out.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"wrote {out}")
        print(
            "verdict "
            f"class={state['verdict']['final_class']} "
            f"continue={state['verdict']['risk_continue']} "
            f"chctx_score0={state['verdict']['chctx_score0']} "
            f"chctx_score1={state['verdict']['chctx_score1']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
