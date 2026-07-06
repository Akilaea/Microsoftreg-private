import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_PARAMS = {
    "canary",
    "uaid",
    "sru",
    "contextid",
    "opid",
    "opidt",
    "client_id",
    "cobrandid",
    "suc",
    "epct",
    "epctrc",
    "state",
    "nonce",
    "code_challenge",
    "session_id",
    "c",
}

SENSITIVE_HEADERS = {
    "cookie",
    "set-cookie",
    "canary",
    "authorization",
    "client-request-id",
    "correlationid",
}

INTERESTING_NEEDLES = (
    "signup.live.com",
    "login.live.com",
    "login.microsoftonline.com",
    "iframe.hsprotect.net",
    "client.hsprotect.net",
    "captcha.hsprotect.net",
    "collector-pxzc5j78di.hsprotect.net",
    "stk.hsprotect.net",
    "browser.events.data.microsoft.com",
    "CheckAvailableSigninNames",
    "CreateAccount",
    "risk/verify",
    "risk/initialize",
)


def parse_constants(path: Path) -> dict:
    first = path.open("r", encoding="utf-8", errors="replace").readline()
    return json.loads(first.rstrip("\r\n,") + "}")["constants"]


def parse_event_line(line: str):
    line = line.strip()
    if not line or line.startswith('"events"') or line in ("[", "]", "{", "},"):
        return None
    if line.endswith(","):
        line = line[:-1]
    try:
        return json.loads(line)
    except Exception:
        return None


def iso_from_netlog_ms(offset_ms: int, event_time: str | int | None) -> str:
    try:
        ms = offset_ms + int(event_time)
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""


def redact_url(url: str) -> str:
    if not url:
        return url
    try:
        parts = urlsplit(url)
        q = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            if k.lower() in SENSITIVE_PARAMS:
                q.append((k, "*"))
            else:
                q.append((k, v))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, doseq=True), parts.fragment))
    except Exception:
        return url


def parse_headers(headers) -> tuple[dict, int | None]:
    out = {}
    status = None
    for h in headers or []:
        if not isinstance(h, str):
            continue
        if h.startswith("HTTP/"):
            m = re.search(r"\s(\d{3})\b", h)
            if m:
                status = int(m.group(1))
            continue
        if h.startswith(":status:"):
            try:
                status = int(h.split(":", 2)[2].strip())
            except Exception:
                pass
            continue
        if ":" in h:
            k, v = h.split(":", 1)
            lk = k.strip().lower()
            out[lk] = "*" if lk in SENSITIVE_HEADERS else v.strip()
    return out, status


def label_for(url: str) -> str:
    if "CreateAccount" in url:
        return "CreateAccount"
    if "CheckAvailableSigninNames" in url:
        return "CheckAvailableSigninNames"
    if "risk/verify" in url:
        return "risk/verify"
    if "risk/initialize" in url:
        return "risk/initialize"
    if "iframe.hsprotect.net/index.html" in url:
        return "captcha iframe"
    if "collector-pxzc5j78di.hsprotect.net" in url:
        return "hsprotect collector"
    if "captcha.hsprotect.net" in url:
        return "captcha asset/api"
    if "client.hsprotect.net" in url:
        return "hsprotect client"
    if "stk.hsprotect.net" in url:
        return "hsprotect stk"
    if "OneCollector" in url:
        return "OneCollector"
    if "signup.live.com" in url:
        return "signup"
    if "login.live.com" in url or "login.microsoftonline.com" in url:
        return "login"
    return ""


def interesting(url: str) -> bool:
    return any(n.lower() in (url or "").lower() for n in INTERESTING_NEEDLES)


def load_requests(path: Path):
    const = parse_constants(path)
    offset = int(const["timeTickOffset"])
    rev_type = {v: k for k, v in const["logEventTypes"].items()}
    reqs: dict[int, dict] = {}

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        next(fh, None)
        for line_no, line in enumerate(fh, 2):
            ev = parse_event_line(line)
            if not ev:
                continue
            typ = ev.get("type")
            name = rev_type.get(typ, str(typ))
            src = ev.get("source") or {}
            sid = src.get("id")
            if sid is None:
                continue
            params = ev.get("params") or {}
            r = reqs.setdefault(
                sid,
                {
                    "source_id": sid,
                    "source_type": src.get("type"),
                    "start_time": src.get("start_time"),
                    "line_start": None,
                    "line_response": None,
                    "url": "",
                    "method": "",
                    "request_headers": {},
                    "response_headers": {},
                    "status": None,
                    "request_time": "",
                    "response_time": "",
                    "net_errors": [],
                },
            )

            if name in ("CORS_REQUEST", "URL_REQUEST_START_JOB"):
                if params.get("url") and not r["url"]:
                    r["url"] = params.get("url")
                if name == "URL_REQUEST_START_JOB":
                    r["method"] = params.get("method") or r["method"]
                    r["request_time"] = iso_from_netlog_ms(offset, ev.get("time"))
                    r["line_start"] = r["line_start"] or line_no
                rh = (params.get("request_headers") or {})
                headers, _ = parse_headers(rh.get("headers"))
                r["request_headers"].update(headers)
                line = rh.get("line") or ""
                if line and not r["method"]:
                    r["method"] = line.split(" ", 1)[0]

            elif name in ("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", "HTTP_CACHE_CALLER_REQUEST_HEADERS"):
                headers, _ = parse_headers(params.get("headers"))
                r["request_headers"].update(headers)
                line = params.get("line") or ""
                if line and not r["method"]:
                    r["method"] = line.split(" ", 1)[0]

            elif name == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS":
                headers, status = parse_headers(params.get("headers"))
                r["response_headers"].update(headers)
                if status:
                    r["status"] = status
                r["response_time"] = iso_from_netlog_ms(offset, ev.get("time"))
                r["line_response"] = line_no

            if "net_error" in params and params.get("net_error"):
                r["net_errors"].append(params.get("net_error"))

    return [r for r in reqs.values() if r.get("url")]


def emit_jsonl(reqs, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for r in sorted(reqs, key=lambda x: (x.get("request_time") or "", x.get("source_id") or 0)):
            if not interesting(r["url"]):
                continue
            common = {
                "method": r.get("method") or "",
                "url": redact_url(r.get("url") or ""),
                "source_id": r.get("source_id"),
                "netlog_line_start": r.get("line_start"),
            }
            fh.write(json.dumps({"ts": r.get("request_time"), "event": "request", "headers": r.get("request_headers"), **common}, ensure_ascii=False) + "\n")
            if r.get("status") is not None or r.get("response_time"):
                fh.write(json.dumps({"ts": r.get("response_time"), "event": "response", "status": r.get("status"), "headers": r.get("response_headers"), **common}, ensure_ascii=False) + "\n")


def print_timeline(reqs):
    selected = [r for r in reqs if interesting(r["url"])]
    selected.sort(key=lambda x: (x.get("request_time") or "", x.get("source_id") or 0))
    base_ms = None
    # Compute relative base from first hsprotect iframe, else first selected request.
    for r in selected:
        if "iframe.hsprotect.net/index.html" in r["url"]:
            base_ms = datetime.fromisoformat(r["request_time"].replace("Z", "+00:00")).timestamp() * 1000
            break
    if base_ms is None and selected:
        base_ms = datetime.fromisoformat(selected[0]["request_time"].replace("Z", "+00:00")).timestamp() * 1000
    for r in selected:
        ts = r.get("request_time") or ""
        rel = ""
        if base_ms and ts:
            ms = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000
            rel = f"{(ms - base_ms)/1000:+8.3f}s"
        status = r.get("status")
        dur = ""
        if r.get("request_time") and r.get("response_time"):
            a = datetime.fromisoformat(r["request_time"].replace("Z", "+00:00")).timestamp() * 1000
            b = datetime.fromisoformat(r["response_time"].replace("Z", "+00:00")).timestamp() * 1000
            dur = f" dur={(b-a)/1000:.3f}s"
        print(f"{rel:>10} sid={r['source_id']:>5} {r.get('method') or '-':<6} st={status or '-':<3}{dur:<12} {label_for(r['url']):<24} {redact_url(r['url'])[:180]}")


def main():
    ap = argparse.ArgumentParser(description="Stream-parse incomplete Chromium NetLog into a compact signup timeline.")
    ap.add_argument("netlog", type=Path)
    ap.add_argument("--jsonl-out", type=Path)
    args = ap.parse_args()
    reqs = load_requests(args.netlog)
    print_timeline(reqs)
    if args.jsonl_out:
        emit_jsonl(reqs, args.jsonl_out)
        print(f"\nWROTE {args.jsonl_out}")


if __name__ == "__main__":
    main()
