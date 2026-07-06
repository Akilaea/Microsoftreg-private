import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


NETWORK_DIR = Path("Results") / "network"


def load_events(path):
    events = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"event": "decode_error", "raw": line[:300]})
    return events


def latest_traces(limit=5):
    return sorted(NETWORK_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]


def sha(text):
    if text is None:
        return "-"
    return hashlib.sha256(str(text).encode("utf-8", errors="ignore")).hexdigest()


def short_url(url):
    u = urlparse(url or "")
    return f"{u.netloc}{u.path}"


def parse_form(body):
    if not body or body == "<redacted>":
        return {}
    try:
        return dict(parse_qsl(body, keep_blank_values=True))
    except Exception:
        return {}


def parse_json_body(body):
    if not body or body == "<redacted>":
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def px_hash_key(tag):
    """
    hsprotect main.min.js uses the same small hash (el(tag) % 128) to XOR-decode
    collector response commands after base64 decoding.
    """
    value = 0
    for ch in str(tag or "YjIYfyxJHRR9"):
        value = (31 * value + ord(ch)) % 2147483647
    return (value % 900 + 100) % 128


def decode_collector_commands(response_body, tag):
    parsed = parse_json_body(response_body)
    if not isinstance(parsed, dict):
        return None
    encoded = parsed.get("do") or parsed.get("ob")
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        raw = base64.b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        key = px_hash_key(tag)
        decoded = "".join(chr(b ^ key) for b in raw)
        commands = []
        for part in decoded.split("~~~~"):
            if not part:
                continue
            bits = part.split("|")
            commands.append({
                "id": bits[0],
                "args": bits[1:],
                "preview": part[:260],
            })
        return {"decoded_len": len(decoded), "commands": commands}
    except Exception as exc:
        return {"decode_error": repr(exc)}


def response_after(events, req_index):
    req = events[req_index]
    for event in events[req_index + 1:]:
        if (
            event.get("event") == "response"
            and event.get("method") == req.get("method")
            and event.get("url") == req.get("url")
        ):
            return event
    return None


def summarize_collector_request(event):
    body = event.get("post_data")
    params = parse_form(body)
    payload = params.get("payload")
    keys = ["appId", "tag", "uuid", "seq", "sid", "vid", "p1", "ci", "cs", "rsc", "ft", "en", "pc"]
    compact = {k: params.get(k) for k in keys if params.get(k) is not None}
    if payload is not None:
        compact["payload_len"] = len(payload)
        compact["payload_sha256"] = sha(payload)[:16]
    return compact


def summarize_response(event, tag=None):
    if not event:
        return "status=-"
    parts = [f"status={event.get('status')}"]
    if "body_len" in event:
        parts.append(f"body_len={event.get('body_len')}")
        parts.append(f"body_sha={str(event.get('body_sha256', '-'))[:16]}")
        body = event.get("body")
        parsed = parse_json_body(body)
        if isinstance(parsed, dict):
            parts.append("json_keys=" + ",".join(list(parsed.keys())[:12]))
            # Do not dump full proof-like values to console; show shape only.
            for k in ("token", "proof", "result", "status", "success", "error", "requestId"):
                if k in parsed:
                    v = parsed[k]
                    if isinstance(v, str):
                        parts.append(f"{k}=str(len={len(v)},sha={sha(v)[:12]})")
                    else:
                        parts.append(f"{k}={v!r}")
        elif body:
            preview = str(body)[:80].replace("\n", "\\n")
            parts.append(f"preview={preview!r}")

        if tag:
            decoded = decode_collector_commands(body, tag)
            if decoded and decoded.get("commands"):
                ids = [c["id"] for c in decoded["commands"]]
                parts.append("cmds=" + ",".join(ids[:18]))
                special = [
                    c["preview"]
                    for c in decoded["commands"]
                    if c["id"] in {"oIIoIooo", "IoooII", "IoIoIo", "oIIoIIoo", "IooIIo", "oIIooIoo"}
                ]
                if special:
                    parts.append("special=" + " || ".join(special[:4]))
    elif "body_error" in event:
        parts.append(f"body_error={event.get('body_error')}")
    return " ".join(parts)


def analyze_trace(path):
    events = load_events(path)
    print(f"\n=== {path} ===")
    print(f"events={len(events)}")

    create_req = None
    create_req_idx = None
    for idx, event in enumerate(events):
        if event.get("event") == "request" and "signup.live.com/API/CreateAccount" in event.get("url", ""):
            create_req = event
            create_req_idx = idx
            break

    if create_req:
        data = parse_json_body(create_req.get("post_data")) or {}
        ct = data.get("ContinuationToken", "")
        print("[CreateAccount]")
        print(f"  request_index={create_req_idx} post_len={create_req.get('post_data_len')} status={summarize_response(response_after(events, create_req_idx))}")
        print(f"  uaid={data.get('uaid')} hpgid={data.get('hpgid')} scid={data.get('scid')} uiflvr={data.get('uiflvr')}")
        print(f"  member={data.get('MemberName')} continuation_len={len(ct)} continuation_sha={sha(ct)[:16]}")
        print(f"  private_access_token_present={bool(data.get('PrivateAccessToken'))}")
    else:
        print("[CreateAccount] not reached")

    print("[hsprotect collector POSTs]")
    hs_posts = []
    for idx, event in enumerate(events):
        if event.get("event") != "request" or event.get("method") != "POST":
            continue
        url = event.get("url", "")
        if "collector-" not in url or "hsprotect.net" not in url:
            continue
        hs_posts.append((idx, event))

    for n, (idx, event) in enumerate(hs_posts, 1):
        marker = ""
        if create_req_idx is not None and idx < create_req_idx:
            marker = " before_CreateAccount"
        elif create_req_idx is not None:
            marker = " after_CreateAccount"
        compact = summarize_collector_request(event)
        resp = response_after(events, idx)
        tag = compact.get("tag") or "YjIYfyxJHRR9"
        print(f"  {n:02d} idx={idx}{marker} {short_url(event.get('url'))} post_len={event.get('post_data_len')} post_sha={str(event.get('post_data_sha256','-'))[:16]}")
        if compact:
            print("     form=" + json.dumps(compact, ensure_ascii=True, sort_keys=True))
        print("     response=" + summarize_response(resp, tag=tag))

    # Last few protocol-relevant requests before CreateAccount are usually the proof boundary.
    if create_req_idx is not None:
        print("[last protocol requests before CreateAccount]")
        start = max(0, create_req_idx - 12)
        for idx in range(start, create_req_idx):
            event = events[idx]
            if event.get("event") != "request":
                continue
            url = event.get("url", "")
            if not any(k in url for k in ("hsprotect.net", "signup.live.com/API", "fpt.live.com")):
                continue
            print(f"  idx={idx:03d} {event.get('method')} {short_url(url)} post_len={event.get('post_data_len','')}")


def main():
    parser = argparse.ArgumentParser(description="Analyze hsprotect proof boundary from network traces")
    parser.add_argument("traces", nargs="*", help="Trace JSONL paths. Defaults to latest traces.")
    parser.add_argument("--latest", type=int, default=5)
    args = parser.parse_args()

    paths = [Path(p) for p in args.traces] if args.traces else latest_traces(args.latest)
    if not paths:
        print(f"No traces under {NETWORK_DIR}")
        return 1
    for path in paths:
        analyze_trace(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
