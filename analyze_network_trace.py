import argparse
import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


DEFAULT_KEYWORDS = (
    "signup.live.com",
    "login.live.com",
    "account.live.com",
    "client.hip.live.com",
    "hsprotect.net",
)


def latest_trace(network_dir):
    files = sorted(Path(network_dir).glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError(f"No trace files found in {network_dir}")
    return files[0]


def load_events(path):
    events = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"event": "decode_error", "raw": line[:500]})
    return events


def params_summary(url):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    # 只输出参数名，避免控制台泄露大 token；完整内容仍在原始 jsonl。
    return {
        "host": parsed.netloc,
        "path": parsed.path,
        "query_keys": [k for k, _ in params],
    }


def event_key(event):
    parsed = urlparse(event.get("url", ""))
    return event.get("method", ""), parsed.netloc, parsed.path


def main():
    parser = argparse.ArgumentParser(description="Summarize Outlook registration network trace")
    parser.add_argument("--trace", default=None, help="Path to a Results/network/*.jsonl file")
    parser.add_argument("--network-dir", default=str(Path("Results") / "network"))
    parser.add_argument("--keywords", nargs="*", default=list(DEFAULT_KEYWORDS))
    parser.add_argument("--show-post-preview", action="store_true", help="Print first 300 chars of captured POST bodies")
    args = parser.parse_args()

    try:
        trace_path = Path(args.trace) if args.trace else latest_trace(args.network_dir)
    except FileNotFoundError as exc:
        print(f"[Trace] {exc}")
        print("[Hint] Run first: powershell -ExecutionPolicy Bypass -File .\\run_manual_trace.ps1")
        return 0
    events = load_events(trace_path)

    responses = defaultdict(list)
    for event in events:
        if event.get("event") == "response":
            responses[event_key(event)].append(event.get("status"))

    print(f"[Trace] {trace_path}")
    print(f"[Events] {len(events)}")
    print()

    interesting_requests = [
        event for event in events
        if event.get("event") == "request"
        and any(keyword in event.get("url", "") for keyword in args.keywords)
    ]

    for idx, event in enumerate(interesting_requests, 1):
        key = event_key(event)
        statuses = responses.get(key, [])
        parsed = params_summary(event["url"])
        line = (
            f"{idx:03d} {event.get('method')} "
            f"{parsed['host']}{parsed['path']} "
            f"status={statuses[-1] if statuses else '-'}"
        )
        if "post_data_len" in event:
            line += f" post_len={event['post_data_len']} post_sha256={event.get('post_data_sha256', '-')[:16]}"
        print(line)
        if parsed["query_keys"]:
            print(f"    query_keys={','.join(parsed['query_keys'])}")
        if args.show_post_preview and event.get("post_data") and event["post_data"] != "<redacted>":
            preview = event["post_data"][:300].replace("\n", "\\n")
            print(f"    post_preview={preview}")

    post_targets = {}
    for event in interesting_requests:
        if event.get("method") == "POST":
            key = event_key(event)
            post_targets.setdefault(key, 0)
            post_targets[key] += 1

    print()
    print("[POST targets]")
    for (method, host, path), count in sorted(post_targets.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count:03d} {method} {host}{path}")


if __name__ == "__main__":
    raise SystemExit(main() or 0)
