import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from analyze_protocol_run import analyze_network


FLOW_PATTERNS = [
    ("CreateAccount", "CreateAccount"),
    ("CheckAvailableSigninNames", "CheckAvailableSigninNames"),
    ("risk/verify", "risk/verify"),
    ("risk/initialize", "risk/initialize"),
    ("ch_ctx=1", "HumanCaptcha iframe"),
    ("captcha.hsprotect.net", "captcha.js"),
]


def ts_ms(value):
    if not value:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp() * 1000.0
    except Exception:
        return None


def short_url(url):
    url = re.sub(
        r"([?&](?:canary|uaid|sru|contextid|opid|opidt|client_id|cobrandid|mkt|fl|uiflavor|suc|lic|fluent)=)[^&]+",
        r"\1*",
        str(url or ""),
    )
    return url[:150] + ("..." if len(url) > 150 else "")


def labels_for(event):
    text = "\n".join(str(x or "") for x in (event.get("url"), event.get("post_data"), event.get("body")))
    labels = [label for needle, label in FLOW_PATTERNS if needle.lower() in text.lower()]
    labels.extend(re.findall(r"HumanCaptcha_[A-Za-z]+", text))
    labels.extend(re.findall(r"RiskBlock|Abuse|Enforcement|CreateAccount", text))
    return list(dict.fromkeys(labels))


def load_flow(path: Path):
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            labels = labels_for(event)
            url = event.get("url") or ""
            if labels:
                rows.append(
                    {
                        "idx": idx,
                        "ts": event.get("timestamp") or event.get("ts") or event.get("time") or "",
                        "ts_ms": ts_ms(event.get("timestamp") or event.get("ts") or event.get("time")),
                        "event": event.get("event"),
                        "method": event.get("method"),
                        "status": event.get("status"),
                        "labels": labels[:8],
                        "url": url,
                    }
                )
    return rows


def collector_rows(path: Path):
    posts, results = analyze_network(path)
    out = []
    for p in posts:
        tags = p.get("tags") or []
        kind = None
        if "PX561" in tags:
            kind = "final"
        elif "W0cqQR4rLnA=" in tags:
            kind = "w0"
        elif "U0MpSRYiJH8=" in tags:
            kind = "u0"
        elif "Y1NZWSUzXWs=" in tags:
            kind = "y1"
        elif "KnpQcG8ZVUI=" in tags:
            kind = "knp"
        else:
            kind = ",".join(tags[:2]) or "collector"
        resp = p.get("response") or {}
        out.append(
            {
                "idx": p.get("idx"),
                "ts": p.get("ts") or "",
                "ts_ms": p.get("ts_ms"),
                "kind": kind,
                "seq": p.get("seq"),
                "qi": p.get("qi"),
                "score": ",".join(resp.get("scores") or []),
                "result": ",".join(resp.get("results") or []),
            }
        )
    return out, results


def print_run(name: str, path: Path):
    print(f"=== {name}: {path} ===")
    flow = load_flow(path)
    collectors, results = collector_rows(path)
    create200 = any("CreateAccount" in r["labels"] and r.get("event") == "response" and int(r.get("status") or 0) == 200 for r in flow)
    print(f"CreateAccount200={create200} collector_results={','.join(results) if results else '-'}")

    base_ms = None
    for r in flow:
        if "HumanCaptcha iframe" in r["labels"] and r["event"] == "request":
            base_ms = r["ts_ms"]
            break
    if base_ms is None and flow:
        base_ms = flow[0]["ts_ms"]

    merged = []
    for r in flow:
        merged.append(("host", r))
    for c in collectors:
        if c["kind"] in {"u0", "w0", "final"} or c.get("result"):
            merged.append(("collector", c))
    merged.sort(key=lambda x: (x[1].get("ts_ms") is None, x[1].get("ts_ms") or 0, x[1].get("idx") or 0))

    for typ, r in merged:
        delta = ""
        if base_ms is not None and r.get("ts_ms") is not None:
            delta = f"+{(r['ts_ms'] - base_ms) / 1000:7.3f}s"
        if typ == "host":
            print(
                f"{delta:>10} idx={r['idx']:>3} HOST {r.get('event')}/{r.get('method')} "
                f"st={r.get('status')} labels={r['labels']} {short_url(r.get('url'))}"
            )
        else:
            print(
                f"{delta:>10} idx={r['idx']:>3} COLL {r['kind']:<5} "
                f"seq={r.get('seq')} qi={r.get('qi')} score={r.get('score') or '-'} result={r.get('result') or '-'}"
            )


def main():
    ap = argparse.ArgumentParser(description="Compare signup host-flow timing against hsprotect collector timing.")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()
    for i, path in enumerate(args.paths, 1):
        if not path.exists():
            raise SystemExit(f"missing: {path}")
        print_run(f"run{i}", path)


if __name__ == "__main__":
    main()
