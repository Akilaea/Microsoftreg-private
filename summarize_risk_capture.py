import argparse
import json
from pathlib import Path


def load(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                yield idx, json.loads(line)
            except Exception:
                continue


def jget(text: str):
    try:
        return json.loads(text or "")
    except Exception:
        return {}


def short_token(token: str) -> str:
    if not token:
        return ""
    return f"{token[:24]}...{token[-16:]} len={len(token)}"


def summarize(path: Path):
    print(f"=== {path} ===")
    risk_rows = []
    create_rows = []
    for idx, ev in load(path):
        url = ev.get("url") or ""
        if ev.get("event") == "response" and "api/v1.0/risk/verify" in url:
            body = jget(ev.get("body") or "")
            risk_rows.append((idx, ev, body))
        if "signup.live.com/API/CreateAccount" in url:
            create_rows.append((idx, ev, jget(ev.get("post_data") or ev.get("body") or "")))

    if not risk_rows:
        print("risk/verify responses: none")
    for idx, ev, body in risk_rows:
        state = body.get("state")
        keys = sorted(body.keys())
        token = body.get("continuationToken") or body.get("ContinuationToken") or ""
        challenge = ((body.get("challengeDetails") or {}).get("challengeType") or "")
        print(
            f"risk idx={idx} ts={ev.get('ts')} status={ev.get('status')} "
            f"state={state} challenge={challenge or '-'} token={short_token(token)} keys={keys}"
        )
        if state and state != "riskChallengeRequired":
            print("  PASS_LIKE_BODY=" + json.dumps(body, ensure_ascii=False)[:3000])

    if not create_rows:
        print("CreateAccount events: none")
    for idx, ev, body in create_rows:
        token = body.get("ContinuationToken") or ""
        print(
            f"create idx={idx} event={ev.get('event')} ts={ev.get('ts')} "
            f"status={ev.get('status')} token={short_token(token)}"
        )


def main():
    ap = argparse.ArgumentParser(description="Summarize manual risk/verify capture JSONL.")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()
    for p in args.paths:
        summarize(p)


if __name__ == "__main__":
    main()
