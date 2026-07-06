import argparse
import json
import math
from pathlib import Path


def latest_event_log(events_dir):
    files = sorted(Path(events_dir).glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError(f"No captcha event logs found in {events_dir}")
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
                pass
    return events


def dist(a, b):
    if a.get("clientX") is None or b.get("clientX") is None:
        return None
    return math.hypot(a["clientX"] - b["clientX"], a["clientY"] - b["clientY"])


def main():
    parser = argparse.ArgumentParser(description="Analyze manual captcha hold pointer events")
    parser.add_argument("--events", default=None)
    parser.add_argument("--events-dir", default=str(Path("Results") / "captcha_events"))
    args = parser.parse_args()

    try:
        path = Path(args.events) if args.events else latest_event_log(args.events_dir)
    except FileNotFoundError as exc:
        print(f"[CaptchaEvents] {exc}")
        print("[Hint] Run first: python main.py --config config.ctf.captcha_learn.json --max-tasks 1 --concurrent 1")
        return 0

    events = load_events(path)
    pointer_events = [e for e in events if e.get("type", "").startswith("pointer")]
    mouse_events = [e for e in events if e.get("type", "").startswith("mouse")]
    downs = [e for e in events if e.get("type") in ("pointerdown", "mousedown", "touchstart")]
    ups = [e for e in events if e.get("type") in ("pointerup", "mouseup", "touchend", "pointercancel")]

    print(f"[CaptchaEvents] {path}")
    print(f"events={len(events)} pointer={len(pointer_events)} mouse={len(mouse_events)} down={len(downs)} up={len(ups)}")

    if downs and ups:
        first_down = downs[0]
        last_up = ups[-1]
        if first_down.get("perfNow") is not None and last_up.get("perfNow") is not None:
            hold_ms = last_up["perfNow"] - first_down["perfNow"]
            print(f"hold_ms={hold_ms:.1f}")
            print(f"suggested_hold_min_ms={max(1500, int(hold_ms * 0.85))}")
            print(f"suggested_hold_max_ms={int(hold_ms * 1.18)}")
        print(f"down=({first_down.get('clientX')},{first_down.get('clientY')}) target={first_down.get('target')}")
        print(f"up=({last_up.get('clientX')},{last_up.get('clientY')}) target={last_up.get('target')}")

    moves = [e for e in events if e.get("type") in ("pointermove", "mousemove", "touchmove") and e.get("clientX") is not None]
    if moves and downs:
        origin = downs[0]
        distances = [d for d in (dist(origin, e) for e in moves) if d is not None]
        if distances:
            print(f"move_count={len(moves)} max_distance_from_down={max(distances):.2f} avg_distance={sum(distances)/len(distances):.2f}")

    target_counts = {}
    for e in events:
        t = e.get("target") or {}
        key = f"{t.get('tag')}#{t.get('id')}[{t.get('role')}]"
        target_counts[key] = target_counts.get(key, 0) + 1
    print("[targets]")
    for key, count in sorted(target_counts.items(), key=lambda item: -item[1])[:10]:
        print(f"{count:04d} {key}")


if __name__ == "__main__":
    raise SystemExit(main() or 0)
