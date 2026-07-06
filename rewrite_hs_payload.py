import argparse
import hashlib
import hmac
import json
from pathlib import Path

from decode_hs_payload import (
    _b64_utf8,
    _hidden_suffix_from_sid,
    _insertion_positions,
    _xor,
    decode_payload_from_form,
    parse_form_preserve_payload,
)


TIMING_KEYS = [
    "GCgpLl1AKRw=",
    "eEgJDj4mCD4=",
    "WiZrIB9LbBU=",
    "ZjoXPCNQGQw=",
    "Ui5jKBREZxs=",
    "PARNQnlrTHQ=",
    "KVkYX2w2GWg=",
    "QS07ZwRKPlU=",
    "XQUsAxhpKjU=",
    "KDhZPm1XWAo=",
    "KVkYX28zG2o=",
    "QABxRgZqcXQ=",
]


def pc_from_json(json_text: str, form: dict) -> str:
    key = f"{form.get('uuid','')}:{form.get('tag','YjIYfyxJHRR9')}:{form.get('ft','369')}".encode("utf-8")
    digest = hmac.new(key, json_text.encode("utf-8"), hashlib.md5).hexdigest()
    digits, rest = "", ""
    for ch in digest:
        if ch.isdigit():
            digits += ch
        else:
            rest += str(ord(ch) % 10)
    return (digits + rest)[::2]


def encode_payload(events: list, form: dict) -> tuple[str, str, str]:
    json_text = json.dumps(events, ensure_ascii=False, separators=(",", ":"))
    stripped = _b64_utf8(_xor(json_text, 50))
    qi = _hidden_suffix_from_sid(form.get("sid", "")) or "1604064986000"
    inserted = _xor(_b64_utf8(qi), 10)
    positions = _insertion_positions(len(inserted), len(stripped), form.get("uuid", ""))
    out, cursor = "", 0
    for idx, pos in enumerate(positions):
        cut = max(0, pos - idx - 1)
        out += stripped[cursor:cut] + inserted[idx]
        cursor = cut
    return out + stripped[cursor:], json_text, pc_from_json(json_text, form)


def _parse_coord_point(point: str) -> tuple[str, str, float]:
    parts = str(point or "").split(",")
    x = parts[0] if len(parts) > 0 else "0"
    y = parts[1] if len(parts) > 1 else "0"
    try:
        t = float(parts[2] if len(parts) > 2 else 0)
    except Exception:
        t = 0.0
    return x, y, t


def scale_coord_array(values, start_t: float, end_t: float):
    if not isinstance(values, list) or len(values) < 2:
        return values
    parsed = [_parse_coord_point(v) for v in values]
    times = [p[2] for p in parsed]
    min_t, max_t = min(times), max(times)
    if max_t <= min_t:
        return values
    out = []
    for x, y, t in parsed:
        ratio = max(0.0, min(1.0, (t - min_t) / (max_t - min_t)))
        nt = round(start_t + ratio * (end_t - start_t))
        out.append(f"{x},{y},{nt}")
    return out


def align_envelope(px_data: dict, source_data: dict) -> None:
    try:
        e = float(px_data.get("eEgJDj4mCD4=", 0))
        wi = float(px_data.get("WiZrIB9LbBU=", 0))
        ui = float(px_data.get("Ui5jKBREZxs=", 0))
    except Exception:
        return
    if "XQUsAxhpKjU=" in px_data and "XQUsAxhpKjU=" not in source_data:
        px_data["XQUsAxhpKjU="] = round(ui + 5)
    if wi > e:
        start_t = max(0, e - 120)
        end_t = max(e + 300, wi - 3000)
        px_data["GUloT18mZ3U="] = scale_coord_array(px_data.get("GUloT18mZ3U="), start_t, end_t)
        px_data["JnpXfGMUUUc="] = scale_coord_array(px_data.get("JnpXfGMUUUc="), start_t, end_t)
        if isinstance(px_data.get("DzN+dUlTekE="), list):
            for item in px_data["DzN+dUlTekE="]:
                if isinstance(item, dict) and item.get("PX12343") == "pointerup":
                    item["PX11699"] = round(wi)


def iter_collector_requests(trace: Path):
    with trace.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            event = json.loads(line)
            if (
                event.get("event") == "request"
                and event.get("method") == "POST"
                and "collector-" in event.get("url", "")
                and "hsprotect.net" in event.get("url", "")
            ):
                form = parse_form_preserve_payload(event.get("post_data", ""))
                decoded = decode_payload_from_form(form)
                tags = [item.get("t") for item in decoded if isinstance(item, dict)]
                yield idx, event, form, decoded, tags


def find_payloads(trace: Path):
    px561 = None
    w0c = None
    for item in iter_collector_requests(trace):
        idx, event, form, decoded, tags = item
        if px561 is None and "PX561" in tags:
            px561 = item
        if px561 is not None and w0c is None and "W0cqQR4rLnA=" in tags:
            w0c = item
            break
    return px561, w0c


def first_event_data(decoded: list, tag: str) -> dict | None:
    for item in decoded:
        if isinstance(item, dict) and item.get("t") == tag and isinstance(item.get("d"), dict):
            return item["d"]
    return None


def extract_runtime_px1200(runtime_path: Path) -> dict | None:
    data = json.loads(runtime_path.read_text(encoding="utf-8"))
    for frame in data.get("frames") or []:
        for event in (frame.get("probe") or {}).get("events") or []:
            kind = event.get("kind")
            payload = event.get("data") or {}
            if isinstance(kind, str) and kind.startswith("child_") and isinstance(payload, dict) and payload.get("kind"):
                payload = payload
                kind = payload.get("kind")
                data_inner = payload.get("data") or {}
            else:
                data_inner = payload
            if kind == "api_call" and data_inner.get("name") == "PX1200":
                args = data_inner.get("args") or []
                if len(args) >= 2 and isinstance(args[1], dict):
                    return args[1]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline hsprotect payload rewrite validator.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--mode", choices=["align-px561-timing"], default="align-px561-timing")
    parser.add_argument("--source", choices=["w0c", "runtime-px1200"], default="w0c")
    parser.add_argument("--runtime", type=Path, default=None, help="protocol_runtime JSON for --source runtime-px1200")
    parser.add_argument("--dump-body", type=Path, default=None)
    args = parser.parse_args()

    px_item, w0_item = find_payloads(args.trace)
    if not px_item:
        raise SystemExit("missing PX561 collector post")
    if args.source == "w0c" and not w0_item:
        raise SystemExit("missing W0cqQR4rLnA= collector post")

    px_idx, px_event, px_form, px_decoded, px_tags = px_item
    px_data = first_event_data(px_decoded, "PX561")
    if not px_data:
        raise SystemExit("missing proof data")

    w0_idx, w0_tags, source_data = None, [], None
    if args.source == "w0c":
        w0_idx, _w0_event, _w0_form, w0_decoded, w0_tags = w0_item
        source_data = first_event_data(w0_decoded, "W0cqQR4rLnA=")
    else:
        if not args.runtime:
            raise SystemExit("--runtime is required for --source runtime-px1200")
        source_data = extract_runtime_px1200(args.runtime)
    if not source_data:
        raise SystemExit("missing source proof data")

    before = {k: px_data.get(k) for k in TIMING_KEYS}
    for key in TIMING_KEYS:
        if key in source_data:
            px_data[key] = source_data[key]
    align_envelope(px_data, source_data)
    after = {k: px_data.get(k) for k in TIMING_KEYS}

    payload, json_text, pc = encode_payload(px_decoded, px_form)
    rewritten = px_event.get("post_data", "")
    rewritten = rewritten.replace("payload=" + px_form.get("payload", ""), "payload=" + payload)
    if "pc=" in rewritten:
        rewritten = rewritten.replace("pc=" + px_form.get("pc", ""), "pc=" + pc)
    else:
        rewritten += "&pc=" + pc

    check_form = parse_form_preserve_payload(rewritten)
    check_decoded = decode_payload_from_form(check_form)
    check_tags = [item.get("t") for item in check_decoded if isinstance(item, dict)]
    check_pc = pc_from_json(json.dumps(check_decoded, ensure_ascii=False, separators=(",", ":")), check_form)

    print(f"PX561 request idx={px_idx} tags={px_tags}")
    print(f"source={args.source} idx={w0_idx} tags={w0_tags}")
    print("before=" + json.dumps(before, ensure_ascii=False))
    print("after =" + json.dumps(after, ensure_ascii=False))
    print(f"old_pc={px_form.get('pc')} new_pc={pc} check_pc={check_pc} pc_ok={pc == check_pc}")
    print(f"new_payload_len={len(payload)} decoded_tags={check_tags}")
    print(f"px561_keys={len(px_data)} source_keys={len(source_data)}")

    if args.dump_body:
        args.dump_body.parent.mkdir(parents=True, exist_ok=True)
        args.dump_body.write_text(rewritten, encoding="utf-8")
        print(f"[wrote] {args.dump_body}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
