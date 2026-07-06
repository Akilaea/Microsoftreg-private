import argparse
import base64
import hashlib
import hmac
import json
import math
import urllib.parse
from collections import Counter
from pathlib import Path


def _b64_utf8(s: str) -> str:
    # hsprotect uses btoa(unescape(encodeURIComponent(s))) in JS, i.e. base64
    # over the UTF-8 bytes of the JavaScript string.  Latin-1 happens to work
    # for ASCII-only posts but breaks PX561 posts that contain localized
    # timezone / platform strings; then pc recomputation also diverges.
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64decode_utf8(s: str) -> str:
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4)).decode("utf-8")


def _xor(s: str, key: int) -> str:
    return "".join(chr(ord(ch) ^ key) for ch in s)


def _hidden_suffix_from_sid(sid: str) -> str:
    # main.min.js Kl() stores Qi() digits as Unicode tag characters U+E01xx.
    return "".join(chr(ord(ch) - 0xE0100) for ch in sid if 0xE0100 <= ord(ch) <= 0xE01FF)


def parse_form_preserve_payload(body: str) -> dict:
    """Parse hsprotect form body without converting '+' to space inside payload."""
    out = {}
    for part in (body or "").split("&"):
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, ""
        out[key] = value if key == "payload" else urllib.parse.unquote_plus(value)
    return out


def _insertion_positions(insert_len: int, original_len: int, uuid: str) -> list[int]:
    # Port of main.pretty.js Vs() inner permutation.  The returned numbers are
    # one-based positions in the final string, so callers remove p - 1.
    h = _xor(_b64_utf8(uuid), 10)
    if not h:
        raise ValueError("cannot decode hsprotect payload without uuid")
    positions = []
    vmax = -1
    for p in range(insert_len):
        m = math.floor(p / len(h)) + 1
        g = p % len(h) if p >= len(h) else p
        y = ord(h[g]) * ord(h[m]) if m < len(h) else float("nan")
        if not math.isnan(y) and y > vmax:
            vmax = y
    for b in range(insert_len):
        i = math.floor(b / len(h)) + 1
        e = b % len(h)
        value = ord(h[e]) * ord(h[i]) if i < len(h) else 0
        if value >= original_len:
            value = math.floor(value / vmax * (original_len - 1)) if vmax else 0
        while value in positions:
            value += 1
        positions.append(value)
    return sorted(positions)


def pc_from_json_text(json_text: str, form: dict) -> str:
    # main.pretty.js: Jt(ut(events), [po(), tag, ft].join(":"))
    key = f"{form.get('uuid','')}:{form.get('tag','YjIYfyxJHRR9')}:{form.get('ft','369')}".encode("utf-8")
    digest = hmac.new(key, json_text.encode("utf-8"), hashlib.md5).hexdigest()
    digits, rest = "", ""
    for ch in digest:
        if ch.isdigit():
            digits += ch
        else:
            rest += str(ord(ch) % 10)
    return (digits + rest)[::2]


def encode_payload_from_events(events: list, form: dict) -> tuple[str, str, str]:
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
    return out + stripped[cursor:], json_text, pc_from_json_text(json_text, form)


def decode_payload_meta_from_form(form: dict) -> dict:
    payload = form.get("payload", "")
    uuid = form.get("uuid", "")
    qi = _hidden_suffix_from_sid(form.get("sid", "")) or "1604064986000"
    # Vs() inserts ne(J(Qi()), 10): XOR over the base64 text itself.
    inserted = _xor(_b64_utf8(qi), 10)
    positions = _insertion_positions(len(inserted), len(payload) - len(inserted), uuid)
    remove = {p - 1 for p in positions}
    stripped = "".join(ch for idx, ch in enumerate(payload) if idx not in remove)
    observed_inserted = "".join(payload[p - 1] for p in positions if 0 <= p - 1 < len(payload))
    decoded = _xor(_b64decode_utf8(stripped), 50)
    events = json.loads(decoded)
    encoded_payload, json_text, recomputed_pc = encode_payload_from_events(events, form)
    return {
        "events": events,
        "qi": qi,
        "inserted": inserted,
        "observed_inserted": observed_inserted,
        "noise_ok": observed_inserted == inserted,
        "payload_roundtrip": encoded_payload == payload,
        "pc": form.get("pc"),
        "recomputed_pc": recomputed_pc,
        "pc_ok": recomputed_pc == form.get("pc"),
        "positions": positions,
        "stripped_len": len(stripped),
    }


def decode_payload_from_form(form: dict) -> list:
    return decode_payload_meta_from_form(form)["events"]


def iter_collector_posts(trace_path: Path):
    with trace_path.open("r", encoding="utf-8", errors="replace") as fh:
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
                if not form.get("payload") or not form.get("uuid"):
                    continue
                try:
                    meta = decode_payload_meta_from_form(form)
                except Exception:
                    continue
                yield idx, event, form, meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode hsprotect collector request payloads from a network trace.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--dump-json", type=Path, default=None, help="Write decoded posts to a JSON file.")
    args = parser.parse_args()

    decoded_posts = []
    for ordinal, (idx, event, form, meta) in enumerate(iter_collector_posts(args.trace), 1):
        decoded = meta["events"]
        tags = [item.get("t") for item in decoded if isinstance(item, dict)]
        decoded_posts.append(
            {
                "ordinal": ordinal,
                "index": idx,
                "url": event.get("url"),
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "payload_len": len(form.get("payload", "")),
                "noise_ok": meta.get("noise_ok"),
                "payload_roundtrip": meta.get("payload_roundtrip"),
                "pc_ok": meta.get("pc_ok"),
                "pc": meta.get("pc"),
                "recomputed_pc": meta.get("recomputed_pc"),
                "qi": meta.get("qi"),
                "tags": tags,
                "decoded": decoded,
            }
        )
        print(
            f"{ordinal:02d} idx={idx} seq={form.get('seq')} rsc={form.get('rsc')} "
            f"payload_len={len(form.get('payload',''))} noise_ok={meta.get('noise_ok')} "
            f"roundtrip={meta.get('payload_roundtrip')} pc_ok={meta.get('pc_ok')} "
            f"events={len(decoded)} tags={tags}"
        )
        counts = Counter(tags)
        if len(counts) != len(tags):
            print("    repeated=" + json.dumps(counts, ensure_ascii=False))

    if args.dump_json:
        args.dump_json.parent.mkdir(parents=True, exist_ok=True)
        args.dump_json.write_text(json.dumps(decoded_posts, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[wrote] {args.dump_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
