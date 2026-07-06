import argparse
import base64
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from decode_hs_payload import iter_collector_posts, parse_form_preserve_payload
from project_knp_scope import final_invariants


def _tags(events):
    return [ev.get("t") for ev in events or [] if isinstance(ev, dict)]


def _find_event(events, tag):
    for ev in events or []:
        if isinstance(ev, dict) and ev.get("t") == tag:
            return ev.get("d") or {}
    return None


def _short_bool(v):
    return "Y" if v else "N"


def _knp_core_hash(knp: dict | None) -> str | None:
    if not knp:
        return None
    core = knp.get("U0MpSRYgLHo=") or {}
    if not core:
        return None
    raw = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def _px_hash_key(tag: str) -> int:
    tag = str(tag or "YjIYfyxJHRR9")
    e = 0
    for ch in tag:
        e = (31 * e + ord(ch)) % 2147483647
    return (e % 900 + 100) % 128


def _ts_ms(value) -> float | None:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp() * 1000.0
    except Exception:
        return None


def _decode_collector_response(text: str, sent_body: str) -> dict:
    try:
        obj = json.loads(text or "")
        cmd = obj.get("do") or obj.get("ob")
        if not isinstance(cmd, str) or not cmd:
            return {}
        form = parse_form_preserve_payload(sent_body or "")
        key = _px_hash_key(form.get("tag"))
        raw = base64.b64decode(cmd + "=" * ((4 - len(cmd) % 4) % 4))
        decoded = "".join(chr(b ^ key) for b in raw)
        parts = [p for p in decoded.split("~~~~") if p]
        return {
            "parts": parts,
            "scores": [p for p in parts if p.startswith("IoIoIo|score|")],
            "results": [p for p in parts if p.startswith("oIIoIooo|")],
            "pxde": [p for p in parts if p.startswith("oIIoIIoo|_pxde|")],
        }
    except Exception as exc:
        return {"error": str(exc)}


def decode_collector_response_map(path: Path) -> dict:
    """Pair collector POST responses with their request line index."""
    pending = []
    out = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            event = json.loads(line)
            url = event.get("url", "")
            if (
                event.get("event") == "request"
                and event.get("method") == "POST"
                and "collector-" in url
                and "hsprotect.net" in url
            ):
                form = parse_form_preserve_payload(event.get("post_data", ""))
                pending.append(
                    {
                        "idx": idx,
                        "url": url,
                        "body": event.get("post_data", ""),
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                    }
                )
            elif (
                event.get("event") == "response"
                and event.get("method") == "POST"
                and "collector-" in url
                and "hsprotect.net" in url
            ):
                req = None
                for pos, item in enumerate(pending):
                    if item["url"] == url:
                        req = pending.pop(pos)
                        break
                if not req:
                    continue
                decoded = _decode_collector_response(event.get("body", ""), req["body"])
                out[req["idx"]] = {
                    "response_idx": idx,
                    "status": event.get("status"),
                    "seq": req.get("seq"),
                    "rsc": req.get("rsc"),
                    **decoded,
                }
    return out


def analyze_network(path: Path):
    posts = []
    collector_results = []
    responses = decode_collector_response_map(path)
    for ordinal, (idx, event, form, meta) in enumerate(iter_collector_posts(path), 1):
        events = meta["events"]
        tags = _tags(events)
        resp = responses.get(idx) or {}
        for result in resp.get("results") or []:
            collector_results.append(result.rsplit("|", 1)[-1])
        px = _find_event(events, "PX561")
        knp = _find_event(events, "KnpQcG8ZVUI=")
        posts.append(
            {
                "ordinal": ordinal,
                "idx": idx,
                "ts": event.get("timestamp") or event.get("ts") or event.get("time"),
                "ts_ms": _ts_ms(event.get("timestamp") or event.get("ts") or event.get("time")),
                "url": event.get("url"),
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "qi": meta.get("qi"),
                "tags": tags,
                "pc_ok": meta.get("pc_ok"),
                "noise_ok": meta.get("noise_ok"),
                "roundtrip": meta.get("payload_roundtrip"),
                "payload_len": len(form.get("payload", "")),
                "px561": px,
                "knp": knp,
                "knp_core_hash": _knp_core_hash(knp),
                "events": events,
                "final_invariants": final_invariants(events) if "PX561" in tags else None,
                "response": resp,
            }
        )
    return posts, collector_results


def summarize_runtime(path: Path):
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    counts = {}
    interesting = []
    for fr in data.get("frames") or []:
        if not isinstance(fr, dict):
            continue
        for ev in (fr.get("probe") or {}).get("events") or []:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("kind") or ""
            if (
                "knp_sandbox" in kind
                or "knp_scope_normalized" in kind
                or "final_proof_envelope_normalized" in kind
                or "collector_request_normalized" in kind
                or "px1200_timing_normalized" in kind
                or "px561_timing_aligned" in kind
                or "exact_knp_wait" in kind
                or "synthetic_u0" in kind
                or "xhr_early_w0" in kind
                or "xhr_send_delayed_for_exact_knp" in kind
                or "xhr_delayed_" in kind
                or "host_message_event" in kind
            ):
                counts[kind] = counts.get(kind, 0) + 1
                if any(
                    needle in kind
                    for needle in (
                        "knp_sandbox_event_injected",
                        "knp_sandbox_cached_from_payload",
                        "knp_sandbox_ready_broadcast",
                        "knp_sandbox_ready_received",
                        "knp_sandbox_broker_ready",
                        "knp_sandbox_broker_force_restart",
                        "knp_sandbox_broker_error",
                        "knp_sandbox_broker_timeout",
                        "knp_sandbox_hold_prestart",
                        "knp_sandbox_hold_prestart_skip",
                        "knp_sandbox_challenge_prestart",
                        "knp_sandbox_exact_required_missing",
                        "collector_request_normalized",
                        "knp_scope_normalized",
                        "final_proof_envelope_normalized",
                        "exact_knp_wait_start",
                        "exact_knp_wait_done",
                        "exact_knp_wait_fallback_enabled",
                        "exact_knp_wait_error",
                        "synthetic_u0_send_start",
                        "synthetic_u0_send_done",
                        "synthetic_u0_send_error",
                        "synthetic_u0_final_shifted",
                        "synthetic_u0_bfa_removed",
                        "synthetic_u0_interaction_normalized",
                        "synthetic_u0_proof_timing_fields_normalized",
                        "xhr_send_delayed_for_exact_knp",
                        "xhr_delayed_send_now",
                        "xhr_delayed_final_sent_recorded",
                        "xhr_delayed_queue_flush",
                        "xhr_delayed_queue_send_now",
                        "xhr_delayed_queue_drop_stale",
                        "xhr_early_w0_held_for_final",
                        "xhr_early_w0_drop_after_final",
                        "xhr_early_w0_queue_drain",
                        "xhr_early_w0_hold_timeout",
                        "xhr_delayed_hard_timeout",
                        "xhr_delayed_hard_timeout_fallback_enabled",
                        "xhr_delayed_send_error",
                        "xhr_delayed_normalize_error",
                        "xhr_delayed_hard_timeout_error",
                        "host_message_event",
                    )
                ):
                    interesting.append(
                        {
                            "kind": kind,
                            "data": ev.get("data"),
                        }
                    )
    return {"counts": counts, "interesting_tail": interesting[-40:]}


def print_collector_timing(posts):
    by_qi = {}
    for p in posts:
        qi = str(p.get("qi") or "")
        if not qi or qi == "1604064986000":
            continue
        by_qi.setdefault(qi, []).append(p)
    rows = []
    for qi, items in by_qi.items():
        u0 = next((p for p in items if "U0MpSRYiJH8=" in p.get("tags", [])), None)
        w0 = next((p for p in items if "W0cqQR4rLnA=" in p.get("tags", []) and "PX561" not in p.get("tags", [])), None)
        final = next((p for p in items if "PX561" in p.get("tags", [])), None)
        if not (u0 or w0 or final):
            continue
        def delta(a, b):
            if not a or not b or a.get("ts_ms") is None or b.get("ts_ms") is None:
                return None
            return round(b["ts_ms"] - a["ts_ms"], 1)
        rows.append({
            "qi": qi,
            "u0_ord": u0 and u0.get("ordinal"),
            "w0_ord": w0 and w0.get("ordinal"),
            "final_ord": final and final.get("ordinal"),
            "u0_to_w0_ms": delta(u0, w0),
            "u0_to_final_ms": delta(u0, final),
            "w0_to_final_ms": delta(w0, final),
            "final_to_w0_ms": delta(final, w0),
        })
    if not rows:
        return
    print("collector_timing:")
    for r in rows:
        print(
            "  "
            f"qi={r['qi']} u0={r['u0_ord']} w0={r['w0_ord']} final={r['final_ord']} "
            f"u0->w0={r['u0_to_w0_ms']}ms u0->final={r['u0_to_final_ms']}ms "
            f"w0->final={r['w0_to_final_ms']}ms final->w0={r['final_to_w0_ms']}ms"
        )


def print_key_network_events(path: Path):
    key = []
    host_flow = []
    seen_flow = set()
    flow_patterns = [
        ("CreateAccount", "CreateAccount"),
        ("CheckAvailableSigninNames", "CheckAvailableSigninNames"),
        ("risk/verify", "risk/verify"),
        ("risk/initialize", "risk/initialize"),
        ("ch_ctx=1", "HumanCaptcha iframe"),
        ("captcha.hsprotect.net", "captcha.js"),
    ]
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if not line.strip():
                    continue
                event = json.loads(line)
                url = event.get("url", "")
                if "captcha_close" in url or "CreateAccount" in url:
                    key.append({
                        "idx": idx,
                        "event": event.get("event"),
                        "method": event.get("method"),
                        "status": event.get("status"),
                        "url": url,
                    })
                text = " ".join(
                    str(x or "")
                    for x in (url, event.get("post_data", ""), event.get("body", ""))
                )
                labels = [label for needle, label in flow_patterns if needle.lower() in text.lower()]
                labels.extend(re.findall(r"HumanCaptcha_[A-Za-z]+", text))
                labels.extend(re.findall(r"RiskBlock|Abuse|Enforcement|CreateAccount", text))
                labels = list(dict.fromkeys(labels))
                if labels:
                    dedup_key = (idx, tuple(labels[:4]))
                    if dedup_key not in seen_flow:
                        seen_flow.add(dedup_key)
                        host_flow.append({
                            "idx": idx,
                            "ts": event.get("timestamp") or event.get("ts") or event.get("time") or "",
                            "event": event.get("event"),
                            "method": event.get("method"),
                            "status": event.get("status"),
                            "labels": labels[:6],
                            "url": url,
                        })
    except Exception:
        return
    if not key:
        key = []
    if key:
        print("key_network_events:")
        for item in key:
            url = item["url"]
            if len(url) > 120:
                url = url[:117] + "..."
            print(
                f"  idx={item['idx']} {item.get('event')} {item.get('method')} "
                f"status={item.get('status')} {url}"
            )
    if host_flow:
        print("host_flow_tail:")
        for item in host_flow[-30:]:
            url = item["url"]
            if len(url) > 100:
                url = url[:97] + "..."
            ts = str(item.get("ts") or "")
            ts_short = ts[11:23] if len(ts) > 12 else ts
            print(
                f"  idx={item['idx']} {ts_short} {item.get('event')} {item.get('method')} "
                f"status={item.get('status')} labels={item.get('labels')} {url}"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize a hsprotect protocol run.")
    ap.add_argument("network_jsonl", type=Path)
    ap.add_argument("--runtime", type=Path, default=None)
    args = ap.parse_args()

    posts, collector_results = analyze_network(args.network_jsonl)
    print(f"network={args.network_jsonl}")
    print(f"collector_result={'/'.join(collector_results) if collector_results else 'none'}")
    print(f"collector_posts={len(posts)}")
    print_collector_timing(posts)
    print_key_network_events(args.network_jsonl)
    prior_knp_hashes = []
    for p in posts:
        marker = ""
        if "PX561" in p["tags"]:
            marker = " <PX561>"
        elif "KnpQcG8ZVUI=" in p["tags"]:
            marker = " <KNP>"
        print(
            f"{p['ordinal']:02d} seq={p['seq']} qi={p['qi']} "
            f"pc={_short_bool(p['pc_ok'])} noise={_short_bool(p['noise_ok'])} "
            f"rt={_short_bool(p['roundtrip'])} tags={p['tags']}{marker}"
        )
        resp = p.get("response") or {}
        resp_bits = []
        if resp.get("scores"):
            resp_bits.append("scores=" + ",".join(resp["scores"]))
        if resp.get("results"):
            resp_bits.append("results=" + ",".join(resp["results"]))
        if resp.get("error"):
            resp_bits.append("resp_error=" + resp["error"])
        if resp_bits:
            print("    response " + " ".join(resp_bits))
        if p["px561"]:
            inv = p.get("final_invariants") or {}
            print(
                "    final_invariants "
                f"ok={inv.get('ok')} shape={inv.get('shape_ok')} "
                f"hu={inv.get('hu_ok')} qs={inv.get('qs_ok')} r3={inv.get('r3_ok')} "
                f"r3_ui={inv.get('r3_ui_delta')} r3_ui_ok={inv.get('r3_ui_ok')} "
                f"order={inv.get('order')}"
            )
            hu_seq = []
            qs_seq = []
            r3_seq = []
            for ev in p.get("events") or []:
                d = ev.get("d") if isinstance(ev, dict) else None
                if isinstance(d, dict):
                    if "HUlnQ1slanM=" in d:
                        hu_seq.append(f"{ev.get('t')}:{d.get('HUlnQ1slanM=')}")
                    if "QS07ZwRKPlU=" in d:
                        qs_seq.append(f"{ev.get('t')}:{d.get('QS07ZwRKPlU=')}")
                    if "R3c9PQEXNg8=" in d:
                        r3_seq.append(f"{ev.get('t')}:{d.get('R3c9PQEXNg8=')}")
            if hu_seq:
                print("    hu_seq " + " ".join(hu_seq))
            if qs_seq:
                print("    qs_seq " + " ".join(qs_seq))
            if r3_seq:
                print("    r3_seq " + " ".join(r3_seq))
            x = p["px561"]
            try:
                ui_wi = float(x.get("Ui5jKBREZxs=")) - float(x.get("WiZrIB9LbBU="))
            except Exception:
                ui_wi = None
            try:
                e_value = float(x.get("eEgJDj4mCD4="))
                e_ok = 1700 <= e_value <= 3400
            except Exception:
                e_ok = False
            event_types = [
                item.get("PX12343")
                for item in (x.get("DzN+dUlTekE=") or [])
                if isinstance(item, dict)
            ]
            event_counts = [
                int(item.get("PX11652", 0))
                for item in (x.get("DzN+dUlTekE=") or [])
                if isinstance(item, dict)
            ]
            print(
                "    px561 "
                f"e={x.get('eEgJDj4mCD4=')} wi={x.get('WiZrIB9LbBU=')} "
                f"z={x.get('ZjoXPCNQGQw=')} ui={x.get('Ui5jKBREZxs=')} "
                f"ui_wi={ui_wi} e_ok={e_ok} "
                f"click={'click' in event_types} dz_len={len(event_types)} "
                f"max11652={max(event_counts) if event_counts else None} "
                f"s3={x.get('S3sxMQ0YNQo=')} bzt={x.get('Bzt2fUFRcw==')} "
                f"hu={x.get('HUlnQ1slanM=')} r3={x.get('R3c9PQEXNg8=')}"
            )
        if p["knp"]:
            k = p["knp"]
            core = k.get("U0MpSRYgLHo=") or {}
            prior_match = None
            if "PX561" in p["tags"] and p.get("knp_core_hash"):
                for item in reversed(prior_knp_hashes):
                    if item.get("hash") == p.get("knp_core_hash"):
                        prior_match = item
                        break
            print(
                "    knp "
                f"hasEn={bool(core.get('en'))} mtr={core.get('mtr')} "
                f"hu={k.get('HUlnQ1slanM=')} r3={k.get('R3c9PQEXNg8=')} "
                f"uuid={k.get('FUFvS1Mga38=')} core_hash={p.get('knp_core_hash')}"
                + (
                    f" prior_match=ord{prior_match['ordinal']}/qi{prior_match['qi']}"
                    if prior_match
                    else ""
                )
            )
            if "PX561" not in p["tags"] and p.get("knp_core_hash"):
                prior_knp_hashes.append(
                    {
                        "ordinal": p["ordinal"],
                        "seq": p["seq"],
                        "qi": p["qi"],
                        "hash": p["knp_core_hash"],
                    }
                )

    if args.runtime:
        rt = summarize_runtime(args.runtime)
        print(f"\nruntime={args.runtime}")
        print("runtime_counts=" + json.dumps(rt.get("counts", {}), ensure_ascii=False, sort_keys=True))
        for ev in rt.get("interesting_tail", []):
            print("  " + json.dumps(ev, ensure_ascii=False)[:500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
