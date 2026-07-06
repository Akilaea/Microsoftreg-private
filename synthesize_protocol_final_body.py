import argparse
import json
import re
import sys
import urllib.parse
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from decode_hs_payload import (
    decode_payload_meta_from_form,
    encode_payload_from_events,
    iter_collector_posts,
    parse_form_preserve_payload,
)
from project_knp_scope import final_invariants

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


ROOT = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = ROOT / "Results" / "network" / "20260704_200613_vde2anwfdvoerk.jsonl"

FINAL_TAGS = {"aRVTHy91Wio=", "KnpQcG8ZVUI=", "PX561", "JDBeOmJSWwo=", "BFA+GkExMiE="}
COMMON_KEYS = [
    "VGBuahICYlE=",
    "QS07ZwRKPlU=",
    "FUFvS1Mga38=",
    "fg4ERDtuD3I=",
    "XGhmYhkIbVU=",
    "RTE/ewNXNUA=",
    "O2sBIX4NDBQ=",
    "AzN5eUVQckM=",
    "WQUjDxxjKjU=",
    "GUVjT1wnbn4=",
    "SlpwEAw5eSc=",
]


def set_form_field(body: str, key: str, value) -> str:
    # payload is intentionally kept raw: hsprotect's payload noise can include
    # '+' and '/' and parse_form_preserve_payload deliberately does not
    # URL-decode it.
    enc = str(value) if key == "payload" else urllib.parse.quote_plus(str(value))
    pattern = re.compile(r"(^|&)" + re.escape(key) + r"=[^&]*")
    if pattern.search(body):
        return pattern.sub(r"\1" + key + "=" + enc, body)
    sep = "" if body.endswith("&") or not body else "&"
    return body + sep + key + "=" + enc


def replace_payload_and_pc(body: str, form: dict, events: list) -> tuple[str, dict]:
    payload, json_text, pc = encode_payload_from_events(events, form)
    out = body
    out = set_form_field(out, "payload", payload)
    out = set_form_field(out, "pc", pc)
    check_form = parse_form_preserve_payload(out)
    check = decode_payload_meta_from_form(check_form)
    return out, {
        "pc": pc,
        "json_len": len(json_text),
        "payload_len": len(payload),
        "roundtrip": check.get("payload_roundtrip"),
        "pc_ok": check.get("pc_ok"),
        "noise_ok": check.get("noise_ok"),
        "tags": [ev.get("t") for ev in check.get("events") or [] if isinstance(ev, dict)],
    }


def collector_posts(path: Path):
    return list(iter_collector_posts(path))


def find_last_y1(path: Path):
    candidates = []
    for idx, event, form, meta in collector_posts(path):
        tags = [ev.get("t") for ev in meta.get("events") or [] if isinstance(ev, dict)]
        if "Y1NZWSUzXWs=" in tags and str(meta.get("qi") or "") != "1604064986000":
            candidates.append((idx, event, form, meta, tags))
    if not candidates:
        raise SystemExit(f"missing target Y1NZ collector post: {path}")
    return candidates[-1]


def find_template_final(path: Path):
    finals = []
    w0s = []
    u0s = []
    for idx, event, form, meta in collector_posts(path):
        events = meta.get("events") or []
        tags = [ev.get("t") for ev in events if isinstance(ev, dict)]
        item = (idx, event, form, meta, tags)
        if "PX561" in tags:
            finals.append(item)
        if "W0cqQR4rLnA=" in tags and "PX561" not in tags:
            w0s.append(item)
        if "U0MpSRYiJH8=" in tags:
            u0s.append(item)
    if not finals:
        raise SystemExit(f"missing template PX561 final: {path}")
    return finals[-1], (u0s[-1] if u0s else None), (w0s[-1] if w0s else None)


def first_event(events: list, tag: str):
    for ev in events or []:
        if isinstance(ev, dict) and ev.get("t") == tag and isinstance(ev.get("d"), dict):
            return ev
    return None


def extract_runtime_knp(runtime_path: Path, qi: str) -> dict | None:
    if not runtime_path or not runtime_path.exists():
        return None
    data = json.loads(runtime_path.read_text(encoding="utf-8"))
    for frame in data.get("frames") or []:
        probe = frame.get("probe") or {}
        knp_by_qi = probe.get("knpByQi") or {}
        if isinstance(knp_by_qi, dict) and qi in knp_by_qi and isinstance(knp_by_qi[qi], dict):
            return deepcopy(knp_by_qi[qi])
    for frame in data.get("frames") or []:
        probe = frame.get("probe") or {}
        last_qi = str(probe.get("lastKnpQi") or "")
        if last_qi == qi and isinstance(probe.get("lastKnpData"), dict):
            return deepcopy(probe.get("lastKnpData"))
    return None


def runtime_challenge_href(runtime_path: Path, qi: str) -> str:
    if not runtime_path or not runtime_path.exists():
        return ""
    try:
        data = json.loads(runtime_path.read_text(encoding="utf-8"))
        for frame in data.get("frames") or []:
            url = str(frame.get("url") or "")
            if "iframe.hsprotect.net/index.html" in url and "ch_ctx=1" in url:
                return url
        for frame in data.get("frames") or []:
            url = str(frame.get("url") or "")
            if "iframe.hsprotect.net/index.html" in url:
                return url
    except Exception:
        return ""
    return ""


def shift_epoch_like_values(events: list, template_qi: str, target_qi: str):
    try:
        delta = int(target_qi) - int(template_qi)
    except Exception:
        return
    # Only shift fields that are clearly epoch-like; R3/perf fields are relative and stay as template/normalizer values.
    for ev in events:
        d = ev.get("d") if isinstance(ev, dict) else None
        if not isinstance(d, dict):
            continue
        for key in ("QS07ZwRKPlU=", "cR1LFzd8RSQ="):
            if key in d:
                try:
                    d[key] = int(d[key]) + delta
                except Exception:
                    pass


def apply_current_common(events: list, target_form: dict, target_qi: str, target_knp: dict | None, challenge_href: str):
    # Replace UUID / qi / URL-like common fields with current run values.
    uuid = target_form.get("uuid") or ""
    for ev in events:
        d = ev.get("d") if isinstance(ev, dict) else None
        if not isinstance(d, dict):
            continue
        if "cR1LFzd8RSQ=" in d:
            try:
                d["cR1LFzd8RSQ="] = int(target_qi)
            except Exception:
                d["cR1LFzd8RSQ="] = target_qi
        if uuid and "FUFvS1Mga38=" in d:
            d["FUFvS1Mga38="] = uuid
        if challenge_href and "SlpwEAw5eSc=" in d:
            d["SlpwEAw5eSc="] = challenge_href

    # Replace KNP core with exact current sandbox result when available.
    if target_knp:
        knp_ev = first_event(events, "KnpQcG8ZVUI=")
        arv_ev = first_event(events, "aRVTHy91Wio=")
        if knp_ev:
            old = knp_ev.get("d") or {}
            new = deepcopy(target_knp)
            # Keep natural final-envelope counters/timing from template where useful, but exact encrypted core from current.
            for key in ("HUlnQ1slanM=", "R3c9PQEXNg8="):
                if key in old and key not in new:
                    new[key] = deepcopy(old[key])
            for key in COMMON_KEYS:
                if arv_ev and isinstance(arv_ev.get("d"), dict) and key in arv_ev["d"]:
                    new[key] = deepcopy(arv_ev["d"][key])
                elif key in old and key not in new:
                    new[key] = deepcopy(old[key])
            try:
                new["cR1LFzd8RSQ="] = int(target_qi)
            except Exception:
                new["cR1LFzd8RSQ="] = target_qi
            knp_ev["d"] = new

    # Make later events share aRV envelope fields, matching runtime normalizer behavior.
    arv_ev = first_event(events, "aRVTHy91Wio=")
    if arv_ev and isinstance(arv_ev.get("d"), dict):
        base = arv_ev["d"]
        for ev in events:
            d = ev.get("d") if isinstance(ev, dict) else None
            if not isinstance(d, dict) or ev.get("t") == "aRVTHy91Wio=":
                continue
            if ev.get("t") not in ("KnpQcG8ZVUI=", "PX561", "JDBeOmJSWwo=", "BFA+GkExMiE="):
                continue
            for key in COMMON_KEYS:
                if key in base and key in d:
                    d[key] = deepcopy(base[key])


def make_u0_from_final(final_events: list) -> dict | None:
    arv = first_event(final_events, "aRVTHy91Wio=")
    if not arv:
        return None
    base = arv.get("d") or {}
    out = {}
    try:
        out["HUlnQ1slanM="] = int(base.get("HUlnQ1slanM=", 2)) + 1
    except Exception:
        out["HUlnQ1slanM="] = 3
    try:
        out["R3c9PQEXNg8="] = round(float(base.get("R3c9PQEXNg8=", 2400)) + 460)
    except Exception:
        out["R3c9PQEXNg8="] = 2876
    try:
        out["QS07ZwRKPlU="] = round(float(base.get("QS07ZwRKPlU=")) - 9300)
    except Exception:
        pass
    for key in [
        "FUFvS1Mga38=",
        "fg4ERDtuD3I=",
        "XGhmYhkIbVU=",
        "RTE/ewNXNUA=",
        "O2sBIX4NDBQ=",
        "AzN5eUVQckM=",
        "WQUjDxxjKjU=",
        "GUVjT1wnbn4=",
        "SlpwEAw5eSc=",
    ]:
        if key in base:
            out[key] = deepcopy(base[key])
    return {"t": "U0MpSRYiJH8=", "d": out}


def summarize_body(body: str):
    form = parse_form_preserve_payload(body)
    meta = decode_payload_meta_from_form(form)
    return {
        "seq": form.get("seq"),
        "rsc": form.get("rsc"),
        "qi": meta.get("qi"),
        "pc_ok": meta.get("pc_ok"),
        "noise_ok": meta.get("noise_ok"),
        "roundtrip": meta.get("payload_roundtrip"),
        "tags": [ev.get("t") for ev in meta.get("events") or [] if isinstance(ev, dict)],
        "final_invariants": final_invariants(meta.get("events") or []) if any(ev.get("t") == "PX561" for ev in meta.get("events") or [] if isinstance(ev, dict)) else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline synthesize U0/final hsprotect collector bodies for the restarted 1s protocol route.")
    ap.add_argument("--target-network", required=True, type=Path)
    ap.add_argument("--target-runtime", type=Path, default=None)
    ap.add_argument("--template-network", type=Path, default=DEFAULT_TEMPLATE)
    ap.add_argument("--preserve-bfa", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()

    target_idx, target_event, target_form, target_meta, target_tags = find_last_y1(args.target_network)
    target_qi = str(target_meta.get("qi") or "")
    template_final, template_u0, template_w0 = find_template_final(args.template_network)
    t_idx, t_event, t_form, t_meta, t_tags = template_final
    template_qi = str(t_meta.get("qi") or "")

    target_knp = extract_runtime_knp(args.target_runtime, target_qi) if args.target_runtime else None
    challenge_href = runtime_challenge_href(args.target_runtime, target_qi) if args.target_runtime else ""

    final_events = [
        deepcopy(ev)
        for ev in (t_meta.get("events") or [])
        if isinstance(ev, dict)
        and ev.get("t") in FINAL_TAGS
        and (args.preserve_bfa or ev.get("t") != "BFA+GkExMiE=")
    ]
    shift_epoch_like_values(final_events, template_qi, target_qi)
    apply_current_common(final_events, target_form, target_qi, target_knp, challenge_href)

    u0_event = make_u0_from_final(final_events)
    if not u0_event:
        raise SystemExit("failed to synthesize U0")

    # Build bodies from the target Y1NZ form.  Current observed flow has Y1NZ at seq=1/rsc=2.
    target_body = target_event.get("post_data", "")
    u0_body, u0_enc = replace_payload_and_pc(target_body, target_form, [u0_event])
    u0_body = set_form_field(u0_body, "seq", 2)
    u0_body = set_form_field(u0_body, "rsc", 3)

    final_body, final_enc = replace_payload_and_pc(target_body, target_form, final_events)
    final_body = set_form_field(final_body, "seq", 3)
    final_body = set_form_field(final_body, "rsc", 4)

    # Recompute pc after seq/rsc changes are not needed because pc signs JSON only, but re-summarize final body.
    u0_summary = summarize_body(u0_body)
    final_summary = summarize_body(final_body)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out_dir or (ROOT / "Results" / "protocol_runtime" / f"synthetic_final_{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "synthetic_u0.body.txt").write_text(u0_body, encoding="utf-8")
    (out_dir / "synthetic_final.body.txt").write_text(final_body, encoding="utf-8")
    manifest = {
        "created_at": datetime.now().isoformat(),
        "target_network": str(args.target_network),
        "target_runtime": str(args.target_runtime) if args.target_runtime else None,
        "template_network": str(args.template_network),
        "target_y1": {"idx": target_idx, "url": target_event.get("url"), "qi": target_qi, "seq": target_form.get("seq"), "rsc": target_form.get("rsc"), "tags": target_tags},
        "template_final": {"idx": t_idx, "qi": template_qi, "seq": t_form.get("seq"), "rsc": t_form.get("rsc"), "tags": t_tags},
        "has_runtime_knp": bool(target_knp),
        "challenge_href": challenge_href,
        "preserve_bfa": bool(args.preserve_bfa),
        "u0_encode": u0_enc,
        "final_encode": final_enc,
        "u0_summary": u0_summary,
        "final_summary": final_summary,
        "files": {
            "u0_body": str(out_dir / "synthetic_u0.body.txt"),
            "final_body": str(out_dir / "synthetic_final.body.txt"),
        },
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"target qi={target_qi} y1 seq={target_form.get('seq')} rsc={target_form.get('rsc')} idx={target_idx}")
    print(f"template qi={template_qi} final seq={t_form.get('seq')} rsc={t_form.get('rsc')} idx={t_idx}")
    print(f"runtime_knp={bool(target_knp)} preserve_bfa={args.preserve_bfa}")
    print("u0=" + json.dumps(u0_summary, ensure_ascii=False))
    print("final=" + json.dumps(final_summary, ensure_ascii=False)[:1400])
    print(f"out={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
