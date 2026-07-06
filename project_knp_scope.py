import argparse
import json
from pathlib import Path

from decode_hs_payload import (
    decode_payload_meta_from_form,
    encode_payload_from_events,
    iter_collector_posts,
)


KNP_TAG = "KnpQcG8ZVUI="
ARV_TAG = "aRVTHy91Wio="
PX_TAG = "PX561"
JDBE_TAG = "JDBeOmJSWwo="
BFA_TAG = "BFA+GkExMiE="

COPY_KEYS = [
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
]

ENVELOPE_KEYS = [
    "QS07ZwRKPlU=",
    "FUFvS1Mga38=",
    "fg4ERDtuD3I=",
    "XGhmYhkIbVU=",
    "RTE/ewNXNUA=",
    "O2sBIX4NDBQ=",
    "AzN5eUVQckM=",
    "WQUjDxxjKjU=",
    "GUVjT1wnbn4=",
]


def tags(events):
    return [ev.get("t") for ev in events or [] if isinstance(ev, dict)]


def make_knp_from_core(core, base, qi):
    d = {}
    d["U0MpSRYgLHo="] = json.loads(json.dumps(core["U0MpSRYgLHo="], ensure_ascii=False))
    try:
        d["cR1LFzd8RSQ="] = int(qi)
    except Exception:
        d["cR1LFzd8RSQ="] = core.get("cR1LFzd8RSQ=")
    base_count = base.get("HUlnQ1slanM=")
    try:
        d["HUlnQ1slanM="] = int(base_count) + 1
    except Exception:
        d["HUlnQ1slanM="] = 3
    try:
        d["R3c9PQEXNg8="] = round(float(base.get("R3c9PQEXNg8=")) + 330)
    except Exception:
        pass
    for key in COPY_KEYS:
        if key in base:
            d[key] = json.loads(json.dumps(base[key], ensure_ascii=False))
    return {"t": KNP_TAG, "d": d}


def canonicalize_knp_placement(events, inserted_new_knp=False):
    knp_indices = [idx for idx, ev in enumerate(events) if ev.get("t") == KNP_TAG]
    if not knp_indices:
        return events
    rest = []
    seen_knp = False
    for ev in events:
        if ev.get("t") == KNP_TAG:
            if seen_knp:
                continue
            seen_knp = True
        rest.append(ev)

    knp_index = next(idx for idx, ev in enumerate(rest) if ev.get("t") == KNP_TAG)
    knp = rest[knp_index]
    first_proof = next((idx for idx, ev in enumerate(rest) if ev.get("t") in (PX_TAG, JDBE_TAG)), None)
    if first_proof is not None and knp_index > first_proof:
        knp = rest.pop(knp_index)
        if knp_index < first_proof:
            first_proof -= 1
        rest.insert(first_proof, knp)
        knp_index = first_proof
        knp = rest[knp_index]

    if inserted_new_knp:
        for ev in rest[knp_index + 1 :]:
            d = ev.get("d")
            if isinstance(d, dict):
                try:
                    d["HUlnQ1slanM="] = int(d["HUlnQ1slanM="]) + 1
                except Exception:
                    pass
    elif PX_TAG in tags(rest):
        try:
            knp_hu = int(knp.get("d", {}).get("HUlnQ1slanM="))
            px_ev = next(ev for ev in rest if ev.get("t") == PX_TAG and isinstance(ev.get("d"), dict))
            px_hu = int(px_ev["d"].get("HUlnQ1slanM="))
            if px_hu == knp_hu + 1:
                for ev in rest[knp_index + 1 :]:
                    d = ev.get("d")
                    if isinstance(d, dict) and "HUlnQ1slanM=" in d:
                        d["HUlnQ1slanM="] = int(d["HUlnQ1slanM="]) + 1
        except Exception:
            pass
    return rest


def normalize_final_envelope(events):
    current = tags(events)
    if ARV_TAG not in current or PX_TAG not in current:
        return events
    arv = next((ev.get("d") for ev in events if ev.get("t") == ARV_TAG and isinstance(ev.get("d"), dict)), None)
    px = next((ev.get("d") for ev in events if ev.get("t") == PX_TAG and isinstance(ev.get("d"), dict)), None)
    if not arv or not px:
        return events
    for ev in events:
        d = ev.get("d")
        if not isinstance(d, dict) or ev.get("t") not in (KNP_TAG, PX_TAG, JDBE_TAG, BFA_TAG):
            continue
        for key in ENVELOPE_KEYS:
            if key in arv and key in d:
                d[key] = json.loads(json.dumps(arv[key], ensure_ascii=False))
    if "R3c9PQEXNg8=" in px:
        for ev in events:
            d = ev.get("d")
            if ev.get("t") in (JDBE_TAG, BFA_TAG) and isinstance(d, dict):
                d["R3c9PQEXNg8="] = json.loads(json.dumps(px["R3c9PQEXNg8="], ensure_ascii=False))
    try:
        ui = float(px.get("Ui5jKBREZxs="))
        r3 = float(px.get("R3c9PQEXNg8="))
        if r3 - ui > 2500 or r3 - ui < 700:
            target = round(ui + 1375)
            px["R3c9PQEXNg8="] = target
            for ev in events:
                d = ev.get("d")
                if ev.get("t") in (JDBE_TAG, BFA_TAG) and isinstance(d, dict):
                    d["R3c9PQEXNg8="] = target
    except Exception:
        pass
    return events


def _stable_value(v):
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _int_field(d, key):
    try:
        return int(d.get(key))
    except Exception:
        return None


def _float_field(d, key):
    try:
        return float(d.get(key))
    except Exception:
        return None


def final_invariants(events):
    """Check the relative invariants observed in successful final proofs.

    Success traces are not tied to absolute HU values: both
    aRV,Knp,PX,JDBe and Knp,aRV,PX,JDBe appear, sometimes shifted by +1.
    This checker intentionally models the relative shape only.
    """
    current = tags(events)
    targets = (
        [ARV_TAG, KNP_TAG, PX_TAG, JDBE_TAG],
        [KNP_TAG, ARV_TAG, PX_TAG, JDBE_TAG],
        # 20260705 accepted accelerated ADS-like trace: BFA is an early/middle
        # proof between KNP and PX, not a tail proof after JDBe.
        [ARV_TAG, KNP_TAG, BFA_TAG, PX_TAG, JDBE_TAG],
        [KNP_TAG, ARV_TAG, BFA_TAG, PX_TAG, JDBE_TAG],
    )
    order = None
    shape_ok = False
    extras = []
    for target in targets:
        if current[: len(target)] == list(target):
            order = ",".join(target)
            extras = current[len(target) :]
            shape_ok = extras in ([], [BFA_TAG]) and not (BFA_TAG in target and extras)
            break
    if order is None:
        extras = current[4:] if len(current) > 4 else []

    by_tag = {}
    for ev in events or []:
        if isinstance(ev, dict) and isinstance(ev.get("d"), dict):
            by_tag.setdefault(ev.get("t"), ev.get("d"))

    relevant = [t for t in (ARV_TAG, KNP_TAG, PX_TAG, JDBE_TAG, BFA_TAG) if t in by_tag]
    qs_values = [_stable_value(by_tag[t].get("QS07ZwRKPlU=")) for t in relevant if "QS07ZwRKPlU=" in by_tag[t]]
    qs_ok = len(qs_values) == len(relevant) and len(set(qs_values)) == 1 if relevant else False

    r3_tags = [t for t in (PX_TAG, JDBE_TAG, BFA_TAG) if t in by_tag]
    r3_values = [_stable_value(by_tag[t].get("R3c9PQEXNg8=")) for t in r3_tags if "R3c9PQEXNg8=" in by_tag[t]]
    r3_ok = len(r3_values) == len(r3_tags) and len(set(r3_values)) == 1 if r3_tags else False

    hu = {t: _int_field(by_tag.get(t) or {}, "HUlnQ1slanM=") for t in relevant}
    a_hu, k_hu, px_hu, jd_hu, bfa_hu = (
        hu.get(ARV_TAG),
        hu.get(KNP_TAG),
        hu.get(PX_TAG),
        hu.get(JDBE_TAG),
        hu.get(BFA_TAG),
    )
    hu_ok = all(v is not None for v in (a_hu, k_hu, px_hu, jd_hu))
    if hu_ok:
        base_hu = max(a_hu, k_hu)
        early_bfa = bool(order and order.split(",")[:5] in ([ARV_TAG, KNP_TAG, BFA_TAG, PX_TAG, JDBE_TAG], [KNP_TAG, ARV_TAG, BFA_TAG, PX_TAG, JDBE_TAG]))
        if early_bfa:
            hu_ok = (
                bfa_hu is not None
                and abs(a_hu - k_hu) <= 2
                and bfa_hu == base_hu + 1
                and px_hu == bfa_hu + 2
                and jd_hu == px_hu + 1
            )
        else:
            hu_ok = (
                abs(a_hu - k_hu) <= 2
                and px_hu == base_hu + 2
                and jd_hu == px_hu + 1
                and (bfa_hu is None or bfa_hu == jd_hu + 1)
            )

    px = by_tag.get(PX_TAG) or {}
    ui = _float_field(px, "Ui5jKBREZxs=")
    r3 = _float_field(px, "R3c9PQEXNg8=")
    r3_ui_delta = None
    r3_ui_ok = False
    if ui is not None and r3 is not None:
        r3_ui_delta = r3 - ui
        r3_ui_ok = 900 <= r3_ui_delta <= 1800

    ok = bool(shape_ok and qs_ok and r3_ok and hu_ok and r3_ui_ok)
    return {
        "ok": ok,
        "order": order,
        "shape_ok": shape_ok,
        "extras": extras,
        "qs_ok": qs_ok,
        "r3_ok": r3_ok,
        "hu_ok": hu_ok,
        "hu": hu,
        "r3_ui_ok": r3_ui_ok,
        "r3_ui_delta": r3_ui_delta,
    }


def project_events_narrow_knp(events, qi=None, fallback_core=None):
    """Project the runtime's intended narrow Knp scope onto decoded events.

    Natural successful traces carry Knp only with the aRVTHy91Wio= envelope:
    first as [aRV, Knp], then finally as [aRV, Knp, PX561, JDBe...].
    Earlier probes also injected Knp into seq=1 Y1... and retry W0c/GC
    packets; those runs produced score|1.  This helper removes that over-
    injection and canonicalizes Knp placement for offline sanity checks.
    """
    events = json.loads(json.dumps(events, ensure_ascii=False))
    current = tags(events)
    if ARV_TAG not in current:
        non_knp = [t for t in current if t != KNP_TAG]
        if non_knp:
            return [ev for ev in events if ev.get("t") != KNP_TAG]
        return events

    inserted_new_knp = False
    if KNP_TAG not in tags(events) and fallback_core and fallback_core.get("U0MpSRYgLHo="):
        base = next((ev.get("d") for ev in events if ev.get("t") == ARV_TAG and isinstance(ev.get("d"), dict)), None)
        if base:
            events.append(make_knp_from_core(fallback_core, base, qi))
            inserted_new_knp = True

    events = canonicalize_knp_placement(events, inserted_new_knp=inserted_new_knp)
    return normalize_final_envelope(events)


def summarize_projection(trace_path: Path):
    rows = []
    last_knp = None
    last_knp_qi = None
    for ordinal, (idx, event, form, meta) in enumerate(iter_collector_posts(trace_path), 1):
        original = meta["events"]
        projected = project_events_narrow_knp(original, qi=meta.get("qi"), fallback_core=last_knp)
        old_tags = tags(original)
        new_tags = tags(projected)
        changed = old_tags != new_tags or json.dumps(original, ensure_ascii=False, separators=(",", ":")) != json.dumps(
            projected, ensure_ascii=False, separators=(",", ":")
        )
        pc_ok = meta.get("pc_ok")
        noise_ok = meta.get("noise_ok")
        roundtrip = meta.get("payload_roundtrip")
        payload_len = len(form.get("payload", ""))
        if changed:
            payload, _, pc = encode_payload_from_events(projected, form)
            form2 = dict(form)
            form2["payload"] = payload
            form2["pc"] = pc
            check = decode_payload_meta_from_form(form2)
            pc_ok = check["pc_ok"]
            noise_ok = check["noise_ok"]
            roundtrip = check["payload_roundtrip"]
            payload_len = len(payload)
        hu_seq = []
        qs_seq = []
        r3_seq = []
        for ev in projected:
            d = ev.get("d")
            if isinstance(d, dict):
                if "HUlnQ1slanM=" in d:
                    hu_seq.append(f"{ev.get('t')}:{d.get('HUlnQ1slanM=')}")
                if "QS07ZwRKPlU=" in d:
                    qs_seq.append(f"{ev.get('t')}:{d.get('QS07ZwRKPlU=')}")
                if "R3c9PQEXNg8=" in d:
                    r3_seq.append(f"{ev.get('t')}:{d.get('R3c9PQEXNg8=')}")
        rows.append(
            {
                "ordinal": ordinal,
                "idx": idx,
                "url": event.get("url"),
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "qi": meta.get("qi"),
                "old_tags": old_tags,
                "projected_tags": new_tags,
                "changed": changed,
                "payload_len": payload_len,
                "pc_ok": pc_ok,
                "noise_ok": noise_ok,
                "roundtrip": roundtrip,
                "fallback_source_qi": last_knp_qi if KNP_TAG in new_tags and KNP_TAG not in old_tags else None,
                "hu_seq": hu_seq,
                "qs_seq": qs_seq,
                "r3_seq": r3_seq,
                "final_invariants": final_invariants(projected) if PX_TAG in new_tags else None,
            }
        )
        for ev in projected:
            if ev.get("t") == KNP_TAG and isinstance(ev.get("d"), dict) and ev["d"].get("U0MpSRYgLHo="):
                last_knp = ev["d"]
                last_knp_qi = meta.get("qi")
                break
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline-project narrow Knp injection scope onto a hsprotect trace.")
    ap.add_argument("network_jsonl", type=Path)
    ap.add_argument("--dump-json", type=Path, default=None)
    args = ap.parse_args()

    rows = summarize_projection(args.network_jsonl)
    final_rows = [r for r in rows if PX_TAG in r["projected_tags"]]
    print(f"trace={args.network_jsonl}")
    print(f"posts={len(rows)} final_px={len(final_rows)}")
    all_ok = all(r["pc_ok"] and r["noise_ok"] and r["roundtrip"] for r in rows)
    print(f"codec_ok={all_ok}")
    for r in rows:
        marker = " <PX561>" if PX_TAG in r["projected_tags"] else (" <KNP>" if KNP_TAG in r["projected_tags"] else "")
        print(
            f"{r['ordinal']:02d} seq={r['seq']} qi={r['qi']} changed={r['changed']} "
            f"pc={r['pc_ok']} noise={r['noise_ok']} rt={r['roundtrip']} "
            f"old={r['old_tags']} projected={r['projected_tags']}{marker}"
            + (f" fallback_source_qi={r['fallback_source_qi']}" if r.get("fallback_source_qi") else "")
        )
    if final_rows:
        targets = ([ARV_TAG, KNP_TAG, PX_TAG, JDBE_TAG], [KNP_TAG, ARV_TAG, PX_TAG, JDBE_TAG])
        for r in final_rows:
            prefix_ok = any(r["projected_tags"][:4] == list(target) for target in targets)
            extras = r["projected_tags"][4:]
            print(f"final_shape seq={r['seq']} prefix_ok={prefix_ok} extras={extras}")
            inv = r.get("final_invariants") or {}
            print(
                "final_invariants "
                f"ok={inv.get('ok')} shape={inv.get('shape_ok')} "
                f"hu={inv.get('hu_ok')} qs={inv.get('qs_ok')} r3={inv.get('r3_ok')} "
                f"r3_ui={inv.get('r3_ui_delta')} r3_ui_ok={inv.get('r3_ui_ok')} "
                f"order={inv.get('order')}"
            )
            if r.get("hu_seq"):
                print("final_hu_seq " + " ".join(r["hu_seq"]))
            if r.get("qs_seq"):
                print("final_qs_seq " + " ".join(r["qs_seq"]))
            if r.get("r3_seq"):
                print("final_r3_seq " + " ".join(r["r3_seq"]))

    if args.dump_json:
        args.dump_json.parent.mkdir(parents=True, exist_ok=True)
        args.dump_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[wrote] {args.dump_json}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
