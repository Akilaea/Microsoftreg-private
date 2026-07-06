import statistics
from pathlib import Path

from analyze_protocol_run import analyze_network
from decode_hs_payload import iter_collector_posts


NETWORK_DIR = Path("Results") / "network"


def num(d, key):
    v = d.get(key)
    if isinstance(v, list) and v:
        v = v[0]
    try:
        return float(v)
    except Exception:
        return None


def main() -> int:
    rows = []
    for trace in sorted(NETWORK_DIR.glob("*.jsonl")):
        try:
            _, results = analyze_network(trace)
        except Exception:
            continue
        if "0" not in results:
            continue
        for ordinal, (_idx, _event, form, meta) in enumerate(iter_collector_posts(trace), 1):
            events = meta["events"]
            tags = [ev.get("t") for ev in events if isinstance(ev, dict)]
            if "PX561" not in tags:
                continue
            px = next(ev["d"] for ev in events if ev.get("t") == "PX561")
            e = num(px, "eEgJDj4mCD4=")
            wi = num(px, "WiZrIB9LbBU=")
            ui = num(px, "Ui5jKBREZxs=")
            r3 = num(px, "R3c9PQEXNg8=")
            hu_seq = []
            qs_vals = []
            r3_vals = []
            for ev in events:
                d = ev.get("d") if isinstance(ev, dict) else None
                if isinstance(d, dict):
                    if "HUlnQ1slanM=" in d:
                        hu_seq.append((ev.get("t"), d.get("HUlnQ1slanM=")))
                    if "QS07ZwRKPlU=" in d:
                        qs_vals.append(d.get("QS07ZwRKPlU="))
                    if "R3c9PQEXNg8=" in d:
                        r3_vals.append((ev.get("t"), d.get("R3c9PQEXNg8=")))
            rows.append(
                {
                    "trace": trace.name,
                    "ordinal": ordinal,
                    "seq": form.get("seq"),
                    "tags": tags,
                    "duration": wi - e if wi is not None and e is not None else None,
                    "ui_wi": ui - wi if ui is not None and wi is not None else None,
                    "r3_ui": r3 - ui if r3 is not None and ui is not None else None,
                    "hu_seq": hu_seq,
                    "qs_unique": len(set(qs_vals)),
                    "r3_vals": r3_vals,
                }
            )

    print(f"successful_px_posts={len(rows)}")
    first_like = [r for r in rows if r["seq"] in {"2", "3"} and r["r3_ui"] is not None and r["r3_ui"] < 2500]
    print(f"first_like_success_posts={len(first_like)}")
    for label, key in (("duration", "duration"), ("ui_wi", "ui_wi"), ("r3_ui", "r3_ui")):
        vals = [r[key] for r in first_like if r[key] is not None]
        if vals:
            print(
                f"{label}: min={min(vals):.0f} median={statistics.median(vals):.0f} "
                f"max={max(vals):.0f} n={len(vals)}"
            )
    print("\nfirst_like_details:")
    for r in first_like:
        print(
            f"{r['trace']} seq={r['seq']} tags={r['tags']} "
            f"duration={r['duration']:.0f} ui_wi={r['ui_wi']:.0f} r3_ui={r['r3_ui']:.0f} "
            f"qs_unique={r['qs_unique']} hu_seq={r['hu_seq']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
