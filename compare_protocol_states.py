import argparse
import json
from collections import Counter
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collector_signature(state):
    return [
        {
            "phase": c.get("phase"),
            "seq": c.get("seq"),
            "rsc": c.get("rsc"),
            "score": c.get("score"),
            "tags": c.get("tags") or [],
            "results": c.get("results") or [],
        }
        for c in state.get("collectors") or []
    ]


def risk_signature(state):
    return [
        {
            "kind": r.get("kind"),
            "status": r.get("status"),
            "state": r.get("state"),
            "error_code": r.get("error_code"),
            "inner_error_code": r.get("inner_error_code"),
            "has_px3": (r.get("request") or {}).get("has_px3"),
            "has_pxde": (r.get("request") or {}).get("has_pxde"),
            "countryCode": (r.get("request") or {}).get("countryCode"),
        }
        for r in state.get("risk") or []
    ]


def telemetry_signature(state):
    return [
        {
            "kind": t.get("kind"),
            "metricName": t.get("metricName"),
            "metricValue": t.get("metricValue"),
            "responseCode": t.get("responseCode"),
            "view": t.get("view"),
        }
        for t in state.get("telemetry") or []
    ]


def seq_counts(items, key):
    return Counter(str(x.get(key)) for x in items if x.get(key) not in (None, ""))


def compact(path: Path, state):
    collectors = collector_signature(state)
    risk = risk_signature(state)
    telemetry = telemetry_signature(state)
    return {
        "path": str(path),
        "source": state.get("source"),
        "class": (state.get("verdict") or {}).get("final_class"),
        "verdict": state.get("verdict") or {},
        "fingerprint": state.get("fingerprint") or {},
        "risk_states": [r.get("state") or r.get("inner_error_code") or r.get("error_code") for r in risk],
        "collector_scores": [c.get("score") for c in collectors],
        "collector_phases": seq_counts(collectors, "phase"),
        "collector_tag_counts": [len(c.get("tags") or []) for c in collectors],
        "hcaptcha_metrics": [t.get("metricName") for t in telemetry if t.get("kind") == "telemetry_hcaptcha"],
    }


def print_matrix(rows):
    print("path\tclass\trisk_states\tcollector_scores\thcaptcha")
    for row in rows:
        print(
            f"{row['path']}\t{row['class']}\t"
            f"{','.join(str(x) for x in row['risk_states'] if x)}\t"
            f"{','.join(str(x) for x in row['collector_scores'])}\t"
            f"{','.join(str(x) for x in row['hcaptcha_metrics'] if x)}"
        )


def print_pairwise(rows):
    if len(rows) < 2:
        return
    base = rows[0]
    print("\nbase=", base["path"])
    for row in rows[1:]:
        print("\ncompare=", row["path"])
        for key in ["class", "risk_states", "collector_scores", "hcaptcha_metrics"]:
            if base.get(key) != row.get(key):
                print(f"- {key}:")
                print(f"  base={base.get(key)}")
                print(f"  curr={row.get(key)}")
        bfp = base.get("fingerprint") or {}
        cfp = row.get("fingerprint") or {}
        for key in ["ua_chrome", "accept_language", "sec_ch_ua"]:
            if bfp.get(key) != cfp.get(key):
                print(f"- fingerprint.{key}:")
                print(f"  base={bfp.get(key)}")
                print(f"  curr={cfp.get(key)}")
        by1 = bfp.get("y1nz_latest") or {}
        cy1 = cfp.get("y1nz_latest") or {}
        for key in ["screen", "tz", "rtt", "downlink", "OSUD", "Pk5", "U0Mpk", "outer_w_delta", "outer_h_delta"]:
            if by1.get(key) != cy1.get(key):
                print(f"- y1nz.{key}: base={by1.get(key)} curr={cy1.get(key)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare machine-readable protocol states.")
    ap.add_argument("states", nargs="+", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = [compact(path, load(path)) for path in args.states]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print_matrix(rows)
        print_pairwise(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
