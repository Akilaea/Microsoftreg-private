import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from analyze_protocol_run import analyze_network
from compare_protocol_1s_shapes import _network_host_status


def _sha(v: Any) -> str:
    raw = json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def _compact(v: Any) -> Any:
    """Keep field diffs useful without dumping full encrypted/session blobs."""
    if isinstance(v, dict):
        return {
            "type": "dict",
            "len": len(v),
            "keys": list(v.keys())[:12],
            "sha12": _sha(v),
        }
    if isinstance(v, list):
        item = {
            "type": "list",
            "len": len(v),
            "sha12": _sha(v),
        }
        if v and all(isinstance(x, (int, float, str, bool, type(None))) for x in v[:5]):
            item["head"] = v[:5]
        elif v and isinstance(v[0], dict):
            item["head_keys"] = list(v[0].keys())[:10]
            # For pointer streams, preserve just the timeline/type shape.
            shaped = []
            for x in v[:16]:
                if not isinstance(x, dict):
                    continue
                shaped.append(
                    {
                        "type": x.get("PX12343"),
                        "cnt": x.get("PX11652"),
                        "t": x.get("PX11699"),
                        "pt": x.get("PX12301"),
                    }
                )
            item["shape_head"] = shaped
        return item
    if isinstance(v, str):
        if len(v) > 120:
            return {"type": "str", "len": len(v), "sha12": _sha(v), "prefix": v[:80]}
        return v
    return v


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except Exception:
        return None


def _first_list_num(v: Any) -> float | None:
    if isinstance(v, list) and v:
        return _num(v[0])
    return _num(v)


def _dz_summary(dz: Any) -> dict:
    if not isinstance(dz, list):
        return {"len": 0}
    rows = [x for x in dz if isinstance(x, dict)]
    cnts = []
    ts = []
    types = []
    for x in rows:
        types.append(x.get("PX12343"))
        try:
            cnts.append(int(x.get("PX11652", 0)))
        except Exception:
            pass
        try:
            ts.append(float(x.get("PX11699")))
        except Exception:
            pass
    return {
        "len": len(rows),
        "types": types[:40],
        "max_cnt": max(cnts) if cnts else None,
        "t_min": min(ts) if ts else None,
        "t_max": max(ts) if ts else None,
        "shape_head": [
            {
                "type": x.get("PX12343"),
                "cnt": x.get("PX11652"),
                "t": x.get("PX11699"),
                "pt": x.get("PX12301"),
            }
            for x in rows[:16]
        ],
    }


def _event_map(events: list[dict]) -> dict[str, dict]:
    out = {}
    for ev in events or []:
        if isinstance(ev, dict) and isinstance(ev.get("d"), dict):
            out[str(ev.get("t"))] = ev["d"]
    return out


def _pick_final(path: Path, ordinal: int | None = None, seq: str | None = None) -> dict:
    posts, _ = analyze_network(path)
    finals = [p for p in posts if "PX561" in (p.get("tags") or [])]
    if not finals:
        raise SystemExit(f"no PX561 final in {path}")
    if ordinal is not None:
        for p in finals:
            if int(p.get("ordinal") or -1) == int(ordinal):
                return p
        raise SystemExit(f"no PX561 final ordinal={ordinal} in {path}")
    if seq is not None:
        for p in finals:
            if str(p.get("seq")) == str(seq):
                return p
        raise SystemExit(f"no PX561 final seq={seq} in {path}")
    return finals[-1]


def _apply_normalizer(events: list[dict], mode: str, preserve_bfa: bool) -> tuple[list[dict], dict]:
    mode = (mode or "off").strip().lower()
    if mode in ("", "off", "none", "false", "0"):
        return events, {"mode": "off", "changed": False}
    # Import lazily so the script can still summarize traces if probe deps change.
    from protocol_runtime_probe import _normalize_final_proof_events

    changed, info = _normalize_final_proof_events(events, mode=mode, preserve_bfa=preserve_bfa)
    return events, {"mode": mode, "changed": bool(changed), "info": info}


def _summary(path: Path, label: str, normalizer: str, preserve_bfa: bool, ordinal: int | None, seq: str | None) -> dict:
    final = _pick_final(path, ordinal=ordinal, seq=seq)
    events = copy.deepcopy(final.get("events") or [])
    events, norm = _apply_normalizer(events, normalizer, preserve_bfa)
    evm = _event_map(events)
    px = evm.get("PX561") or {}
    bfa = evm.get("BFA+GkExMiE=") or {}
    host = _network_host_status(path)
    resp = final.get("response") or {}
    return {
        "label": label,
        "path": str(path),
        "host": {
            "create_200": host.get("create_200"),
            "create_statuses": host.get("create_statuses"),
            "human_success": host.get("human_success"),
            "riskblock": host.get("riskblock"),
        },
        "post": {
            "ordinal": final.get("ordinal"),
            "seq": final.get("seq"),
            "rsc": final.get("rsc"),
            "qi": final.get("qi"),
            "tags": [ev.get("t") for ev in events if isinstance(ev, dict)],
            "response_scores": resp.get("scores") or [],
            "response_results": resp.get("results") or [],
        },
        "normalizer": norm,
        "quick": {
            "e": _num(px.get("eEgJDj4mCD4=")),
            "z0": _first_list_num(px.get("ZjoXPCNQGQw=")),
            "wi": _num(px.get("WiZrIB9LbBU=")),
            "ui": _num(px.get("Ui5jKBREZxs=")),
            "r3": _num(px.get("R3c9PQEXNg8=")),
            "r3_ui": (
                _num(px.get("R3c9PQEXNg8=")) - _num(px.get("Ui5jKBREZxs="))
                if _num(px.get("R3c9PQEXNg8=")) is not None and _num(px.get("Ui5jKBREZxs=")) is not None
                else None
            ),
            "xghm": _num(px.get("XGhmYhkIbVU=")),
            "dz": _dz_summary(px.get("DzN+dUlTekE=")),
            "gu_len": len(px.get("GUloT18mZ3U=") or []) if isinstance(px.get("GUloT18mZ3U="), list) else None,
            "jnp_len": len(px.get("JnpXfGMUUUc=") or []) if isinstance(px.get("JnpXfGMUUUc="), list) else None,
            "bfa_cx_len": len(bfa.get("CXVzP0wQeg0=") or []) if isinstance(bfa.get("CXVzP0wQeg0="), list) else None,
            "bfa_dea_len": len(bfa.get("dEAOCjIjCjA=") or []) if isinstance(bfa.get("dEAOCjIjCjA="), list) else None,
            "bfa_ef_keys": list((bfa.get("EFwqFlU4ISQ=") or {}).keys()) if isinstance(bfa.get("EFwqFlU4ISQ="), dict) else None,
        },
        "events": events,
    }


def _field_diff(a: dict, b: dict) -> dict:
    out = {}
    ae = _event_map(a.get("events") or [])
    be = _event_map(b.get("events") or [])
    for tag in sorted(set(ae) | set(be)):
        ad = ae.get(tag) or {}
        bd = be.get(tag) or {}
        keys = sorted(set(ad) | set(bd))
        diff = []
        same = 0
        for k in keys:
            if ad.get(k) == bd.get(k):
                same += 1
                continue
            diff.append({"key": k, "a": _compact(ad.get(k)), "b": _compact(bd.get(k))})
        out[tag] = {"keys": len(keys), "same": same, "diff_count": len(diff), "diff": diff}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Field-level diff for hsprotect PX561 final proof packets.")
    ap.add_argument("--success", required=True, type=Path, help="Accepted/success network jsonl.")
    ap.add_argument("--candidate", required=True, type=Path, help="Candidate/failure network jsonl.")
    ap.add_argument("--success-label", default="success")
    ap.add_argument("--candidate-label", default="candidate")
    ap.add_argument("--success-normalizer", default="off")
    ap.add_argument("--candidate-normalizer", default="off")
    ap.add_argument("--preserve-bfa", action="store_true", default=True)
    ap.add_argument("--success-ordinal", type=int)
    ap.add_argument("--candidate-ordinal", type=int)
    ap.add_argument("--success-seq")
    ap.add_argument("--candidate-seq")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    a = _summary(
        args.success,
        args.success_label,
        args.success_normalizer,
        args.preserve_bfa,
        args.success_ordinal,
        args.success_seq,
    )
    b = _summary(
        args.candidate,
        args.candidate_label,
        args.candidate_normalizer,
        args.preserve_bfa,
        args.candidate_ordinal,
        args.candidate_seq,
    )
    payload = {
        "success": {k: v for k, v in a.items() if k != "events"},
        "candidate": {k: v for k, v in b.items() if k != "events"},
        "field_diff": _field_diff(a, b),
    }
    out = args.out or Path("Results/protocol_runtime/final_field_diff.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"success {args.success_label}: {a['post']} quick={a['quick']}")
    print(f"candidate {args.candidate_label}: {b['post']} quick={b['quick']}")
    print("top diff counts:")
    for tag, item in payload["field_diff"].items():
        print(f"  {tag}: same={item['same']} diff={item['diff_count']} keys={item['keys']}")
    print(f"written={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
