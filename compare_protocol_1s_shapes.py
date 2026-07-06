import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from analyze_protocol_run import analyze_network

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


ROOT = Path(__file__).resolve().parent
DEFAULT_OLD_SUCCESS = Path(
    r"C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-main\Results\network\20260620_223515_fznzlfjgdsorzt.jsonl"
)
DEFAULT_UNDER5_SUMMARY = ROOT / "Results" / "protocol_runtime" / "under5_stability_continue_20260704_200610.json"


def _num(v):
    try:
        return float(v)
    except Exception:
        return None


def _first_list_num(v):
    if isinstance(v, list) and v:
        return _num(v[0])
    return _num(v)


def _px561_summary(d):
    if not isinstance(d, dict):
        return {}
    dz = d.get("DzN+dUlTekE=") or []
    if not isinstance(dz, list):
        dz = []
    event_types = [x.get("PX12343") for x in dz if isinstance(x, dict)]
    counts = []
    for x in dz:
        if not isinstance(x, dict):
            continue
        try:
            counts.append(int(x.get("PX11652", 0)))
        except Exception:
            pass
    e = _num(d.get("eEgJDj4mCD4="))
    z0 = _first_list_num(d.get("ZjoXPCNQGQw="))
    wi = _num(d.get("WiZrIB9LbBU="))
    ui = _num(d.get("Ui5jKBREZxs="))
    r3 = _num(d.get("R3c9PQEXNg8="))
    return {
        "e": e,
        "z0": z0,
        "wi": wi,
        "ui": ui,
        "r3": r3,
        "ui_wi": round(ui - wi, 1) if ui is not None and wi is not None else None,
        "r3_ui": round(r3 - ui, 1) if r3 is not None and ui is not None else None,
        "bzt": _num(d.get("Bzt2fUFRcw==")),
        "s3": _num(d.get("S3sxMQ0YNQo=")),
        "xq": _num(d.get("XQUsAxhpKjU=")),
        "hu": _num(d.get("HUlnQ1slanM=")),
        "r3_field": d.get("R3c9PQEXNg8="),
        "dz_len": len(dz),
        "click": "click" in event_types,
        "max11652": max(counts) if counts else None,
        "has_bfa": False,
    }


def _event_ts_ms(p):
    v = p.get("ts_ms")
    return v if isinstance(v, (int, float)) else None


def _delta_ms(a, b):
    ta = _event_ts_ms(a or {})
    tb = _event_ts_ms(b or {})
    if ta is None or tb is None:
        return None
    return round(tb - ta, 1)


def _network_host_status(path: Path):
    out = {
        "create_statuses": [],
        "create_200": False,
        "captcha_close_minus1": False,
        "human_success": False,
        "riskblock": False,
        "interesting_tail": [],
    }
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                url = str(ev.get("url") or "")
                text = " ".join(
                    str(x or "")
                    for x in (url, ev.get("post_data", ""), ev.get("body", ""), ev.get("status", ""))
                )
                labels = []
                if "CreateAccount" in text:
                    labels.append("CreateAccount")
                    if ev.get("event") == "response":
                        out["create_statuses"].append(ev.get("status"))
                        if ev.get("status") == 200:
                            out["create_200"] = True
                if "captcha_close?status=-1" in text:
                    out["captcha_close_minus1"] = True
                    labels.append("captcha_close_-1")
                if "HumanCaptcha_Success" in text:
                    out["human_success"] = True
                    labels.append("HumanCaptcha_Success")
                if re.search(r"RiskBlock|Abuse|unusual activity|异常活动", text, re.I):
                    out["riskblock"] = True
                    labels.append("riskblock")
                if labels:
                    out["interesting_tail"].append(
                        {
                            "idx": idx,
                            "event": ev.get("event"),
                            "method": ev.get("method"),
                            "status": ev.get("status"),
                            "labels": list(dict.fromkeys(labels)),
                            "url": url[:180],
                        }
                    )
    except FileNotFoundError:
        out["missing"] = True
    out["interesting_tail"] = out["interesting_tail"][-12:]
    return out


def summarize_one(path: Path, label: str | None = None):
    posts, collector_results = analyze_network(path)
    host = _network_host_status(path)
    final_posts = [p for p in posts if "PX561" in (p.get("tags") or [])]
    final = final_posts[-1] if final_posts else None
    qi = str((final or {}).get("qi") or "")
    same_qi = [p for p in posts if str(p.get("qi") or "") == qi] if qi else posts
    u0 = next((p for p in same_qi if "U0MpSRYiJH8=" in (p.get("tags") or [])), None)
    w0 = next(
        (
            p
            for p in same_qi
            if "W0cqQR4rLnA=" in (p.get("tags") or []) and "PX561" not in (p.get("tags") or [])
        ),
        None,
    )
    knp = None
    if final:
        for ev in final.get("events") or []:
            if isinstance(ev, dict) and ev.get("t") == "KnpQcG8ZVUI=":
                knp = ev.get("d") or {}
                break
    px = (final or {}).get("px561") or {}
    pxs = _px561_summary(px)
    if final:
        pxs["has_bfa"] = "BFA+GkExMiE=" in (final.get("tags") or [])
    resp = (final or {}).get("response") or {}
    return {
        "label": label or path.stem,
        "network": str(path),
        "exists": path.exists(),
        "collector_posts": len(posts),
        "collector_results": collector_results,
        "create_statuses": host.get("create_statuses"),
        "create_200": host.get("create_200"),
        "human_success": host.get("human_success"),
        "captcha_close_minus1": host.get("captcha_close_minus1"),
        "riskblock": host.get("riskblock"),
        "qi": qi or None,
        "u0_seq": u0 and u0.get("seq"),
        "final_seq": final and final.get("seq"),
        "w0_seq": w0 and w0.get("seq"),
        "u0_ord": u0 and u0.get("ordinal"),
        "final_ord": final and final.get("ordinal"),
        "w0_ord": w0 and w0.get("ordinal"),
        "u0_to_final_ms": _delta_ms(u0, final),
        "final_to_w0_ms": _delta_ms(final, w0),
        "w0_to_final_ms": _delta_ms(w0, final),
        "final_tags": final and final.get("tags"),
        "final_response_scores": resp.get("scores") or [],
        "final_response_results": resp.get("results") or [],
        "final_invariants": (final or {}).get("final_invariants"),
        "knp": {
            "present": bool(knp),
            "has_en": bool(((knp or {}).get("U0MpSRYgLHo=") or {}).get("en")),
            "mtr": ((knp or {}).get("U0MpSRYgLHo=") or {}).get("mtr"),
            "hu": (knp or {}).get("HUlnQ1slanM="),
            "r3": (knp or {}).get("R3c9PQEXNg8="),
        },
        "px561": pxs,
        "host_tail": host.get("interesting_tail"),
    }


def paths_from_batch_summary(path: Path) -> list[tuple[str, Path]]:
    if not path or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for item in data.get("results") or []:
        net = item.get("network")
        if not net:
            continue
        label = f"batch#{item.get('idx')} {item.get('verdict') or ''} {item.get('node') or ''}".strip()
        out.append((label, Path(net)))
    return out


def print_table(rows):
    print("label | create | result | seq u0/final/w0 | Δu0-final | Δfinal-w0 | tags | px e/z/ui/r3/dz/click/bfa")
    print("-" * 150)
    for r in rows:
        px = r.get("px561") or {}
        result = ",".join(r.get("final_response_results") or r.get("collector_results") or []) or "-"
        create = "200" if r.get("create_200") else (",".join(str(x) for x in r.get("create_statuses") or []) or "-")
        tags = ",".join(r.get("final_tags") or []) or "-"
        print(
            f"{r.get('label')} | {create} | {result} | "
            f"{r.get('u0_seq')}/{r.get('final_seq')}/{r.get('w0_seq')} | "
            f"{r.get('u0_to_final_ms')} | {r.get('final_to_w0_ms')} | "
            f"{tags} | "
            f"e={px.get('e')} z={px.get('z0')} ui={px.get('ui')} r3={px.get('r3')} "
            f"dz={px.get('dz_len')} click={px.get('click')} bfa={px.get('has_bfa')}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a compact baseline diff for the restarted 1s protocol route.")
    ap.add_argument("network", nargs="*", type=Path, help="Network jsonl files to summarize.")
    ap.add_argument("--batch-summary", action="append", type=Path, default=[], help="Batch summary JSON containing result.network paths.")
    ap.add_argument("--include-default-baselines", action="store_true", help="Include the known old 1s success and current under5 summary samples.")
    ap.add_argument("--out", type=Path, default=None, help="Output JSON path. Defaults to Results/protocol_runtime/protocol_1s_restart_baseline_<ts>.json")
    args = ap.parse_args()

    labeled: list[tuple[str, Path]] = []
    if args.include_default_baselines or (not args.network and not args.batch_summary):
        if DEFAULT_OLD_SUCCESS.exists():
            labeled.append(("old_1s_success_20260620", DEFAULT_OLD_SUCCESS))
        labeled.extend(paths_from_batch_summary(DEFAULT_UNDER5_SUMMARY)[:6])

    for item in args.batch_summary:
        labeled.extend(paths_from_batch_summary(item))

    for p in args.network:
        labeled.append((p.stem, p))

    seen = set()
    rows = []
    for label, path in labeled:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if not path.exists():
            rows.append({"label": label, "network": str(path), "exists": False})
            continue
        rows.append(summarize_one(path, label=label))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = args.out or (ROOT / "Results" / "protocol_runtime" / f"protocol_1s_restart_baseline_{stamp}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now().isoformat(),
        "rows": rows,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print_table(rows)
    print(f"\nwritten={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
