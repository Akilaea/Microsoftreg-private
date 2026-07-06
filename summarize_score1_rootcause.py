import argparse
import json
import re
from pathlib import Path

from analyze_protocol_run import decode_collector_response_map
from decode_hs_payload import iter_collector_posts


RISK_VERIFY = "api/v1.0/risk/verify"
RISK_INIT = "api/v1.0/risk/initialize"


def load_events(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                yield idx, json.loads(line)
            except Exception:
                continue


def jloads(text):
    try:
        return json.loads(text or "")
    except Exception:
        return None


def short(text, n=90):
    text = "" if text is None else str(text)
    return text if len(text) <= n else text[: n - 3] + "..."


def first_header(events, name):
    lname = name.lower()
    for _, ev in events:
        headers = ev.get("headers") or {}
        for k, v in headers.items():
            if str(k).lower() == lname:
                return v
    return ""


def chrome_major(ua):
    m = re.search(r"Chrome/(\d+)", ua or "")
    return m.group(1) if m else ""


def onecollector_risk_telemetry(events):
    rows = []
    for idx, ev in events:
        if ev.get("event") != "request":
            continue
        url = ev.get("url") or ""
        if "browser.events.data.microsoft.com/OneCollector" not in url:
            continue
        for line in str(ev.get("post_data") or "").splitlines():
            obj = jloads(line)
            if not isinstance(obj, dict):
                continue
            data = obj.get("data") or {}
            api = data.get("apiName") or ""
            metric = data.get("metricName") or ""
            action = data.get("actionName") or ""
            if RISK_VERIFY in api or metric.startswith("HumanCaptcha_") or action == "BeginNavigation":
                rows.append(
                    {
                        "idx": idx,
                        "name": obj.get("name"),
                        "api": api,
                        "responseCode": data.get("responseCode"),
                        "networkDuration": data.get("networkDuration"),
                        "metricName": metric,
                        "metricValue": data.get("metricValue"),
                        "actionName": action,
                        "actionValue": data.get("actionValue"),
                        "view": ((data.get("dimensions") or {}).get("view")),
                    }
                )
    return rows


def summarize_risk(events):
    rows = []
    pending_verify_reqs = []
    pending_init_reqs = []
    for idx, ev in events:
        url = ev.get("url") or ""
        if ev.get("method") != "POST":
            continue
        if RISK_INIT in url:
            if ev.get("event") == "request":
                pending_init_reqs.append((idx, ev, jloads(ev.get("post_data") or "")))
            elif ev.get("event") == "response":
                body = jloads(ev.get("body") or "")
                rows.append(("risk_initialize", idx, ev, body, None))
        if RISK_VERIFY in url:
            if ev.get("event") == "request":
                body = jloads(ev.get("post_data") or "") or {}
                sig = body.get("msaRiskVerifySignature") or {}
                meta = (body.get("riskProviderMetadata") or [{}])[0] if isinstance(body.get("riskProviderMetadata"), list) else {}
                pending_verify_reqs.append(
                    {
                        "idx": idx,
                        "memberName": sig.get("memberName"),
                        "countryCode": sig.get("countryCode"),
                        "birthdate": sig.get("birthdate"),
                        "firstName": sig.get("firstName"),
                        "lastName": sig.get("lastName"),
                        "action": sig.get("action"),
                        "deviceDetails": sig.get("deviceDetails"),
                        "has_px3": bool(meta.get("px3")),
                        "has_pxde": bool(meta.get("pxde")),
                        "pxvid": meta.get("pxvid"),
                    }
                )
            elif ev.get("event") == "response":
                body = jloads(ev.get("body") or "")
                req = pending_verify_reqs[-1] if pending_verify_reqs else None
                rows.append(("risk_verify", idx, ev, body, req))
    return rows


def summarize_collectors(path: Path, events):
    chctx_idx = None
    for idx, ev in events:
        url = ev.get("url") or ""
        target_url = ev.get("target_url") or ""
        if (
            ev.get("event") == "request"
            and "iframe.hsprotect.net/index.html" in url
            and "ch_ctx=1" in url
        ):
            chctx_idx = idx
            break
        if "iframe.hsprotect.net/index.html" in target_url and "ch_ctx=1" in target_url:
            chctx_idx = idx
            break
    responses = decode_collector_response_map(path)
    posts = []
    for ordinal, (idx, _event, form, meta) in enumerate(iter_collector_posts(path), 1):
        event_target = _event.get("target_url") or ""
        tags = [x.get("t") for x in meta.get("events") or [] if isinstance(x, dict)]
        resp = responses.get(idx) or {}
        phase = (
            "ch_ctx"
            if ("iframe.hsprotect.net/index.html" in event_target and "ch_ctx=1" in event_target)
            or (chctx_idx is not None and idx > chctx_idx)
            else "initial"
        )
        scores = resp.get("scores") or []
        results = resp.get("results") or []
        score = None
        for s in scores:
            m = re.search(r"score\|([01])", s)
            if m:
                score = m.group(1)
        posts.append(
            {
                "ordinal": ordinal,
                "idx": idx,
                "phase": phase,
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "qi": meta.get("qi"),
                "tags": tags,
                "score": score,
                "results": results,
            }
        )
    return posts


def y1nz_selected(path: Path):
    out = []
    for ordinal, (idx, _event, form, meta) in enumerate(iter_collector_posts(path), 1):
        for ev in meta.get("events") or []:
            if not isinstance(ev, dict) or ev.get("t") != "Y1NZWSUzXWs=":
                continue
            d = ev.get("d") or {}
            out.append(
                {
                    "ordinal": ordinal,
                    "idx": idx,
                    "seq": form.get("seq"),
                    "screen": d.get("RlZ8HAMweSk="),
                    "tz": d.get("GwthAV5raTA="),
                    "rtt": d.get("KxsREW58GCI="),
                    "downlink": d.get("LVkXU2s6EmI="),
                    "OSUD": d.get("OSUDb3xGBlk="),
                    "Pk5": d.get("Pk5EBHgvSTA="),
                    "U0Mpk": d.get("U0MpSRYkIX8="),
                    "outer_w_delta": d.get("AEw6BkUvPzI="),
                    "outer_h_delta": d.get("FmYsbFMFKVk="),
                }
            )
    return out


def summarize(path: Path):
    events = list(load_events(path))
    print(f"=== {path} ===")
    ua = first_header(events, "user-agent")
    print(f"ua_chrome={chrome_major(ua) or '-'} ua={short(ua, 140)}")
    print(f"accept_language={first_header(events, 'accept-language') or '-'} sec_ch_ua={short(first_header(events, 'sec-ch-ua'), 110)}")

    risk_rows = summarize_risk(events)
    if not risk_rows:
        print("risk_api: direct capture none")
    for kind, idx, ev, body, req in risk_rows:
        if kind == "risk_initialize":
            print(
                f"risk_initialize idx={idx} status={ev.get('status')} "
                f"state={(body or {}).get('state') if isinstance(body, dict) else '-'}"
            )
        else:
            err = (body or {}).get("error") if isinstance(body, dict) else {}
            inner = (err or {}).get("innerError") or {}
            state = (body or {}).get("state") if isinstance(body, dict) else None
            print(
                f"risk_verify idx={idx} status={ev.get('status')} state={state or '-'} "
                f"err={short((err or {}).get('code') or '')} inner={short(inner.get('code') or '')}"
            )
            if req:
                print(
                    "  req "
                    f"member={short(req.get('memberName'), 45)} country={req.get('countryCode')} "
                    f"birth={req.get('birthdate')} name={req.get('firstName')}/{req.get('lastName')} "
                    f"px3={req.get('has_px3')} pxde={req.get('has_pxde')} pxvid={req.get('pxvid')}"
                )
            if err:
                print(f"  message={short(err.get('message'), 180)}")

    telem = onecollector_risk_telemetry(events)
    for r in telem:
        if RISK_VERIFY in (r.get("api") or ""):
            print(
                f"telemetry_risk_verify idx={r['idx']} responseCode={r.get('responseCode')} "
                f"duration={r.get('networkDuration')} view={r.get('view')}"
            )
        elif str(r.get("metricName") or "").startswith("HumanCaptcha_"):
            print(
                f"telemetry_hcaptcha idx={r['idx']} metric={r.get('metricName')} "
                f"value={r.get('metricValue')} view={r.get('view')}"
            )

    posts = summarize_collectors(path, events)
    if not posts:
        print("collector: none")
    for p in posts:
        score = f" score={p['score']}" if p.get("score") is not None else ""
        results = f" results={','.join(p['results'])}" if p.get("results") else ""
        print(
            f"collector #{p['ordinal']} idx={p['idx']} phase={p['phase']} "
            f"seq={p['seq']} rsc={p['rsc']}{score}{results} tags={'+'.join(p['tags'])}"
        )
    for y in y1nz_selected(path)[-2:]:
        print(
            "y1nz "
            f"#{y['ordinal']} seq={y['seq']} screen={y['screen']} tz={y['tz']} "
            f"rtt={y['rtt']} downlink={y['downlink']} OSUD={y['OSUD']} "
            f"Pk5={y['Pk5']} U0Mpk={y['U0Mpk']} outerΔ={y['outer_w_delta']},{y['outer_h_delta']}"
        )

    # Compact verdict for the current root-cause hypothesis.
    direct_block = any(
        kind == "risk_verify"
        and int((ev.get("status") or 0)) in (401, 403)
        and isinstance(body, dict)
        and (((body.get("error") or {}).get("innerError") or {}).get("code") == "riskBlock")
        for kind, _idx, ev, body, _req in risk_rows
    )
    telemetry_200 = any(RISK_VERIFY in (r.get("api") or "") and int(r.get("responseCode") or 0) == 200 for r in telem)
    ch_score1 = any(p.get("phase") == "ch_ctx" and p.get("score") == "1" for p in posts)
    ch_score0 = any(p.get("phase") == "ch_ctx" and p.get("score") == "0" for p in posts)
    print(
        "verdict "
        f"direct_riskBlock={direct_block} telemetry_risk200={telemetry_200} "
        f"chctx_score0={ch_score0} chctx_score1={ch_score1}"
    )


def main():
    ap = argparse.ArgumentParser(description="Summarize evidence for hsprotect score|1 root-cause analysis.")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()
    for path in args.paths:
        summarize(path)


if __name__ == "__main__":
    main()
