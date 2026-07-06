import argparse
import json
import re
from datetime import datetime
from pathlib import Path


TIMING_RE = re.compile(
    r"\[SemiProtocolFillTiming\]\s+(\w+)\s+\+(\d+)ms\s+total=(\d+)ms(?:\s+(.*))?"
)

PHASES = [
    "entry_ready",
    "email_ready",
    "email_submitted",
    "password_ready",
    "password_submitted",
    "dob_submitted",
    "names_ready",
    "name_submitted",
    "captcha_phase_done",
]


def parse_log(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    phases = {}
    for line in text.splitlines():
        match = TIMING_RE.search(line)
        if not match:
            continue
        phase, delta_ms, total_ms, suffix = match.groups()
        phases[phase] = {
            "delta_ms": int(delta_ms),
            "total_ms": int(total_ms),
            "suffix": suffix or "",
        }
    if not phases:
        return None
    row = {
        "file": str(path),
        "success": "[Success: Email Registration]" in text
        and "[Probe] outlook_register result=True" in text,
        "result_false": "[Probe] outlook_register result=False" in text,
        "riskblock": "riskblock" in text or "一些异常活动" in text,
        "rechallenge": text.count("fresh 5s hold") + max(0, text.count("time_warp_hold: locating hold button") - 1),
    }
    for phase in PHASES:
        if phase in phases:
            row[phase] = phases[phase]["total_ms"]
            if phases[phase]["suffix"]:
                row[f"{phase}_suffix"] = phases[phase]["suffix"]
    prev = None
    for phase in PHASES:
        if phase not in phases:
            continue
        if prev:
            row[f"{prev}->{phase}"] = phases[phase]["total_ms"] - phases[prev]["total_ms"]
        prev = phase
    return row


def stat(values):
    values = [int(v) for v in values if v is not None]
    if not values:
        return None
    values.sort()
    return {
        "n": len(values),
        "avg_ms": round(sum(values) / len(values), 1),
        "min_ms": values[0],
        "max_ms": values[-1],
        "p50_ms": values[len(values) // 2],
    }


def main():
    parser = argparse.ArgumentParser(description="Summarize semiprotocol fill timing from live_probe logs.")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Log files or directories. Defaults to Results/protocol_runtime.",
    )
    parser.add_argument("--limit", type=int, default=40, help="Newest log count when scanning directories.")
    parser.add_argument("--success-only", action="store_true", help="Only include successful registrations.")
    parser.add_argument("--json-out", default="", help="Optional JSON summary output path.")
    args = parser.parse_args()

    inputs = [Path(p) for p in args.paths] if args.paths else [Path("Results/protocol_runtime")]
    logs = []
    for item in inputs:
        if item.is_dir():
            logs.extend(item.glob("*_live_probe.log"))
        elif item.is_file():
            logs.append(item)
    logs = sorted(set(logs), key=lambda p: p.stat().st_mtime, reverse=True)[: max(1, args.limit)]
    rows = [parse_log(p) for p in logs]
    rows = [r for r in rows if r]
    if args.success_only:
        rows = [r for r in rows if r.get("success")]

    duration_keys = []
    for idx, phase in enumerate(PHASES):
        if idx == 0:
            duration_keys.append(phase)
        else:
            duration_keys.append(f"{PHASES[idx-1]}->{phase}")
    duration_keys.append("captcha_phase_done")

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "log_count": len(rows),
        "success_count": sum(1 for r in rows if r.get("success")),
        "stats": {
            key: stat([r.get(key) for r in rows])
            for key in duration_keys
            if any(r.get(key) is not None for r in rows)
        },
        "rows": rows,
    }

    print(f"logs={summary['log_count']} success={summary['success_count']}")
    for key, value in summary["stats"].items():
        print(
            f"{key:36s} n={value['n']:2d} "
            f"avg={value['avg_ms']:8.1f} min={value['min_ms']:6d} "
            f"p50={value['p50_ms']:6d} max={value['max_ms']:6d}"
        )
    print("\nlatest rows:")
    for row in rows[: min(12, len(rows))]:
        print(
            f"{Path(row['file']).name} ok={row.get('success')} "
            f"total={row.get('captcha_phase_done')} entry={row.get('entry_ready')} "
            f"pwd_dob={row.get('password_submitted->dob_submitted')} "
            f"name_submit={row.get('names_ready->name_submitted')} "
            f"captcha={row.get('name_submitted->captcha_phase_done')} "
            f"state={row.get('name_submitted_suffix', '')}"
        )

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\njson_out={out}")


if __name__ == "__main__":
    main()
