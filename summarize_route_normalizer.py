import argparse
import json
from collections import Counter
from pathlib import Path


def short_result(decoded):
    if not isinstance(decoded, dict):
        return ""
    parts = []
    for key in ("scores", "results"):
        vals = decoded.get(key) or []
        if vals:
            parts.extend(vals)
    return " ; ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Summarize route normalizer JSONL logs.")
    parser.add_argument("jsonl", type=Path)
    args = parser.parse_args()

    rows = []
    with args.jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            rows.append(json.loads(line))

    print(f"log={args.jsonl}")
    print(f"records={len(rows)}")
    tag_counter = Counter()
    for row in rows:
        tags = tuple((row.get("before") or {}).get("tags") or [])
        tag_counter[tags] += 1
    for tags, count in tag_counter.items():
        print(f"  {count}x tags={list(tags)}")

    for idx, row in enumerate(rows, 1):
        before = row.get("before") or {}
        after = row.get("after") or {}
        px_before = before.get("px561") or {}
        px_after = after.get("px561") or {}
        inv_after = after.get("final_invariants") or {}
        final_modes = []
        for change in row.get("changes") or []:
            if isinstance(change, dict) and isinstance(change.get("final_proof"), dict):
                mode = change["final_proof"].get("mode")
                if mode:
                    final_modes.append(mode)
        print(
            f"\n#{idx} qi={row.get('qi')} seq={row.get('seq')} "
            f"old/new={row.get('old_len')}/{row.get('new_len')} "
            f"pc={row.get('patched_pc_ok')} noise={row.get('patched_noise_ok')} rt={row.get('patched_roundtrip')}"
        )
        if final_modes:
            print(f"  final_proof_mode={','.join(final_modes)}")
        print(f"  tags_before={before.get('tags')}")
        print(f"  tags_after ={after.get('tags')}")
        if px_before or px_after:
            print(
                "  px561 "
                f"before e={px_before.get('e')} z={px_before.get('z')} dz={px_before.get('dz_len')} click={px_before.get('click')} "
                f"after e={px_after.get('e')} z={px_after.get('z')} dz={px_after.get('dz_len')} click={px_after.get('click')}"
            )
            print(f"  invariants_after={inv_after}")
        if row.get("response_status") is not None:
            print(f"  response_status={row.get('response_status')} response_len={row.get('response_len')}")
        resp = short_result(row.get("response_decoded"))
        if resp:
            print(f"  response={resp}")
        if row.get("route_fetch_error"):
            print(f"  route_fetch_error={row.get('route_fetch_error')}")


if __name__ == "__main__":
    main()
