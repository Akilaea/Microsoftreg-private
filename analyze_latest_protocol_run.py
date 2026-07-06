import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NETWORK_DIR = ROOT / "Results" / "network"
RUNTIME_DIR = ROOT / "Results" / "protocol_runtime"


def latest_file(pattern: str, directory: Path) -> Path | None:
    files = [p for p in directory.glob(pattern) if p.is_file()]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def infer_email_from_network(path: Path) -> str:
    # Expected: 20260620_153833_nakhibhrmfii.jsonl
    parts = path.stem.split("_", 2)
    return parts[2] if len(parts) >= 3 else path.stem


def find_runtime_for_network(network: Path) -> Path | None:
    email = infer_email_from_network(network)
    candidates = list(RUNTIME_DIR.glob(f"*_{email}_*_final.json"))
    if not candidates:
        candidates = list(RUNTIME_DIR.glob(f"*{email}*final.json"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode and analyze the latest hsprotect protocol run.")
    ap.add_argument("--network", type=Path, default=None, help="Network JSONL. Defaults to latest Results/network/*.jsonl")
    ap.add_argument("--runtime", type=Path, default=None, help="Runtime final JSON. Defaults to matching latest final JSON")
    ap.add_argument("--no-decode-dump", action="store_true", help="Skip writing decoded_<network>.json")
    args = ap.parse_args()

    network = args.network or latest_file("*.jsonl", NETWORK_DIR)
    if not network or not network.exists():
        raise SystemExit(f"network trace not found under {NETWORK_DIR}")
    runtime = args.runtime or find_runtime_for_network(network)

    print(f"[network] {network}", flush=True)
    if runtime:
        print(f"[runtime] {runtime}", flush=True)
    else:
        print("[runtime] not found; analysis will omit runtime events", flush=True)

    if not args.no_decode_dump:
        decoded = RUNTIME_DIR / f"decoded_{network.stem}.json"
        subprocess.run(
            [sys.executable, str(ROOT / "decode_hs_payload.py"), str(network), "--dump-json", str(decoded)],
            cwd=ROOT,
            check=True,
        )

    cmd = [sys.executable, str(ROOT / "analyze_protocol_run.py"), str(network)]
    if runtime:
        cmd += ["--runtime", str(runtime)]
    subprocess.run(cmd, cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
