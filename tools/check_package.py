#!/usr/bin/env python
"""Read-only package consistency checks for the clean CTF source bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", "Results", "profiles", ".mihomo-isolated", ".release", "__pycache__"}


def package_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        yield path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(root: Path) -> dict:
    path = root / "PACKAGE_MANIFEST.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_checksums(root: Path) -> dict[str, str]:
    path = root / "PACKAGE_CHECKSUMS.txt"
    if not path.exists():
        return {}
    items = {}
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, rel = line.partition("  ")
        if digest and rel:
            items[rel.replace("\\", "/")] = digest
    return items


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate package manifest, checksums, duplicates, and Python syntax.")
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--compile", action="store_true", help="Also py_compile every Python file in the package.")
    args = ap.parse_args()

    root = args.root.resolve()
    files = sorted(package_files(root))
    rels = [str(path.relative_to(root)).replace("\\", "/") for path in files]
    rel_set = set(rels)

    manifest = load_manifest(root)
    manifest_files = set(manifest.get("files") or [])
    checksum_map = load_checksums(root)

    errors = []
    warnings = []

    if manifest_files:
        missing = sorted(manifest_files - rel_set)
        extra = sorted(rel_set - manifest_files - {"PACKAGE_MANIFEST.json", "PACKAGE_CHECKSUMS.txt"})
        if missing:
            errors.append({"manifest_missing_on_disk": missing})
        if extra:
            warnings.append({"not_listed_in_manifest": extra})

    if checksum_map:
        for rel, expected in sorted(checksum_map.items()):
            path = root / rel
            if not path.exists():
                errors.append({"checksum_file_missing": rel})
                continue
            actual = sha256(path)
            if actual != expected:
                errors.append({"checksum_mismatch": rel, "expected": expected, "actual": actual})

    by_hash: dict[str, list[str]] = defaultdict(list)
    for path in files:
        by_hash[sha256(path)].append(str(path.relative_to(root)).replace("\\", "/"))
    duplicates = {digest: names for digest, names in by_hash.items() if len(names) > 1}
    if duplicates:
        warnings.append({"duplicate_content": duplicates})

    compile_failures = []
    if args.compile:
        for path in files:
            if path.suffix.lower() != ".py":
                continue
            try:
                py_compile.compile(str(path), doraise=True)
            except py_compile.PyCompileError as exc:
                compile_failures.append({"file": str(path.relative_to(root)), "error": str(exc)})
        if compile_failures:
            errors.append({"py_compile_failures": compile_failures})

    report = {
        "root": str(root),
        "file_count": len(files),
        "manifest_count": len(manifest_files) if manifest_files else None,
        "checksum_count": len(checksum_map) if checksum_map else None,
        "excluded_dirs": sorted(EXCLUDED_DIRS),
        "warnings": warnings,
        "errors": errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
