#!/usr/bin/env python
"""Check repository text files for strict UTF-8 readability."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".py",
    ".ps1",
    ".md",
    ".json",
    ".txt",
    ".html",
    ".js",
    ".example",
}
SKIP_DIRS = {".git", "__pycache__", "Results", "profiles", ".mihomo-isolated", ".release"}


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or ".bak_" in path.name:
            yield path


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate UTF-8 decoding for source/package text files.")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args()

    root = args.root.resolve()
    failures = []
    replacement_warnings = []
    total = 0
    for path in iter_text_files(root):
        total += 1
        rel = path.relative_to(root)
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            failures.append((str(rel), str(exc)))
            continue
        if "\ufffd" in text:
            replacement_warnings.append(str(rel))

    print(f"checked_text_files={total}")
    if replacement_warnings:
        print("replacement_char_warnings:")
        for rel in replacement_warnings:
            print(f"  {rel}")
    if failures:
        print("utf8_failures:")
        for rel, err in failures:
            print(f"  {rel}: {err}")
        return 1
    print("UTF8_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
