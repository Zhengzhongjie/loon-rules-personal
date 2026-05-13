#!/usr/bin/env python3
"""Fail if public repository artifacts contain obvious private material."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PEM_BOUNDARY = "-" * 5

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(PEM_BOUNDARY + r"BEGIN [A-Z ]*PRIVATE KEY" + PEM_BOUNDARY)),
    ("certificate", re.compile(PEM_BOUNDARY + r"BEGIN CERTIFICATE" + PEM_BOUNDARY)),
    ("proxy uri", re.compile(r"\b(?:ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://", re.I)),
    (
        "token query parameter",
        re.compile(r"[?&](?:token|key|api_key|access_token|auth|password|passwd|secret)=", re.I),
    ),
    ("loon proxy section", re.compile(r"^\[(?:Proxy|Remote Proxy|Mitm)\]$", re.M)),
]

TEXT_SUFFIXES = {
    ".list",
    ".md",
    ".py",
    ".txt",
    ".yml",
    ".yaml",
    ".gitignore",
}


def should_scan(path: Path) -> bool:
    if ".git" in path.parts:
        return False
    if "__pycache__" in path.parts:
        return False
    return path.suffix in TEXT_SUFFIXES or path.name in {".gitignore"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    args = parser.parse_args()

    errors: list[str] = []
    for path in sorted(p for p in args.root.rglob("*") if p.is_file() and should_scan(p)):
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{path}: contains {label}")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: public artifact audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
