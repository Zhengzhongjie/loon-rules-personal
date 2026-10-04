#!/usr/bin/env python3
"""Fail if public repository artifacts contain obvious private material."""

from __future__ import annotations

import argparse
import re
import subprocess
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
]

# Placeholder-aware leak model for private config sections. A config skeleton legitimately carries
# [Proxy]/[Mitm] section headers, so a header alone is not a leak (ADR-0004). Instead, any value in a
# private section must be a {{PLACEHOLDER}}; a real node definition or a real CA cert/passphrase is
# the leak. This runs in addition to the unconditional value patterns above.
_PLACEHOLDER = re.compile(r"\{\{[A-Za-z0-9_-]+\}\}")
_PROXY_SECTIONS = {"proxy", "remote proxy"}
_MITM_SECTIONS = {"mitm", "https"}
# Allowlist of MITM keys that may carry a real value; everything else (hostname, ca-p12,
# ca-passphrase, and any future cert/key option) must be a placeholder in a public skeleton.
# MITM hostnames are private per docs/security-posture.md — they reveal which apps are intercepted.
_MITM_PUBLIC_KEYS = {"enable", "h2"}
# Diagnostics may name recognized fields, never arbitrary text from a private assignment.
# Proxy labels and unknown key names can themselves contain private material.
_MITM_DIAGNOSTIC_FIELDS = {"hostname", "ca-p12", "ca-passphrase", "certificate", "private-key"}


def _is_placeholder_value(value: str) -> bool:
    """True when the value is only {{…}} placeholders (plus separators) — nothing real leaks."""
    return _PLACEHOLDER.sub("", value).strip(" ,\t") == ""


def private_section_leaks(text: str) -> list[str]:
    """Flag private values by line/field only; never echo assignments or proxy labels."""
    problems: list[str] = []
    section: str | None = None
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if section in _PROXY_SECTIONS:
            value = line.split("=", 1)[1] if "=" in line else line
            if not _is_placeholder_value(value):
                problems.append(
                    f"line {line_number}: non-placeholder value in [{section}] section (field: proxy definition)"
                )
        elif section in _MITM_SECTIONS and "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            if key not in _MITM_PUBLIC_KEYS and not _is_placeholder_value(value):
                field = key if key in _MITM_DIAGNOSTIC_FIELDS else "unknown"
                problems.append(
                    f"line {line_number}: non-placeholder value in MITM section (field: {field})"
                )
    return problems

# Scan every committed file as text by default, excluding only known-binary
# suffixes. Fails closed: a new artifact type (config skeleton .conf, module
# .sgmodule/.srmodule) is covered the moment it lands, instead of silently
# skipped until someone remembers to widen an allowlist. Binaries that slip
# through are caught by the UnicodeDecodeError guard in main().
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
}


# Secret-bearing file types are a leak by *existence*, independent of content: a
# binary CA bundle (.p12/.pfx/.der) or private key store cannot be text-scanned
# (it UnicodeDecodeErrors and would otherwise be skipped silently), and no
# legitimate public artifact in this repo is one of these. Flag them by name so
# a committed cert/key/profile fails the audit even though its bytes never decode.
SECRET_MATERIAL_SUFFIXES = {
    ".p12",
    ".pfx",
    ".der",
    ".key",
    ".keystore",
    ".jks",
    ".mobileconfig",
    ".ovpn",
    ".p8",
    ".pkcs12",
}


def should_scan(path: Path) -> bool:
    if ".git" in path.parts or "__pycache__" in path.parts:
        return False
    if path.name == ".DS_Store":
        return False
    return path.suffix.lower() not in SKIP_SUFFIXES


def secret_material_problem(rel_path: str) -> str | None:
    """Flag a path whose file type carries key/cert material regardless of content."""
    if Path(rel_path).suffix.lower() in SECRET_MATERIAL_SUFFIXES:
        return f"{rel_path}: secret-material file type must not be committed"
    return None


def scan_text(rel_path: str, text: str) -> list[str]:
    problems: list[str] = []
    # Keep one finding per category, as before. Search the full text in the regex engine
    # rather than running every pattern in Python for every generated rule line.
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            prefix = text[:match.start()]
            line_number = 1 + prefix.count("\n") + prefix.count("\r") - prefix.count("\r\n")
            problems.append(f"{rel_path}: line {line_number}: contains {label}")
    problems.extend(f"{rel_path}: {problem}" for problem in private_section_leaks(text))
    return problems


# The default scan set is the git index (tracked ∪ staged): exactly what the next
# commit publishes. Reading blob content from the index (`git show :<path>`) rather
# than the working tree means the audited bytes are the committed bytes (no
# check-then-commit race) and untracked local files (backups, tool logs) cannot
# produce noise that trains people to ignore failures. `--all` keeps the old
# whole-tree disk scan for ad-hoc sweeps.
def index_paths(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        capture_output=True,
        check=True,
    )
    return [p.decode() for p in out.stdout.split(b"\0") if p]


def index_text(root: Path, rel_path: str) -> str | None:
    """Blob content for rel_path as staged in the index, or None for binary content."""
    out = subprocess.run(
        ["git", "-C", str(root), "show", f":{rel_path}"],
        capture_output=True,
        check=True,
    )
    try:
        return out.stdout.decode()
    except UnicodeDecodeError:
        return None


def audit_index(root: Path) -> list[str]:
    errors: list[str] = []
    for rel_path in sorted(index_paths(root)):
        if ".git" in Path(rel_path).parts:
            continue
        # Name-based check first: it must fire even for suffixes should_scan skips
        # and for blobs whose bytes never decode to text.
        material = secret_material_problem(rel_path)
        if material:
            errors.append(material)
        if not should_scan(Path(rel_path)):
            continue
        text = index_text(root, rel_path)
        if text is not None:
            errors.extend(scan_text(rel_path, text))
    return errors


def audit_tree(root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        material = secret_material_problem(str(path))
        if material:
            errors.append(material)
        if not should_scan(path):
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        errors.extend(scan_text(str(path), text))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument(
        "--all",
        action="store_true",
        help="scan every file on disk instead of the git index (noisy: includes untracked local files)",
    )
    args = parser.parse_args(argv)

    try:
        errors = audit_tree(args.root) if args.all else audit_index(args.root)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        # Fail closed: if git is unavailable the audit cannot vouch for the index.
        print(f"FAIL: cannot read git index under {args.root}: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: public artifact audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
