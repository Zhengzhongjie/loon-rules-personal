#!/usr/bin/env python3
"""Check whether generated Loon rules still match reviewed upstream inputs."""

from __future__ import annotations

import argparse
import contextlib
import difflib
import io
import tempfile
from pathlib import Path

import build_loon_rules


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GENERATED_DIR = REPO_ROOT / "rules" / "loon" / "generated"


def public_files(root: Path) -> dict[str, Path]:
    return {
        str(path.relative_to(root)): path
        for path in root.rglob("*")
        if path.is_file() and path.name != ".DS_Store" and "__pycache__" not in path.parts
    }


def unified_diff(current: Path | None, rebuilt: Path | None, rel_path: str) -> list[str]:
    current_lines = current.read_text().splitlines(keepends=True) if current else []
    rebuilt_lines = rebuilt.read_text().splitlines(keepends=True) if rebuilt else []
    return list(
        difflib.unified_diff(
            current_lines,
            rebuilt_lines,
            fromfile=f"current/{rel_path}",
            tofile=f"rebuilt/{rel_path}",
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild generated Loon rules in a temporary directory and report upstream drift."
    )
    parser.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED_DIR)
    parser.add_argument("--diff", action="store_true", help="print a bounded unified diff for changed files")
    parser.add_argument("--max-diff-lines", type=int, default=300)
    args = parser.parse_args()

    generated_dir = args.generated_dir.resolve()
    if not generated_dir.exists():
        print(f"FAIL: generated rule directory does not exist: {generated_dir}")
        return 1

    with tempfile.TemporaryDirectory(prefix="loon-rule-drift-") as tmp:
        rebuilt_dir = Path(tmp) / "generated"
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            build_status = build_loon_rules.build(rebuilt_dir, strict=True)
        print(captured.getvalue().strip())
        if build_status != 0:
            print("FAIL: strict rebuild failed; cannot assess drift")
            return build_status

        current_files = public_files(generated_dir)
        rebuilt_files = public_files(rebuilt_dir)
        current_names = set(current_files)
        rebuilt_names = set(rebuilt_files)

        added = sorted(rebuilt_names - current_names)
        removed = sorted(current_names - rebuilt_names)
        changed = sorted(
            name
            for name in current_names & rebuilt_names
            if current_files[name].read_text() != rebuilt_files[name].read_text()
        )

        if not (added or removed or changed):
            print("OK: generated Loon rules match the current upstream snapshot")
            return 0

        print("DRIFT: generated Loon rules differ from the current upstream snapshot")
        if added:
            print("added: " + ", ".join(added))
        if removed:
            print("removed: " + ", ".join(removed))
        if changed:
            print("changed: " + ", ".join(changed))

        if args.diff:
            printed = 0
            for name in added + removed + changed:
                diff_lines = unified_diff(current_files.get(name), rebuilt_files.get(name), name)
                for line in diff_lines:
                    if printed >= args.max_diff_lines:
                        print(f"... diff truncated after {args.max_diff_lines} lines")
                        return 2
                    print(line, end="")
                    printed += 1

        return 2


if __name__ == "__main__":
    raise SystemExit(main())
