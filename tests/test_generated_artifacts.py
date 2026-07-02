"""Validation for committed generated Loon rule artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest
from rulegrammar import parse_rule, render_rule


GENERATED_DIR = Path(__file__).resolve().parent.parent / "rules" / "loon" / "generated"
GENERATED_LIST_FILES = sorted(GENERATED_DIR.glob("*.list"))


def _line_context(rule_file: Path, line_number: int, line: str) -> str:
    return f"{rule_file.name}:{line_number}: {line}"


@pytest.mark.parametrize(
    "rule_file",
    GENERATED_LIST_FILES,
    ids=lambda rule_file: rule_file.name,
)
def test_generated_rule_artifact_lines_parse_and_round_trip(rule_file: Path):
    for line_number, line in enumerate(rule_file.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        context = _line_context(rule_file, line_number, line)
        rule = parse_rule(line)
        assert rule is not None, f"unparseable generated rule: {context}"

        rendered_rule = render_rule(rule)
        assert parse_rule(rendered_rule) == rule, (
            f"generated rule does not round-trip after rendering: {context}"
        )

        assert "//" not in rule.value and "#" not in rule.value, (
            f"inline-comment residue in generated rule value: {context}"
        )
        for modifier in rule.modifiers:
            assert "//" not in modifier and "#" not in modifier, (
                f"inline-comment residue in generated rule modifier: {context}"
            )
