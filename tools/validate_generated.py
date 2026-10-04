#!/usr/bin/env python3
"""Validate a generated rule-list tree — dialect-neutral, shared by every client validator.

The dialect trees share deduped `.list` files plus a MANIFEST.csv. Shared rule-value checks account
for Shadowrocket's dual-stack IP-CIDR syntax. The validator checks the manifest order against the
RULESETS oracle, flags stale files, and re-runs the builder's
dedup/coverage over the emitted lines. Both the order and the coverage exemption are derived from
RULESETS so the check tracks the builder's authored intent, not a hand-copied mirror.
"""

from __future__ import annotations

from pathlib import Path

import build_loon_rules
from rulegrammar import LOON, SHADOWROCKET, CoverageIndex, parse_rule, rule_value_problems

# Authored intent, shared across dialects: the tag order and the "keep even if covered" exemption.
RULESET_ORDER = [ruleset.tag for ruleset in build_loon_rules.RULESETS]
NO_COVER_TAGS = frozenset(rs.tag for rs in build_loon_rules.RULESETS if not rs.drop_if_covered)


def active_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def manifest_entries(generated_dir: Path) -> list[tuple[str, str, str]]:
    """(tag, policy, filename) rows from a tree's own MANIFEST.csv."""
    entries: list[tuple[str, str, str]] = []
    for raw in (generated_dir / "MANIFEST.csv").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tag, policy, path, _count = [part.strip() for part in line.split(",", 3)]
        entries.append((tag, policy, Path(path).name))
    return entries


def validate_generated_tree(
    generated_dir: Path,
    *,
    dialect: str | None = None,
    rulesets: list[build_loon_rules.RuleSet] | None = None,
    allow_empty: bool = False,
) -> list[str]:
    """Return tree invariant violations, optionally against a staged build's authored rulesets.

    The ordinary tree path identifies Shadowrocket; a staged tree can pass its dialect explicitly.
    Empty rule files remain invalid unless the caller explicitly permits partial/empty output.
    """
    errors: list[str] = []
    if dialect is None:
        dialect = SHADOWROCKET if generated_dir.parent.name == SHADOWROCKET else LOON
    ruleset_order = RULESET_ORDER if rulesets is None else [rs.tag for rs in rulesets]
    no_cover_tags = NO_COVER_TAGS if rulesets is None else {rs.tag for rs in rulesets if not rs.drop_if_covered}
    entries = manifest_entries(generated_dir)
    if [tag for tag, _policy, _file in entries] != ruleset_order:
        errors.append(f"{generated_dir.name}: manifest order does not match expected RULESETS order")
    expected_files = {filename for _tag, _policy, filename in entries}
    actual_files = {path.name for path in generated_dir.glob("*.list")}
    stale_files = sorted(actual_files - expected_files)
    if stale_files:
        errors.append(f"{generated_dir.name}: stale generated rule files: " + ", ".join(stale_files))

    index = CoverageIndex()
    for tag, _policy, filename in entries:
        path = generated_dir / filename
        if not path.exists():
            errors.append(f"generated rule file missing: {filename}")
            continue
        local_seen: set[tuple[str, str]] = set()
        lines = active_lines(path.read_text())
        if not lines and not allow_empty:
            # Only an explicit caller policy can permit empty build output; ordinary
            # artifact checks must still catch truncation or corruption.
            errors.append(f"{filename}: rule file has no active rules")
        for raw in lines:
            rule = parse_rule(raw)
            if rule is None:
                errors.append(f"{filename}: invalid rule line: {raw}")
                continue
            if rule.rule_type not in build_loon_rules.ALLOWED_RULE_TYPES:
                errors.append(f"{filename}: unknown rule type {rule.rule_type}: {raw}")
                continue
            errors.extend(f"{filename}: {msg}: {raw}" for msg in rule_value_problems(rule, dialect=dialect))
            key = (rule.rule_type, rule.value)
            if key in local_seen:
                errors.append(f"{filename}: duplicate local rule: {raw}")
            cross_tag = index.exact_tag(rule)
            if cross_tag is not None:
                errors.append(f"{filename}: duplicate cross-file rule also in {cross_tag}: {raw}")
            covered = index.covered_by(rule)
            if covered is not None and tag not in no_cover_tags:
                errors.append(f"{filename}: rule covered by earlier {covered}: {raw}")
            local_seen.add(key)
            index.add(rule, tag)
    return errors
