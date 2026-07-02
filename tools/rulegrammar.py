"""Shared grammar for Loon rule lines: parsing, rendering, and coverage tracking.

Both the builder (parsing strict upstream input) and the validator (parsing already
generated files) tokenize and track coverage through this one module, so the two cannot
silently diverge. Each caller layers its own policy on top: the builder filters by type
and reduces modifiers; the validator treats unparseable lines as errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_COMMENT_PREFIXES = ("#", "//", ";")
# Inline comments: whitespace followed by // or #. `;` is excluded because USER-AGENT
# values legitimately contain it (e.g. "Mozilla/5.0 (iPhone; CPU ...)").
_INLINE_COMMENT = re.compile(r"\s(?://|#).*$")
_COVERAGE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}


@dataclass(frozen=True)
class Rule:
    rule_type: str                      # upper-cased, e.g. "DOMAIN-SUFFIX"
    value: str                          # domain values lower-cased; IP/other left as-is
    modifiers: tuple[str, ...] = ()     # trailing parts, e.g. ("no-resolve",)


def parse_rule(line: str) -> Rule | None:
    """Tokenize one rule line. Lenient and structural: no type allowlist, no filtering.

    Returns None for blanks, comments, or lines without a ``TYPE,value`` shape. Strips a
    BOM, upper-cases the type, lower-cases domain values, and collects trailing modifiers.
    Policy (which types are allowed, which modifiers to keep) belongs to the caller.
    """
    stripped = line.strip().replace("﻿", "")
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return None
    stripped = _INLINE_COMMENT.sub("", stripped).strip()
    if "," not in stripped:
        return None
    parts = [part.strip() for part in stripped.split(",") if part.strip()]
    if len(parts) < 2:
        return None
    rule_type = parts[0].upper()
    value = parts[1].lower() if rule_type.startswith("DOMAIN") else parts[1]
    return Rule(rule_type, value, tuple(parts[2:]))


def render_rule(rule: Rule) -> str:
    """Inverse of parse_rule for a normalized rule: ``TYPE,value[,modifier...]``."""
    return ",".join((rule.rule_type, rule.value, *rule.modifiers))


class CoverageIndex:
    """Records emitted rules so later exact duplicates and suffix-covered rules can be found.

    Keys are canonicalized (value lower-cased) so dedup is case-insensitive, matching the
    builder's long-standing behaviour. ``exact_tag`` and ``covered_by`` return the owning
    tag (not just a bool) so callers can report which earlier rule set wins.
    """

    def __init__(self) -> None:
        self._exact: dict[tuple[str, str], str] = {}
        # suffix -> (insertion sequence, tag); lookup walks the domain's own label
        # suffixes instead of scanning every recorded suffix, keeping covered_by
        # O(labels) per rule. Earliest-inserted match still wins, as the old scan did.
        self._suffix_map: dict[str, tuple[int, str]] = {}
        self._next_seq = 0

    def exact_tag(self, rule: Rule) -> str | None:
        return self._exact.get((rule.rule_type, rule.value.lower()))

    def covered_by(self, rule: Rule) -> str | None:
        if rule.rule_type not in _COVERAGE_TYPES:
            return None
        labels = rule.value.lower().strip(".").split(".")
        best: tuple[int, str] | None = None
        for i in range(len(labels)):
            hit = self._suffix_map.get(".".join(labels[i:]))
            if hit is not None and (best is None or hit[0] < best[0]):
                best = hit
        return best[1] if best is not None else None

    def add(self, rule: Rule, tag: str) -> None:
        self._exact[(rule.rule_type, rule.value.lower())] = tag
        if rule.rule_type == "DOMAIN-SUFFIX":
            suffix = rule.value.lower().strip(".")
            if suffix not in self._suffix_map:
                self._suffix_map[suffix] = (self._next_seq, tag)
                self._next_seq += 1
