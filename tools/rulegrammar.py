"""Shared grammar for Loon rule lines: parsing, rendering, and coverage tracking.

Both the builder (parsing strict upstream input) and the validator (parsing already
generated files) tokenize and track coverage through this one module, so the two cannot
silently diverge. Each caller layers its own policy on top: the builder filters by type
and reduces modifiers; the validator treats unparseable lines as errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_network


_COMMENT_PREFIXES = ("#", "//", ";")
# Inline comments: whitespace followed by // or #. `;` is excluded because USER-AGENT
# values legitimately contain it (e.g. "Mozilla/5.0 (iPhone; CPU ...)").
_INLINE_COMMENT = re.compile(r"\s(?://|#).*$")
_COVERAGE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
_NO_WHITESPACE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX", "IP-CIDR", "IP-CIDR6", "IP-ASN"}


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
    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    rule_type = parts[0].upper()
    value = parts[1].lower() if rule_type.startswith("DOMAIN") else parts[1]
    return Rule(rule_type, value, tuple(part for part in parts[2:] if part))


def render_rule(rule: Rule) -> str:
    """Inverse of parse_rule for a normalized rule: ``TYPE,value[,modifier...]``."""
    return ",".join((rule.rule_type, rule.value, *rule.modifiers))


LOON = "loon"
SHADOWROCKET = "shadowrocket"
SURGE = "surge"


def rule_value_problems(rule: Rule, *, dialect: str = LOON) -> list[str]:
    """Check semantic values without filtering rule types or changing rendered text.

    Canonical inputs and Loon/Surge outputs require IPv4 ``IP-CIDR`` and IPv6 ``IP-CIDR6``.
    Shadowrocket's rendered ``IP-CIDR`` is dual-stack. CIDRs require a decimal prefix length;
    host bits remain accepted, matching the builder's existing ``strict=False`` JSON handling.
    ASN values must be ASCII decimal numbers in the nonzero unsigned 32-bit range.
    USER-AGENT and PROCESS-NAME values may legitimately contain whitespace.
    """
    problems: list[str] = []
    if rule.rule_type in _NO_WHITESPACE_TYPES and any(ch.isspace() for ch in rule.value):
        problems.append("rule value has whitespace (inline comment?)")
    if rule.rule_type == "IP-ASN":
        if not re.fullmatch(r"[0-9]+", rule.value):
            problems.append("IP-ASN value must be a bare AS number")
        elif len(rule.value) > 10 or not 1 <= int(rule.value) <= 4294967295:
            problems.append("IP-ASN value must be in the range 1..4294967295")
    elif rule.rule_type in {"IP-CIDR", "IP-CIDR6"}:
        if not re.fullmatch(r"[^/%\s]+/[0-9]{1,3}", rule.value):
            problems.append("CIDR value must be an IP address with a decimal prefix length")
        else:
            try:
                network = ip_network(rule.value, strict=False)
            except ValueError:
                problems.append("CIDR value has an invalid IP address or prefix length")
            else:
                if rule.rule_type == "IP-CIDR6" and network.version != 6:
                    problems.append("IP-CIDR6 value must be IPv6")
                elif rule.rule_type == "IP-CIDR" and network.version != 4 and dialect != SHADOWROCKET:
                    problems.append("IP-CIDR value must be IPv4")
    return problems


def fold(rule: Rule, dialect: str) -> Rule:
    """Normalize a canonical rule into a dialect's rule vocabulary.

    The dialects share one text grammar and differ in exactly one rule type: IPv6 CIDRs. Loon and
    Surge keep the separate ``IP-CIDR6`` type (Surge is the reference implementation that syntax was
    copied from), while Shadowrocket's ``IP-CIDR`` is dual-stack, so IPv6 CIDRs fold into it.
    Applied at render time, downstream of all dedup, so all dialect trees keep identical row counts —
    the v4 and v6 value spaces are disjoint, so the fold never merges two rows into one. Loon and
    Surge are the identity; any unhandled dialect passes through unchanged.
    """
    if dialect == SHADOWROCKET and rule.rule_type == "IP-CIDR6":
        return Rule("IP-CIDR", rule.value, rule.modifiers)
    return rule


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
