"""Regression guard: functional service domains must not be shadowed by earlier
reject rules under first-match-wins ordering.

The core reject ruleset precedes most service rules; optional Heavy is last.
A reject rule only preempts a service when it actually precedes that service
in the catalogue, regardless of its numeric filename.
For a *functional* domain (auth, API, feature flags) that silently breaks the
service — the statsig.com class of bug that SERVICE_ALLOWLIST fixes. For a
*telemetry* domain (RUM, analytics) the preemption is harmless and intended.

This test asserts the set of shadowed service domains never grows beyond a small,
explicitly-reviewed telemetry baseline. A new entry means upstream (or a builder
change) started shadowing something — triage it:
  * functional -> add to SERVICE_ALLOWLIST in tools/build_loon_rules.py, regenerate
  * telemetry  -> add to ACCEPTED_TELEMETRY_SHADOWS below, with a reason
Both dialects are checked because artifacts are generated per-dialect and can
drift independently (a stale shadowrocket tree once carried hosts loon had already
stripped).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from build_loon_rules import RULESETS, SERVICE_ALLOWLIST
from rulegrammar import parse_rule

REPO_ROOT = Path(__file__).resolve().parents[1]
DIALECT_DIRS = [
    REPO_ROOT / "rules" / "loon" / "generated",
    REPO_ROOT / "rules" / "shadowrocket" / "generated",
    REPO_ROOT / "rules" / "surge" / "generated",
]
REJECT_FILES = ("00-Ads-Reject.list", "27-Ads-Reject-Heavy.list")
SERVICE_FILES = ("06-FinanceCrypto-Stable.list", "08-Claude.list", "08-AI.list")

# Service domains that reject lists legitimately shadow: pure telemetry/analytics
# whose blocking does NOT break the service. Reviewed 2026-07-05.
ACCEPTED_TELEMETRY_SHADOWS = frozenset(
    {
        "browser-intake-datadoghq.com",      # Datadog RUM intake (ChatGPT web telemetry)
        "rum.browser-intake-datadoghq.com",  # Datadog RUM intake
        "cdn.usefathom.com",                 # Fathom Analytics
    }
)


def _domain_rules(path: Path):
    """Parsed DOMAIN / DOMAIN-SUFFIX rules from a generated .list file."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rule = parse_rule(stripped)
        if rule is not None and rule.rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
            yield rule


def _parent_suffixes(host: str):
    """host and every parent suffix: a.b.c -> a.b.c, b.c, c."""
    labels = host.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def _reject_index(generated_dir: Path, files=REJECT_FILES):
    """Build lookup structures from a dialect's reject lists.

    - reject_domain / reject_suffix: exact rule values by type
    - covered: every suffix at or under which some reject rule lives, so
      ``sv in covered`` answers "does a reject rule sit inside sv's subtree?"
      in O(1) instead of scanning ~170k rules per service domain.
    """
    reject_domain: set[str] = set()
    reject_suffix: set[str] = set()
    covered: set[str] = set()
    for fname in files:
        for rule in _domain_rules(generated_dir / fname):
            (reject_domain if rule.rule_type == "DOMAIN" else reject_suffix).add(rule.value)
            covered.update(_parent_suffixes(rule.value))
    return reject_domain, reject_suffix, covered


def _shadowed_service_domains(generated_dir: Path) -> set[str]:
    """Service-rule values preempted by some reject rule in the same dialect tree."""
    shadowed: set[str] = set()
    order = [rs.file for rs in RULESETS]
    for fname in SERVICE_FILES:
        earlier = tuple(reject for reject in REJECT_FILES if order.index(reject) < order.index(fname))
        reject_domain, reject_suffix, covered = _reject_index(generated_dir, earlier)

        def host_rejected(host: str) -> bool:
            return host in reject_domain or any(p in reject_suffix for p in _parent_suffixes(host))

        for rule in _domain_rules(generated_dir / fname):
            if rule.rule_type == "DOMAIN":
                if host_rejected(rule.value):
                    shadowed.add(rule.value)
            else:  # DOMAIN-SUFFIX,value covers value + subdomains
                # apex host rejected, or a reject rule lives at/under this subtree
                if host_rejected(rule.value) or rule.value in covered:
                    shadowed.add(rule.value)
    return shadowed


@pytest.mark.parametrize("generated_dir", DIALECT_DIRS, ids=lambda p: p.parent.name)
def test_no_unreviewed_shadowed_service_domains(generated_dir: Path):
    unexpected = _shadowed_service_domains(generated_dir) - ACCEPTED_TELEMETRY_SHADOWS
    assert not unexpected, (
        f"{generated_dir.parent.name}: service domains shadowed by reject rules and not in "
        f"ACCEPTED_TELEMETRY_SHADOWS: {sorted(unexpected)}. If functional, add to "
        f"SERVICE_ALLOWLIST and regenerate; if telemetry, add to the baseline with a reason."
    )


@pytest.mark.parametrize("generated_dir", DIALECT_DIRS, ids=lambda p: p.parent.name)
def test_service_allowlist_domains_absent_from_reject_lists(generated_dir: Path):
    """Every SERVICE_ALLOWLIST domain (and its subdomains) is stripped from reject lists."""
    reject_domain, reject_suffix, _ = _reject_index(generated_dir)
    reject_values = reject_domain | reject_suffix
    offenders = sorted(
        v
        for v in reject_values
        for d in SERVICE_ALLOWLIST
        if v == d or v.endswith("." + d)
    )
    assert not offenders, (
        f"{generated_dir.parent.name}: SERVICE_ALLOWLIST domains still present in reject lists "
        f"(allowlist not applied / stale artifacts?): {offenders}"
    )
