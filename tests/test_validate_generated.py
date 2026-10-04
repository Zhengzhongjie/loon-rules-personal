"""Tests for the shared, dialect-neutral generated-tree validator."""

from __future__ import annotations

from pathlib import Path

import pytest

import validate_generated as vg
from rulegrammar import LOON, SHADOWROCKET, SURGE, Rule

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_single_file_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    generated_dir = tmp_path / "generated"
    generated_dir.mkdir()
    monkeypatch.setattr(vg, "RULESET_ORDER", ["Test"])
    (generated_dir / "MANIFEST.csv").write_text(
        "Test,DIRECT,rules/loon/generated/test.list,1\n"
    )
    (generated_dir / "test.list").write_text(body)
    return generated_dir


def test_rule_value_problems_flags_inline_comment_residue():
    assert vg.rule_value_problems(Rule("IP-ASN", "4134 // 中国电信骨干网", ("no-resolve",))) != []
    assert any("bare AS number" in p for p in vg.rule_value_problems(Rule("IP-ASN", "4134x", ())))
    assert any("whitespace" in p for p in vg.rule_value_problems(Rule("DOMAIN", "a b.com", ())))


def test_rule_value_problems_passes_clean_rules():
    assert vg.rule_value_problems(Rule("IP-ASN", "4134", ("no-resolve",))) == []
    assert vg.rule_value_problems(Rule("DOMAIN-SUFFIX", "telegra.ph", ())) == []
    # USER-AGENT values legitimately contain spaces — must not be flagged.
    assert vg.rule_value_problems(Rule("USER-AGENT", "Mozilla/5.0 (iPhone; CPU)", ())) == []


def test_committed_loon_tree_is_valid():
    assert vg.validate_generated_tree(REPO_ROOT / "rules" / "loon" / "generated") == []


def test_committed_shadowrocket_tree_is_valid():
    assert vg.validate_generated_tree(REPO_ROOT / "rules" / "shadowrocket" / "generated") == []


def test_committed_surge_tree_is_valid():
    assert vg.validate_generated_tree(REPO_ROOT / "rules" / "surge" / "generated") == []


def test_manifest_entries_reads_tag_policy_filename():
    entries = vg.manifest_entries(REPO_ROOT / "rules" / "loon" / "generated")
    assert [tag for tag, _p, _f in entries] == vg.RULESET_ORDER
    assert all(fname.endswith(".list") for _t, _p, fname in entries)


def test_missing_generated_directory_fails_closed(tmp_path):
    generated_dir = tmp_path / "missing-generated"

    try:
        errors = vg.validate_generated_tree(generated_dir)
    except FileNotFoundError:
        return

    assert errors, "a missing generated directory must not validate successfully"


def test_empty_generated_rule_file_is_reported(tmp_path, monkeypatch):
    generated_dir = _write_single_file_tree(tmp_path, monkeypatch, "")

    errors = vg.validate_generated_tree(generated_dir)

    assert errors, "an empty generated rule file must not validate successfully"


def test_unknown_generated_rule_type_is_reported(tmp_path, monkeypatch):
    generated_dir = _write_single_file_tree(
        tmp_path,
        monkeypatch,
        "UNKNOWN-RULE,example.com\n",
    )

    errors = vg.validate_generated_tree(generated_dir)

    assert errors, "an unknown generated rule type must not validate successfully"


@pytest.mark.parametrize(
    "line",
    [
        "IP-CIDR,999.0.0.0/24",
        "IP-CIDR,192.0.2.0/33",
        "IP-CIDR,192.0.2.0",
        "IP-CIDR6,2001:db8::/129",
        "IP-CIDR6,192.0.2.0/24",
        "IP-ASN,0",
        "IP-ASN,4294967296",
    ],
)
def test_generated_tree_rejects_malformed_ip_values(tmp_path, monkeypatch, line):
    generated_dir = _write_single_file_tree(tmp_path, monkeypatch, line + "\n")

    assert vg.validate_generated_tree(generated_dir)


@pytest.mark.parametrize("dialect", [LOON, SURGE])
def test_canonical_generated_tree_rejects_ipv6_under_ipv4_type(tmp_path, monkeypatch, dialect):
    root = tmp_path / dialect
    root.mkdir()
    generated_dir = _write_single_file_tree(root, monkeypatch, "IP-CIDR,2001:db8::/32\n")

    assert vg.validate_generated_tree(generated_dir)


def test_shadowrocket_generated_tree_accepts_folded_ipv6(tmp_path, monkeypatch):
    root = tmp_path / SHADOWROCKET
    root.mkdir()
    generated_dir = _write_single_file_tree(root, monkeypatch, "IP-CIDR,2001:db8::/32\n")

    assert vg.validate_generated_tree(generated_dir) == []


def test_staged_tree_uses_explicit_dialect(tmp_path, monkeypatch):
    generated_dir = _write_single_file_tree(tmp_path, monkeypatch, "IP-CIDR,2001:db8::/32\n")

    assert vg.validate_generated_tree(generated_dir, dialect=SHADOWROCKET) == []
    assert vg.validate_generated_tree(generated_dir, dialect=LOON)


def test_staged_tree_checks_custom_ruleset_order(tmp_path):
    rulesets = [vg.build_loon_rules.RuleSet("a.list", "A", "DIRECT", sources=("urlA",))]
    (tmp_path / "MANIFEST.csv").write_text("A,DIRECT,rules/loon/generated/a.list,1\n")
    (tmp_path / "a.list").write_text("DOMAIN,example.com\n")

    assert vg.validate_generated_tree(tmp_path, rulesets=rulesets) == []

    (tmp_path / "MANIFEST.csv").write_text("Other,DIRECT,rules/loon/generated/a.list,1\n")
    assert vg.validate_generated_tree(tmp_path, rulesets=rulesets)


def test_staged_tree_uses_custom_ruleset_coverage_exemptions(tmp_path):
    rulesets = [
        vg.build_loon_rules.RuleSet("a.list", "A", "DIRECT"),
        vg.build_loon_rules.RuleSet("b.list", "B", "DIRECT", drop_if_covered=False),
    ]
    (tmp_path / "MANIFEST.csv").write_text(
        "A,DIRECT,rules/loon/generated/a.list,1\nB,DIRECT,rules/loon/generated/b.list,1\n"
    )
    (tmp_path / "a.list").write_text("DOMAIN-SUFFIX,example.com\n")
    (tmp_path / "b.list").write_text("DOMAIN,api.example.com\n")

    assert vg.validate_generated_tree(tmp_path, rulesets=rulesets) == []


def test_staged_tree_allows_empty_rules_only_when_requested(tmp_path, monkeypatch):
    generated_dir = _write_single_file_tree(tmp_path, monkeypatch, "")

    assert vg.validate_generated_tree(generated_dir, allow_empty=True) == []
    assert vg.validate_generated_tree(generated_dir)
