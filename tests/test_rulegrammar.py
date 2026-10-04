"""Behaviour tests for the shared rule grammar in tools/rulegrammar.py."""

from __future__ import annotations

import pytest

import rulegrammar as rg


def test_parse_rule_uppercases_type_and_lowercases_domain_value():
    rule = rg.parse_rule("DOMAIN-suffix,Example.COM")
    assert rule == rg.Rule("DOMAIN-SUFFIX", "example.com", ())


def test_parse_rule_leaves_ip_value_untouched():
    rule = rg.parse_rule("IP-CIDR,FE80::/10")
    assert rule == rg.Rule("IP-CIDR", "FE80::/10", ())


def test_parse_rule_captures_modifiers():
    rule = rg.parse_rule("IP-CIDR,1.2.3.0/24,no-resolve")
    assert rule.modifiers == ("no-resolve",)


def test_parse_rule_strips_bom():
    rule = rg.parse_rule("﻿DOMAIN,example.com")
    assert rule == rg.Rule("DOMAIN", "example.com", ())


def test_parse_rule_returns_none_for_non_rules():
    assert rg.parse_rule("") is None
    assert rg.parse_rule("   ") is None
    assert rg.parse_rule("# comment") is None
    assert rg.parse_rule("// comment") is None
    assert rg.parse_rule("; comment") is None
    assert rg.parse_rule("FINAL") is None  # no comma
    assert rg.parse_rule("DOMAIN,") is None  # empty value


@pytest.mark.parametrize("line", ["DOMAIN,,example.com", ",DOMAIN,example.com"])
def test_parse_rule_does_not_shift_empty_required_fields(line):
    assert rg.parse_rule(line) is None


def test_parse_rule_strips_inline_comment_before_modifier():
    # Upstream ASN lists ship "IP-ASN,<n> // <name>" with no modifier; the comment must
    # not leak into the value. (The builder re-appends no-resolve for no_resolve rulesets.)
    rule = rg.parse_rule("IP-ASN,4134 // 中国电信骨干网")
    assert rule == rg.Rule("IP-ASN", "4134", ())


def test_parse_rule_strips_inline_comment_after_modifier():
    rule = rg.parse_rule("IP-ASN,4134,no-resolve // 中国电信骨干网")
    assert rule == rg.Rule("IP-ASN", "4134", ("no-resolve",))


def test_parse_rule_strips_inline_hash_comment():
    rule = rg.parse_rule("DOMAIN-SUFFIX,telegra.ph # telegraph")
    assert rule == rg.Rule("DOMAIN-SUFFIX", "telegra.ph", ())


def test_parse_rule_preserves_semicolon_in_user_agent_value():
    # `;` is not an inline comment marker: USER-AGENT values legitimately contain it.
    rule = rg.parse_rule("USER-AGENT,Mozilla/5.0 (iPhone; CPU)")
    assert rule == rg.Rule("USER-AGENT", "Mozilla/5.0 (iPhone; CPU)", ())


def test_render_rule_emits_type_value_modifiers():
    assert rg.render_rule(rg.Rule("DOMAIN", "example.com", ())) == "DOMAIN,example.com"
    assert (
        rg.render_rule(rg.Rule("IP-CIDR", "1.2.3.0/24", ("no-resolve",)))
        == "IP-CIDR,1.2.3.0/24,no-resolve"
    )


def test_parse_render_round_trip():
    line = "IP-CIDR,1.2.3.0/24,no-resolve"
    assert rg.render_rule(rg.parse_rule(line)) == line


def test_coverage_index_exact_tag_is_case_insensitive():
    index = rg.CoverageIndex()
    index.add(rg.Rule("IP-CIDR", "FE80::/10", ()), "A")
    # Same address in lower case must be recognized as a duplicate (the divergence we kill).
    assert index.exact_tag(rg.Rule("IP-CIDR", "fe80::/10", ())) == "A"
    assert index.exact_tag(rg.Rule("IP-CIDR", "2001:db8::/32", ())) is None


def test_coverage_index_suffix_covers_subdomain():
    index = rg.CoverageIndex()
    index.add(rg.Rule("DOMAIN-SUFFIX", "example.com", ()), "A")
    assert index.covered_by(rg.Rule("DOMAIN", "api.example.com", ())) == "A"
    assert index.covered_by(rg.Rule("DOMAIN", "example.com", ())) == "A"
    assert index.covered_by(rg.Rule("DOMAIN", "notexample.com", ())) is None


def test_coverage_index_ignores_non_domain_types():
    index = rg.CoverageIndex()
    index.add(rg.Rule("DOMAIN-SUFFIX", "example.com", ()), "A")
    assert index.covered_by(rg.Rule("IP-CIDR", "1.2.3.0/24", ())) is None


def test_fold_loon_is_identity():
    v6 = rg.Rule("IP-CIDR6", "2001:db8::/32", ("no-resolve",))
    assert rg.fold(v6, rg.LOON) == v6


def test_fold_shadowrocket_rewrites_ipv6_type_only():
    v6 = rg.Rule("IP-CIDR6", "2001:db8::/32", ("no-resolve",))
    assert rg.fold(v6, rg.SHADOWROCKET) == rg.Rule("IP-CIDR", "2001:db8::/32", ("no-resolve",))


def test_fold_shadowrocket_leaves_other_types_untouched():
    for rule in (
        rg.Rule("IP-CIDR", "1.2.3.0/24", ("no-resolve",)),
        rg.Rule("DOMAIN-SUFFIX", "example.com", ()),
    ):
        assert rg.fold(rule, rg.SHADOWROCKET) == rule


def test_fold_surge_is_identity():
    # Surge is the reference implementation and keeps canonical IP-CIDR6, so its fold is the identity.
    for rule in (
        rg.Rule("IP-CIDR6", "2001:db8::/32", ("no-resolve",)),
        rg.Rule("IP-CIDR", "1.2.3.0/24", ("no-resolve",)),
        rg.Rule("DOMAIN-SUFFIX", "example.com", ()),
    ):
        assert rg.fold(rule, rg.SURGE) == rule


@pytest.mark.parametrize(
    "rule",
    [
        rg.Rule("IP-CIDR", "192.0.2.1/24"),
        rg.Rule("IP-CIDR", "0.0.0.0/0"),
        rg.Rule("IP-CIDR6", "2001:DB8::1/32"),
        rg.Rule("IP-CIDR6", "::/0"),
        rg.Rule("IP-ASN", "4134"),
        rg.Rule("IP-ASN", "4294967295"),
        rg.Rule("USER-AGENT", "Mozilla/5.0 (iPhone; CPU)"),
        rg.Rule("PROCESS-NAME", "An App"),
    ],
)
def test_shared_value_checks_preserve_supported_values(rule):
    assert rg.rule_value_problems(rule) == []


@pytest.mark.parametrize(
    "rule",
    [
        rg.Rule("IP-CIDR", "999.0.0.0/24"),
        rg.Rule("IP-CIDR", "example.com/24"),
        rg.Rule("IP-CIDR", "192.0.2.0/33"),
        rg.Rule("IP-CIDR", "192.0.2.0"),
        rg.Rule("IP-CIDR", "192.0.2.0/255.255.255.0"),
        rg.Rule("IP-CIDR", "192.0.2.0/-1"),
        rg.Rule("IP-CIDR", "192.0.2.0/２４"),
        rg.Rule("IP-CIDR6", "2001:db8::/129"),
        rg.Rule("IP-CIDR6", "2001:db8:::1/64"),
        rg.Rule("IP-CIDR6", "fe80::%eth0/64"),
        rg.Rule("IP-CIDR", "2001:db8::/32"),
        rg.Rule("IP-CIDR6", "192.0.2.0/24"),
        rg.Rule("IP-ASN", "AS4134"),
        rg.Rule("IP-ASN", "４１３４"),
        rg.Rule("IP-ASN", "0"),
        rg.Rule("IP-ASN", "4294967296"),
    ],
)
def test_shared_value_checks_reject_malformed_ip_and_asn_values(rule):
    assert rg.rule_value_problems(rule)


def test_shadowrocket_shared_value_checks_accept_dual_stack_ip_cidr():
    assert rg.rule_value_problems(rg.Rule("IP-CIDR", "2001:db8::/32"), dialect=rg.SHADOWROCKET) == []
    assert rg.rule_value_problems(rg.Rule("IP-CIDR6", "192.0.2.0/24"), dialect=rg.SHADOWROCKET)
