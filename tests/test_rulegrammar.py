"""Behaviour tests for the shared rule grammar in tools/rulegrammar.py."""

from __future__ import annotations

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
