"""Behaviour tests for the pure rule compiler in tools/build_loon_rules.py."""

from __future__ import annotations

import pytest

import build_loon_rules as blr


def test_cross_file_exact_dedup_drops_later_duplicate():
    rulesets = [
        blr.RuleSet("a.list", "A", "POLA", sources=("urlA",)),
        blr.RuleSet("b.list", "B", "POLB", sources=("urlB",)),
    ]
    contents = {
        "urlA": "DOMAIN,example.com\n",
        "urlB": "DOMAIN,example.com\n",
    }

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("DOMAIN", "example.com") in result.compiled["a.list"]
    assert blr.Rule("DOMAIN", "example.com") not in result.compiled["b.list"]
    assert result.stats.duplicates_dropped == 1


def test_within_file_exact_dedup():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    contents = {"urlA": "DOMAIN,dup.com\nDOMAIN,dup.com\n"}

    result = blr.compile_rules(rulesets, contents)

    assert result.compiled["a.list"].count(blr.Rule("DOMAIN", "dup.com")) == 1
    assert result.stats.duplicates_dropped == 1


def test_suffix_coverage_drops_later_covered_domain():
    rulesets = [
        blr.RuleSet("a.list", "A", "POLA", sources=("urlA",)),
        blr.RuleSet("b.list", "B", "POLB", sources=("urlB",)),
    ]
    contents = {
        "urlA": "DOMAIN-SUFFIX,example.com\n",
        "urlB": "DOMAIN,api.example.com\n",
    }

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("DOMAIN", "api.example.com") not in result.compiled["b.list"]
    assert result.stats.covered_dropped == 1


def test_drop_if_covered_false_keeps_covered_rule():
    # The ChinaASN-Direct ruleset sets drop_if_covered=False; a covered rule must survive.
    rulesets = [
        blr.RuleSet("a.list", "A", "POLA", sources=("urlA",)),
        blr.RuleSet("b.list", "B", "POLB", sources=("urlB",), drop_if_covered=False),
    ]
    contents = {
        "urlA": "DOMAIN-SUFFIX,example.com\n",
        "urlB": "DOMAIN,api.example.com\n",
    }

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("DOMAIN", "api.example.com") in result.compiled["b.list"]
    assert result.stats.covered_dropped == 0


def test_no_resolve_appends_to_ip_rules():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), no_resolve=True)]
    contents = {"urlA": "IP-CIDR,1.2.3.0/24\n"}

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("IP-CIDR", "1.2.3.0/24", ("no-resolve",)) in result.compiled["a.list"]


def test_normalize_filters_keyword_unknown_and_comments():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    contents = {
        "urlA": "\n".join(
            [
                "# a comment",
                "",
                "DOMAIN-KEYWORD,tracker",
                "URL-REGEX,something",
                "DOMAIN,keep.com",
            ]
        )
        + "\n"
    }

    result = blr.compile_rules(rulesets, contents)
    rules = result.compiled["a.list"]

    assert rules == [blr.Rule("DOMAIN", "keep.com")]


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        '{"prefixes": {}}',
        '{"prefixes": [null]}',
        "[]",
    ],
    ids=[
        "malformed-json",
        "missing-prefixes",
        "prefixes-not-list",
        "prefix-entry-not-object",
        "top-level-not-object",
    ],
)
def test_bad_json_prefix_source_surfaces_in_failures_not_raised(raw):
    rulesets = [blr.RuleSet("a.list", "A", "POLA", json_prefix_sources=("jsonU",))]
    contents = {"jsonU": raw}

    result = blr.compile_rules(rulesets, contents)

    assert any("jsonU" in f and "JSON_PARSE" in f for f in result.failures)
    assert result.compiled["a.list"] == []


def test_good_json_prefix_source_yields_ip_rules():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", json_prefix_sources=("jsonU",))]
    contents = {"jsonU": '{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"}]}'}

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("IP-CIDR", "1.2.3.0/24", ("no-resolve",)) in result.compiled["a.list"]
    assert result.failures == []


@pytest.mark.parametrize(
    "raw",
    ["", "# only a comment\n", "<!doctype html><html>upstream error</html>\n", "<html>,error\nDOMAIN,example.com\n", "not a rule\n", "DOMAIN-KEYWORD,tracker\n"],
    ids=["empty", "comments-only", "html", "html-with-commas", "invalid-text", "filtered-only"],
)
def test_unusable_text_source_is_reported_as_failure(raw):
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]

    result = blr.compile_rules(rulesets, {"urlA": raw})

    assert any("urlA" in failure and "SOURCE_PARSE" in failure for failure in result.failures)
    assert result.compiled["a.list"] == []


def test_malformed_text_source_is_discarded_as_a_whole():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("bad", "good"))]
    contents = {"bad": "DOMAIN,unsafe.example\nnot a rule\n", "good": "DOMAIN,safe.example\n"}

    result = blr.compile_rules(rulesets, contents)

    assert result.compiled["a.list"] == [blr.Rule("DOMAIN", "safe.example")]
    assert any("bad" in failure and "line 2" in failure for failure in result.failures)


@pytest.mark.parametrize("raw", ["IP-CIDR,999.1.2.0/24", "IP-CIDR,2001:db8::/32", "IP-CIDR6,1.2.3.0/24", "IP-ASN,0", "DOMAIN,,example.com"])
def test_malformed_supported_source_rule_discards_the_source(raw):
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]

    result = blr.compile_rules(rulesets, {"urlA": f"DOMAIN,valid.example\n{raw}\n"})

    assert any("SOURCE_PARSE" in failure and "line 2" in failure for failure in result.failures)
    assert result.compiled["a.list"] == []


def test_missing_required_source_is_reported_by_pure_compiler():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("missing",), additions=("DOMAIN,local.example",))]

    result = blr.compile_rules(rulesets, {})

    assert any("missing" in failure and "SOURCE_MISSING" in failure for failure in result.failures)


def test_exact_exclusions_do_not_remove_a_broader_or_neighboring_rule():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), exclusions=("DOMAIN,blocked.example", "IP-ASN,13335"))]
    contents = {"urlA": "DOMAIN,blocked.example\nDOMAIN,neighbor.example\nDOMAIN-SUFFIX,example\nIP-ASN,13335,no-resolve\nIP-ASN,15169\n"}

    result = blr.compile_rules(rulesets, contents)

    assert blr.Rule("DOMAIN", "blocked.example") not in result.compiled["a.list"]
    assert blr.Rule("IP-ASN", "13335", ("no-resolve",)) not in result.compiled["a.list"]
    assert blr.Rule("DOMAIN-SUFFIX", "example") in result.compiled["a.list"]
    assert blr.Rule("IP-ASN", "15169") in result.compiled["a.list"]
    assert result.stats.excluded_dropped == 2
    assert "reviewed_exclusions_dropped=2" in blr.stats_lines(result.stats)


@pytest.mark.parametrize("broad_first", [False, True])
def test_same_file_suffix_compaction_preserves_host_decisions(broad_first):
    narrow = ["DOMAIN,api.example.com", "DOMAIN-SUFFIX,cdn.example.com", "DOMAIN,other.test", "DOMAIN-REGEX,^example\\.net$"]
    raw_rules = ["DOMAIN-SUFFIX,example.com,no-resolve", *narrow] if broad_first else [*narrow, "DOMAIN-SUFFIX,example.com,no-resolve"]
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    original = [blr.accept_rule(raw) for raw in raw_rules]

    result = blr.compile_rules(rulesets, {"urlA": "\n".join(raw_rules)})
    compacted = result.compiled["a.list"]

    def matches(rules, host):
        return any(rule.rule_type == "DOMAIN" and host == rule.value or rule.rule_type == "DOMAIN-SUFFIX" and (host == rule.value or host.endswith("." + rule.value)) for rule in rules)

    for host in ("example.com", "api.example.com", "cdn.example.com", "img.cdn.example.com", "other.test", "evil-example.com", "example.com.evil"):
        assert matches(original, host) == matches(compacted, host)
    assert blr.Rule("DOMAIN-SUFFIX", "example.com", ("no-resolve",)) in compacted
    assert blr.Rule("DOMAIN", "api.example.com") not in compacted
    assert blr.Rule("DOMAIN-SUFFIX", "cdn.example.com") not in compacted
    assert blr.Rule("DOMAIN-REGEX", "^example\\.net$") in compacted
    assert len(compacted) == 3


def test_later_broader_policy_rule_never_removes_an_earlier_policy_override():
    rulesets = [
        blr.RuleSet("direct.list", "Direct", "DIRECT", additions=("DOMAIN,api.example.com",)),
        blr.RuleSet("proxy.list", "Proxy", "PROXY", additions=("DOMAIN-SUFFIX,example.com",)),
    ]

    result = blr.compile_rules(rulesets, {})

    assert result.compiled["direct.list"] == [blr.Rule("DOMAIN", "api.example.com")]
    assert result.compiled["proxy.list"] == [blr.Rule("DOMAIN-SUFFIX", "example.com")]


@pytest.mark.parametrize("host", ["safebrowsing.googleapis.com", "safebrowsing.apple", "httpdns.alicdn.com", "crl.microsoft.com", "activate.adobe.com", "oaistatsig.com"])
def test_functional_security_and_auth_endpoints_are_removed_from_reject_sources(host):
    rulesets = [blr.RuleSet("ads.list", "Ads", blr.REJECT_POLICY, sources=("ads",))]

    result = blr.compile_rules(rulesets, {"ads": f"DOMAIN,{host}\nDOMAIN,telemetry.vendor.test\n"})

    assert result.compiled["ads.list"] == [blr.Rule("DOMAIN", "telemetry.vendor.test")]
    assert result.stats.allowlisted_dropped == 1


@pytest.mark.parametrize(
    "entry",
    [{"ipv4Prefix": "2001:db8::/32"}, {"ipv6Prefix": "1.2.3.0/24"}, {"ipv4Prefix": "1.2.3.4"}],
    ids=["v6-in-v4-field", "v4-in-v6-field", "missing-prefix-length"],
)
def test_json_prefix_source_rejects_mismatched_family_or_missing_prefix_length(entry):
    import json

    rulesets = [blr.RuleSet("a.list", "A", "POLA", json_prefix_sources=("jsonU",))]

    result = blr.compile_rules(rulesets, {"jsonU": json.dumps({"prefixes": [entry]})})

    assert any("JSON_PARSE" in failure for failure in result.failures)
    assert result.compiled["a.list"] == []


def test_compile_stats_counts_generated_files():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), notes=("note one",))]
    contents = {"urlA": "DOMAIN,keep.com\n"}

    result = blr.compile_rules(rulesets, contents)

    assert result.compiled["a.list"] == [blr.Rule("DOMAIN", "keep.com")]
    assert result.stats.generated == 1


def test_render_tree_emits_header_body_and_manifest():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), notes=("note one",))]
    contents = {"urlA": "DOMAIN,keep.com\n"}

    files = blr.render_tree(blr.compile_rules(rulesets, contents).compiled, rulesets, blr.LOON_DIALECT)
    body = files["a.list"]

    assert body.startswith("# A\n")
    assert "# Policy: POLA" in body
    assert "# note one" in body
    assert "DOMAIN,keep.com" in body
    manifest = files["MANIFEST.csv"]
    assert manifest.splitlines()[0] == "# Generated Loon rules manifest"
    assert "A,POLA,rules/loon/generated/a.list,1" in manifest


def test_shadowrocket_dialect_folds_ipv6_and_repaths_manifest():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    contents = {"urlA": "IP-CIDR6,2001:db8::/32\nIP-CIDR,1.2.3.0/24\nDOMAIN,keep.com\n"}
    compiled = blr.compile_rules(rulesets, contents).compiled

    loon = blr.render_tree(compiled, rulesets, blr.LOON_DIALECT)["a.list"]
    sr = blr.render_tree(compiled, rulesets, blr.SHADOWROCKET_DIALECT)["a.list"]

    # Loon keeps IP-CIDR6; Shadowrocket folds it into dual-stack IP-CIDR.
    assert "IP-CIDR6,2001:db8::/32" in loon
    assert "IP-CIDR6" not in sr
    assert "IP-CIDR,2001:db8::/32" in sr
    # Non-IPv6 rows are untouched and row count stays in parity across dialects.
    assert "IP-CIDR,1.2.3.0/24" in sr and "DOMAIN,keep.com" in sr
    assert len(loon.splitlines()) == len(sr.splitlines())

    manifest = blr.render_tree(compiled, rulesets, blr.SHADOWROCKET_DIALECT)["MANIFEST.csv"]
    assert manifest.splitlines()[0] == "# Generated Shadowrocket rules manifest"
    assert "A,POLA,rules/shadowrocket/generated/a.list,3" in manifest


def test_surge_dialect_keeps_ipv6_and_matches_loon_body():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    contents = {"urlA": "IP-CIDR6,2001:db8::/32\nIP-CIDR,1.2.3.0/24\nDOMAIN,keep.com\n"}
    compiled = blr.compile_rules(rulesets, contents).compiled

    loon = blr.render_tree(compiled, rulesets, blr.LOON_DIALECT)["a.list"]
    surge = blr.render_tree(compiled, rulesets, blr.SURGE_DIALECT)["a.list"]

    # Surge's fold is the identity, so its .list body is byte-identical to Loon's.
    assert surge == loon
    assert "IP-CIDR6,2001:db8::/32" in surge

    manifest = blr.render_tree(compiled, rulesets, blr.SURGE_DIALECT)["MANIFEST.csv"]
    assert manifest.splitlines()[0] == "# Generated Surge rules manifest"
    assert "A,POLA,rules/surge/generated/a.list,3" in manifest


def test_write_result_replaces_artefacts(tmp_path):
    (tmp_path / "stale.list").write_text("old\n")
    (tmp_path / "MANIFEST.csv").write_text("old manifest\n")

    blr.write_result(tmp_path, {"new.list": "fresh\n", "MANIFEST.csv": "new manifest\n"})

    assert not (tmp_path / "stale.list").exists()
    assert (tmp_path / "new.list").read_text() == "fresh\n"
    assert (tmp_path / "MANIFEST.csv").read_text() == "new manifest\n"


def test_stats_lines_format():
    lines = blr.stats_lines(
        blr.CompileStats(generated=3, duplicates_dropped=2, covered_dropped=1, allowlisted_dropped=4)
    )

    assert lines == [
        "generated=3",
        "duplicates_dropped=2",
        "covered_later_rules_dropped=1",
        "service_allowlisted_dropped=4",
    ]
