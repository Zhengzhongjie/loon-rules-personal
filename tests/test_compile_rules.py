"""Behaviour tests for the pure rule compiler in tools/build_loon_rules.py."""

from __future__ import annotations

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

    assert "DOMAIN,example.com" in result.files["a.list"]
    assert "DOMAIN,example.com" not in result.files["b.list"]
    assert result.stats.duplicates_dropped == 1


def test_within_file_exact_dedup():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",))]
    contents = {"urlA": "DOMAIN,dup.com\nDOMAIN,dup.com\n"}

    result = blr.compile_rules(rulesets, contents)

    assert result.files["a.list"].count("DOMAIN,dup.com") == 1
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

    assert "api.example.com" not in result.files["b.list"]
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

    assert "DOMAIN,api.example.com" in result.files["b.list"]
    assert result.stats.covered_dropped == 0


def test_no_resolve_appends_to_ip_rules():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), no_resolve=True)]
    contents = {"urlA": "IP-CIDR,1.2.3.0/24\n"}

    result = blr.compile_rules(rulesets, contents)

    assert "IP-CIDR,1.2.3.0/24,no-resolve" in result.files["a.list"]


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
    body = result.files["a.list"]

    assert "DOMAIN,keep.com" in body
    assert "tracker" not in body
    assert "URL-REGEX" not in body


def test_bad_json_prefix_source_surfaces_in_failures_not_raised():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", json_prefix_sources=("jsonU",))]
    contents = {"jsonU": "not json"}

    result = blr.compile_rules(rulesets, contents)

    assert any("jsonU" in f and "JSON_PARSE" in f for f in result.failures)


def test_good_json_prefix_source_yields_ip_rules():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", json_prefix_sources=("jsonU",))]
    contents = {"jsonU": '{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"}]}'}

    result = blr.compile_rules(rulesets, contents)

    assert "IP-CIDR,1.2.3.0/24,no-resolve" in result.files["a.list"]
    assert result.failures == []


def test_header_manifest_and_stats():
    rulesets = [blr.RuleSet("a.list", "A", "POLA", sources=("urlA",), notes=("note one",))]
    contents = {"urlA": "DOMAIN,keep.com\n"}

    result = blr.compile_rules(rulesets, contents)
    body = result.files["a.list"]

    assert body.startswith("# A\n")
    assert "# Policy: POLA" in body
    assert "# note one" in body
    manifest = result.files["MANIFEST.csv"]
    assert manifest.splitlines()[0] == "# Generated Loon rules manifest"
    assert "A,POLA,rules/loon/generated/a.list,1" in manifest
    assert result.stats.generated == 1


def test_write_result_replaces_artefacts(tmp_path):
    (tmp_path / "stale.list").write_text("old\n")
    (tmp_path / "MANIFEST.csv").write_text("old manifest\n")

    blr.write_result(tmp_path, {"new.list": "fresh\n", "MANIFEST.csv": "new manifest\n"})

    assert not (tmp_path / "stale.list").exists()
    assert (tmp_path / "new.list").read_text() == "fresh\n"
    assert (tmp_path / "MANIFEST.csv").read_text() == "new manifest\n"


def test_stats_lines_format():
    lines = blr.stats_lines(blr.CompileStats(generated=3, duplicates_dropped=2, covered_dropped=1))

    assert lines == ["generated=3", "duplicates_dropped=2", "covered_later_rules_dropped=1"]
