"""Behaviour tests for the LoonConfig model and pure checks in validate_loon_config.py."""

from __future__ import annotations

import validate_loon_config as v


def mk(**overrides) -> v.LoonConfig:
    """Build a minimal LoonConfig, overriding only the fields a test cares about."""
    base = dict(
        section_names=frozenset(),
        general_text="",
        policy_groups=frozenset(),
        rule_lines=[],
        remote_rules=[],
        plugin_lines=[],
    )
    base.update(overrides)
    return v.LoonConfig(**base)


def test_parse_loon_config_extracts_remote_rule_fields():
    text = "\n".join(
        [
            "[Remote Rule]",
            "https://example.com/a.list, tag=Foo, policy=Bar, enabled=true",
        ]
    )
    cfg = v.parse_loon_config(text)
    assert cfg.remote_rules == [v.RemoteRule("https://example.com/a.list", "Foo", "Bar")]


def test_parse_remote_rule_shapes():
    assert v.parse_remote_rule("https://x/a.list, tag=T, policy=P") == v.RemoteRule("https://x/a.list", "T", "P")
    assert v.parse_remote_rule("tag=T") == v.RemoteRule(None, "T", None)
    assert v.parse_remote_rule("https://x/a.list") == v.RemoteRule("https://x/a.list", None, None)
    assert v.parse_remote_rule("enabled=true") == v.RemoteRule(None, None, None)


def test_parse_loon_config_populates_all_fields():
    text = "\n".join(
        [
            "[General]",
            "ip-mode = v4-only",
            "[Proxy Group]",
            "全局代理 = select, A, B",
            "[Rule]",
            "FINAL,全局代理",
            "[Remote Rule]",
            "https://x/a.list, tag=AI, policy=AI",
            "[Plugin]",
            "# comment",
            "https://p.plugin, enabled=false",
        ]
    )
    cfg = v.parse_loon_config(text)
    assert {"General", "Proxy Group", "Rule", "Remote Rule", "Plugin"} <= cfg.section_names
    assert "v4-only" in cfg.general_text
    assert "全局代理" in cfg.policy_groups
    assert cfg.rule_lines == ["FINAL,全局代理"]
    assert cfg.remote_rules == [v.RemoteRule("https://x/a.list", "AI", "AI")]
    assert cfg.plugin_lines == ["https://p.plugin, enabled=false"]


def test_check_required_sections():
    assert v.check_required_sections(mk(section_names=frozenset(v.REQUIRED_SECTIONS))) == []
    assert v.check_required_sections(mk()) != []


def test_check_general_both_directions():
    good = "skip-proxy =\nbypass-tun =\nip-mode = v4-only\nipv6-vif = off\nhijack-dns ="
    assert v.check_general(mk(general_text=good)) == []
    assert "missing General skip-proxy" in v.check_general(mk(general_text=""))


def test_check_rule_section():
    assert v.check_rule_section(mk(rule_lines=["FINAL,全局代理"])) == []
    assert v.check_rule_section(mk(rule_lines=["DOMAIN,x.com,AI"])) != []


def test_check_policy_groups():
    assert v.check_policy_groups(mk(policy_groups=frozenset(v.REQUIRED_POLICY_GROUPS))) == []
    assert any("missing policy group" in e for e in v.check_policy_groups(mk()))


def test_check_remote_tags_passes_in_exact_order():
    rules = [v.RemoteRule(f"u{tag}", tag, "P") for tag in v.REMOTE_RULE_ORDER]
    assert v.check_remote_tags(mk(remote_rules=rules)) == []


def test_check_remote_tags_flags_missing_and_mismatch():
    rules = [v.RemoteRule(None, "AI", None), v.RemoteRule(None, "Ads-Reject", None)]
    errs = v.check_remote_tags(mk(remote_rules=rules))
    assert any("missing remote tags" in e for e in errs)
    assert any("must exactly match" in e for e in errs)


def test_check_remote_urls_flags_dup_and_bad_prefix():
    rules = [
        v.RemoteRule("https://bad/x.list", "T", None),
        v.RemoteRule("https://bad/x.list", "T2", None),
    ]
    errs = v.check_remote_urls(mk(remote_rules=rules))
    assert any("duplicate remote rule URLs" in e for e in errs)
    assert any("should use generated repo subscription" in e for e in errs)


def test_check_remote_urls_passes_generated_prefix():
    url = v.GENERATED_RAW_PREFIX + "00-Ads-Reject.list"
    assert v.check_remote_urls(mk(remote_rules=[v.RemoteRule(url, "T", None)])) == []


def test_check_remote_policies_both_directions():
    ok = mk(policy_groups=frozenset({"AI"}), remote_rules=[v.RemoteRule(None, "AI", "AI")])
    assert v.check_remote_policies(ok) == []
    bad = mk(remote_rules=[v.RemoteRule(None, "AI", "Nonexistent")])
    assert v.check_remote_policies(bad) != []


def test_check_remote_tag_policies_against_manifest():
    cfg = mk(remote_rules=[v.RemoteRule(None, "AI", "AI")])
    assert v.check_remote_tag_policies(cfg, {"AI": "AI"}) == []
    assert any("remote tag policy mismatch" in e for e in v.check_remote_tag_policies(cfg, {"AI": "广告分流"}))


def test_check_plugins_high_risk_marker():
    enabled = ["https://host/BiliBili.ADBlock.plugin, enabled=true"]
    assert any("account-risk plugin should be disabled" in e for e in v.check_plugins(mk(plugin_lines=enabled)))
    disabled = ["https://host/BiliBili.ADBlock.plugin, enabled=false"]
    assert not any("account-risk plugin should be disabled" in e for e in v.check_plugins(mk(plugin_lines=disabled)))
