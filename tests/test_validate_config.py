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
    good = "skip-proxy =\nbypass-tun =\nip-mode = v4-only\nipv6-vif = off\nhijack-dns = *:53"
    assert v.check_general(mk(general_text=good)) == []
    assert "missing General skip-proxy" in v.check_general(mk(general_text=""))


def test_check_general_requires_explicit_all_udp_dns_capture():
    base = "skip-proxy =\nbypass-tun =\nip-mode = v4-only\nipv6-vif = off\n"
    assert any("exactly one hijack-dns" in e for e in v.check_general(mk(general_text=base)))
    assert any("explicitly include *:53" in e for e in v.check_general(mk(general_text=base + "hijack-dns =\n")))
    assert any(
        "explicitly include *:53" in e
        for e in v.check_general(mk(general_text=base + "hijack-dns = 8.8.8.8\n"))
    )


def test_check_rule_section():
    assert v.check_rule_section(mk(rule_lines=["FINAL,全局代理"])) == []
    assert v.check_rule_section(mk(rule_lines=["DOMAIN,x.com,AI"])) != []


def test_check_rule_section_allows_private_device_ip_exception_only():
    private = "IP-CIDR,198.18.0.1/32,Home-Orca-WG,no-resolve"
    assert v.check_rule_section(mk(rule_lines=[private, "FINAL,全局代理"])) == []
    assert v.check_rule_section(mk(rule_lines=["IP-CIDR,1.2.3.4/32,AI,no-resolve", "FINAL,全局代理"])) != []
    assert v.check_rule_section(mk(rule_lines=["URL-REGEX,\\.log\\.,REJECT", "FINAL,全局代理"])) != []


def test_check_policy_groups():
    assert v.check_policy_groups(mk(policy_groups=frozenset(v.REQUIRED_POLICY_GROUPS))) == []
    assert any("missing policy group" in e for e in v.check_policy_groups(mk()))


def test_reviewed_direct_supplement_requires_exact_domain_and_policy():
    assert v.check_rule_section(mk(rule_lines=["DOMAIN-SUFFIX,zbrowser.cn,DIRECT", "FINAL,全局代理"])) == []
    for rule in (
        "DOMAIN-SUFFIX,zbrowser.cn,AI",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,unreviewed.example,DIRECT",
    ):
        assert v.check_rule_section(mk(rule_lines=[rule, "FINAL,全局代理"]))


def test_check_remote_tags_passes_in_exact_order():
    rules = [v.RemoteRule(f"u{tag}", tag, "P") for tag in v.REMOTE_RULE_ORDER]
    assert v.check_remote_tags(mk(remote_rules=rules)) == []


def test_financial_site_supplements_require_their_authored_policy():
    rules = [
        "DOMAIN-SUFFIX,financialresearch.gov,海外社交资讯",
        "DOMAIN-SUFFIX,hypurrscan.io,金融加密",
        "DOMAIN,api.hyperliquid.xyz,金融加密",
        "DOMAIN,api-ui.hyperliquid.xyz,金融加密",
        "DOMAIN,rpc.hyperliquid.xyz,金融加密",
        "FINAL,全局代理",
    ]
    assert v.check_rule_section(mk(rule_lines=rules)) == []
    for rule in (
        "DOMAIN-SUFFIX,financialresearch.gov,DIRECT",
        "DOMAIN-SUFFIX,hypurrscan.io,全局代理",
        "DOMAIN,api.hyperliquid.xyz,全局代理",
        "DOMAIN-SUFFIX,gov,海外社交资讯",
    ):
        assert v.check_rule_section(mk(rule_lines=[rule, "FINAL,全局代理"]))


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


# A WireGuard node whose base64 keys carry '/' and '=' padding — the exact shape that
# breaks Loon's delimiter parser when the values are left unquoted.
_WG_UNQUOTED = (
    "Home-Orca-WG = wireguard, interface-ip = 198.18.0.2, "
    "private-key = FAKEprivateKEY0000000000000000000000000/+A0=, mtu = 1420, keepalive = 25, "
    "peers = [{public-key = FAKEpublicKEY00000000000000000000000000/+B0=, "
    'allowed-ips = "198.18.0.0/24", endpoint = 209.200.235.119:51820, '
    "preshared-key = FAKEpresharedKEY0000000000000000000000/+C00=}]"
)
_WG_QUOTED = (
    'Home-Orca-WG = wireguard,interface-ip=198.18.0.2,'
    'private-key="FAKEprivateKEY0000000000000000000000000/+A0=",mtu=1420,keepalive=25,'
    'peers=[{public-key="FAKEpublicKEY00000000000000000000000000/+B0=",'
    'allowed-ips="198.18.0.0/24",endpoint=209.200.235.119:51820,'
    'preshared-key="FAKEpresharedKEY0000000000000000000000/+C00="}]'
)


def test_parse_loon_config_extracts_proxy_lines():
    cfg = v.parse_loon_config("[Proxy]\n" + _WG_QUOTED + "\n")
    assert cfg.proxy_lines == [_WG_QUOTED]


def test_check_proxy_wireguard_flags_every_unquoted_key():
    errors = v.check_proxy_wireguard(mk(proxy_lines=[_WG_UNQUOTED]))
    # all three base64 keys are unquoted; allowed-ips is already quoted, so 3 hits
    assert len(errors) == 3
    assert all("Home-Orca-WG" in e and "must be double-quoted" in e for e in errors)
    assert {"private-key", "public-key", "preshared-key"} == {e.split(":")[1].split("must")[0].strip() for e in errors}


def test_check_proxy_wireguard_passes_when_quoted():
    assert v.check_proxy_wireguard(mk(proxy_lines=[_WG_QUOTED])) == []


def test_check_proxy_wireguard_ignores_non_wireguard_and_templates():
    other = "US-01 = trojan, host.example.com, 443, password=secret"
    template = "Home-Orca-WG = {{HOME_WG_NODE}}"
    assert v.check_proxy_wireguard(mk(proxy_lines=[other, template])) == []
