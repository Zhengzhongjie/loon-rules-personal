"""Behaviour tests for the LoonConfig model and pure checks in validate_loon_config.py."""

from __future__ import annotations

import sys

import pytest
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


def test_parse_remote_rule_preserves_disabled_state_and_defaults_to_enabled():
    assert v.parse_remote_rule("https://x/a.list, tag=T, policy=P, enabled = false").enabled is False
    assert v.parse_remote_rule("https://x/a.list, tag=T, policy=P").enabled is True


@pytest.mark.parametrize("enabled", ["", "yes", "true, enabled=false"])
def test_parse_remote_rule_rejects_invalid_or_ambiguous_enabled(enabled):
    assert v.parse_remote_rule(f"https://x/a.list, tag=T, policy=P, enabled={enabled}").enabled is None


@pytest.mark.parametrize("field", ["tag", "policy"])
def test_parse_remote_rule_rejects_duplicate_binding_fields(field):
    rule = v.parse_remote_rule(f"https://x/a.list, tag=T, policy=P, {field}=Other")
    assert getattr(rule, field) is None


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


@pytest.mark.parametrize("ip", ["10.2.3.4", "172.16.7.8", "192.168.2.1"])
def test_check_rule_section_allows_rfc1918_direct_host_exception(ip):
    rule = f"IP-CIDR,{ip}/32,DIRECT,no-resolve"
    assert v.check_rule_section(mk(rule_lines=[rule, "FINAL,全局代理"])) == []


@pytest.mark.parametrize("cidr", [
    "0.0.0.0/0", "8.8.8.8/32", "100.64.0.1/32", "198.18.0.1/32",
    "127.0.0.1/32", "169.254.1.1/32", "192.168.0.0/16", "fc00::1/128", "192.168.1.1",
])
def test_check_rule_section_rejects_non_rfc1918_or_broad_direct_exception(cidr):
    rule = f"IP-CIDR,{cidr},DIRECT,no-resolve"
    assert v.check_rule_section(mk(rule_lines=[rule, "FINAL,全局代理"]))


@pytest.mark.parametrize("rule", [
    "IP-CIDR,0.0.0.0/0,Home-Orca-WG,no-resolve",
    "IP-CIDR,8.8.8.8/32,Home-Orca-WG,no-resolve",
    "IP-CIDR,192.168.0.0/16,Home-Orca-WG,no-resolve",
    "IP-CIDR6,198.18.0.1/32,Home-Orca-WG,no-resolve",
])
def test_check_rule_section_rejects_broad_or_public_device_tunnel_exception(rule):
    assert v.check_rule_section(mk(rule_lines=[rule, "FINAL,全局代理"]))


def test_parse_loon_config_extracts_active_mitm_settings_only():
    cfg = v.parse_loon_config("[Mitm]\n# skip-server-cert-verify = true\nskip-server-cert-verify = false\n")
    assert cfg.mitm_lines == ["skip-server-cert-verify = false"]


@pytest.mark.parametrize("setting", [
    "", "skip-server-cert-verify = true", "skip-server-cert-verify = off",
    "skip-server-cert-verify = false\nskip-server-cert-verify = true",
])
def test_check_mitm_requires_one_explicit_false_setting(setting):
    cfg = v.parse_loon_config(f"[Mitm]\n{setting}\n")
    assert any("skip-server-cert-verify must be false" in error for error in v.check_mitm(cfg))


def test_check_mitm_accepts_certificate_verification_with_mitm_disabled():
    cfg = v.parse_loon_config("[Mitm]\nenable = false\nskip-server-cert-verify = false\n")
    assert v.check_mitm(cfg) == []


def test_check_policy_groups():
    assert v.check_policy_groups(mk(policy_groups=frozenset(v.REQUIRED_POLICY_GROUPS))) == []
    assert any("missing policy group" in e for e in v.check_policy_groups(mk()))


def test_policy_references_accept_remote_filters_and_chain_first_choices():
    cfg = v.parse_loon_config("""[Proxy]
Home = {{HOME_NODE}}
[Remote Proxy]
Subscription = {{SUBSCRIPTION_URL}}
[Remote Filter]
Chained-proxy-Filter = NameRegex, FilterKey = "(?i)(vless|reality)"
JP_Filter = NameRegex, FilterKey = "Japan"
[Proxy Group]
全局代理 = select,链式代理链路,日本节点,DIRECT,Chained-proxy-Filter,url = http://probe.invalid/204
Claude = select,链式代理链路,日本节点
链式代理节点 = select,Chained-proxy-Filter
链式代理链路 = select,日本链式代理
日本节点 = url-test,JP_Filter,url = http://probe.invalid/204,interval = 600
Local = select,Home,Subscription
[Proxy Chain]
日本链式代理 = 日本节点,链式代理节点,udp=true
[Rule]
IP-CIDR,198.18.0.1/32,Home,no-resolve
FINAL,全局代理
""")
    assert v.check_policy_references(cfg) == []


@pytest.mark.parametrize("definition", [
    "[Proxy Group]\nAI = select,Missing\n",
    "[Proxy Chain]\nChain = DIRECT,Missing,udp=true\n",
    "[Rule]\nIP-CIDR,198.18.0.1/32,Missing,no-resolve\n",
])
def test_policy_references_reject_unknown_candidate_or_inline_target(definition):
    assert any("missing policy reference" in error and "Missing" in error
               for error in v.check_policy_references(v.parse_loon_config(definition)))


@pytest.mark.parametrize("text", [
    "[Proxy Group]\nAI = select,DIRECT\nAI = select,REJECT\n",
    "[Proxy Group]\nShared = select,DIRECT\n[Proxy Chain]\nShared = DIRECT,DIRECT\n",
    "[Proxy Group]\nShared = select,DIRECT\n[Remote Filter]\nShared = NameRegex,FilterKey = example\n",
    "[Proxy]\nShared = {{NODE}}\n[Proxy Group]\nShared = select,DIRECT\n",
])
def test_policy_references_reject_duplicate_definitions(text):
    assert any("duplicate policy definition" in error for error in v.check_policy_references(v.parse_loon_config(text)))


def test_policy_references_reject_duplicate_group_members():
    cfg = v.parse_loon_config("[Proxy Group]\nAI = select,DIRECT,DIRECT\n")
    assert any("duplicate policy member" in error for error in v.check_policy_references(cfg))


@pytest.mark.parametrize("text", [
    "[Proxy Group]\nAI = select,AI\n",
    "[Proxy Group]\nA = select,B\nB = select,C\nC = select,A\n",
    "[Proxy Group]\nA = select,Chain\n[Proxy Chain]\nChain = DIRECT,A,udp=true\n",
])
def test_policy_references_reject_cycles_across_groups_and_chains(text):
    assert any("policy reference cycle" in error for error in v.check_policy_references(v.parse_loon_config(text)))


def test_policy_references_ignore_commas_in_option_values():
    cfg = v.parse_loon_config('[Proxy Group]\nA = select,DIRECT,img-url="data:image/svg+xml,symbol"\n')
    assert v.check_policy_references(cfg) == []


def _valid_cli_config_text():
    groups = "\n".join(f"{policy} = select,DIRECT" for policy in v.REQUIRED_POLICY_GROUPS)
    rules = "\n".join(
        f"{v.GENERATED_RAW_PREFIX}{ruleset.file}, tag={ruleset.tag}, policy={ruleset.policy}, enabled=true"
        for ruleset in v.build_loon_rules.RULESETS
    )
    mitm_header = "[Mitm]"
    return f"""[General]
skip-proxy =
bypass-tun =
ip-mode = v4-only
ipv6-vif = off
hijack-dns = *:53
[Proxy Group]
{groups}
[Remote Filter]
[Proxy Chain]
[Rule]
FINAL,全局代理
[Remote Rule]
{rules}
[Plugin]
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/Loon/AdvertisingLite/AdvertisingLite.plugin, enabled=true
{mitm_header}
skip-server-cert-verify = false
"""


@pytest.fixture
def cli_config(tmp_path, monkeypatch):
    """Run the actual CLI entry point against a complete, isolated generated tree."""
    generated = tmp_path / "generated"
    generated.mkdir()
    manifest = []
    for index, ruleset in enumerate(v.build_loon_rules.RULESETS):
        (generated / ruleset.file).write_text(f"DOMAIN,host-{index}.invalid\n")
        manifest.append(f"{ruleset.tag},{ruleset.policy},rules/loon/generated/{ruleset.file},1")
    (generated / "MANIFEST.csv").write_text("\n".join(manifest) + "\n")
    config = tmp_path / "config.lcf"
    monkeypatch.setattr(v, "GENERATED_RULE_DIR", generated)
    monkeypatch.setattr(sys, "argv", [v.__file__, str(config)])
    return config


@pytest.mark.parametrize("before,after,error", [
    ("skip-server-cert-verify = false", "skip-server-cert-verify = true", "skip-server-cert-verify must be false"),
    ("tag=AI, policy=AI, enabled=true", "tag=AI, policy=AI, enabled=false", "AI must be enabled"),
    ("AI = select,DIRECT", "AI = select,Missing", "missing policy reference"),
    ("08-AI.list, tag=AI", "08-Claude.list, tag=AI", "tag URL mismatch"),
])
def test_cli_rejects_dangerous_config_changes(cli_config, capsys, before, after, error):
    text = _valid_cli_config_text()
    assert before in text
    cli_config.write_text(text.replace(before, after))
    assert v.main() == 1
    assert error in capsys.readouterr().err


def test_cli_accepts_catalogue_and_safe_device_local_direct_exception(cli_config, capsys):
    cli_config.write_text(_valid_cli_config_text().replace("FINAL,全局代理", "IP-CIDR,192.168.1.1/32,DIRECT,no-resolve\nFINAL,全局代理"))
    assert v.main() == 0
    assert "invariants passed" in capsys.readouterr().out


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


def test_check_remote_urls_rejects_swapped_catalogue_files():
    first, second = v.build_loon_rules.RULESETS[:2]
    cfg = mk(remote_rules=[
        v.RemoteRule(v.GENERATED_RAW_PREFIX + second.file, first.tag, first.policy),
        v.RemoteRule(v.GENERATED_RAW_PREFIX + first.file, second.tag, second.policy),
    ])
    assert len(v.check_remote_urls(cfg)) == 2
    assert all("tag URL mismatch" in error for error in v.check_remote_urls(cfg))


@pytest.mark.parametrize("url", [None, "missing.list", v.GENERATED_RAW_PREFIX + "00-Ads-Reject.list?ref=other"])
def test_check_remote_urls_requires_exact_catalogue_url(url):
    first = v.build_loon_rules.RULESETS[0]
    assert any("tag URL mismatch" in error for error in v.check_remote_urls(
        mk(remote_rules=[v.RemoteRule(url, first.tag, first.policy)])
    ))


def test_check_remote_bindings_accepts_complete_catalogue_with_heavy_disabled():
    rules = [v.parse_remote_rule(
        f"{v.GENERATED_RAW_PREFIX}{ruleset.file}, tag={ruleset.tag}, policy={ruleset.policy}, "
        f"enabled={'false' if ruleset.tag == 'Ads-Reject-Heavy' else 'true'}"
    ) for ruleset in v.build_loon_rules.RULESETS]
    cfg = mk(remote_rules=rules)
    assert v.check_remote_tags(cfg) == []
    assert v.check_remote_urls(cfg) == []
    assert v.check_remote_tag_policies(cfg) == []


@pytest.mark.parametrize("disabled_tag", ["Ads-Reject", "LAN-Direct", "Claude", "AI"])
def test_check_remote_tags_rejects_disabled_required_rule(disabled_tag):
    rules = [v.parse_remote_rule(
        f"{v.GENERATED_RAW_PREFIX}{ruleset.file}, tag={ruleset.tag}, policy={ruleset.policy}, "
        f"enabled={'false' if ruleset.tag == disabled_tag else 'true'}"
    ) for ruleset in v.build_loon_rules.RULESETS]
    assert any(disabled_tag in error and "must be enabled" in error for error in v.check_remote_tags(mk(remote_rules=rules)))


def test_check_remote_tags_rejects_invalid_enabled_even_for_optional_heavy():
    rules = [v.parse_remote_rule(
        f"{v.GENERATED_RAW_PREFIX}{ruleset.file}, tag={ruleset.tag}, policy={ruleset.policy}, "
        f"enabled={'yes' if ruleset.tag == 'Ads-Reject-Heavy' else 'true'}"
    ) for ruleset in v.build_loon_rules.RULESETS]
    assert any("invalid enabled" in error for error in v.check_remote_tags(mk(remote_rules=rules)))


def test_check_remote_tag_policies_defaults_to_authored_catalogue():
    ruleset = next(ruleset for ruleset in v.build_loon_rules.RULESETS if ruleset.policy != "DIRECT")
    wrong = mk(remote_rules=[v.RemoteRule(v.GENERATED_RAW_PREFIX + ruleset.file, ruleset.tag, "DIRECT")])
    mismatch = f"{ruleset.tag}: expected {ruleset.policy}, got DIRECT"
    assert any(mismatch in error for error in v.check_remote_tag_policies(wrong))


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
