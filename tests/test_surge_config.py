"""Tests for the Surge config skeleton generator."""

from __future__ import annotations

import build_surge_config as su
from build_loon_rules import RULESETS

BUILTIN_POLICIES = {"DIRECT", "REJECT", "PROXY"}


def _sections(conf: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for raw in conf.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections[current] = []
        elif current and line and not line.startswith("#"):
            sections[current].append(line)
    return sections


def test_canonical_sections_present_and_ordered():
    conf = su.render_config(su.DEVICES[0])
    headers = [ln.strip()[1:-1] for ln in conf.splitlines() if ln.startswith("[") and ln.strip().endswith("]")]
    assert headers == ["General", "Host", "Proxy", "Proxy Group", "Rule", "MITM"]


def test_rule_section_derives_one_ruleset_line_each_plus_final():
    rules = _sections(su.render_config(su.DEVICES[0]))["Rule"]
    rule_set_lines = [ln for ln in rules if ln.startswith("RULE-SET,")]
    required = [ruleset for ruleset in RULESETS if ruleset.tag != "Ads-Reject-Heavy"]
    assert len(rule_set_lines) == len(required)
    assert rules[-1] == "FINAL,全局代理"
    # Each ruleset maps to its policy at its Surge tree URL, in RULESETS priority order.
    for ruleset, line in zip(required, rule_set_lines):
        assert line == f"RULE-SET,{su.SURGE_RAW_BASE}/{ruleset.file},{ruleset.policy}"


def test_every_rule_policy_resolves_to_a_group_or_builtin():
    conf = su.render_config(su.DEVICES[0])
    sections = _sections(conf)
    group_names = {ln.split("=", 1)[0].strip() for ln in sections["Proxy Group"]}
    for line in sections["Rule"]:
        policy = line.rsplit(",", 1)[1]
        assert policy in group_names or policy in BUILTIN_POLICIES, f"dangling policy: {policy}"


def test_all_service_groups_choose_chain_first():
    groups = _sections(su.render_config(su.DEVICES[0]))["Proxy Group"]
    policies = {ruleset.policy for ruleset in RULESETS} - BUILTIN_POLICIES - {"广告分流"}
    policies |= {"全局代理", "大陆流量", "Claude"}
    for policy in policies:
        line = next(line for line in groups if line.startswith(f"{policy} = "))
        assert line.split(",", 2)[1] == "链式代理链路", policy


def test_service_groups_preserve_direct_and_all_region_choices():
    groups = _sections(su.render_config(su.DEVICES[0]))["Proxy Group"]
    policies = {ruleset.policy for ruleset in RULESETS} - BUILTIN_POLICIES - {"广告分流"}
    for policy in policies | {"全局代理", "大陆流量"}:
        line = next(line for line in groups if line.startswith(f"{policy} = "))
        members = set(line.split(",")[1:])
        assert {"DIRECT", *su.REGIONS} <= members, policy


def test_chain_selector_contains_only_configured_chain_link_nodes():
    groups = _sections(su.render_config(su.DEVICES[0]))["Proxy Group"]
    assert "链式代理链路 = select,{{CHAIN_LINK_NODES}}" in groups
    assert "链式代理节点 = select,{{CHAIN_NODES}}" in groups


def test_heavy_ads_binding_is_commented_opt_in():
    text = su.render_config(su.DEVICES[0])
    heavy = next(ruleset for ruleset in RULESETS if ruleset.tag == "Ads-Reject-Heavy")
    binding = f"RULE-SET,{su.SURGE_RAW_BASE}/{heavy.file},{heavy.policy}"
    assert f"#{binding}" in text.splitlines()
    assert binding not in _sections(text)["Rule"]


def test_device_delta_is_home_access_mitm_hostname_and_mac_general_keys():
    ios = su.render_config(su.DEVICES[0]).splitlines()
    mac = su.render_config(su.DEVICES[1]).splitlines()
    # Ignore the first line (header names the device).
    only_ios = set(ios[1:]) - set(mac[1:])
    only_mac = set(mac[1:]) - set(ios[1:])
    assert only_ios == {"Home-Orca-WG = {{HOME_WG_NODE}}", "hostname = {{MITM_HOSTNAMES}}"}
    assert only_mac == set(su.MAC_GENERAL_EXTRA)


def test_mac_general_extra_enables_lan_sharing_and_http_api():
    general = _sections(su.render_config(su.DEVICES[1]))["General"]
    assert "allow-wifi-access = true" in general
    assert "http-api-web-dashboard = true" in general
    # The HTTP-API key is private and must stay a placeholder in the public skeleton.
    http_api = next(ln for ln in general if ln.startswith("http-api = "))
    assert "{{HTTP_API_KEY}}" in http_api
    # iOS must not carry the Mac-only gateway/control keys.
    ios_general = _sections(su.render_config(su.DEVICES[0]))["General"]
    assert not any(ln.startswith(("allow-wifi-access", "http-api")) for ln in ios_general)


def test_private_sections_are_all_placeholders():
    import audit_public_artifacts as audit

    for device in su.DEVICES:
        assert audit.private_section_leaks(su.render_config(device)) == []


def test_okx_family_pinned_to_encrypted_doh():
    # OKX/OKLink/OKEX geo-steer by DNS; the system resolver hands back a dead 169.254.0.2 sinkhole
    # for the AWS-China line, so the site won't open. Each must be pinned (apex + wildcard) to an
    # encrypted DoH resolver — plain UDP would be spoofable on a hostile network.
    host = _sections(su.render_config(su.DEVICES[0]))["Host"]
    assert su.CLEAN_DOH.startswith("https://"), "DNS pin must be DoH, not spoofable plain UDP"
    for domain in ("okx.com", "oklink.com", "okex.com"):
        assert f"{domain} = server:{su.CLEAN_DOH}" in host
        assert f"*.{domain} = server:{su.CLEAN_DOH}" in host


def test_host_pins_do_not_leak_beyond_the_finance_hosts():
    # The pin is deliberately narrow so the tailnet's MagicDNS stays the default resolver for
    # everything else (home-access machine names depend on it). Guard against scope creep.
    host = _sections(su.render_config(su.DEVICES[0]))["Host"]
    assert len(host) == 2 * len(su.DOH_PINNED_HOSTS)


def test_build_writes_both_devices(tmp_path):
    su.build(tmp_path)
    assert (tmp_path / "ios.conf").exists()
    assert (tmp_path / "mac.conf").exists()
