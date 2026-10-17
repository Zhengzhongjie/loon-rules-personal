"""Protect functional endpoints and service ownership in the published trees."""
from pathlib import Path

import pytest

from inspect_routing import DomainRouter, load_domain_routes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("dialect", ["loon", "shadowrocket", "surge"])
def test_functional_hosts_reach_their_owner_policy(dialect):
    router = DomainRouter(load_domain_routes(ROOT / "rules" / dialect / "generated"))
    expected = {
        "api.stripe.com": "金融加密", "js.stripe.com": "金融加密",
        "m.stripe.network": "金融加密", "assets.stripecdn.com": "金融加密",
        "accounts.google.com": "Google", "gemini.google.com": "Google",
        "aistudio.google.com": "Google", "generativelanguage.googleapis.com": "Google",
        "notebooklm.google.com": "Google", "copilot.microsoft.com": "Microsoft",
        "login.live.com": "Microsoft", "api.githubcopilot.com": "GitHub",
        "chatgpt.com": "AI", "auth0.openai.com": "AI", "api.oaistatsig.com": "AI",
        "o207216.ingest.sentry.io": "AI", "unrelated.auth0.com": "FINAL",
        "other.ingest.sentry.io": "FINAL", "unrelated.algolia.net": "FINAL",
        "data.financialresearch.gov": "海外社交资讯", "api.hypurrscan.io": "金融加密",
        "sec.gov": "金融加密", "www.sec.gov": "金融加密",
        "api.hyperliquid.xyz": "金融加密", "api-ui.hyperliquid.xyz": "金融加密",
        "rpc.hyperliquid.xyz": "金融加密", "down.zbrowser.cn": "DIRECT",
        "www.amazon.com": "Amazon", "atv-ps.amazon.com": "境外流媒体",
        "unrelated.edgesuite.net": "FINAL", "unrelated.akadns.net": "FINAL",
        "safebrowsing.googleapis.com": "Google", "sb-ssl.google.com": "Google",
        "proxy.safebrowsing.apple": "Apple", "token.safebrowsing.apple": "Apple",
        "safebrowsing.g.applimg.com": "Apple", "safebrowsing.urlsec.qq.com": "DIRECT",
        "crl.microsoft.com": "Microsoft", "activate.adobe.com": "Adobe",
        "lm.licenses.adobe.com": "Adobe", "na2m-pr.licenses.adobe.com": "Adobe",
        "na1r.services.adobe.com": "Adobe", "api.iqiyi.com": "DIRECT",
        "httpdns.alicdn.com": "DIRECT", "x.com": "X", "twitter.com": "X",
        "staticxx.facebook.com": "Meta", "sdb.amazonaws.com": "Amazon",
        "auto.platform.atas.net": "金融加密", "api.atas.net": "金融加密",
        "assets.atas.net": "金融加密", "cfg.atas.net": "金融加密",
        "my.atas.net": "金融加密", "sntp.atas.net": "DIRECT",
        "updates.orderflowtrading.net": "金融加密",
        "support.orderflowtrading.ru": "金融加密",
        "atas.featurebase.app": "金融加密", "feed.financialjuice.com": "金融加密",
        "other.featurebase.app": "FINAL", "other.financialjuice.com": "FINAL",
        "tools.dxfeed.com": "金融加密", "get-prod-dxlink-d15m.dxfeed.com": "金融加密",
    }
    for host, policy in expected.items():
        assert router.match(host) == policy, (dialect, host, router.match(host), policy)


@pytest.mark.parametrize("dialect", ["loon", "shadowrocket", "surge"])
def test_atas_literal_auth_and_data_hosts_have_exact_routes(dialect):
    from ipaddress import ip_address, ip_network
    from rulegrammar import parse_rule

    tree = ROOT / "rules" / dialect / "generated"
    rules = [r for line in (tree / "06-FinanceCrypto-Stable.list").read_text().splitlines()
             if (r := parse_rule(line)) and r.rule_type == "IP-CIDR"]
    for host in ("51.178.130.10", "142.132.201.231", "65.21.32.251", "135.181.115.236",
                 "116.202.174.36", "178.105.188.57", "157.180.79.0", "51.89.6.194",
                 "65.21.228.47", "51.89.20.177", "65.108.201.31"):
        matching = [r for r in rules if ip_address(host) in ip_network(r.value)]
        assert len(matching) == 1
        assert ip_network(matching[0].value).prefixlen == 32
        assert matching[0].modifiers == ("no-resolve",)
        assert not any(ip_address(str(ip_address(host) + 1)) in ip_network(r.value) for r in rules)


def test_index_preserves_first_match_order_against_linear_reference():
    rules = [
        ("DOMAIN", "api.example.com", "API"),
        ("DOMAIN-SUFFIX", "example.com", "SITE"),
        ("DOMAIN-SUFFIX", "com", "TAIL"),
        ("DOMAIN", "api.example.com", "LATE"),
    ]
    router = DomainRouter(rules)
    for host in ["api.example.com", "other.example.com", "example.com", "com", "different.com", "none.test"]:
        expected = next((policy for kind, value, policy in rules if host == value or
                         kind == "DOMAIN-SUFFIX" and host.endswith("." + value)), "FINAL")
        assert router.match(host.upper() + ".") == expected


def test_heavy_remains_opt_in_and_can_reject_telemetry():
    tree = ROOT / "rules" / "loon" / "generated"
    light = DomainRouter(load_domain_routes(tree))
    heavy = DomainRouter(load_domain_routes(tree, include_heavy=True))
    assert light.match("metrics.hyperliquid.xyz") == "FINAL"
    assert heavy.match("metrics.hyperliquid.xyz") == "广告分流"
    assert heavy.match("api.hyperliquid.xyz") == "金融加密"
