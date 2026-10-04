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
    }
    for host, policy in expected.items():
        assert router.match(host) == policy, (dialect, host, router.match(host), policy)


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
