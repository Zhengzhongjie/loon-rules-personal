#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate high-signal invariants for the user's Loon config."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REMOTE_RULE_ORDER = [
    "AWAvenue-Ads-Rule-Surge-RULE-SET.list",
    "LAN@奶思",
    "百度",
    "WeChat",
    "Tencent",
    "Alibaba",
    "NetEase",
    "PayPal",
    "Stripe",
    "Binance",
    "OKX",
    "Crypto",
    "Bloomberg",
    "Adobe",
    "AdobeActivation",
    "OpenAI",
    "Claude",
    "Anthropic",
    "Gemini",
    "Copilot",
    "AI合集",
    "Apple",
    "iCloud",
    "iCloudPrivateRelay",
    "TestFlight",
    "AppleNews",
    "AppleTV",
    "AppleMusic",
    "XiaoHongShu.list",
    "Weibo",
    "DouYin",
    "TikTok",
    "字节跳动",
    "BiliBili",
    "BiliBiliIntl",
    "Telegram",
    "ASN.Telegram.list",
    "Microsoft",
    "OneDrive",
    "Teams",
    "Bing",
    "Xbox",
    "LinkedIn",
    "Facebook",
    "Instagram",
    "Whatsapp",
    "Threads",
    "YouTube",
    "YouTubeMusic",
    "GoogleVoice",
    "GoogleDrive",
    "Google",
    "GitHub",
    "GitLab",
    "Docker",
    "X/Twitter",
    "Discord",
    "Reddit",
    "Wikipedia",
    "Dropbox",
    "Netflix",
    "Disney",
    "HBO",
    "Hulu",
    "PrimeVideo",
    "ParamountPlus",
    "Peacock",
    "DAZN",
    "Twitch",
    "Spotify",
    "BBC",
    "Bahamut",
    "ViuTV",
    "AbemaTV",
    "Niconico",
    "ProxyMedia.list",
    "Amazon",
    "Talkatone分流",
    "ASN.China.list",
]

REQUIRED_REMOTE_TAGS = {
    "AWAvenue-Ads-Rule-Surge-RULE-SET.list",
    "LAN@奶思",
    "百度",
    "WeChat",
    "Tencent",
    "Alibaba",
    "PayPal",
    "Stripe",
    "Binance",
    "OKX",
    "Crypto",
    "Adobe",
    "AdobeActivation",
    "OpenAI",
    "Claude",
    "Anthropic",
    "Gemini",
    "Copilot",
    "AI合集",
    "TestFlight",
    "Apple",
    "iCloud",
    "iCloudPrivateRelay",
    "AppleTV",
    "YouTube",
    "YouTubeMusic",
    "Google",
    "GoogleDrive",
    "Facebook",
    "Instagram",
    "Whatsapp",
    "Threads",
    "GitHub",
    "XiaoHongShu.list",
    "DouYin",
    "TikTok",
    "字节跳动",
    "Telegram",
    "ASN.Telegram.list",
    "BiliBili",
    "Microsoft",
    "OneDrive",
    "Spotify",
    "ProxyMedia.list",
    "ASN.China.list",
}

BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DICT", "REJECT-DROP"}


def parse_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(raw_line)
    return sections


def active_lines(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def group_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for line in active_lines(lines):
        if "=" in line:
            names.add(line.split("=", 1)[0].strip())
    return names


def remote_rule_tags(lines: list[str]) -> list[str]:
    tags: list[str] = []
    for line in active_lines(lines):
        match = re.search(r"(?:^|,\s*)tag=([^,]+)", line)
        if match:
            tags.append(match.group(1).strip())
    return tags


def remote_rule_policies(lines: list[str]) -> list[str]:
    policies: list[str] = []
    for line in active_lines(lines):
        match = re.search(r"(?:^|,\s*)policy=([^,]+)", line)
        if match:
            policies.append(match.group(1).strip())
    return policies


def remote_rule_urls(lines: list[str]) -> list[str]:
    urls: list[str] = []
    for line in active_lines(lines):
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line.split(",", 1)[0].strip())
    return urls


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()

    text = args.config.read_text()
    sections = parse_sections(text)
    errors: list[str] = []

    for section in ["General", "Proxy Group", "Remote Filter", "Proxy Chain", "Rule", "Remote Rule", "Plugin", "Mitm"]:
        if section not in sections:
            errors.append(f"missing section [{section}]")

    general = "\n".join(sections.get("General", []))
    if "skip-proxy =" not in general:
        errors.append("missing General skip-proxy")
    if "bypass-tun =" not in general:
        errors.append("missing General bypass-tun")

    rule_lines = active_lines(sections.get("Rule", []))
    if "FINAL,全局代理" not in rule_lines:
        errors.append("FINAL must route to 全局代理")
    for reconnect_rule in [
        "DOMAIN-SUFFIX,chatgpt.com,AI",
        "DOMAIN-SUFFIX,openai.com,AI",
        "DOMAIN-SUFFIX,oaistatic.com,AI",
        "DOMAIN-SUFFIX,oaiusercontent.com,AI",
        "DOMAIN-SUFFIX,statsigapi.net,AI",
        "DOMAIN-SUFFIX,featuregates.org,AI",
        "DOMAIN-SUFFIX,launchdarkly.com,AI",
        "DOMAIN,challenges.cloudflare.com,AI",
    ]:
        if reconnect_rule not in rule_lines:
            errors.append(f"missing Codex reconnect rule: {reconnect_rule}")

    for local_rule in [
        "DOMAIN-SUFFIX,seetong.com,Seetong",
        "DOMAIN-SUFFIX,seetong.app,Seetong",
        "DOMAIN-SUFFIX,wise.com,金融加密",
        "DOMAIN-SUFFIX,revolut.com,金融加密",
        "DOMAIN-SUFFIX,interactivebrokers.com,金融加密",
        "DOMAIN-SUFFIX,ibkr.com,金融加密",
        "DOMAIN-SUFFIX,payoneer.com,金融加密",
        "DOMAIN-SUFFIX,plaid.com,金融加密",
    ]:
        if local_rule not in rule_lines:
            errors.append(f"missing local supplemental rule: {local_rule}")

    groups = group_names(sections.get("Proxy Group", [])) | group_names(sections.get("Proxy Chain", []))
    for group in [
        "全局代理",
        "广告分流",
        "Adobe",
        "AI",
        "金融加密",
        "Seetong",
        "Amazon",
        "开发协作",
        "海外社交资讯",
        "Telegram",
        "境外流媒体",
        "大陆流量",
    ]:
        if group not in groups:
            errors.append(f"missing policy group {group}")

    remote_lines = sections.get("Remote Rule", [])
    tags = remote_rule_tags(remote_lines)
    missing_tags = sorted(REQUIRED_REMOTE_TAGS - set(tags))
    if missing_tags:
        errors.append("missing remote tags: " + ", ".join(missing_tags))

    order_positions = [tags.index(tag) for tag in REMOTE_RULE_ORDER if tag in tags]
    if order_positions != sorted(order_positions):
        errors.append("remote rule tags are not in expected priority order")

    urls = remote_rule_urls(remote_lines)
    duplicate_urls = sorted({url for url in urls if urls.count(url) > 1})
    if duplicate_urls:
        errors.append("duplicate remote rule URLs: " + ", ".join(duplicate_urls))

    allowed_policies = groups | BUILTIN_POLICIES
    unresolved = sorted({policy for policy in remote_rule_policies(remote_lines) if policy not in allowed_policies})
    if unresolved:
        errors.append("remote rules reference missing policies: " + ", ".join(unresolved))

    plugins = "\n".join(active_lines(sections.get("Plugin", [])))
    if "cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rewrite/Loon/AdvertisingLite" in plugins:
        errors.append("AdvertisingLite still uses jsDelivr URL")
    if "raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/Loon/AdvertisingLite/AdvertisingLite.plugin" not in plugins:
        errors.append("AdvertisingLite raw GitHub URL missing")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: Loon config invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
