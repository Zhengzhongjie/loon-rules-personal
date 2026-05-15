#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate high-signal invariants for the user's Loon config."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REMOTE_RULE_ORDER = [
    "Ads-Reject",
    "LAN-Direct",
    "AccountSafety-DIRECT",
    "Mainland-Services-Direct",
    "Seetong-Local",
    "PayPal-Stable",
    "FinanceCrypto-Stable",
    "Adobe",
    "AI",
    "Apple",
    "RedNote",
    "Weibo",
    "TikTok",
    "Douyin-ByteDance",
    "Bilibili",
    "Telegram",
    "Microsoft",
    "Meta",
    "YouTube",
    "Google",
    "GitHub",
    "Developer-Collab",
    "Global-Social-Info",
    "Streaming",
    "Amazon",
    "Talkatone",
    "ChinaASN-Direct",
]

REQUIRED_REMOTE_TAGS = set(REMOTE_RULE_ORDER)

GENERATED_RULE_DIR = Path(__file__).resolve().parents[1] / "rules" / "loon" / "generated"
GENERATED_RAW_PREFIX = "https://raw.githubusercontent.com/Zhengzhongjie/codex-loon-rules/main/rules/loon/generated/"

BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DICT", "REJECT-DROP"}

HIGH_RISK_PLUGIN_MARKERS = {
    "BiliBili.ADBlock.plugin",
    "BiliBili.Enhanced.plugin",
    "Disney%2B.plugin",
    "Netflix.beta.plugin",
}


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


def remote_rule_tag_policies(lines: list[str]) -> dict[str, str]:
    policies: dict[str, str] = {}
    for line in active_lines(lines):
        tag_match = re.search(r"(?:^|,\s*)tag=([^,]+)", line)
        policy_match = re.search(r"(?:^|,\s*)policy=([^,]+)", line)
        if tag_match and policy_match:
            policies[tag_match.group(1).strip()] = policy_match.group(1).strip()
    return policies


def manifest_entries() -> list[tuple[str, str, Path]]:
    manifest = GENERATED_RULE_DIR / "MANIFEST.csv"
    entries: list[tuple[str, str, Path]] = []
    for raw in manifest.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tag, policy, path, _count = [part.strip() for part in line.split(",", 3)]
        entries.append((tag, policy, Path(path)))
    return entries


def split_rule(line: str) -> tuple[str, str] | None:
    if not line or line.startswith("#") or "," not in line:
        return None
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        return None
    return parts[0].upper(), parts[1].lower() if parts[0].upper().startswith("DOMAIN") else parts[1]


def covered_by_suffix(rule_type: str, value: str, suffixes: list[tuple[str, str]]) -> str | None:
    if rule_type not in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return None
    domain = value.lower().strip(".")
    for suffix, tag in suffixes:
        if domain == suffix or domain.endswith("." + suffix):
            return tag
    return None


def validate_generated_rules(errors: list[str]) -> None:
    entries = manifest_entries()
    if [tag for tag, _policy, _path in entries] != REMOTE_RULE_ORDER:
        errors.append("generated rule manifest order does not match expected remote-rule order")
    expected_files = {Path(path).name for _tag, _policy, path in entries}
    actual_files = {path.name for path in GENERATED_RULE_DIR.glob("*.list")}
    stale_files = sorted(actual_files - expected_files)
    if stale_files:
        errors.append("stale generated rule files: " + ", ".join(stale_files))

    exact_seen: dict[tuple[str, str], str] = {}
    suffixes: list[tuple[str, str]] = []
    for tag, _policy, rel_path in entries:
        path = Path(__file__).resolve().parents[1] / rel_path
        if not path.exists():
            errors.append(f"generated rule file missing: {rel_path}")
            continue
        local_seen: set[tuple[str, str]] = set()
        for raw in active_lines(path.read_text().splitlines()):
            parsed = split_rule(raw)
            if parsed is None:
                errors.append(f"{rel_path}: invalid rule line: {raw}")
                continue
            rule_type, value = parsed
            key = (rule_type, value)
            if key in local_seen:
                errors.append(f"{rel_path}: duplicate local rule: {raw}")
            if key in exact_seen:
                errors.append(f"{rel_path}: duplicate cross-file rule also in {exact_seen[key]}: {raw}")
            covered = covered_by_suffix(rule_type, value, suffixes)
            if covered is not None and tag != "ChinaASN-Direct":
                errors.append(f"{rel_path}: rule covered by earlier {covered}: {raw}")
            local_seen.add(key)
            exact_seen[key] = tag
            if rule_type == "DOMAIN-SUFFIX":
                suffixes.append((value.strip("."), tag))


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
    if "ip-mode = ipv4-only" not in general:
        errors.append("ip-mode should be ipv4-only while IPv6 is being tested off")
    if "ipv6-vif = off" not in general:
        errors.append("ipv6-vif should stay off during stability testing")
    if "hijack-dns =" not in general:
        errors.append("DNS hijack should be enabled for the fake-IP rule system")

    rule_lines = active_lines(sections.get("Rule", []))
    if rule_lines != ["FINAL,全局代理"]:
        errors.append("[Rule] should contain only FINAL; service rules belong in generated remote subscriptions")

    groups = group_names(sections.get("Proxy Group", [])) | group_names(sections.get("Proxy Chain", []))
    for group in [
        "全局代理",
        "广告分流",
        "Adobe",
        "AI",
        "PayPal",
        "金融加密",
        "Seetong",
        "Amazon",
        "Apple",
        "YouTube",
        "Google",
        "GitHub",
        "开发协作",
        "海外社交资讯",
        "Microsoft",
        "Meta",
        "Telegram",
        "TikTok",
        "Bilibili",
        "RedNote",
        "抖音",
        "Weibo",
        "境外流媒体",
    ]:
        if group not in groups:
            errors.append(f"missing policy group {group}")

    remote_lines = sections.get("Remote Rule", [])
    tags = remote_rule_tags(remote_lines)
    missing_tags = sorted(REQUIRED_REMOTE_TAGS - set(tags))
    if missing_tags:
        errors.append("missing remote tags: " + ", ".join(missing_tags))
    extra_tags = sorted(set(tags) - REQUIRED_REMOTE_TAGS)
    if extra_tags:
        errors.append("unexpected remote tags: " + ", ".join(extra_tags))
    if tags != REMOTE_RULE_ORDER:
        errors.append("remote rule tags must exactly match generated priority order")

    order_positions = [tags.index(tag) for tag in REMOTE_RULE_ORDER if tag in tags]
    if order_positions != sorted(order_positions):
        errors.append("remote rule tags are not in expected priority order")

    urls = remote_rule_urls(remote_lines)
    duplicate_urls = sorted({url for url in urls if urls.count(url) > 1})
    if duplicate_urls:
        errors.append("duplicate remote rule URLs: " + ", ".join(duplicate_urls))
    for url in urls:
        if not url.startswith(GENERATED_RAW_PREFIX):
            errors.append(f"remote rule should use generated repo subscription, got: {url}")

    allowed_policies = groups | BUILTIN_POLICIES
    unresolved = sorted({policy for policy in remote_rule_policies(remote_lines) if policy not in allowed_policies})
    if unresolved:
        errors.append("remote rules reference missing policies: " + ", ".join(unresolved))
    manifest_policies = {tag: policy for tag, policy, _path in manifest_entries()}
    actual_policies = remote_rule_tag_policies(remote_lines)
    policy_mismatches = sorted(
        f"{tag}: expected {policy}, got {actual_policies.get(tag)}"
        for tag, policy in manifest_policies.items()
        if actual_policies.get(tag) != policy
    )
    if policy_mismatches:
        errors.append("remote tag policy mismatch: " + "; ".join(policy_mismatches))

    validate_generated_rules(errors)

    plugins = "\n".join(active_lines(sections.get("Plugin", [])))
    if "cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rewrite/Loon/AdvertisingLite" in plugins:
        errors.append("AdvertisingLite still uses jsDelivr URL")
    if "raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/Loon/AdvertisingLite/AdvertisingLite.plugin" not in plugins:
        errors.append("AdvertisingLite raw GitHub URL missing")
    for line in active_lines(sections.get("Plugin", [])):
        for marker in HIGH_RISK_PLUGIN_MARKERS:
            if marker in line and "enabled=false" not in line:
                errors.append(f"account-risk plugin should be disabled: {marker}")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: Loon config invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
