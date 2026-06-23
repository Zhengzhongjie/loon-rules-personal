#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate high-signal invariants for the user's Loon config."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from rulegrammar import CoverageIndex, parse_rule


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


@dataclass(frozen=True)
class RemoteRule:
    url: str | None
    tag: str | None
    policy: str | None


@dataclass(frozen=True)
class LoonConfig:
    section_names: frozenset[str]
    general_text: str
    policy_groups: frozenset[str]
    rule_lines: list[str]
    remote_rules: list[RemoteRule]
    plugin_lines: list[str]


def _first(pattern: str, line: str) -> str | None:
    match = re.search(pattern, line)
    return match.group(1).strip() if match else None


def parse_remote_rule(line: str) -> RemoteRule:
    url = line.split(",", 1)[0].strip() if line.startswith(("http://", "https://")) else None
    return RemoteRule(url, _first(r"(?:^|,\s*)tag=([^,]+)", line), _first(r"(?:^|,\s*)policy=([^,]+)", line))


def parse_loon_config(text: str) -> LoonConfig:
    sections = parse_sections(text)
    return LoonConfig(
        section_names=frozenset(sections),
        general_text="\n".join(sections.get("General", [])),
        policy_groups=frozenset(
            group_names(sections.get("Proxy Group", [])) | group_names(sections.get("Proxy Chain", []))
        ),
        rule_lines=active_lines(sections.get("Rule", [])),
        remote_rules=[parse_remote_rule(line) for line in active_lines(sections.get("Remote Rule", []))],
        plugin_lines=active_lines(sections.get("Plugin", [])),
    )


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


def validate_generated_rules(errors: list[str]) -> None:
    entries = manifest_entries()
    if [tag for tag, _policy, _path in entries] != REMOTE_RULE_ORDER:
        errors.append("generated rule manifest order does not match expected remote-rule order")
    expected_files = {Path(path).name for _tag, _policy, path in entries}
    actual_files = {path.name for path in GENERATED_RULE_DIR.glob("*.list")}
    stale_files = sorted(actual_files - expected_files)
    if stale_files:
        errors.append("stale generated rule files: " + ", ".join(stale_files))

    index = CoverageIndex()
    for tag, _policy, rel_path in entries:
        path = Path(__file__).resolve().parents[1] / rel_path
        if not path.exists():
            errors.append(f"generated rule file missing: {rel_path}")
            continue
        local_seen: set[tuple[str, str]] = set()
        for raw in active_lines(path.read_text().splitlines()):
            rule = parse_rule(raw)
            if rule is None:
                errors.append(f"{rel_path}: invalid rule line: {raw}")
                continue
            key = (rule.rule_type, rule.value)
            if key in local_seen:
                errors.append(f"{rel_path}: duplicate local rule: {raw}")
            cross_tag = index.exact_tag(rule)
            if cross_tag is not None:
                errors.append(f"{rel_path}: duplicate cross-file rule also in {cross_tag}: {raw}")
            covered = index.covered_by(rule)
            if covered is not None and tag != "ChinaASN-Direct":
                errors.append(f"{rel_path}: rule covered by earlier {covered}: {raw}")
            local_seen.add(key)
            index.add(rule, tag)


REQUIRED_SECTIONS = ["General", "Proxy Group", "Remote Filter", "Proxy Chain", "Rule", "Remote Rule", "Plugin", "Mitm"]

REQUIRED_POLICY_GROUPS = [
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
]


def check_required_sections(cfg: LoonConfig) -> list[str]:
    return [f"missing section [{name}]" for name in REQUIRED_SECTIONS if name not in cfg.section_names]


def check_general(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    general = cfg.general_text
    if "skip-proxy =" not in general:
        errors.append("missing General skip-proxy")
    if "bypass-tun =" not in general:
        errors.append("missing General bypass-tun")
    if not re.search(r"(?m)^\s*ip-mode\s*=\s*(?:v4-only|ipv4-only)\s*$", general):
        errors.append("ip-mode should be v4-only while IPv6 is being tested off")
    if "ipv6-vif = off" not in general:
        errors.append("ipv6-vif should stay off during stability testing")
    if "hijack-dns =" not in general:
        errors.append("DNS hijack should be enabled for the fake-IP rule system")
    return errors


def check_rule_section(cfg: LoonConfig) -> list[str]:
    if cfg.rule_lines != ["FINAL,全局代理"]:
        return ["[Rule] should contain only FINAL; service rules belong in generated remote subscriptions"]
    return []


def check_policy_groups(cfg: LoonConfig) -> list[str]:
    return [f"missing policy group {group}" for group in REQUIRED_POLICY_GROUPS if group not in cfg.policy_groups]


def check_remote_tags(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    tags = [rule.tag for rule in cfg.remote_rules if rule.tag]
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
    return errors


def check_remote_urls(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    urls = [rule.url for rule in cfg.remote_rules if rule.url]
    duplicate_urls = sorted({url for url in urls if urls.count(url) > 1})
    if duplicate_urls:
        errors.append("duplicate remote rule URLs: " + ", ".join(duplicate_urls))
    for url in urls:
        if not url.startswith(GENERATED_RAW_PREFIX):
            errors.append(f"remote rule should use generated repo subscription, got: {url}")
    return errors


def check_remote_policies(cfg: LoonConfig) -> list[str]:
    allowed_policies = cfg.policy_groups | BUILTIN_POLICIES
    policies = [rule.policy for rule in cfg.remote_rules if rule.policy]
    unresolved = sorted({policy for policy in policies if policy not in allowed_policies})
    if unresolved:
        return ["remote rules reference missing policies: " + ", ".join(unresolved)]
    return []


def check_remote_tag_policies(cfg: LoonConfig, manifest_policies: dict[str, str]) -> list[str]:
    actual_policies = {rule.tag: rule.policy for rule in cfg.remote_rules if rule.tag and rule.policy}
    policy_mismatches = sorted(
        f"{tag}: expected {policy}, got {actual_policies.get(tag)}"
        for tag, policy in manifest_policies.items()
        if actual_policies.get(tag) != policy
    )
    if policy_mismatches:
        return ["remote tag policy mismatch: " + "; ".join(policy_mismatches)]
    return []


def check_plugins(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    plugins = "\n".join(cfg.plugin_lines)
    if "cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rewrite/Loon/AdvertisingLite" in plugins:
        errors.append("AdvertisingLite still uses jsDelivr URL")
    if "raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/Loon/AdvertisingLite/AdvertisingLite.plugin" not in plugins:
        errors.append("AdvertisingLite raw GitHub URL missing")
    for line in cfg.plugin_lines:
        for marker in HIGH_RISK_PLUGIN_MARKERS:
            if marker in line and "enabled=false" not in line:
                errors.append(f"account-risk plugin should be disabled: {marker}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()

    cfg = parse_loon_config(args.config.read_text())
    manifest_policies = {tag: policy for tag, policy, _path in manifest_entries()}

    errors: list[str] = []
    errors += check_required_sections(cfg)
    errors += check_general(cfg)
    errors += check_rule_section(cfg)
    errors += check_policy_groups(cfg)
    errors += check_remote_tags(cfg)
    errors += check_remote_urls(cfg)
    errors += check_remote_policies(cfg)
    errors += check_remote_tag_policies(cfg, manifest_policies)
    validate_generated_rules(errors)
    errors += check_plugins(cfg)

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: Loon config invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
