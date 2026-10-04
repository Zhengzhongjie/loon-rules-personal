#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate high-signal invariants for the user's Loon config."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path

import build_loon_rules
from validate_generated import validate_generated_tree


# The intended remote-rule order is the builder's RULESETS order — the single
# source of truth. Deriving it here (instead of re-typing 27 tags) stops the
# validator and builder from drifting. RULESETS is the build-time authored
# intent, not the generated MANIFEST, so validate still checks output (the
# manifest and the .lcf) against an oracle independent of those artifacts.
REMOTE_RULE_ORDER = [ruleset.tag for ruleset in build_loon_rules.RULESETS]

REQUIRED_REMOTE_TAGS = set(REMOTE_RULE_ORDER)
OPTIONAL_DISABLED_REMOTE_TAGS = {"Ads-Reject-Heavy"}

GENERATED_RULE_DIR = Path(__file__).resolve().parents[1] / "rules" / "loon" / "generated"
GENERATED_RAW_PREFIX = "https://raw.githubusercontent.com/Zhengzhongjie/loon-rules-personal/main/rules/loon/generated/"

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
    enabled: bool | None = True


@dataclass(frozen=True)
class LoonConfig:
    section_names: frozenset[str]
    general_text: str
    policy_groups: frozenset[str]
    rule_lines: list[str]
    remote_rules: list[RemoteRule]
    plugin_lines: list[str]
    proxy_lines: list[str] = field(default_factory=list)
    mitm_lines: list[str] = field(default_factory=list)
    proxy_group_lines: list[str] = field(default_factory=list)
    proxy_chain_lines: list[str] = field(default_factory=list)
    remote_filter_lines: list[str] = field(default_factory=list)
    remote_proxy_lines: list[str] = field(default_factory=list)


def _single(pattern: str, line: str) -> str | None:
    matches = re.findall(pattern, line)
    if len(matches) != 1:
        return None
    return matches[0].strip() or None


def parse_remote_rule(line: str) -> RemoteRule:
    url = line.split(",", 1)[0].strip() if line.startswith(("http://", "https://")) else None
    enabled_values = re.findall(r"(?:^|,\s*)enabled\s*=\s*([^,]*)", line)
    if not enabled_values:
        enabled = True
    elif len(enabled_values) == 1 and enabled_values[0].strip().lower() in {"true", "false"}:
        enabled = enabled_values[0].strip().lower() == "true"
    else:
        enabled = None
    return RemoteRule(
        url,
        _single(r"(?:^|,\s*)tag\s*=\s*([^,]*)", line),
        _single(r"(?:^|,\s*)policy\s*=\s*([^,]*)", line),
        enabled,
    )


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
        proxy_lines=active_lines(sections.get("Proxy", [])),
        mitm_lines=active_lines(sections.get("Mitm", [])),
        proxy_group_lines=active_lines(sections.get("Proxy Group", [])),
        proxy_chain_lines=active_lines(sections.get("Proxy Chain", [])),
        remote_filter_lines=active_lines(sections.get("Remote Filter", [])),
        remote_proxy_lines=active_lines(sections.get("Remote Proxy", [])),
    )


REQUIRED_SECTIONS = ["General", "Proxy Group", "Remote Filter", "Proxy Chain", "Rule", "Remote Rule", "Plugin", "Mitm"]

# Every non-builtin policy a ruleset routes to must exist as a policy group in the
# config. Derived from RULESETS (first-appearance order) so retagging or adding a
# ruleset updates the requirement in one place instead of a hand-typed mirror.
REQUIRED_POLICY_GROUPS = [
    policy
    for policy in dict.fromkeys(rs.policy for rs in build_loon_rules.RULESETS)
    if policy not in BUILTIN_POLICIES
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
    hijack_values = re.findall(r"(?m)^\s*hijack-dns\s*=\s*([^#\r\n]*)", general)
    if len(hijack_values) != 1:
        errors.append("General must define exactly one hijack-dns setting")
    elif "*:53" not in {token.strip() for token in hijack_values[0].split(",") if token.strip()}:
        errors.append("hijack-dns should explicitly include *:53 for app UDP DNS capture")
    return errors


RFC1918_NETWORKS = tuple(ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
HOME_TUNNEL_NETWORK = ip_network("198.18.0.0/15")


def _is_device_local_ip_rule(line: str) -> bool:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) not in (3, 4) or parts[0].upper() != "IP-CIDR":
        return False
    if len(parts) == 4 and parts[3].lower() != "no-resolve":
        return False
    if "/" not in parts[1]:
        return False
    try:
        network = ip_network(parts[1], strict=False)
    except ValueError:
        return False
    if network.version != 4 or network.prefixlen != 32:
        return False
    private_host = any(network.subnet_of(private) for private in RFC1918_NETWORKS)
    if parts[2] == "DIRECT":
        return private_host
    # Generated service rules own managed policies. Inline IP rules are reserved for a device-only
    # proxy target that cannot be published. The existing home tunnel uses the benchmarking range;
    # only single private/tunnel hosts qualify, never public hosts or a replacement global route.
    managed_policies = set(REQUIRED_POLICY_GROUPS) | BUILTIN_POLICIES
    return bool(parts[2]) and parts[2] not in managed_policies and (
        private_host or network.subnet_of(HOME_TUNNEL_NETWORK)
    )


def check_rule_section(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    if not cfg.rule_lines or cfg.rule_lines[-1] != "FINAL,全局代理" or cfg.rule_lines.count("FINAL,全局代理") != 1:
        errors.append("[Rule] must end with exactly one FINAL,全局代理")
    # Allow authored domain supplements locally while remote subscriptions refresh.
    reviewed_supplements = {
        f"{rule},{ruleset.policy}"
        for ruleset in build_loon_rules.RULESETS
        for rule in ruleset.additions
        if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,"))
    }
    unexpected = [
        line for line in cfg.rule_lines
        if line != "FINAL,全局代理" and line not in reviewed_supplements and not _is_device_local_ip_rule(line)
    ]
    if unexpected:
        errors.append(
            "[Rule] may contain only device-local IP-CIDR exceptions or reviewed domain supplements before FINAL; "
            "other service and regex rules belong in generated subscriptions"
        )
    return errors


def check_policy_groups(cfg: LoonConfig) -> list[str]:
    return [f"missing policy group {group}" for group in REQUIRED_POLICY_GROUPS if group not in cfg.policy_groups]


def check_policy_references(cfg: LoonConfig) -> list[str]:
    """Check the authored policy graph, treating remote filters/subscriptions as leaves."""
    errors: list[str] = []
    definition_lines = (
        cfg.proxy_group_lines + cfg.proxy_chain_lines + cfg.proxy_lines
        + cfg.remote_filter_lines + cfg.remote_proxy_lines
    )
    names = [line.partition("=")[0].strip() for line in definition_lines if "=" in line]
    for name, count in sorted(Counter(names).items()):
        if count > 1:
            errors.append(f"duplicate policy definition: {name}")
    allowed = set(names) | cfg.policy_groups | BUILTIN_POLICIES
    graph: dict[str, list[str]] = {}
    for lines, is_group in ((cfg.proxy_group_lines, True), (cfg.proxy_chain_lines, False)):
        for line in lines:
            name, separator, body = line.partition("=")
            if not separator:
                continue
            name = name.strip()
            fields = body.split(",")
            if is_group:
                fields = fields[1:]  # select/url-test/fallback type precedes candidate names
            members: list[str] = []
            for field in fields:
                member = field.strip()
                if "=" in member:
                    break  # trailing options may contain quoted commas; they are not policy references
                if member:
                    members.append(member)
            for member, count in sorted(Counter(members).items()):
                if count > 1:
                    errors.append(f"duplicate policy member: {name} -> {member}")
                if member not in allowed:
                    errors.append(f"missing policy reference: {name} -> {member}")
            graph[name] = members

    for line in cfg.rule_lines:
        fields = [part.strip() for part in line.split(",")]
        if len(fields) < 2:
            continue
        policy = fields[-2] if fields[-1].lower() == "no-resolve" else fields[-1]
        if policy not in allowed:
            errors.append(f"missing policy reference: [Rule] -> {policy}")

    visited: set[str] = set()
    visiting: list[str] = []

    def visit(name: str) -> None:
        if name in visiting:
            cycle = visiting[visiting.index(name):] + [name]
            errors.append("policy reference cycle: " + " -> ".join(cycle))
            return
        if name in visited:
            return
        visiting.append(name)
        for member in graph[name]:
            if member in graph:
                visit(member)
        visiting.pop()
        visited.add(name)

    for name in sorted(graph):
        visit(name)
    return errors


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
    for rule in cfg.remote_rules:
        if rule.enabled is None:
            errors.append(f"remote rule {rule.tag or '(untagged)'} has invalid enabled setting")
        elif rule.tag in REQUIRED_REMOTE_TAGS - OPTIONAL_DISABLED_REMOTE_TAGS and rule.enabled is not True:
            errors.append(f"remote rule {rule.tag} must be enabled")
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
    expected_urls = {ruleset.tag: GENERATED_RAW_PREFIX + ruleset.file for ruleset in build_loon_rules.RULESETS}
    for rule in cfg.remote_rules:
        if rule.tag in expected_urls and rule.url != expected_urls[rule.tag]:
            errors.append(f"remote tag URL mismatch: {rule.tag}: expected {expected_urls[rule.tag]}, got {rule.url}")
    return errors


def check_remote_policies(cfg: LoonConfig) -> list[str]:
    allowed_policies = cfg.policy_groups | BUILTIN_POLICIES
    policies = [rule.policy for rule in cfg.remote_rules if rule.policy]
    unresolved = sorted({policy for policy in policies if policy not in allowed_policies})
    if unresolved:
        return ["remote rules reference missing policies: " + ", ".join(unresolved)]
    return []


def check_remote_tag_policies(cfg: LoonConfig, manifest_policies: dict[str, str] | None = None) -> list[str]:
    # The authored catalogue is the default oracle, independent of generated artifacts.
    if manifest_policies is None:
        manifest_policies = {ruleset.tag: ruleset.policy for ruleset in build_loon_rules.RULESETS}
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


def check_mitm(cfg: LoonConfig) -> list[str]:
    settings = [
        line.partition("=")[2].strip().lower()
        for line in cfg.mitm_lines
        if line.partition("=")[0].strip() == "skip-server-cert-verify"
    ]
    if settings != ["false"]:
        return ["[Mitm] skip-server-cert-verify must be false and defined exactly once"]
    return []


# WireGuard node values that carry base64 padding ('=') or '/'/'+' (keys) or a CIDR
# slash (allowed-ips) collide with Loon's '=' (key/value) and ',' (field) delimiters.
# Loon only parses them when double-quoted; an unquoted value silently corrupts the
# whole [Proxy] line and Loon reports a syntax error. This has bitten the live
# Home-Orca-WG node repeatedly — gate it. See memory: loon-wireguard-quote-base64.
WG_QUOTED_FIELDS = ("private-key", "public-key", "preshared-key", "allowed-ips")


def check_proxy_wireguard(cfg: LoonConfig) -> list[str]:
    errors: list[str] = []
    for line in cfg.proxy_lines:
        name, sep, body = line.partition("=")
        # Only WireGuard nodes need the quoting guard; a '{{...}}' template placeholder
        # (committed config) has no literal keys, so it is correctly skipped here.
        if not sep or body.strip().split(",", 1)[0].strip() != "wireguard":
            continue
        name = name.strip()
        for field_name in WG_QUOTED_FIELDS:
            match = re.search(rf"(?<![\w-]){re.escape(field_name)}\s*=\s*([^,}}\]]+)", line)
            if not match:
                continue
            value = match.group(1).strip()
            if not (len(value) >= 2 and value.startswith('"') and value.endswith('"')):
                errors.append(
                    f"[Proxy] WireGuard node '{name}': {field_name} must be double-quoted "
                    "(base64/CIDR values collide with Loon's '=' and ',' delimiters)"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()

    cfg = parse_loon_config(args.config.read_text())

    errors: list[str] = []
    errors += check_required_sections(cfg)
    errors += check_general(cfg)
    errors += check_rule_section(cfg)
    errors += check_proxy_wireguard(cfg)
    errors += check_policy_groups(cfg)
    errors += check_policy_references(cfg)
    errors += check_remote_tags(cfg)
    errors += check_remote_urls(cfg)
    errors += check_remote_policies(cfg)
    errors += check_remote_tag_policies(cfg)
    errors += validate_generated_tree(GENERATED_RULE_DIR)
    errors += check_plugins(cfg)
    errors += check_mitm(cfg)

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: Loon config invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
