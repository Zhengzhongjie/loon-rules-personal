"""Patch private Loon configs without publishing nodes or certificate values."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import build_loon_rules as builder
import validate_loon_config as validator

CONFIG_NAMES = ("loon rules for iphone & ipad.lcf", "loon rules for mac.lcf")
LOCAL_SUPPLEMENTS = (
    "DOMAIN-SUFFIX,zbrowser.cn,DIRECT",
    "DOMAIN-SUFFIX,financialresearch.gov,海外社交资讯",
    "DOMAIN-SUFFIX,hypurrscan.io,金融加密",
    "DOMAIN,api.hyperliquid.xyz,金融加密",
    "DOMAIN,api-ui.hyperliquid.xyz,金融加密",
    "DOMAIN,rpc.hyperliquid.xyz,金融加密",
)


def split_fields(body):
    """Split comma-delimited Loon fields while keeping quoted values intact."""
    fields, start, quote, escaped = [], 0, None, False
    for index, char in enumerate(body):
        if escaped:
            escaped = False
        elif quote and char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ('"', "'") and (
            not body[start:index].strip() or body[start:index].rstrip().endswith("=")
        ):
            quote = char
        elif char == ",":
            fields.append(body[start:index].strip())
            start = index + 1
    if quote:
        raise ValueError("unterminated quoted group option")
    fields.append(body[start:].strip())
    return fields


def atomic_write(target, content, *, expected=None, mode=0o600):
    """Stage bytes, then optimistically recheck the target just before replacement.

    Unrelated writers do not share a compare-and-swap primitive with this tool;
    this catches edits during preparation without claiming a filesystem lock.
    """
    fd, temporary = tempfile.mkstemp(prefix=".loon-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if expected is not None:
            try:
                current = target.read_bytes()
            except FileNotFoundError:
                raise ValueError("configuration changed during update; stopped") from None
            if current != expected:
                raise ValueError("configuration changed during update; stopped")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rollback_writes(written, backup):
    """Restore our writes only; preserve any subsequent edit or deletion."""
    preserved = []
    for target, content in reversed(written):
        try:
            atomic_write(target, (backup / target.name).read_bytes(), expected=content,
                         mode=target.stat().st_mode & 0o777)
        except (OSError, ValueError):
            preserved.append(target)
    return preserved


def optimize_text(text):
    newline = "\r\n" if "\r\n" in text else "\n"
    sections = validator.parse_sections(text)
    chain_names = validator.group_names(sections.get("Proxy Chain", []))
    static_terminal_nodes = [line.split("=", 1)[0].strip()
                             for line in validator.active_lines(sections.get("Proxy", []))
                             if "=" in line and line.split("=", 1)[1].strip().split(",", 1)[0].lower() == "vless"]
    existing_rules = validator.active_lines(sections.get("Rule", []))
    if existing_rules.count("FINAL,全局代理") != 1:
        raise ValueError("config must have one FINAL,全局代理")
    result = []
    current = None
    remote_emitted = False
    for raw in text.splitlines(keepends=True):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            result.append(raw)
            if current == "Remote Rule":
                if remote_emitted:
                    raise ValueError("duplicate Remote Rule section")
                for rs in builder.RULESETS:
                    enabled = "false" if rs.tag == "Ads-Reject-Heavy" else "true"
                    result.append(f"{validator.GENERATED_RAW_PREFIX}{rs.file},policy={rs.policy},tag={rs.tag},enabled={enabled}" + newline)
                remote_emitted = True
            continue
        if not line or line.startswith(("#", ";", "//")):
            result.append(raw)
            continue
        updated = raw.rstrip("\r\n")
        if current == "Remote Rule":
            continue
        if current == "General" and "=" in line:
            key = line.split("=", 1)[0].strip()
            values = {"allow-wifi-access": "false", "mitm-on-wifi-access": "false",
                      "disconnect-on-policy-change": "true"}
            if key in values:
                updated = f"{key} = {values[key]}"
            elif key == "skip-proxy":
                updated = updated.replace(",e.crashlytics.com", "")
            elif key == "ssid-trigger":
                updated = 'ssid-trigger = "default":rule, "cellular":rule'
        elif current == "Proxy Group" and "=" in line:
            name, body = line.split("=", 1)
            name = name.strip()
            parts = split_fields(body)
            kind, rest = parts[0], parts[1:]
            option_start = next((index for index, part in enumerate(rest) if "=" in part), len(rest))
            members, parameters = rest[:option_start], rest[option_start:]
            if kind == "select" and name == "链式代理节点":
                # Keep explicit choices; a filter-only default otherwise depends on subscription order.
                if static_terminal_nodes and not any(member in static_terminal_nodes for member in members):
                    members = [static_terminal_nodes[0], *members]
            elif kind == "select" and name == "链式代理链路":
                members = [member for member in members if member in chain_names]
                if not members:
                    raise ValueError("chain selector has no two-hop Proxy Chain candidates")
            elif kind == "select" and "链式代理链路" in members:
                members = ["链式代理链路"] + [member for member in members if member != "链式代理链路"]
                # A raw filter is not a two-hop path; expose it only through the terminal selector.
                members = [member for member in members if member != "Chained-proxy-Filter"]
            if kind == "url-test":
                parameters = [p for p in parameters if p.split("=", 1)[0].strip() not in {"interval", "tolerance"}]
                parameters += ["interval = 600", "tolerance = 100"]
            updated = f"{name} = {','.join([kind, *members, *parameters])}"
        elif current == "Remote Proxy":
            updated = re.sub(r"skip-cert-verify\s*=\s*true", "skip-cert-verify=false", updated)
        elif current == "Rule":
            if line == "IP-CIDR,198.18.0.1/32,DIRECT,no-resolve":
                continue
            if line == "FINAL,全局代理":
                for rule in LOCAL_SUPPLEMENTS:
                    if rule not in existing_rules:
                        result.append(rule + newline)
        elif current == "Plugin" and any(marker in line for marker in validator.HIGH_RISK_PLUGIN_MARKERS):
            updated = re.sub(r"enabled\s*=\s*true", "enabled=false", updated)
            if not re.search(r"(?:^|,)\s*enabled\s*=", updated):
                updated += ",enabled=false"
        elif current == "Mitm" and line.startswith("skip-server-cert-verify"):
            updated = "skip-server-cert-verify = false"
        result.append(updated + (newline if raw.endswith(("\n", "\r")) else ""))
    if not remote_emitted:
        raise ValueError("missing Remote Rule section")
    updated = "".join(result)
    before, after = validator.parse_sections(text), validator.parse_sections(updated)
    if before.get("Proxy", []) != after.get("Proxy", []):
        raise ValueError("private proxy definitions changed unexpectedly")
    if before.get("Proxy Chain", []) != after.get("Proxy Chain", []):
        raise ValueError("two-hop chain wiring changed unexpectedly")
    wg_errors = validator.check_proxy_wireguard(validator.parse_loon_config(updated))
    if wg_errors:
        raise ValueError("; ".join(wg_errors))
    return updated


def validate_text(text):
    config = validator.parse_loon_config(text)
    checks = (validator.check_required_sections, validator.check_general, validator.check_rule_section,
              validator.check_proxy_wireguard, validator.check_policy_groups, validator.check_policy_references,
              validator.check_remote_tags, validator.check_remote_urls, validator.check_remote_policies,
              validator.check_remote_tag_policies, validator.check_plugins, validator.check_mitm)
    return [error for check in checks for error in check(config)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-directory", type=Path, default=Path.home() / "Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-directory", type=Path)
    destination.add_argument("--in-place", action="store_true")
    parser.add_argument("--open-loon", action="store_true", help="On macOS, request Loon to open the Mac config; does not verify VPN state")
    args = parser.parse_args()
    if args.open_loon and sys.platform != "darwin":
        parser.error("--open-loon requires macOS")
    tree_errors = validator.validate_generated_tree(validator.GENERATED_RULE_DIR)
    if tree_errors:
        raise ValueError("generated subscriptions failed validation: " + "; ".join(tree_errors))
    plans = []
    for name in CONFIG_NAMES:
        path = args.input_directory / name
        original = path.read_bytes()
        updated = optimize_text(original.decode("utf-8-sig"))
        errors = validate_text(updated)
        if errors:
            raise ValueError(f"{name}: " + "; ".join(errors))
        content = updated.encode("utf-8")
        if original.startswith(b'\xef\xbb\xbf'):
            content = b'\xef\xbb\xbf' + content
        plans.append((path, original, content))
    target_root = args.input_directory if args.in_place else args.output_directory
    target_root.mkdir(parents=True, exist_ok=True)
    backup = None
    if args.in_place and any(original != updated for _, original, updated in plans):
        backup = args.input_directory / ".backups-loon-lcf" / ("optimized-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        backup.mkdir(parents=True, mode=0o700)
        for path, original, _ in plans:
            (backup / path.name).write_bytes(original)
            (backup / path.name).chmod(0o600)
    written = []
    try:
        for path, original, content in plans:
            target = target_root / path.name
            if args.in_place and path.read_bytes() != original:
                raise ValueError("configuration changed during update; stopped")
            if args.in_place and original == content:
                continue
            atomic_write(target, content, expected=original if args.in_place else None,
                         mode=path.stat().st_mode & 0o777 if args.in_place else 0o600)
            written.append((target, content))
            print(f"OK: {path.name}: validated and updated")
    except (OSError, ValueError):
        if backup is not None:
            preserved = rollback_writes(written, backup)
            if preserved:
                print("Preserved newer edits or unavailable targets: " + ", ".join(path.name for path in preserved), file=sys.stderr)
            print(f"Recovery backup: {backup}", file=sys.stderr)
        raise
    if backup is not None:
        print(f"Backup: {backup}")
    if args.open_loon:
        subprocess.run(["open", "-a", "Loon", str(target_root / CONFIG_NAMES[1])], check=True)
        print("Requested Loon to open the Mac config; active selection and VPN state require device verification.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
