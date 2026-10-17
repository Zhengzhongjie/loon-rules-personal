#!/usr/bin/env python3
"""Read ATAS's server cache/logs and report offline routing gaps, without credentials."""

from __future__ import annotations

import argparse
import json
import re
from ipaddress import ip_address, ip_network
from pathlib import Path

from build_loon_rules import (
    ATAS_DATA_PROVIDER_SUFFIXES, ATAS_EXACT_HOSTS, ATAS_FIRST_PARTY_SUFFIXES, ATAS_NTP_HOSTS,
)
from inspect_routing import DomainRouter, load_domain_routes
from rulegrammar import parse_rule

ROOT = Path(__file__).resolve().parents[1]


def inventory(data_dir: Path, app_dir: Path) -> tuple[set[str], set[tuple[str, int]]]:
    hosts = (set(ATAS_FIRST_PARTY_SUFFIXES) | set(ATAS_EXACT_HOSTS)
             | set(ATAS_NTP_HOSTS) | set(ATAS_DATA_PROVIDER_SUFFIXES))
    endpoints: set[tuple[str, int]] = set()
    for entry in json.loads((data_dir / "AvaliableServers.cnf").read_text()):
        host, port = entry["EndPoint"].rsplit(":", 1)
        endpoints.add((host, int(port)))
        try:
            ip_address(host)
        except ValueError:
            hosts.add(host)
    vendor_pattern = re.compile(
        r"(?i)\b(?:[a-z0-9-]+\.)*(?:atas\.net|orderflowtrading\.(?:net|ru)|dxfeed\.com)\b"
    )
    for path in (data_dir / "Logs").glob("app_*.log"):
        text = path.read_text(errors="replace")
        hosts.update(host.lower() for host in vendor_pattern.findall(text))
        for host, port in re.findall(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b", text):
            try:
                address = ip_address(host)
            except ValueError:
                continue
            if address.is_global:
                endpoints.add((host, int(port)))
    # Localization contains public URLs for cfg/assets/help/news. Other assemblies
    # include SDK certificate/docs URLs, which are not platform runtime endpoints.
    path = app_dir / "Contents/MonoBundle/OFT.Localization.dll"
    if path.exists():
        data = path.read_bytes()
        for text in (data.decode("latin-1"), data.decode("utf-16-le", errors="ignore"),
                     data[1:].decode("utf-16-le", errors="ignore")):
            hosts.update(host.lower() for host in vendor_pattern.findall(text))
    return hosts, endpoints


def audit(data_dir: Path, app_dir: Path, tree: Path) -> dict:
    hosts, endpoints = inventory(data_dir, app_dir)
    router = DomainRouter(load_domain_routes(tree))
    finance_ips = []
    for line in (tree / "06-FinanceCrypto-Stable.list").read_text().splitlines():
        rule = parse_rule(line)
        if rule and rule.rule_type == "IP-CIDR":
            finance_ips.append(ip_network(rule.value))
    domain_routes = {host: router.match(host) for host in sorted(hosts)}
    ip_routes = {}
    for host, port in sorted(endpoints):
        try:
            address = ip_address(host)
        except ValueError:
            continue
        ip_routes[f"{host}:{port}"] = (
            "金融加密" if any(address in network for network in finance_ips) else "UNREVIEWED"
        )
    return {
        "scope": "Offline generated-rule coverage only; not active Loon or login verification.",
        "domain_routes": domain_routes,
        "literal_ip_routes": ip_routes,
        "missing": [host for host, policy in {**domain_routes, **ip_routes}.items()
                    if policy != ("DIRECT" if host in ATAS_NTP_HOSTS else "金融加密")],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path,
                        default=Path.home() / "Library/Application Support/ATAS")
    parser.add_argument("--app-dir", type=Path, default=Path("/Applications/ATAS X.app"))
    parser.add_argument("--tree", type=Path, default=ROOT / "rules/loon/generated")
    args = parser.parse_args()
    report = audit(args.data_dir, args.app_dir, args.tree)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(bool(report["missing"]))


if __name__ == "__main__":
    raise SystemExit(main())
