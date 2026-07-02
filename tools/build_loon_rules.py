#!/usr/bin/env python3
"""Build deduplicated public Loon rules from reviewed upstream sources."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.client import IncompleteRead
from ipaddress import ip_network
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from rulegrammar import CoverageIndex, Rule, parse_rule, render_rule


USER_AGENT = "codex-loon-rules-builder/1.0"
RAW_BASE = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon"
FETCH_TIMEOUT_SECONDS = 30
FETCH_RETRIES = 3
FETCH_RETRY_DELAY_SECONDS = 1.5
FETCH_WORKERS = 4
FETCH_ERRORS = (HTTPError, URLError, TimeoutError, OSError, IncompleteRead)
SYSTEM_CURL = Path("/usr/bin/curl")


def blackmatrix(name: str) -> str:
    return f"{RAW_BASE}/{name}/{name}.list"


@dataclass(frozen=True)
class RuleSet:
    file: str
    tag: str
    policy: str
    sources: tuple[str, ...] = ()
    json_prefix_sources: tuple[str, ...] = ()
    additions: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    no_resolve: bool = False
    drop_if_covered: bool = True


RULESETS: list[RuleSet] = [
    RuleSet(
        "00-Ads-Reject.list",
        "Ads-Reject",
        "广告分流",
        (
            "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET.list",
            "https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/rule/rejectAd.list",
        ),
        notes=(
            "Advertising and tracker rules. Keep before account-safety direct rules.",
            "Precision layer: AWAvenue targets in-app ad SDKs, fmz200 rejectAd curates CN app ads.",
            "Bulk AdGuard-grade coverage lives in 27-Ads-Reject-Heavy so it can be toggled on-device.",
        ),
    ),
    RuleSet(
        "01-LAN-Direct.list",
        "LAN-Direct",
        "DIRECT",
        ("https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/rule/LAN.list",),
        notes=("LAN and private network direct rules.",),
    ),
    RuleSet(
        "02-AccountSafety-Direct.list",
        "AccountSafety-DIRECT",
        "DIRECT",
        additions=(
            "DOMAIN-SUFFIX,wechat.com",
            "DOMAIN-SUFFIX,weixin.qq.com",
            "DOMAIN-SUFFIX,qq.com",
            "DOMAIN-SUFFIX,qpic.cn",
            "DOMAIN-SUFFIX,gtimg.cn",
            "DOMAIN-SUFFIX,tenpay.com",
            "DOMAIN-SUFFIX,alipay.com",
            "DOMAIN-SUFFIX,alipayobjects.com",
            "DOMAIN-SUFFIX,taobao.com",
            "DOMAIN-SUFFIX,tmall.com",
            "DOMAIN-SUFFIX,alicdn.com",
            "DOMAIN-SUFFIX,aliyuncs.com",
        ),
        notes=("China-region auth/payment foundations stay DIRECT. App domains stay in their dedicated service groups.",),
    ),
    RuleSet(
        "03-Mainland-Services-Direct.list",
        "Mainland-Services-Direct",
        "DIRECT",
        tuple(blackmatrix(name) for name in ("Baidu", "WeChat", "Tencent", "Alibaba", "NetEase")),
    ),
    RuleSet(
        "04-Seetong.list",
        "Seetong-Local",
        "Seetong",
        additions=("DOMAIN-SUFFIX,seetong.com", "DOMAIN-SUFFIX,seetong.app"),
        notes=("Seetong camera traffic. Prefer DIRECT first in the policy group.",),
    ),
    RuleSet(
        "05-PayPal-Stable.list",
        "PayPal-Stable",
        "PayPal",
        (blackmatrix("PayPal"),),
        additions=("DOMAIN-SUFFIX,paypal.com", "DOMAIN-SUFFIX,paypalobjects.com", "DOMAIN-SUFFIX,paypal.me"),
        notes=("Keep PayPal separate from finance/crypto for stable egress.",),
    ),
    RuleSet(
        "06-FinanceCrypto-Stable.list",
        "FinanceCrypto-Stable",
        "金融加密",
        tuple(blackmatrix(name) for name in ("Stripe", "Binance", "OKX", "Crypto", "Bloomberg")),
        additions=(
            "DOMAIN-SUFFIX,stripecdn.com",
            "DOMAIN-SUFFIX,binance.us",
            "DOMAIN-SUFFIX,oklink.com",
            "DOMAIN-SUFFIX,coinbase.com",
            "DOMAIN-SUFFIX,kraken.com",
            "DOMAIN-SUFFIX,wise.com",
            "DOMAIN-SUFFIX,transferwise.com",
            "DOMAIN-SUFFIX,revolut.com",
            "DOMAIN-SUFFIX,robinhood.com",
            "DOMAIN-SUFFIX,interactivebrokers.com",
            "DOMAIN-SUFFIX,ibkr.com",
            "DOMAIN-SUFFIX,payoneer.com",
            "DOMAIN-SUFFIX,skrill.com",
            "DOMAIN-SUFFIX,plaid.com",
            "DOMAIN-SUFFIX,bloombergchina.com",
        ),
        notes=("Use a manually selected stable policy. Avoid frequent automatic region switching.",),
    ),
    RuleSet("07-Adobe.list", "Adobe", "Adobe", tuple(blackmatrix(name) for name in ("Adobe", "AdobeActivation"))),
    RuleSet(
        "08-AI.list",
        "AI",
        "AI",
        tuple(blackmatrix(name) for name in ("OpenAI", "Claude", "Anthropic", "Gemini", "Copilot"))
        + ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list",),
        json_prefix_sources=("https://openai.com/chatgpt-voice.json",),
        additions=(
            "DOMAIN-SUFFIX,chatgpt.com",
            "DOMAIN-SUFFIX,openai.com",
            "DOMAIN-SUFFIX,oaistatic.com",
            "DOMAIN-SUFFIX,oaiusercontent.com",
            "DOMAIN-SUFFIX,ct.sendgrid.net",
            "DOMAIN-SUFFIX,statsig.com",
            "DOMAIN-SUFFIX,statsigapi.net",
            "DOMAIN-SUFFIX,featuregates.org",
            "DOMAIN-SUFFIX,launchdarkly.com",
            "DOMAIN,cdn.openaimerge.com",
            "DOMAIN,cdn.workos.com",
            "DOMAIN,challenges.cloudflare.com",
            "DOMAIN,featureassets.org",
            "DOMAIN,forwarder.workos.com",
            "DOMAIN,humb.apple.com",
            "DOMAIN,images.workoscdn.com",
            "DOMAIN,o207216.ingest.sentry.io",
            "DOMAIN,o33249.ingest.sentry.io",
            "DOMAIN,prodregistryv2.org",
            "DOMAIN,rum.browser-intake-datadoghq.com",
            "DOMAIN,setup.workos.com",
            "DOMAIN,workos.imgix.net",
        ),
        notes=(
            "ChatGPT/OpenAI supplemental domains mirror the official OpenAI network recommendations.",
            "ChatGPT Voice IP prefixes are generated from https://openai.com/chatgpt-voice.json.",
        ),
    ),
    RuleSet(
        "09-Apple.list",
        "Apple",
        "Apple",
        tuple(blackmatrix(name) for name in ("Apple", "iCloud", "iCloudPrivateRelay", "TestFlight", "AppleNews", "AppleTV", "AppleMusic")),
    ),
    RuleSet("10-RedNote.list", "RedNote", "RedNote", (blackmatrix("XiaoHongShu"),)),
    RuleSet("11-Weibo.list", "Weibo", "Weibo", (blackmatrix("Weibo"),)),
    RuleSet("12-TikTok.list", "TikTok", "TikTok", (blackmatrix("TikTok"),)),
    RuleSet("13-Douyin-ByteDance.list", "Douyin-ByteDance", "抖音", tuple(blackmatrix(name) for name in ("DouYin", "ByteDance"))),
    RuleSet("14-Bilibili.list", "Bilibili", "Bilibili", tuple(blackmatrix(name) for name in ("BiliBili", "BiliBiliIntl"))),
    RuleSet(
        "15-Telegram.list",
        "Telegram",
        "Telegram",
        (blackmatrix("Telegram"), "https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/ruleset/ASN.Telegram.list"),
        no_resolve=True,
    ),
    RuleSet(
        "16-Microsoft.list",
        "Microsoft",
        "Microsoft",
        tuple(blackmatrix(name) for name in ("Microsoft", "OneDrive", "Teams", "Bing", "Xbox", "LinkedIn")),
    ),
    RuleSet("17-Meta.list", "Meta", "Meta", tuple(blackmatrix(name) for name in ("Facebook", "Instagram", "Whatsapp", "Threads"))),
    RuleSet("18-YouTube.list", "YouTube", "YouTube", tuple(blackmatrix(name) for name in ("YouTube", "YouTubeMusic"))),
    RuleSet("19-Google.list", "Google", "Google", tuple(blackmatrix(name) for name in ("GoogleVoice", "GoogleDrive", "Google"))),
    RuleSet("20-GitHub.list", "GitHub", "GitHub", (blackmatrix("GitHub"),)),
    RuleSet("21-Developer-Collab.list", "Developer-Collab", "开发协作", tuple(blackmatrix(name) for name in ("GitLab", "Docker", "Dropbox"))),
    RuleSet("22-Global-Social-Info.list", "Global-Social-Info", "海外社交资讯", tuple(blackmatrix(name) for name in ("Twitter", "Discord", "Reddit", "Wikipedia"))),
    RuleSet(
        "23-Streaming.list",
        "Streaming",
        "境外流媒体",
        tuple(blackmatrix(name) for name in ("Netflix", "Disney", "HBO", "Hulu", "PrimeVideo", "ParamountPlus", "Peacock", "DAZN", "Twitch", "Spotify", "BBC", "Bahamut", "ViuTV", "AbemaTV", "Niconico"))
        + ("https://whatshub.top/rule/ProxyMedia.list",),
    ),
    RuleSet("24-Amazon.list", "Amazon", "Amazon", (blackmatrix("Amazon"),)),
    RuleSet("25-Talkatone.list", "Talkatone", "全局代理", ("https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/rule/Talkatone.list",)),
    RuleSet(
        "26-ChinaASN-Direct.list",
        "ChinaASN-Direct",
        "DIRECT",
        ("https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/ruleset/ASN.China.list",),
        no_resolve=True,
        drop_if_covered=False,
    ),
    RuleSet(
        "27-Ads-Reject-Heavy.list",
        "Ads-Reject-Heavy",
        "广告分流",
        ("https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list",),
        notes=(
            "Bulk AdGuard-grade layer: AdRules aggregates AdGuard DNS Filter, EasyList China and more (~170k rules).",
            "Stays last so service/payment/direct rules win first; safe to disable on-device if iOS memory gets tight.",
        ),
    ),
]


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            with urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8", errors="replace")
        except FETCH_ERRORS as exc:
            last_error = exc
            if SYSTEM_CURL.exists() and "CERTIFICATE_VERIFY_FAILED" in str(exc):
                return fetch_with_system_curl(url)
            if attempt == FETCH_RETRIES:
                break
            time.sleep(FETCH_RETRY_DELAY_SECONDS * attempt)
    assert last_error is not None
    raise last_error


def fetch_with_system_curl(url: str) -> str:
    try:
        result = subprocess.run(
            [
                str(SYSTEM_CURL),
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--http1.1",
                "--max-time",
                str(FETCH_TIMEOUT_SECONDS),
                "--connect-timeout",
                "8",
                "--retry",
                "2",
                "--retry-delay",
                "1",
                "--retry-all-errors",
                "--user-agent",
                USER_AGENT,
                url,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=FETCH_TIMEOUT_SECONDS + 3,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise URLError(f"system curl fallback failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise URLError(f"system curl fallback failed: {detail}")
    return result.stdout


def fetch_all() -> tuple[dict[str, str], list[str]]:
    urls: list[str] = []
    for ruleset in RULESETS:
        urls.extend(ruleset.sources)
        urls.extend(ruleset.json_prefix_sources)
    unique_urls = sorted(set(urls))
    contents: dict[str, str] = {}
    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        future_to_url = {pool.submit(fetch, url): url for url in unique_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                contents[url] = future.result()
            except FETCH_ERRORS as exc:
                failures.append(f"{url}: {type(exc).__name__}: {exc}")
    return contents, failures


def json_prefix_rules(raw: str, source: str) -> list[str]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc

    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list):
        raise ValueError("missing prefixes list")

    rules: list[str] = []
    for index, item in enumerate(prefixes):
        if not isinstance(item, dict):
            raise ValueError(f"prefix entry {index} is not an object")
        for key, rule_type in (("ipv4Prefix", "IP-CIDR"), ("ipv6Prefix", "IP-CIDR6")):
            prefix = item.get(key)
            if prefix is None:
                continue
            if not isinstance(prefix, str) or not prefix:
                raise ValueError(f"prefix entry {index} has invalid {key}")
            ip_network(prefix, strict=False)
            rules.append(f"{rule_type},{prefix},no-resolve")

    if not rules:
        raise ValueError(f"no IP prefixes found in {source}")
    return rules


ALLOWED_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "PROCESS-NAME",
    "USER-AGENT",
}


def accept_rule(raw: str) -> Rule | None:
    """Parse one upstream line and apply the builder's policy.

    Drops keyword rules and unrecognized types, and keeps only the ``no-resolve`` modifier.
    The shared grammar handles tokenization; this is the builder-specific filtering on top.
    """
    rule = parse_rule(raw)
    if rule is None:
        return None
    if rule.rule_type == "DOMAIN-KEYWORD":
        # Keyword rules are too broad for this account-risk posture.
        return None
    if rule.rule_type not in ALLOWED_RULE_TYPES:
        return None
    modifiers = ("no-resolve",) if any(m.lower() == "no-resolve" for m in rule.modifiers) else ()
    return Rule(rule.rule_type, rule.value, modifiers)


@dataclass(frozen=True)
class CompileStats:
    generated: int
    duplicates_dropped: int
    covered_dropped: int


@dataclass(frozen=True)
class CompileResult:
    files: dict[str, str]
    stats: CompileStats
    failures: list[str]


def compile_rules(rulesets: list[RuleSet], source_contents: dict[str, str]) -> CompileResult:
    """Pure transform: fetched content in, generated files + stats + parse failures out.

    Knows nothing about the network or the filesystem. Reports only the failures it can
    observe while transforming (JSON-prefix parse errors); fetch failures belong to the
    caller. Same inputs always yield the same result, so it is testable without I/O.
    """
    index = CoverageIndex()
    duplicate_count = 0
    covered_count = 0
    failures: list[str] = []
    files: dict[str, str] = {}
    manifest: list[str] = [
        "# Generated Loon rules manifest",
        "# Do not include proxy nodes, subscriptions, certificates, or secrets.",
        "",
    ]

    for ruleset in rulesets:
        raw_lines: list[str] = []
        for source in ruleset.sources:
            raw_lines.extend(source_contents.get(source, "").splitlines())
        raw_lines.extend(ruleset.additions)
        for source in ruleset.json_prefix_sources:
            raw = source_contents.get(source)
            if raw is None:
                continue
            try:
                raw_lines.extend(json_prefix_rules(raw, source))
            except ValueError as exc:
                failures.append(f"{source}: JSON_PARSE: {exc}")

        kept: list[str] = []
        local_seen: set[str] = set()
        for raw in raw_lines:
            rule = accept_rule(raw)
            if rule is None:
                continue
            if ruleset.no_resolve and rule.rule_type.startswith("IP-") and "no-resolve" not in rule.modifiers:
                rule = Rule(rule.rule_type, rule.value, rule.modifiers + ("no-resolve",))
            rendered = render_rule(rule)
            if rendered in local_seen:
                duplicate_count += 1
                continue
            if index.exact_tag(rule) is not None:
                duplicate_count += 1
                continue
            if ruleset.drop_if_covered and index.covered_by(rule) is not None:
                covered_count += 1
                continue
            local_seen.add(rendered)
            kept.append(rendered)
            index.add(rule, ruleset.tag)

        header = [
            f"# {ruleset.tag}",
            "# Generated by tools/build_loon_rules.py.",
            "# Public rule list only. No proxy nodes, subscriptions, certificates, or secrets.",
            f"# Policy: {ruleset.policy}",
        ]
        header.extend(f"# {note}" for note in ruleset.notes)
        files[ruleset.file] = "\n".join(header + [""] + kept) + "\n"
        manifest.append(f"{ruleset.tag},{ruleset.policy},rules/loon/generated/{ruleset.file},{len(kept)}")

    files["MANIFEST.csv"] = "\n".join(manifest) + "\n"
    return CompileResult(
        files=files,
        stats=CompileStats(
            generated=len(rulesets),
            duplicates_dropped=duplicate_count,
            covered_dropped=covered_count,
        ),
        failures=failures,
    )


def stats_lines(stats: CompileStats) -> list[str]:
    """Human-readable stat lines shared by the build shell and the drift checker."""
    return [
        f"generated={stats.generated}",
        f"duplicates_dropped={stats.duplicates_dropped}",
        f"covered_later_rules_dropped={stats.covered_dropped}",
    ]


def write_result(output_dir: Path, files: dict[str, str]) -> None:
    """Replace the generated artefacts on disk with ``files``. No policy, no decisions."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("*.list"):
        stale.unlink()
    manifest_path = output_dir / "MANIFEST.csv"
    if manifest_path.exists():
        manifest_path.unlink()
    for file_name, text in files.items():
        (output_dir / file_name).write_text(text)


def build(output_dir: Path, strict: bool, allow_partial: bool = False) -> int:
    """Compose fetch -> compile -> write, and own the write/exit-code policy."""
    source_contents, fetch_failures = fetch_all()
    result = compile_rules(RULESETS, source_contents)
    failures = fetch_failures + result.failures

    if failures:
        for failure in failures:
            print(f"FETCH_FAIL: {failure}", file=sys.stderr)
        if not allow_partial:
            print("FAIL: refusing to overwrite generated rules after upstream fetch or parse failures", file=sys.stderr)
            return 1

    write_result(output_dir, result.files)

    for line in stats_lines(result.stats):
        print(line)
    if failures and strict:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("rules/loon/generated"))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="write partial generated output even if upstream fetches or JSON parsing fail",
    )
    args = parser.parse_args()
    if args.strict and args.allow_partial:
        parser.error("--strict cannot be combined with --allow-partial")
    return build(args.output_dir, args.strict, args.allow_partial)


if __name__ == "__main__":
    raise SystemExit(main())
