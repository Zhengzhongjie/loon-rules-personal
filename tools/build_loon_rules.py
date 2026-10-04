#!/usr/bin/env python3
"""Build deduplicated public Loon rules from reviewed upstream sources."""

from __future__ import annotations

import argparse
import hashlib
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

from rulegrammar import LOON, SHADOWROCKET, SURGE, CoverageIndex, Rule, fold, parse_rule, render_rule


USER_AGENT = "loon-rules-personal-builder/1.0"
RAW_BASE = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon"
FETCH_TIMEOUT_SECONDS = 30
FETCH_RETRIES = 3
FETCH_RETRY_DELAY_SECONDS = 1.5
FETCH_WORKERS = 4
FETCH_ERRORS = (HTTPError, URLError, TimeoutError, OSError, IncompleteRead)
SYSTEM_CURL = Path("/usr/bin/curl")
UPSTREAM_CACHE_DIR = Path(".cache/upstream")


def blackmatrix(name: str) -> str:
    return f"{RAW_BASE}/{name}/{name}.list"


CLAUDE_FIRST_PARTY_SUFFIXES: tuple[str, ...] = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
)
CLAUDE_EXACT_HOSTS: tuple[str, ...] = (
    "cdn.usefathom.com",  # third-party analytics; reject rules may still block it
    "servd-anthropic-website.b-cdn.net",
)
CLAUDE_BASELINE_RULES: tuple[str, ...] = tuple(
    f"DOMAIN-SUFFIX,{domain}" for domain in CLAUDE_FIRST_PARTY_SUFFIXES
) + tuple(f"DOMAIN,{host}" for host in CLAUDE_EXACT_HOSTS)


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
    exclusions: tuple[str, ...] = ()


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
            "Advertising and tracker rules. Keep after LAN and account-safety direct rules.",
            "Precision layer: AWAvenue targets in-app ad SDKs, fmz200 rejectAd curates CN app ads.",
            "Bulk AdGuard-grade coverage lives in 27-Ads-Reject-Heavy so it can be toggled on-device.",
        ),
        exclusions=("IP-CIDR,203.107.1.1/24", "IP-CIDR,203.107.1.0/24", "DOMAIN-SUFFIX,pagespeed-mod"),
    ),
    RuleSet(
        "01-LAN-Direct.list",
        "LAN-Direct",
        "DIRECT",
        ("https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/rule/LAN.list",),
        additions=(
            "DOMAIN-SUFFIX,local",
            "IP-CIDR,169.254.0.0/16,no-resolve",
            "IP-CIDR,224.0.0.0/4,no-resolve",
        ),
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
        additions=("DOMAIN-SUFFIX,gaokao.cn", "DOMAIN-SUFFIX,zbrowser.cn", "DOMAIN-SUFFIX,iqiyi.com"),
        notes=("Keep the Gaokao service direct when migrating private inline rules.",),
        exclusions=("IP-ASN,132203",),
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
        "05-TradingView-Fast.list",
        "TradingView-Fast",
        "TradingView",
        additions=(
            "DOMAIN-SUFFIX,tradingview.com",
            "DOMAIN-SUFFIX,tradingviewstatic.com",
            "DOMAIN-SUFFIX,tradingview-widget.com",
        ),
        notes=(
            "TradingView pulled out of FinanceCrypto so cn.tradingview.com can go DIRECT.",
            "Policy group defaults to DIRECT; switch to a nearby node if chart data websockets stall.",
        ),
    ),
    RuleSet(
        "05-Binance-Geo.list",
        "Binance-Geo",
        "Binance",
        (blackmatrix("Binance"),),
        additions=(
            "DOMAIN-SUFFIX,binance.vision",
            "DOMAIN-SUFFIX,binance.info",
        ),
        notes=(
            "Binance pulled out of FinanceCrypto: api.binance.com answers HTTP 451",
            "'Service unavailable from a restricted location' on US/UK egress.",
            "OKX stays in FinanceCrypto so its egress IP is untouched (exchange risk control).",
            "Policy group must sit on ONE stable non-US, non-UK node (JP/SG/HK).",
            "binance.us intentionally NOT here — it needs US egress and stays in FinanceCrypto.",
            "binance.vision is the public data mirror that stays reachable when api.binance.com 451s.",
        ),
    ),
    RuleSet(
        "06-FinanceCrypto-Stable.list",
        "FinanceCrypto-Stable",
        "金融加密",
        tuple(blackmatrix(name) for name in ("OKX", "Crypto", "Bloomberg")),
        additions=(
            "DOMAIN-SUFFIX,stripecdn.com",
            "DOMAIN-SUFFIX,binance.us",
            "DOMAIN-SUFFIX,oklink.com",
            "DOMAIN-SUFFIX,tealstreet.io",
            "DOMAIN-SUFFIX,safepal.com",
            "DOMAIN-SUFFIX,safepal.io",
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
            # 永续合约衍生品数据站（资金费率 / OI / 爆仓 / 期权），2026-08-20 补
            "DOMAIN-SUFFIX,coinglass.com",
            "DOMAIN-SUFFIX,coinalyze.net",
            "DOMAIN-SUFFIX,velo.xyz",
            "DOMAIN-SUFFIX,velodata.app",
            "DOMAIN-SUFFIX,laevitas.ch",
            "DOMAIN-SUFFIX,hyblockcapital.com",
            "DOMAIN-SUFFIX,deribit.com",
            "DOMAIN-SUFFIX,bitget.com",
            "DOMAIN-SUFFIX,bitget.fit",
            "DOMAIN-SUFFIX,coinank.com",
            "DOMAIN-SUFFIX,hypurrscan.io",
            # Hypurrscan's public data requests use this separate API origin.
            "DOMAIN,api.hyperliquid.xyz",
            "DOMAIN,api-ui.hyperliquid.xyz",
            "DOMAIN,rpc.hyperliquid.xyz",
            "DOMAIN-SUFFIX,stripe.com",
            "DOMAIN-SUFFIX,stripe.network",
        ),
        notes=("Use a manually selected stable policy. Avoid frequent automatic region switching.",),
    ),
    RuleSet("07-Adobe.list", "Adobe", "Adobe", tuple(blackmatrix(name) for name in ("Adobe", "AdobeActivation"))),
    RuleSet(
        "08-Claude.list",
        "Claude",
        "Claude",
        tuple(blackmatrix(name) for name in ("Claude", "Anthropic")),
        additions=CLAUDE_BASELINE_RULES,
        notes=(
            "Claude and Anthropic first-party domains use one stable, supported-region policy.",
            "Fathom is third-party analytics and may still be preempted by the earlier reject layer.",
        ),
    ),
    RuleSet(
        "08-Gemini.list", "Gemini", "Google", (blackmatrix("Gemini"),),
        additions=(
            "DOMAIN-SUFFIX,gemini.google.com", "DOMAIN,aistudio.google.com",
            "DOMAIN,ai.google.dev", "DOMAIN,generativelanguage.googleapis.com",
            "DOMAIN-SUFFIX,notebooklm.google", "DOMAIN-SUFFIX,notebooklm.google.com",
            "DOMAIN-SUFFIX,makersuite.google.com",
        ),
        exclusions=("DOMAIN-SUFFIX,apis.google.com",),
        notes=("Gemini, AI Studio and NotebookLM share the Google login policy.",),
    ),
    RuleSet(
        "08-Microsoft-Copilot.list", "Microsoft-Copilot", "Microsoft",
        additions=(
            "DOMAIN-SUFFIX,copilot.microsoft.com", "DOMAIN-SUFFIX,copilot.cloud.microsoft",
            "DOMAIN,sydney.bing.com", "DOMAIN-SUFFIX,edgeservices.bing.com",
            "DOMAIN,gateway.bingviz.microsoft.net", "DOMAIN,gateway.bingviz.microsoftapp.net",
            "DOMAIN,services.bingapis.com",
        ),
        notes=(
            "Microsoft Copilot shares the Microsoft identity policy; GitHub Copilot remains with GitHub.",
            "Reviewed Microsoft endpoints only; upstream Copilot incorrectly includes broad OpenAI/shared infrastructure.",
        ),
    ),
    RuleSet(
        "08-AI.list",
        "AI",
        "AI",
        (blackmatrix("OpenAI"),)
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
            "DOMAIN-SUFFIX,oaistatsig.com",
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
        exclusions=(
            "DOMAIN-SUFFIX,auth0.com",
            "DOMAIN-SUFFIX,sentry.io",
            "DOMAIN-SUFFIX,stripe.com",
            "IP-ASN,20473",
            "IP-ASN,14061",
            "DOMAIN-SUFFIX,apis.google.com",
            "DOMAIN-SUFFIX,algolia.net",
            "DOMAIN-SUFFIX,identrust.com",
            "DOMAIN-SUFFIX,intercom.io",
            "DOMAIN,api.githubcopilot.com",
            "DOMAIN,copilot-proxy.githubusercontent.com",
        ),
    ),
    RuleSet(
        "09-Apple.list",
        "Apple",
        "Apple",
        tuple(blackmatrix(name) for name in ("Apple", "iCloud", "iCloudPrivateRelay", "TestFlight", "AppleNews", "AppleTV", "AppleMusic")),
        additions=("DOMAIN-SUFFIX,safebrowsing.apple", "DOMAIN,safebrowsing.g.applimg.com"),
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
        exclusions=("DOMAIN-SUFFIX,akadns.net", "DOMAIN-SUFFIX,edgesuite.net"),
    ),
    RuleSet("17-Meta.list", "Meta", "Meta", tuple(blackmatrix(name) for name in ("Facebook", "Instagram", "Whatsapp", "Threads"))),
    RuleSet("18-YouTube.list", "YouTube", "YouTube", tuple(blackmatrix(name) for name in ("YouTube", "YouTubeMusic"))),
    RuleSet("19-Google.list", "Google", "Google", tuple(blackmatrix(name) for name in ("GoogleVoice", "GoogleDrive", "Google"))),
    RuleSet("20-GitHub.list", "GitHub", "GitHub", (blackmatrix("GitHub"),),
            additions=("DOMAIN,api.githubcopilot.com", "DOMAIN,copilot-proxy.githubusercontent.com")),
    RuleSet("21-Developer-Collab.list", "Developer-Collab", "开发协作", tuple(blackmatrix(name) for name in ("GitLab", "Docker", "Dropbox"))),
    RuleSet("22-X.list", "X", "X", (blackmatrix("Twitter"),)),
    RuleSet(
        "22-Global-Social-Info.list",
        "Global-Social-Info",
        "海外社交资讯",
        tuple(blackmatrix(name) for name in ("Discord", "Reddit", "Wikipedia")),
        additions=("DOMAIN-SUFFIX,financialresearch.gov",),
    ),
    RuleSet(
        "23-Streaming.list",
        "Streaming",
        "境外流媒体",
        tuple(blackmatrix(name) for name in ("Netflix", "Disney", "HBO", "Hulu", "PrimeVideo", "ParamountPlus", "Peacock", "DAZN", "Twitch", "Spotify", "BBC", "Bahamut", "ViuTV", "AbemaTV", "Niconico"))
        + (blackmatrix("GlobalMedia"),),
        exclusions=(
            "DOMAIN,www.amazon.com", "DOMAIN-SUFFIX,us-west-2.amazonaws.com",
            "DOMAIN-SUFFIX,sentry.io", "DOMAIN-SUFFIX,intercom.io",
            "DOMAIN-SUFFIX,execute-api.us-east-1.amazonaws.com",
            "DOMAIN-SUFFIX,execute-api.ap-southeast-1.amazonaws.com",
            "DOMAIN-SUFFIX,cognito-identity.us-east-1.amazonaws.com",
            "DOMAIN-SUFFIX,mobileanalytics.us-east-1.amazonaws.com",
        ),
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
        exclusions=("IP-CIDR,203.107.1.1/24", "IP-CIDR,203.107.1.0/24", "DOMAIN-SUFFIX,pagespeed-mod"),
    ),
]

# Local/private destinations and account foundations outrank the reject layer.
RULESETS[:3] = [RULESETS[1], RULESETS[2], RULESETS[0]]


def _fetch_cache_paths(url: str, cache_dir: Path) -> tuple[Path, Path]:
    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{cache_key}.json", cache_dir / f"{cache_key}.body"


def _load_fetch_cache(url: str, cache_dir: Path) -> tuple[dict[str, str | None], bytes | None]:
    metadata_path, body_path = _fetch_cache_paths(url, cache_dir)
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        body = body_path.read_bytes()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, None
    if not isinstance(metadata, dict):
        return {}, None
    return {
        "etag": metadata.get("etag") if isinstance(metadata.get("etag"), str) else None,
        "last_modified": (
            metadata.get("last_modified") if isinstance(metadata.get("last_modified"), str) else None
        ),
    }, body


def _write_fetch_cache(url: str, cache_dir: Path, body: bytes, etag: str | None, last_modified: str | None) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    metadata_path, body_path = _fetch_cache_paths(url, cache_dir)
    body_path.write_bytes(body)
    metadata_path.write_text(
        json.dumps({"etag": etag, "last_modified": last_modified}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _response_status(response: object) -> int | None:
    status = getattr(response, "status", None)
    if status is not None:
        return int(status)
    getcode = getattr(response, "getcode", None)
    return int(getcode()) if getcode is not None else None


def _response_header(response: object, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(name)
    return value if isinstance(value, str) else None


def _response_text(body: bytes) -> str:
    """Reject transport-success error pages and damaged text before caching or using it."""
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise URLError(f"upstream response is not valid UTF-8: {exc}") from exc
    stripped = text.lstrip()
    if not stripped:
        raise URLError("upstream response is empty")
    if stripped.startswith("<"):
        raise URLError("upstream response is HTML/XML rather than rule data")
    return text


def fetch(url: str, *, opener=None, cache_dir: Path | None = None) -> str:
    cache_dir = UPSTREAM_CACHE_DIR if cache_dir is None else cache_dir
    opener = urlopen if opener is None else opener
    metadata, cached_body = _load_fetch_cache(url, cache_dir)
    headers = {"User-Agent": USER_AGENT}
    if metadata.get("etag"):
        headers["If-None-Match"] = metadata["etag"]
    if metadata.get("last_modified"):
        headers["If-Modified-Since"] = metadata["last_modified"]
    req = Request(url, headers=headers)
    last_error: Exception | None = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            with opener(req, timeout=FETCH_TIMEOUT_SECONDS) as response:
                status = _response_status(response)
                if status == 304:
                    if cached_body is None:
                        raise URLError("received 304 without a cached response body")
                    return _response_text(cached_body)
                if status != 200:
                    raise URLError(f"unexpected upstream HTTP status {status}; expected 200 or 304")
                body = response.read()
                text = _response_text(body)
                _write_fetch_cache(
                    url,
                    cache_dir,
                    body,
                    _response_header(response, "ETag"),
                    _response_header(response, "Last-Modified"),
                )
                return text
        except FETCH_ERRORS as exc:
            if isinstance(exc, HTTPError) and exc.code == 304 and cached_body is not None:
                return _response_text(cached_body)
            last_error = exc
            if SYSTEM_CURL.exists() and "CERTIFICATE_VERIFY_FAILED" in str(exc):
                body = fetch_with_system_curl(url).encode("utf-8")
                text = _response_text(body)
                _write_fetch_cache(url, cache_dir, body, None, None)
                return text
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
            encoding="utf-8",
            timeout=FETCH_TIMEOUT_SECONDS + 3,
        )
    except UnicodeDecodeError as exc:
        raise URLError(f"system curl response is not valid UTF-8: {exc}") from exc
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
    from rulegrammar import rule_value_problems

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("top-level JSON value is not an object")

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
            problems = rule_value_problems(Rule(rule_type, prefix))
            if problems:
                raise ValueError(f"prefix entry {index} has invalid {key}: {'; '.join(problems)}")
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
    return _accept_parsed_rule(rule)


def _accept_parsed_rule(rule: Rule) -> Rule | None:
    from rulegrammar import rule_value_problems

    if rule.rule_type == "DOMAIN-KEYWORD":
        # Keyword rules are too broad for this account-risk posture.
        return None
    if rule.rule_type not in ALLOWED_RULE_TYPES:
        return None
    problems = rule_value_problems(rule)
    if problems:
        raise ValueError("; ".join(problems))
    modifiers = ("no-resolve",) if any(m.lower() == "no-resolve" for m in rule.modifiers) else ()
    return Rule(rule.rule_type, rule.value, modifiers)


def _text_source_rules(raw: str, *, require_rules: bool = True) -> list[Rule]:
    """Validate a complete source before admitting any of its rows into the compiler."""
    rules: list[Rule] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        stripped = line.strip().lstrip("\ufeff")
        if not stripped or stripped.startswith(("#", "//", ";")):
            continue
        parsed = parse_rule(line)
        if stripped.startswith("<") or parsed is None:
            raise ValueError(f"line {line_number}: invalid rule syntax")
        try:
            rule = _accept_parsed_rule(parsed)
        except ValueError as exc:
            raise ValueError(f"line {line_number}: {exc}") from exc
        if rule is not None:
            rules.append(rule)
    if require_rules and not rules:
        raise ValueError("source contains no supported rules")
    return rules


# Policy of the reject rulesets (00-Ads-Reject, 27-Ads-Reject-Heavy).
REJECT_POLICY = "广告分流"

# Service-critical domains that upstream ad/tracker lists wrongly include. Because rules are
# first-match-wins and the reject lists sit before the service lists, an entry here is stripped
# from every reject ruleset so the later service rule wins. Matches a domain and its subdomains.
SERVICE_ALLOWLIST = frozenset(
    {
        *CLAUDE_FIRST_PARTY_SUFFIXES,
        "servd-anthropic-website.b-cdn.net",
        "statsig.com",        # OpenAI/ChatGPT feature-flag + experimentation (08-AI); 00 REJECTed api.statsig.com
        "statsigapi.net",     # statsig API host; 00 REJECTed it outright
        "featureassets.org",  # OpenAI feature-assets host (08-AI)
        "oaistatsig.com",     # OpenAI feature flags
        "safebrowsing.googleapis.com",
        "safebrowsing.google.com",
        "sb-ssl.google.com",
        "safebrowsing.apple",
        "safebrowsing.g.applimg.com",
        "safebrowsing.urlsec.qq.com",
        "safebrowsing.urlsec.gg.com",
        "crl.microsoft.com",  # certificate revocation checks
        "activate.adobe.com",
        "licenses.adobe.com",
        "na1r.services.adobe.com",
        "api.iqiyi.com",
        "httpdns.alicdn.com",  # shared functional DNS endpoint
        "sdb.amazonaws.com",  # Amazon SimpleDB API
        "staticxx.facebook.com",  # official Facebook SDK cross-domain authentication bridge
    }
)


def is_service_allowlisted(rule: Rule) -> bool:
    """True if a domain rule targets a SERVICE_ALLOWLIST domain (or a subdomain of one)."""
    if rule.rule_type not in ("DOMAIN", "DOMAIN-SUFFIX"):
        return False
    value = rule.value
    return any(value == domain or value.endswith("." + domain) for domain in SERVICE_ALLOWLIST)


@dataclass(frozen=True)
class CompileStats:
    generated: int
    duplicates_dropped: int
    covered_dropped: int
    allowlisted_dropped: int = 0
    excluded_dropped: int = 0


@dataclass(frozen=True)
class CompileResult:
    compiled: dict[str, list[Rule]]
    stats: CompileStats
    failures: list[str]


def compile_rules(rulesets: list[RuleSet], source_contents: dict[str, str]) -> CompileResult:
    """Pure transform: fetched content in, canonical per-file rule lists + stats + failures out.

    Dialect-blind. Dedup and coverage run once on canonical rules (IPv6 stays IP-CIDR6);
    rendering — and any dialect fold — happens downstream in render_tree, so every dialect
    tree dedups identically and per-file row counts stay in parity. Knows nothing about the
    network or the filesystem, so the same inputs always yield the same result without I/O.
    """
    index = CoverageIndex()
    duplicate_count = 0
    covered_count = 0
    allowlisted_count = 0
    excluded_count = 0
    failures: list[str] = []
    compiled: dict[str, list[Rule]] = {}
    parsed_sources: dict[tuple[str, str], list[Rule]] = {}

    def source_rules(source: str, kind: str) -> list[Rule]:
        key = (source, kind)
        if key not in parsed_sources:
            raw = source_contents.get(source)
            if raw is None:
                failures.append(f"{source}: SOURCE_MISSING: required source was not fetched")
                parsed_sources[key] = []
            else:
                try:
                    if kind == "JSON":
                        parsed_sources[key] = _text_source_rules("\n".join(json_prefix_rules(raw, source)))
                    else:
                        parsed_sources[key] = _text_source_rules(raw)
                except ValueError as exc:
                    label = "JSON_PARSE" if kind == "JSON" else "SOURCE_PARSE"
                    failures.append(f"{source}: {label}: {exc}")
                    parsed_sources[key] = []
        return parsed_sources[key]

    for ruleset in rulesets:
        candidates: list[Rule] = []
        for source in ruleset.sources:
            candidates.extend(source_rules(source, "TEXT"))
        try:
            candidates.extend(_text_source_rules("\n".join(ruleset.additions), require_rules=False))
        except ValueError as exc:
            failures.append(f"{ruleset.file}: ADDITIONS_PARSE: {exc}")
        for source in ruleset.json_prefix_sources:
            candidates.extend(source_rules(source, "JSON"))

        try:
            exclusions = {
                (rule.rule_type, rule.value.lower())
                for rule in _text_source_rules("\n".join(ruleset.exclusions), require_rules=False)
            }
        except ValueError as exc:
            failures.append(f"{ruleset.file}: EXCLUSIONS_PARSE: {exc}")
            exclusions = set()

        eligible: list[Rule] = []
        for rule in candidates:
            if (rule.rule_type, rule.value.lower()) in exclusions:
                excluded_count += 1
                continue
            if ruleset.policy == REJECT_POLICY and is_service_allowlisted(rule):
                allowlisted_count += 1
                continue
            eligible.append(rule)

        # A suffix anywhere in the same policy file covers narrower domain rows even when
        # it follows them upstream. Compute this before adding anything to the cross-file
        # index so discarded rows cannot accidentally influence later policy ownership.
        local_suffixes = {
            rule.value.lower().strip(".") for rule in eligible if rule.rule_type == "DOMAIN-SUFFIX"
        }

        kept: list[Rule] = []
        for rule in eligible:
            if rule.rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                labels = rule.value.lower().strip(".").split(".")
                start = 1 if rule.rule_type == "DOMAIN-SUFFIX" else 0
                if any(".".join(labels[offset:]) in local_suffixes for offset in range(start, len(labels))):
                    covered_count += 1
                    continue
            if ruleset.no_resolve and rule.rule_type.startswith("IP-") and "no-resolve" not in rule.modifiers:
                rule = Rule(rule.rule_type, rule.value, rule.modifiers + ("no-resolve",))
            # exact_tag dedups within and across files alike (add() populates the index for
            # both), so a separate rendered-string set would be redundant.
            if index.exact_tag(rule) is not None:
                duplicate_count += 1
                continue
            if ruleset.drop_if_covered and index.covered_by(rule) is not None:
                covered_count += 1
                continue
            kept.append(rule)
            index.add(rule, ruleset.tag)

        compiled[ruleset.file] = kept

    return CompileResult(
        compiled=compiled,
        stats=CompileStats(
            generated=len(rulesets),
            duplicates_dropped=duplicate_count,
            covered_dropped=covered_count,
            allowlisted_dropped=allowlisted_count,
            excluded_dropped=excluded_count,
        ),
        failures=failures,
    )


@dataclass(frozen=True)
class Dialect:
    name: str            # rulegrammar dialect id; also the fold key
    subdir: str          # output tree lives at rules/<subdir>/generated
    manifest_title: str  # first line of that tree's MANIFEST.csv


LOON_DIALECT = Dialect(LOON, "loon", "# Generated Loon rules manifest")
SHADOWROCKET_DIALECT = Dialect(SHADOWROCKET, "shadowrocket", "# Generated Shadowrocket rules manifest")
# Surge keeps canonical IP-CIDR6 (identity fold), so its .list bodies match the Loon tree; only the
# manifest title and path prefix differ. It gets its own tree so the config's RULE-SET URLs live in a
# reserved surge/ namespace and can evolve independently (per docs/adr/0002).
SURGE_DIALECT = Dialect(SURGE, "surge", "# Generated Surge rules manifest")
DIALECTS: tuple[Dialect, ...] = (LOON_DIALECT, SHADOWROCKET_DIALECT, SURGE_DIALECT)


def render_tree(compiled: dict[str, list[Rule]], rulesets: list[RuleSet], dialect: Dialect) -> dict[str, str]:
    """Render canonical rule lists into one dialect: .list text + MANIFEST.csv.

    The render half of "compile once, render twice". The only rule-body divergence is the fold
    applied right before render_rule (Loon = identity, Shadowrocket = IP-CIDR6 -> IP-CIDR). The
    manifest title and path prefix are the per-dialect near-constants that live builder-side, not
    in the shared grammar. Header attribution is identical across dialects — both are built here.
    """
    files: dict[str, str] = {}
    manifest: list[str] = [
        dialect.manifest_title,
        "# Do not include proxy nodes, subscriptions, certificates, or secrets.",
        "",
    ]
    for ruleset in rulesets:
        rules = compiled.get(ruleset.file, [])
        header = [
            f"# {ruleset.tag}",
            "# Generated by tools/build_loon_rules.py.",
            "# Public rule list only. No proxy nodes, subscriptions, certificates, or secrets.",
            f"# Policy: {ruleset.policy}",
        ]
        header.extend(f"# {note}" for note in ruleset.notes)
        body = [render_rule(fold(rule, dialect.name)) for rule in rules]
        files[ruleset.file] = "\n".join(header + [""] + body) + "\n"
        manifest.append(f"{ruleset.tag},{ruleset.policy},rules/{dialect.subdir}/generated/{ruleset.file},{len(rules)}")

    files["MANIFEST.csv"] = "\n".join(manifest) + "\n"
    return files


def stats_lines(stats: CompileStats) -> list[str]:
    """Human-readable stat lines shared by the build shell and the drift checker."""
    lines = [
        f"generated={stats.generated}",
        f"duplicates_dropped={stats.duplicates_dropped}",
        f"covered_later_rules_dropped={stats.covered_dropped}",
        f"service_allowlisted_dropped={stats.allowlisted_dropped}",
    ]
    if stats.excluded_dropped:
        lines.append(f"reviewed_exclusions_dropped={stats.excluded_dropped}")
    return lines


def _write_results(trees: list[tuple[Path, dict[str, str]]], verify=None) -> None:
    """Stage and verify every tree, then publish them with rollback on a write/swap failure.

    Each stage/backup is a sibling of its destination, so directory renames stay on the same
    filesystem. Files outside the generated .list/manifest set retain write_result's behavior.
    """
    import shutil
    import tempfile

    staged: list[tuple[Path, Path]] = []
    backups: dict[Path, Path] = {}
    backup_roots: list[Path] = []
    published: list[Path] = []
    committed = False
    try:
        for output_dir, files in trees:
            output_dir.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=".generated-stage-", dir=output_dir.parent))
            staged.append((output_dir, stage))
            if output_dir.exists():
                for retained in output_dir.iterdir():
                    if retained.name == "MANIFEST.csv" or retained.suffix == ".list":
                        continue
                    destination = stage / retained.name
                    if retained.is_dir() and not retained.is_symlink():
                        shutil.copytree(retained, destination, symlinks=True)
                    else:
                        shutil.copy2(retained, destination, follow_symlinks=False)
            for name, text in files.items():
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError(f"invalid generated filename: {name}")
                (stage / name).write_text(text, encoding="utf-8", newline="\n")
            for name, text in files.items():
                if (stage / name).read_bytes() != text.encode("utf-8"):
                    raise ValueError(f"staged generated file failed byte verification: {output_dir / name}")
            if verify is not None:
                verify(output_dir, stage)
            if output_dir.exists():
                shutil.copymode(output_dir, stage)

        for output_dir, stage in staged:
            if output_dir.exists():
                backup_root = Path(tempfile.mkdtemp(prefix=".generated-backup-", dir=output_dir.parent))
                backup_roots.append(backup_root)
                backup = backup_root / "previous"
                output_dir.rename(backup)
                backups[output_dir] = backup
            stage.rename(output_dir)
            published.append(output_dir)
        committed = True
    except (OSError, ValueError) as exc:
        rollback_errors: list[str] = []
        for output_dir, _stage in reversed(staged):
            try:
                if output_dir in published:
                    shutil.rmtree(output_dir)
                backup = backups.get(output_dir)
                if backup is not None:
                    backup.rename(output_dir)
            except OSError as rollback_error:
                rollback_errors.append(f"{output_dir}: {rollback_error}; previous tree retained at {backups.get(output_dir)}")
        if rollback_errors:
            raise OSError(f"{exc}; rollback failed: {'; '.join(rollback_errors)}") from exc
        raise
    finally:
        for _output_dir, stage in staged:
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
        for backup_root in backup_roots:
            # Preserve the previous snapshot for manual recovery if rollback itself failed.
            if committed or not (backup_root / "previous").exists():
                shutil.rmtree(backup_root, ignore_errors=True)


def write_result(output_dir: Path, files: dict[str, str]) -> None:
    """Safely replace one generated tree; build publishes all dialects together."""
    _write_results([(output_dir, files)])


def build(rules_dir: Path, strict: bool, allow_partial: bool = False) -> int:
    """Compose fetch -> compile -> render each dialect -> write, and own the exit-code policy."""
    source_contents, fetch_failures = fetch_all()
    result = compile_rules(RULESETS, source_contents)
    failures = fetch_failures + result.failures

    if failures:
        for failure in failures:
            print(f"FETCH_FAIL: {failure}", file=sys.stderr)
        if not allow_partial:
            print("FAIL: refusing to overwrite generated rules after upstream fetch or parse failures", file=sys.stderr)
            return 1

    from validate_generated import validate_generated_tree

    dialect_by_output = {
        rules_dir / dialect.subdir / "generated": dialect for dialect in DIALECTS
    }

    def verify(output_dir: Path, stage: Path) -> None:
        errors = validate_generated_tree(
            stage,
            dialect=dialect_by_output[output_dir].name,
            rulesets=RULESETS,
            allow_empty=allow_partial,
        )
        if errors:
            raise ValueError("staged generated tree is invalid: " + "; ".join(errors))

    try:
        trees = [
            (output_dir, render_tree(result.compiled, RULESETS, dialect))
            for output_dir, dialect in dialect_by_output.items()
        ]
        _write_results(trees, verify=verify)
    except (OSError, ValueError) as exc:
        print(f"BUILD_FAIL: {exc}", file=sys.stderr)
        return 1

    for line in stats_lines(result.stats):
        print(line)
    if failures and strict:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", type=Path, default=Path("rules"))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="write partial generated output even if upstream fetches or JSON parsing fail",
    )
    args = parser.parse_args()
    if args.strict and args.allow_partial:
        parser.error("--strict cannot be combined with --allow-partial")
    return build(args.rules_dir, args.strict, args.allow_partial)


if __name__ == "__main__":
    raise SystemExit(main())
