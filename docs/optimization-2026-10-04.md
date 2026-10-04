# 2026-10-04 routing and configuration optimization

The user requires `链式代理链路` to be the first service selector candidate and
explicitly keeps two-hop connections. Existing private proxy definitions,
WireGuard quoting, chain wiring, certificates and MITM hostname values are
preserved. A filter-only terminal selector now starts with the first existing
static VLESS node when available, making its fresh default independent of
subscription sorting; an existing explicit terminal choice is preserved.
This does not measure node quality or replace Loon's persisted selection.

## Service ownership and functional endpoints

| Traffic | Policy/change |
| --- | --- |
| Gemini, AI Studio, NotebookLM and Google login | `Google`; dedicated Gemini rule list precedes broad AI |
| Microsoft Copilot and Microsoft identity | `Microsoft`; reviewed Microsoft hosts only |
| GitHub Copilot and GitHub | `GitHub` |
| Stripe API, checkout and static assets | `金融加密`; no longer split between AI and finance |
| X/Twitter | Existing `X` selector now has its own rule list |
| OFR and its `data.financialresearch.gov` API | `海外社交资讯` |
| Hypurrscan, Hyperliquid API/UI API/RPC | `金融加密` |
| ZBrowser and domestic iQIYI | `DIRECT` |
| Amazon shopping / PrimeVideo | `Amazon` / `境外流媒体`; shopping host excluded from streaming |

Remove early whole-cloud AS20473, AS14061 and AS132203 ownership, shared Auth0,
Sentry, Algolia, Intercom and Akamai root captures, and shared regional AWS
API/identity captures. Retain reviewed service-specific CDN and Sentry hosts,
including OpenAI's documented Intercom CDN and new `oaistatsig.com` dependency.

The upstream Copilot list includes broad OpenAI/shared infrastructure, so it is
replaced with reviewed Microsoft hosts. The upstream Stripe list only contains
a deliberately unsupported keyword rule, so explicit Stripe supplements replace
that fetch. Unavailable `whatshub.top` media input is replaced with the existing
reviewed blackmatrix GlobalMedia source.

## Advertising safety and configuration defaults

LAN and account foundations precede the core reject list. Core and Heavy reject
lists exclude reviewed functional endpoints: Apple/Google/QQ Safe Browsing,
Microsoft certificate revocation, Adobe activation/licensing, Facebook SDK
cross-domain authentication, Amazon SimpleDB, iQIYI API, Alibaba HTTPDNS and AI
feature flags. The overbroad Alibaba HTTPDNS `/24` and the single-label
`pagespeed-mod` suffix are removed. Blocking telemetry remains supported.

Same-file domain compaction removes narrower matches only when a broader suffix
has the same policy. Cross-service overrides remain ordered; the regression
checks use actual catalogue order, including Heavy last.

All client service selectors use chain first, with manual DIRECT/region choices
available. Chain selectors contain genuine chain links only. Regional ingress
tests in the private Loon variants use 600-second intervals and 100 ms tolerance.
Heavy is disabled by default in Loon and commented as opt-in in public
Shadowrocket/Surge skeletons. MITM and proxy certificate verification are enabled;
LAN proxy sharing/shared-flow MITM and reviewed high-risk enhancement plugins
are disabled. SSID defaults use rule mode. Remove the obsolete DIRECT fake-IP
`198.18.0.1/32` exception.

## Generator, validation and leak protection

Reject malformed, empty, HTML, invalid UTF-8 and wrong-family upstream input.
Stage, byte-check and validate all dialect outputs before replacing any tree;
roll back previous trees on ordinary write/rename failures. Explicit partial
builds remain an opt-in. Multi-directory swaps cannot promise atomicity under
a process kill; failed rollback retains recovery paths.

Validate exact tag/file/policy/enabled bindings, graph references, duplicate
members, cycles, safe local IP exceptions and MITM verification. IPv4/IPv6/ASN
semantics are checked with Shadowrocket's dual-stack output exception. Leak
diagnostics report only location, known field and category, never secret values.

The three dialect trees contain 34 rule lists each. The upstream digests are in
`upstream-snapshot-2026-10-04.json`. Unit, routing, negative-source, write-failure,
secret-redaction and private-config preservation tests cover the changed behavior.

## Measured scope and results

| Metric | Previous published tree | Updated tree |
| --- | ---: | ---: |
| Core ad rules | 2,935 | 2,526 |
| Heavy ad rules (disabled) | 178,353 | 193,092 |
| Enabled total rules, excluding Heavy | 14,158 | 14,540 |
| Enabled DOMAIN/SUFFIX rows | 7,579 | 7,063 |
| Python enabled-domain index peak allocation | 895,364 bytes | 757,924 bytes |

The core ad list shrinks 13.9%; overall active rule count grows 2.7% as media and
functional coverage expand. Upstream changes also contribute to these deltas.
This build drops 1,306 duplicates, 4,451 covered entries, 30 protected functional
rejects and 28 explicitly reviewed captures.

`tools/inspect_routing.py` compares an ordered linear DOMAIN/SUFFIX reference
with its indexed implementation using identical deterministic probes for before
and after, three rounds, Heavy on/off. Both agree on all tested decisions.
Enabled-profile median linear lookup decreases 27.70 to 24.83 ms for 80 probes;
Heavy-profile median increases 606.16 to 761.63 ms as upstream coverage grows.
Raw measurements and probes are in `benchmarks/2026-10-04-domain-routing.json`.

These are offline Python measurements. They exclude client rule engine behavior,
IP/ASN, regex/process matches, DNS timing, device memory, two-hop RTT/throughput and
real node quality. They establish no measured Loon device speedup. Private Loon
configs are separately validated; actual import, persisted selections and VPN
operation require access to the Mac. Current cloud tools cannot execute there.

## Evidence and commands

- [OpenAI network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)
- [Apple enterprise network endpoints](https://support.apple.com/en-us/101555)
- [Adobe licensing endpoints](https://helpx.adobe.com/enterprise/kb/network-endpoints.html)
- [Facebook JavaScript SDK](https://connect.facebook.net/en_US/sdk.js)
- [Amazon SimpleDB endpoints](https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/Endpoints.html)

```sh
python3 -m pytest -q
python3 tools/build_loon_rules.py --strict
python3 tools/check_loon_rule_drift.py
python3 tools/validate_shadowrocket_config.py
python3 tools/validate_surge_config.py
python3 tools/audit_public_artifacts.py .
python3 tools/inspect_routing.py --rounds 3 --json-output /tmp/routing-performance.json
python3 tools/optimize_loon_config.py --in-place --open-loon
```

The private optimizer preflights both configs, creates private backups, preserves
node/chain definitions, validates before writing and rechecks original bytes after
staging/fsync. Rollback preserves newer external edits or deletions. These are
optimistic checks; they cannot lock out an unrelated writer between a check and
replacement. Quoted commas in group options are preserved. The tool requests macOS to open the
Mac config in Loon when `--open-loon` is used. Opening a document does not verify
that Loon activated that configuration or started its VPN.
