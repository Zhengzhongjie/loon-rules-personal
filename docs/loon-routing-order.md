# Loon routing order

This config keeps two layers:

1. Dedicated company/service rules first, so sensitive services can use their own policy group.
2. Consolidated category rules later, so uncovered domains still land in the right broad bucket.

## Recommended policy groups

- `广告分流`: `REJECT`, then `DIRECT`.
- `Seetong`: `DIRECT` first for camera latency and LAN-like behavior, then proxy choices.
- `Adobe`: `DIRECT` first unless Adobe account or regional access requires proxy.
- `Apple`: `DIRECT` first, then proxy choices.
- `Claude`: use one stable supported-region group only (`美国节点`, `狮城节点`, `日本节点`, `台湾节点`, `韩国节点`, or `英国节点`). Do not offer `DIRECT`, Hong Kong, Macao, unknown-region, or multi-region chain choices.
- `Binance`: one stable **non-US, non-UK** node only (`日本节点`, `狮城节点`, `香港节点`, `台湾节点`, `韩国节点`). `api.binance.com` answers HTTP 451 "Service unavailable from a restricted location" on US/UK egress. Do not put `DIRECT` first, and do not region-hop — exchange risk control dislikes it.
- `AI`, `Google`, `YouTube`, `Telegram`, `TikTok`, `Microsoft`, `Meta`, `GitHub`, `金融加密`, `Amazon`, `开发协作`, `海外社交资讯`, `境外流媒体`: proxy first, then `DIRECT`.
- `RedNote`, `抖音`, `Bilibili`, `Weibo`: `DIRECT` first, then proxy choices.

## Rule priority

Use this order in `[Remote Rule]`:

1. `Ads-Reject`
2. `LAN-Direct`
3. `AccountSafety-DIRECT`
4. `Mainland-Services-Direct`
5. `Seetong-Local`
6. `PayPal-Stable`
7. `TradingView-Fast`
8. `Binance-Geo`
9. `FinanceCrypto-Stable`
10. `Adobe`
11. `Claude`
12. `AI`
13. `Apple`
14. `RedNote`
15. `Weibo`
16. `TikTok`
17. `Douyin-ByteDance`
18. `Bilibili`
19. `Telegram`
20. `Microsoft`
21. `Meta`
22. `YouTube`
23. `Google`
24. `GitHub`
25. `Developer-Collab`
26. `Global-Social-Info`
27. `Streaming`
28. `Amazon`
29. `Talkatone`
30. `ChinaASN-Direct`
31. `FINAL,全局代理`

## Conflict decisions

- Service-specific rules outrank category catchalls.
- YouTube outranks Google.
- TikTok outranks ByteDance.
- PrimeVideo outranks Amazon.
- Telegram domain rules outrank ASN.Telegram.
- ASN.China stays late and uses hard `DIRECT` so it does not steal explicitly routed global services or expose mainland catchall traffic to manual proxy selection.
- Account-sensitive direct rules outrank ad, app-enhancement, and broad category rules.
- Finance/crypto rules should use a manually selected stable route, not frequent automatic region switching.
- The original upstream subscriptions are build inputs only. The Loon config should subscribe to generated repository rules to avoid duplicate and shadowed entries.

## Reviewed site supplements (2026-10-04)

| Domain (including subdomains) | Rule list | Policy |
| --- | --- | --- |
| `zbrowser.cn` | `Mainland-Services-Direct` | `DIRECT` |
| `financialresearch.gov` | `Global-Social-Info` | `海外社交资讯` |
| `hypurrscan.io` | `FinanceCrypto-Stable` | `金融加密` |
| `api.hyperliquid.xyz` (exact host) | `FinanceCrypto-Stable` | `金融加密` |
| `api-ui.hyperliquid.xyz` (exact host) | `FinanceCrypto-Stable` | `金融加密` |
| `rpc.hyperliquid.xyz` (exact host) | `FinanceCrypto-Stable` | `金融加密` |

These supplements are authored in `tools/build_loon_rules.py` and included in
all three generated dialect trees and their manifests. Private Loon configs may
also bind these exact domain/policy pairs in `[Rule]` before `FINAL` so the
rules apply while remote subscriptions refresh. Preserve existing policy-group
choices and order; the supplements do not select an egress node or establish
that a failing chart or API has recovered.

The OFR chart page declares `https://data.financialresearch.gov/hf/` as its
data API, covered by the OFR suffix rule. Hypurrscan's page separately references
`https://api.hyperliquid.xyz/info`; its application bundle also declares the
`api-ui.hyperliquid.xyz` API and `rpc.hyperliquid.xyz` EVM backup/WebSocket.
Bind those exact hosts to the same finance policy
so page and data requests use the same selection. Do not exempt all Hyperliquid
subdomains from ad filtering (for example, its existing metrics reject rule).

## Test command

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
```
