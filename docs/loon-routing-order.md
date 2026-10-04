# Loon routing order

This config keeps two layers:

1. Dedicated company/service rules first, so sensitive services can use their own policy group.
2. Consolidated category rules later, so uncovered domains still land in the right broad bucket.

## Policy groups and two-hop defaults

The user explicitly requires `链式代理链路` first in service selectors and
retains two-hop connections. This includes services previously documented as
DIRECT-first, such as Apple, Adobe and Seetong. DIRECT and regional choices
remain available manually. Built-in DIRECT foundations remain DIRECT rules.

- `链式代理链路` contains actual `[Proxy Chain]` links only, with existing link
  order preserved. Each link selects a regional ingress and `链式代理节点`.
- `链式代理节点` preserves explicit terminal choices. If previously filter-only,
  prepend the first existing static VLESS node when present so a fresh default
  does not depend on subscription ordering. No node-quality measurement is implied.
- `广告分流` keeps REJECT first, with DIRECT available for troubleshooting.
- Keep the selected two-hop ingress/exit stable for Claude, payment and crypto
  accounts. A group being first does not override an existing persisted selection.
- Binance requires an eligible stable exit: US/UK egress previously returned
  HTTP 451. Avoid frequent region switching for authenticated exchange traffic.

## Rule priority

Use the authored `tools/build_loon_rules.py` catalogue order in `[Remote Rule]`:

1. `LAN-Direct`
2. `AccountSafety-DIRECT`
3. `Ads-Reject`
4. `Mainland-Services-Direct`
5. `Seetong-Local`
6. `PayPal-Stable`
7. `TradingView-Fast`
8. `Binance-Geo`
9. `FinanceCrypto-Stable`
10. `Adobe`
11. `Claude`
12. `Gemini`
13. `Microsoft-Copilot`
14. `AI`
15. `Apple`
16. `RedNote`
17. `Weibo`
18. `TikTok`
19. `Douyin-ByteDance`
20. `Bilibili`
21. `Telegram`
22. `Microsoft`
23. `Meta`
24. `YouTube`
25. `Google`
26. `GitHub`
27. `Developer-Collab`
28. `X`
29. `Global-Social-Info`
30. `Streaming`
31. `Amazon`
32. `Talkatone`
33. `ChinaASN-Direct`
34. `Ads-Reject-Heavy` (disabled by default; opt-in only)

Finally use `FINAL,全局代理` in `[Rule]`. Heavy is last and disabled; domain
safety checks use this actual order, rather than assuming Heavy runs first.

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
rules apply while remote subscriptions refresh. The supplements do not select an egress node or establish that a failing
chart or API has recovered. The separately authorized configuration optimizer
places the chain link selector first and keeps the two-hop wiring intact.

The OFR chart page declares `https://data.financialresearch.gov/hf/` as its
data API, covered by the OFR suffix rule. Hypurrscan's page separately references
`https://api.hyperliquid.xyz/info`; its application bundle also declares the
`api-ui.hyperliquid.xyz` API and `rpc.hyperliquid.xyz` EVM backup/WebSocket.
Bind those exact hosts to the same finance policy
so page and data requests use the same selection. Do not exempt all Hyperliquid
subdomains from ad filtering (for example, its existing metrics reject rule).

## Test command

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/loon rules for mac.lcf"
python3 tools/audit_public_artifacts.py .
```
