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

## Crypto DEX and tool coverage (2026-10-09)

The following reviewed supplements belong to `FinanceCrypto-Stable` and use
the existing `金融加密` policy in Loon, Shadowrocket and Surge. Domains below
include subdomains unless marked as exact hosts. Existing Uniswap, PancakeSwap,
Sushi, Raydium, Phantom, DeBank, DefiLlama and DEXTools coverage is also pinned
in the builder's local additions so it does not depend solely on upstream lists.

| Service | Reviewed domains / hosts | Official source |
| --- | --- | --- |
| 1inch | `1inch.com`, `1inch.network`; retain existing `1inch.io` | [Domain and API migration](https://help.1inch.com/en/articles/12360054-rebranding-faq) |
| Curve | `curve.finance` | [Domain incident and replacement frontend](https://news.curve.finance/curve-domain-incident/) |
| Balancer | `balancer.fi` | [Documentation](https://docs.balancer.fi/) |
| CoW Swap | `cow.fi` | [API documentation](https://docs.cow.fi/cow-protocol/integrate/api) |
| Jupiter | `jup.ag` | [Swap API](https://developers.jup.ag/docs/api-reference/swap/v1/swap) |
| Orca | `orca.so` | [API documentation](https://docs.orca.so/api-reference/overview) |
| Meteora | `meteora.ag` | [Data API](https://docs.meteora.ag/developer-guides/dlmm/api-reference/overview.md) |
| Aerodrome / Velodrome | `aerodrome.finance`, `velodrome.finance` | [Aerodrome](https://aerodrome.finance/), [Velodrome](https://velodrome.finance/) |
| Osmosis | `osmosis.zone` | [Endpoints](https://docs.osmosis.zone/integrate/endpoints/) |
| GMX | `gmx.io`, `gmxalt.io`, `gmxapi.io`, `gmxapi.ai`, `gmxinfra.io`, `gmxinfra2.io` | [Frontend](https://docs.gmx.io/docs/api/frontend-integration/), [API URLs](https://docs.gmx.io/docs/api/gmx-api/gmx-io-gmx-public-api/), [Fallback URLs](https://docs.gmx.io/docs/api/rest-api/fallback-urls/) |
| dYdX | `dydx.trade`, `dydx.xyz`; retain existing `dydx.exchange` | [Endpoints](https://docs.dydx.xyz/interaction/endpoints) |
| Drift | `drift.trade` | [Official frontend](https://www.drift.trade/) |
| Hyperliquid | `hyperfoundation.org`; exact `hyperliquid.xyz`, `app.hyperliquid.xyz`, plus the existing three API/RPC hosts | [Official support guide](https://hyperliquid.gitbook.io/hyperliquid-docs/support/read-me-support-guide) |
| MetaMask | Exact `metamask.io`, `www.metamask.io`, `portfolio.metamask.io`, `link.metamask.io`, `docs.metamask.io`, `support.metamask.io`, `bridge.api.cx.metamask.io`, `tokens.api.cx.metamask.io`, `gas.api.cx.metamask.io` | [Website](https://metamask.io/), [Portfolio](https://support.metamask.io/manage-crypto/portfolio/), [Functional API origins](https://github.com/MetaMask/metamask-extension/blob/main/shared/constants/swaps.ts) |
| Rabby / Trust Wallet | `rabby.io`, `trustwallet.com` | [Rabby](https://rabby.io/), [Trust Wallet](https://trustwallet.com/) |
| WalletConnect / Reown | `walletconnect.com`, `walletconnect.org`, `reown.com` | [WalletConnect](https://walletconnect.com/), [Relay origin](https://github.com/WalletConnect/walletconnect-monorepo/blob/v2.0/packages/core/src/constants/relayer.ts), [Reown](https://reown.com/) |
| Zerion | `zerion.io` | [Official website](https://zerion.io/) |
| DEX Screener / GeckoTerminal / Birdeye | `dexscreener.com`, `geckoterminal.com`, `birdeye.so` | [DEX Screener API](https://docs.dexscreener.com/api/reference), [GeckoTerminal](https://www.geckoterminal.com/), [Birdeye](https://birdeye.so/) |
| Dune | `dune.com`; retain existing `duneanalytics.com` | [Official website](https://dune.com/home) |
| DefiLlama | `llama.fi`, plus existing `defillama.com` | [Free and Pro API origins](https://api-docs.defillama.com/) |
| Chain explorers | `solscan.io`, `arbiscan.io`, `basescan.org`, `polygonscan.com` | [Solscan](https://solscan.io/), [Arbiscan](https://arbiscan.io/), [BaseScan](https://basescan.org/), [PolygonScan](https://polygonscan.com/) |
| LI.FI / Jumper | `li.fi`, `li.quest`, `jumper.xyz`, `jumper.exchange` | [LI.FI API base URL](https://docs.li.fi/api-reference/introduction), [Jumper legacy entry redirects to current domain](https://jumper.exchange/) |
| Across / Stargate | `across.to`, `stargate.finance` | [Across](https://across.to/), [Stargate](https://stargate.finance/) |
| Revoke.cash | `revoke.cash` | [Approval management](https://revoke.cash/) |

Hyperliquid and MetaMask use exact functional hosts to keep
`metrics.hyperliquid.xyz` and `mm-sdk-analytics.api.cx.metamask.io` eligible
for the optional Heavy reject rules. WalletConnect's legacy `.org` domain
remains necessary for `relay.walletconnect.org`. Shared CDN and third-party
RPC provider domains are not added to this policy.

The generated lists were compiled from the committed, reviewed rule bodies
plus these additions, preserving the other lists without an upstream refresh.
Future normal builds and drift checks use the same authored additions.

## Test command

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/loon rules for mac.lcf"
python3 tools/audit_public_artifacts.py .
```
