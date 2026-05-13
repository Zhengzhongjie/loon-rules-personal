# Loon routing order

This config keeps two layers:

1. Dedicated company/service rules first, so sensitive services can use their own policy group.
2. Consolidated category rules later, so uncovered domains still land in the right broad bucket.

## Recommended policy groups

- `广告分流`: `REJECT`, then `DIRECT`.
- `大陆流量`: `DIRECT`, with proxy choices only for emergency override.
- `Seetong`: `DIRECT` first for camera latency and LAN-like behavior, then proxy choices.
- `Adobe`: `DIRECT` first unless Adobe account or regional access requires proxy.
- `Apple`: `DIRECT` first, then proxy choices.
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
7. `FinanceCrypto-Stable`
8. `Adobe`
9. `AI`
10. `Apple`
11. `RedNote`
12. `Weibo`
13. `TikTok`
14. `Douyin-ByteDance`
15. `Bilibili`
16. `Telegram`
17. `Microsoft`
18. `Meta`
19. `YouTube`
20. `Google`
21. `GitHub`
22. `Developer-Collab`
23. `Global-Social-Info`
24. `Streaming`
25. `Amazon`
26. `Talkatone`
27. `ChinaASN-Direct`
28. `FINAL,全局代理`

## Conflict decisions

- Service-specific rules outrank category catchalls.
- YouTube outranks Google.
- TikTok outranks ByteDance.
- PrimeVideo outranks Amazon.
- Telegram domain rules outrank ASN.Telegram.
- ASN.China stays late so it does not steal explicitly routed global services.
- Account-sensitive direct rules outrank ad, app-enhancement, and broad category rules.
- Finance/crypto rules should use a manually selected stable route, not frequent automatic region switching.
- The original upstream subscriptions are build inputs only. The Loon config should subscribe to generated repository rules to avoid duplicate and shadowed entries.

## Test command

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
```
