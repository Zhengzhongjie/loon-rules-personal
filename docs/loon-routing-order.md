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

1. Ads and LAN.
2. Mainland direct services: Baidu, WeChat, Tencent, Alibaba, NetEase.
3. Finance and crypto: PayPal, Stripe, Binance, OKX, Crypto, Bloomberg.
4. Adobe: Adobe, AdobeActivation.
5. AI: OpenAI, Claude, Anthropic, Gemini, Copilot, then AI category catchall.
6. Apple suite: Apple, iCloud, iCloudPrivateRelay, TestFlight, AppleNews, AppleTV, AppleMusic.
7. Mainland social/media: Xiaohongshu, Weibo, Douyin.
8. ByteDance split: TikTok before generic ByteDance, so international TikTok does not get swallowed by the mainland ByteDance rule.
9. Bilibili: BiliBili, BiliBiliIntl.
10. Telegram: Telegram domain list, then ASN.Telegram.
11. Microsoft: Microsoft, OneDrive, Teams, Bing, Xbox, LinkedIn.
12. Meta: Facebook, Instagram, Whatsapp, Threads.
13. Google: YouTube and YouTubeMusic before GoogleVoice, GoogleDrive, Google.
14. Developer and social additions: GitHub, GitLab, Docker, X/Twitter, Discord, Reddit, Wikipedia, Dropbox.
15. Overseas streaming: named platforms first, then `ProxyMedia.list`.
16. Amazon after PrimeVideo, because the broad Amazon list includes Prime Video and AWS domains.
17. Talkatone.
18. ASN.China near the end as the mainland catchall.
19. `FINAL,全局代理`.

## Conflict decisions

- Service-specific rules outrank category catchalls.
- YouTube outranks Google.
- TikTok outranks ByteDance.
- PrimeVideo outranks Amazon.
- Telegram domain rules outrank ASN.Telegram.
- ASN.China stays late so it does not steal explicitly routed global services.

## Test command

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
```
