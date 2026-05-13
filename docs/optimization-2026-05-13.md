# Loon optimization summary - 2026-05-13

## Scope

Optimized the local Loon configuration while keeping this public repository free
of private material. The full `.lcf` file was not copied into this repository.

## Local config changes

- Added self-maintained remote rule entries:
  - `AccountSafety-DIRECT` -> `DIRECT`
  - `Seetong-Local` -> `Seetong`
  - `PayPal-Stable` -> `PayPal`
  - `FinanceCrypto-Stable` -> `金融加密`
  - `AI-Reconnect` -> `AI`
- Kept account-sensitive mainland services on direct routing before broad
  category rules.
- Kept PayPal separate from the broader finance/crypto group for stable egress.
- Disabled optional high-risk app business-request rewrite plugins:
  - BiliBili ADBlock
  - BiliBili Enhanced
  - Disney+ plugin
  - Netflix beta plugin

## External rule source check

- Checked 96 configured remote rule/plugin URLs.
- Initial transient failure was observed for the Weibo rule URL; a direct retry
  returned HTTP 200.
- No persistent unreachable external rule source remained after retry.

## Security boundary

- The repository includes only public domain lists, documentation, and tooling.
- It does not include proxy nodes, node subscriptions, certificate data,
  passphrases, API tokens, or MITM hostnames.
- A local backup was created next to the Loon config before editing.

## Validation

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
python3 -m py_compile tools/validate_loon_config.py tools/audit_public_artifacts.py
```
