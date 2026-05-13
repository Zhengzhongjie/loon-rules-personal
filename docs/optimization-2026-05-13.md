# Loon optimization summary - 2026-05-13

## Scope

Optimized the local Loon configuration while keeping this public repository free
of private material. The full `.lcf` file was not copied into this repository.

## Local config changes

- Added self-maintained remote rule entries:
  - 27 generated repo-hosted subscriptions under `rules/loon/generated/`.
  - Original upstream subscriptions are now build inputs, not direct Loon config entries.
- Kept account-sensitive mainland services on direct routing before broad
  category rules.
- Kept PayPal separate from the broader finance/crypto group for stable egress.
- Reduced `[Rule]` to `FINAL,全局代理`; service rules now live in generated remote subscriptions.
- Enabled DNS hijack and corrected `ip-mode` to `ipv4-only`; IPv6 remains off for stability testing.
- Disabled optional high-risk app business-request rewrite plugins:
  - BiliBili ADBlock
  - BiliBili Enhanced
  - Disney+ plugin
  - Netflix beta plugin

## External rule source check

- Generated 27 public rule subscriptions from reviewed upstream sources and
  local supplements.
- Dropped 410 exact duplicate rules and 182 later rules covered by earlier
  higher-priority suffix rules during the latest successful build.
- Transient upstream TLS/connection failures were resolved by retrying through
  the local HTTP proxy.

## Security boundary

- The repository includes only public domain lists, documentation, and tooling.
- It does not include proxy nodes, node subscriptions, certificate data,
  passphrases, API tokens, or MITM hostnames.
- A local backup was created next to the Loon config before editing.

## Validation

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
python3 -m py_compile tools/validate_loon_config.py tools/audit_public_artifacts.py tools/build_loon_rules.py
```
