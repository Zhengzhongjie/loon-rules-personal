# codex-loon-rules

Personal Loon routing notes, supplemental rule lists, and validation tooling.

## Contents

- `docs/loon-routing-order.md`: recommended policy groups, remote-rule order, and conflict decisions.
- `docs/optimization-2026-05-13.md`: sanitized change summary for the current optimization pass.
- `docs/security-posture.md`: public/private boundary and account-risk posture.
- `rules/loon/AccountSafety-Direct.list`: small direct rules for China-region account-sensitive services.
- `rules/loon/AI-Reconnect.list`: AI reconnect and browser challenge dependencies.
- `rules/loon/FinanceCrypto-Stable.list`: finance/crypto stable-route supplements.
- `rules/loon/PayPal-Stable.list`: PayPal-specific stable-route supplements.
- `rules/loon/Seetong.list`: supplemental Seetong domain rules.
- `tools/validate_loon_config.py`: invariant checks for the local Loon configuration.
- `tools/audit_public_artifacts.py`: checks that public repo files do not include obvious secrets.

Do not commit full Loon `.lcf` files, node subscriptions, certificates, passphrases, or MITM hostnames.

## Validation

Run the validator against the target Loon config:

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
```
