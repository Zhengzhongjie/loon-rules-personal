# codex-loon-rules

Personal Loon routing notes, supplemental rule lists, and validation tooling.

## Contents

- `docs/loon-routing-order.md`: recommended policy groups, remote-rule order, and conflict decisions.
- `docs/optimization-2026-05-13.md`: sanitized change summary for the current optimization pass.
- `docs/security-posture.md`: public/private boundary and account-risk posture.
- `rules/loon/generated/`: generated, deduplicated public Loon rule subscriptions.
- `rules/loon/generated/MANIFEST.csv`: generated tag, policy, file, and rule-count manifest.
- `tools/build_loon_rules.py`: rebuilds generated rules from reviewed upstream sources plus local supplements.
- `tools/check_loon_rule_drift.py`: rebuilds generated rules in a temporary directory and reports upstream drift.
- `tools/validate_loon_config.py`: invariant checks for the local Loon configuration.
- `tools/audit_public_artifacts.py`: checks that public repo files do not include obvious secrets.
- `.github/workflows/loon-rule-drift.yml`: weekly and manual drift check for generated public rule lists.

Do not commit full Loon `.lcf` files, node subscriptions, certificates, passphrases, or MITM hostnames.

## Validation

Run the validator against the target Loon config:

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
HTTP_PROXY=http://127.0.0.1:7222 HTTPS_PROXY=http://127.0.0.1:7222 NO_PROXY=localhost,127.0.0.1,::1 python3 tools/build_loon_rules.py --strict
HTTP_PROXY=http://127.0.0.1:7222 HTTPS_PROXY=http://127.0.0.1:7222 NO_PROXY=localhost,127.0.0.1,::1 python3 tools/check_loon_rule_drift.py
```
