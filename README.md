# codex-loon-rules

Personal Loon routing notes, supplemental rule lists, and validation tooling.

## Contents

- `docs/loon-routing-order.md`: recommended policy groups, remote-rule order, and conflict decisions.
- `docs/optimization-2026-05-13.md`: sanitized change summary for the current optimization pass.
- `docs/security-posture.md`: public/private boundary and account-risk posture.
- `rules/loon/generated/`: generated, deduplicated public Loon rule subscriptions.
- `rules/loon/generated/MANIFEST.csv`: generated tag, policy, file, and rule-count manifest.
- `tools/build_loon_rules.py`: rebuilds generated rules from reviewed upstream sources plus local supplements.
- `tools/check_loon_rule_drift.py`: rebuilds generated rules in memory and reports upstream drift.
- `tools/validate_loon_config.py`: invariant checks for the local Loon configuration.
- `tools/rulegrammar.py`: shared rule-line grammar (parse, render, suffix-coverage index) used by both the builder and the validator.
- `tools/audit_public_artifacts.py`: checks that public repo files do not include obvious secrets.
- `tests/`: pytest unit tests for the rule compiler (`test_compile_rules.py`), the shared grammar (`test_rulegrammar.py`), and the config validator (`test_validate_config.py`).
- `.github/workflows/loon-rule-drift.yml`: per-push offline unit tests plus the weekly/manual upstream drift check for generated public rule lists.

Do not commit full Loon `.lcf` files, node subscriptions, certificates, passphrases, or MITM hostnames.

## Validation

Run the validator against the target Loon config:

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
python3 tools/audit_public_artifacts.py .
HTTP_PROXY=http://127.0.0.1:7222 HTTPS_PROXY=http://127.0.0.1:7222 NO_PROXY=localhost,127.0.0.1,::1 python3 tools/build_loon_rules.py --strict
HTTP_PROXY=http://127.0.0.1:7222 HTTPS_PROXY=http://127.0.0.1:7222 NO_PROXY=localhost,127.0.0.1,::1 python3 tools/check_loon_rule_drift.py
```

## Tests

The unit tests are offline (no network, no real Loon config) and run with pytest:

```sh
python3 -m pytest
```

`pytest.ini` puts `tools/` on the import path, so the tests import the tool modules directly. They also run automatically on every push via the `unit-tests` job in the workflow above.
