# codex-loon-rules

Personal Loon routing notes, supplemental rule lists, and validation tooling.

## Contents

- `docs/loon-routing-order.md`: recommended policy groups, remote-rule order, and conflict decisions.
- `rules/loon/Seetong.list`: supplemental Seetong domain rules.
- `tools/validate_loon_config.py`: invariant checks for the local Loon configuration.

## Validation

Run the validator against the target Loon config:

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/20260503-loon.lcf"
```
