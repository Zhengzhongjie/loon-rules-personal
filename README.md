# loon-rules-personal

Personal Loon routing notes, supplemental rule lists, and validation tooling.

## Contents

- `docs/loon-routing-order.md`: recommended policy groups, remote-rule order, and conflict decisions.
- `docs/optimization-2026-10-04.md`: current routing, ad safety, generator and measured performance changes.
- `docs/optimization-2026-05-13.md`: earlier optimization history.
- `docs/security-posture.md`: public/private boundary and account-risk posture.
- `rules/loon/generated/`: generated, deduplicated public Loon rule subscriptions.
- `rules/shadowrocket/generated/`: the same rule lists in the Shadowrocket dialect — identical matches, with IPv6 `IP-CIDR6` folded into Shadowrocket's dual-stack `IP-CIDR`.
- `rules/surge/generated/`: the same rule lists in the Surge dialect — Surge keeps canonical `IP-CIDR6` (identity fold), so the `.list` bodies match the Loon tree; only the manifest title and path prefix differ.
- `rules/<dialect>/generated/MANIFEST.csv`: generated tag, policy, file, and rule-count manifest per dialect.
- `configs/shadowrocket/`: generated Shadowrocket config skeletons (`iphone.conf`, `mac.conf`) — full-shape `.conf` with `{{PLACEHOLDER}}` private values, filled during iCloud assembly.
- `configs/surge/`: generated Surge config skeletons (`ios.conf` for iPhone & iPad, `mac.conf` for Surge Mac with LAN sharing + HTTP API) — same placeholder model.
- `docs/shadowrocket-modules.md`: Loon plugin → Shadowrocket module map (installed in-app, not embedded in the `.conf`).
- `docs/surge-modules.md`: Loon plugin → Surge module map (`.sgmodule`, full fidelity, MediaCheck restored as a Panel; installed in-app).
- `tools/build_loon_rules.py`: compiles rules once from reviewed upstream sources plus local supplements, then renders every dialect tree.
- `tools/build_shadowrocket_config.py`: renders the Shadowrocket config skeletons from the shared RULESETS catalogue plus a committed sanitized spec.
- `tools/build_surge_config.py`: renders the Surge config skeletons from the shared RULESETS catalogue plus a committed sanitized spec.
- `tools/optimize_loon_config.py`: validates and updates both private Loon configs with chain-first two-hop defaults, backups and optimistic concurrent-edit checks.
- `tools/inspect_routing.py`: compares ordered DOMAIN/SUFFIX routing and records offline before/after benchmarks (not Loon device performance).
- `tools/check_loon_rule_drift.py`: rebuilds every dialect's generated rules in memory and reports upstream drift.
- `tools/validate_loon_config.py`: invariant checks for the local Loon configuration.
- `tools/validate_shadowrocket_config.py`: dual-mode checks for the Shadowrocket config — committed skeletons (CI) or a filled private `.conf` (local).
- `tools/validate_surge_config.py`: dual-mode checks for the Surge config — committed skeletons (CI) or a filled private `.conf` (local).
- `tools/validate_generated.py`: shared, dialect-neutral validator for a generated rule tree (manifest order, dedup, coverage); used by every config validator.
- `tools/rulegrammar.py`: shared rule-line grammar (parse, render, per-dialect fold, suffix-coverage index) used by the builder and the validators.
- `tools/audit_public_artifacts.py`: checks that public repo files do not include obvious secrets, with a placeholder-aware model for config skeletons.
- `tests/`: pytest unit tests for the rule compiler, shared grammar, generated-tree validator, both config validators, the Shadowrocket config generator, and the audit.
- `.github/workflows/loon-rule-drift.yml`: per-push offline unit tests plus the weekly/manual upstream drift check for generated public rule lists.

Do not commit full Loon `.lcf` files, node subscriptions, certificates, passphrases, or MITM hostnames.

## One-time clone setup

Enable the fail-closed pre-commit leak gate (audits the git index before every commit):

```sh
git config core.hooksPath githooks
```

`tools/audit_public_artifacts.py` scans tracked + staged content by default; pass
`--all` for a whole-disk sweep. See `docs/security-posture.md` → "Leak defense".

## Validation

Run the validator against the target Loon config:

```sh
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/loon rules for iphone & ipad.lcf"
python3 tools/validate_loon_config.py "/Users/alessiozheng/Library/Mobile Documents/iCloud~com~ruikq~decar/Documents/Configs/loon rules for mac.lcf"
python3 tools/validate_shadowrocket_config.py   # CI mode: committed skeletons + Shadowrocket rule tree
python3 tools/validate_surge_config.py          # CI mode: committed skeletons + Surge rule tree
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
