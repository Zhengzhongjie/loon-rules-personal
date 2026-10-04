#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate the Surge config — dual mode.

Without an argument (CI mode): validate the committed skeletons in configs/surge/ — they must match
the generator output exactly (no manual drift) and carry only placeholders in private sections — plus
the generated Surge rule tree. With a config path (local mode): validate a filled private `.conf`
(placeholders gone, private sections populated) or a skeleton path, auto-detected by the presence of
`{{…}}`. Either way the [Rule] bindings must still match the RULESETS catalogue, so the config can
never drift from the generated rule trees.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import build_surge_config as su
from audit_public_artifacts import private_section_leaks
from validate_generated import validate_generated_tree

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIGS_DIR = REPO_ROOT / "configs" / "surge"
SU_RULE_TREE = REPO_ROOT / "rules" / "surge" / "generated"

REQUIRED_SECTIONS = ["General", "Proxy", "Proxy Group", "Rule", "MITM"]
BUILTIN_POLICIES = {"DIRECT", "REJECT", "PROXY"}


def sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            result[current] = []
        elif current and line and not line.startswith("#"):
            result[current].append(line)
    return result


def check_structure(text: str, name: str) -> list[str]:
    secs = sections(text)
    errors = [f"{name}: missing section [{s}]" for s in REQUIRED_SECTIONS if s not in secs]
    if errors:
        return errors

    # Mandatory bindings must appear exactly in catalogue order. Heavy is opt-in: when enabled,
    # it must retain its exact URL, policy and catalogue position. Inline user rules are separate.
    actual = secs["Rule"]
    actual_rule_sets = [ln for ln in actual if ln.startswith("RULE-SET,")]
    catalogue_bindings = [
        (ruleset.tag, f"RULE-SET,{su.SURGE_RAW_BASE}/{ruleset.file},{ruleset.policy}")
        for ruleset in su.RULESETS
    ]
    expected_rule_sets = [
        binding for tag, binding in catalogue_bindings
        if tag not in su.OPTIONAL_RULESET_TAGS or binding in actual_rule_sets
    ]
    if actual_rule_sets != expected_rule_sets:
        errors.append(f"{name}: [Rule] RULE-SET bindings do not match the generated set (missing/extra/reordered)")
    if not actual or not actual[-1].startswith("FINAL,"):
        errors.append(f"{name}: [Rule] must end with a FINAL line")

    # Every managed rule (RULE-SET / FINAL) must route to a defined proxy group or a builtin.
    # Scoped to managed lines so inline rules carrying trailing modifiers (e.g. ,no-resolve) are
    # not mistaken for a policy, and a comma-less line is reported rather than crashing.
    group_names = {ln.split("=", 1)[0].strip() for ln in secs["Proxy Group"]}
    for line in actual:
        if not (line.startswith("RULE-SET,") or line.startswith("FINAL,")):
            continue
        parts = line.rsplit(",", 1)
        if len(parts) < 2:
            errors.append(f"{name}: malformed rule line (missing policy): {line}")
            continue
        if parts[1] not in group_names and parts[1] not in BUILTIN_POLICIES:
            errors.append(f"{name}: rule policy '{parts[1]}' resolves to no proxy group: {line}")
    return errors


def validate_committed_skeletons() -> list[str]:
    """CI mode: each committed skeleton must equal the generator output and hold only placeholders."""
    errors: list[str] = []
    for device in su.DEVICES:
        path = CONFIGS_DIR / f"{device.name}.conf"
        if not path.exists():
            errors.append(f"missing committed skeleton: {path.name}")
            continue
        text = path.read_text()
        if text != su.render_config(device):
            errors.append(f"{path.name}: skeleton drifted from generator — rerun build_surge_config.py")
        errors += [f"{path.name}: {p}" for p in private_section_leaks(text)]
        errors += check_structure(text, path.name)
    return errors


def _has_placeholder_values(text: str) -> bool:
    # A filled config keeps the header comment (which mentions {{PLACEHOLDER}}), so detect the
    # skeleton by placeholders in real (non-comment) lines only.
    return any("{{" in line for line in text.splitlines() if not line.strip().startswith("#"))


def validate_config_text(text: str, name: str) -> list[str]:
    """Validate a skeleton or a filled .conf's text (auto-detected by placeholder presence)."""
    errors = check_structure(text, name)
    if _has_placeholder_values(text):
        # Skeleton: private sections must be placeholders only.
        errors += [f"{name}: {p}" for p in private_section_leaks(text)]
    else:
        # Filled config: private sections must be populated (stray placeholders are already absent).
        secs = sections(text)
        if not secs.get("Proxy"):
            errors.append(f"{name}: filled config has an empty [Proxy] section")
        mitm_keys = {ln.split("=", 1)[0].strip().lower() for ln in secs.get("MITM", []) if "=" in ln}
        if "ca-p12" not in mitm_keys or "ca-passphrase" not in mitm_keys:
            errors.append(f"{name}: filled config [MITM] is missing ca-p12/ca-passphrase")
    return errors


def validate_config_file(path: Path) -> list[str]:
    """Local mode: validate a config file at ``path``."""
    return validate_config_text(path.read_text(), path.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", type=Path, help="a .conf to validate; omit to check committed skeletons")
    args = parser.parse_args()

    if args.config is None:
        errors = validate_committed_skeletons()
        errors += validate_generated_tree(SU_RULE_TREE)
    else:
        errors = validate_config_file(args.config)

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("OK: Surge config invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
