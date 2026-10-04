"""Tests for the dual-mode Surge config validator."""

from __future__ import annotations

import build_surge_config as su
import validate_surge_config as vs
import pytest


def _filled(device) -> str:
    """A plausibly-filled config: placeholders replaced with realistic (non-secret-looking) values."""
    text = su.render_config(device)
    replacements = {
        "{{PROXY_NODES}}": "US-A = vmess, 1.1.1.1, 443",
        "{{HOME_WG_NODE}}": "wireguard, 2.2.2.2, 51820",
        "{{CHAIN_NODES}}": "US-A",
        "{{CHAIN_LINK_NODES}}": "US-A",
        "{{OTHER_NODES}}": "US-A",
        "{{MITM_HOSTNAMES}}": "*.example.com",
        "{{CA_PASSPHRASE}}": "REPLACEDPASS",
        "{{CA_P12}}": "REPLACEDP12BLOB",
        "{{HTTP_API_KEY}}": "REPLACEDAPIKEY",
    }
    for region in ("US", "HK", "MO", "TW", "JP", "KR", "SG", "UK"):
        replacements[f"{{{{{region}_NODES}}}}"] = "US-A"
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text


def test_committed_skeletons_pass_ci_mode():
    assert vs.validate_committed_skeletons() == []


def test_generated_surge_tree_is_valid():
    assert vs.validate_generated_tree(vs.SU_RULE_TREE) == []


def test_skeleton_rule_bindings_match_rulesets():
    # The [Rule] section a rendered skeleton carries must satisfy the structural check.
    assert vs.check_structure(su.render_config(su.DEVICES[0]), "ios.conf") == []


def test_drifted_skeleton_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "CONFIGS_DIR", tmp_path)
    (tmp_path / "ios.conf").write_text("[General]\n# hand-edited, wrong\n")
    (tmp_path / "mac.conf").write_text(su.render_config(su.DEVICES[1]))
    errors = vs.validate_committed_skeletons()
    assert any("drifted" in e or "missing section" in e for e in errors)


def test_filled_config_passes():
    assert vs.validate_config_text(_filled(su.DEVICES[0]), "ios.conf") == []


def test_filled_mac_config_passes():
    # The Mac config carries the HTTP-API key placeholder in [General]; once filled it must pass too.
    assert vs.validate_config_text(_filled(su.DEVICES[1]), "mac.conf") == []


def test_filled_config_missing_mitm_material_is_flagged():
    text = _filled(su.DEVICES[0]).replace("ca-p12 = REPLACEDP12BLOB", "")
    errors = vs.validate_config_text(text, "ios.conf")
    assert any("ca-p12" in e for e in errors)


def test_filled_config_empty_proxy_is_flagged():
    text = _filled(su.DEVICES[1]).replace("US-A = vmess, 1.1.1.1, 443", "")
    errors = vs.validate_config_text(text, "mac.conf")
    assert any("empty [Proxy]" in e for e in errors)


def test_extra_rule_set_binding_is_flagged():
    text = _filled(su.DEVICES[1]).replace(
        "FINAL,全局代理", "RULE-SET,https://evil.example/rules.list,全局代理\nFINAL,全局代理"
    )
    assert any("RULE-SET bindings do not match" in e for e in vs.validate_config_text(text, "mac.conf"))


def test_scrambled_rule_set_order_is_flagged():
    lines = _filled(su.DEVICES[1]).splitlines()
    rs_idx = [i for i, ln in enumerate(lines) if ln.startswith("RULE-SET,")]
    lines[rs_idx[0]], lines[rs_idx[1]] = lines[rs_idx[1]], lines[rs_idx[0]]
    text = "\n".join(lines) + "\n"
    assert any("RULE-SET bindings do not match" in e for e in vs.validate_config_text(text, "mac.conf"))


def test_malformed_rule_line_reports_not_crashes():
    text = _filled(su.DEVICES[1]).replace("FINAL,全局代理", "FINAL")
    errors = vs.validate_config_text(text, "mac.conf")  # must not raise
    assert any("FINAL" in e for e in errors)


def test_inline_rule_with_no_resolve_modifier_is_not_mistaken_for_policy():
    # A user inline IP rule with a trailing ,no-resolve must not be read as policy 'no-resolve'.
    text = _filled(su.DEVICES[1]).replace(
        "FINAL,全局代理", "IP-CIDR,1.2.3.0/24,DIRECT,no-resolve\nFINAL,全局代理"
    )
    errors = vs.validate_config_text(text, "mac.conf")
    assert not any("no-resolve" in e for e in errors)


def _heavy_binding():
    heavy = next(ruleset for ruleset in su.RULESETS if ruleset.tag == "Ads-Reject-Heavy")
    return f"RULE-SET,{su.SURGE_RAW_BASE}/{heavy.file},{heavy.policy}"


def test_default_rule_bindings_leave_heavy_disabled():
    text = _filled(su.DEVICES[1])
    assert _heavy_binding() not in vs.sections(text)["Rule"]
    assert vs.check_structure(text, "mac.conf") == []


def test_filled_config_can_enable_heavy_in_catalogue_order():
    text = _filled(su.DEVICES[1])
    assert f"#{_heavy_binding()}" in text
    enabled = text.replace(f"#{_heavy_binding()}", _heavy_binding())
    assert vs.validate_config_text(enabled, "mac.conf") == []


@pytest.mark.parametrize("change", ["duplicate", "wrong-policy", "reordered"])
def test_enabled_heavy_must_keep_exact_binding_and_order(change):
    text = _filled(su.DEVICES[1])
    binding = _heavy_binding()
    assert f"#{binding}" in text
    text = text.replace(f"#{binding}", binding)
    if change == "duplicate":
        text = text.replace(binding, binding + "\n" + binding)
    elif change == "wrong-policy":
        text = text.replace(binding, binding.rsplit(",", 1)[0] + ",DIRECT")
    else:
        lines = text.splitlines()
        lines.remove(binding)
        first_ruleset = next(index for index, line in enumerate(lines) if line.startswith("RULE-SET,"))
        lines.insert(first_ruleset, binding)
        text = "\n".join(lines)
    assert any("RULE-SET bindings do not match" in error for error in vs.validate_config_text(text, "mac.conf"))


def test_only_heavy_can_be_disabled_without_binding_error():
    text = _filled(su.DEVICES[1])
    required = next(line for line in vs.sections(text)["Rule"] if line.startswith("RULE-SET,"))
    text = text.replace(required, "#" + required)
    assert any("RULE-SET bindings do not match" in error for error in vs.validate_config_text(text, "mac.conf"))
