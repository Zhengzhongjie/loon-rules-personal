"""Tests for the placeholder-aware public-artifact audit."""

from __future__ import annotations

import subprocess

import pytest

import audit_public_artifacts as audit

# Fake secrets are built by concatenation so this (tracked) test file never
# contains a literal that the audit itself would flag.
SCHEME = "://"
PEM = "-" * 5
FAKE_KEY = f"{PEM}BEGIN EC PRIVATE KEY{PEM}\nAAAA\n{PEM}END EC PRIVATE KEY{PEM}"
FAKE_CERT = f"{PEM}BEGIN CERTIFICATE{PEM}\nAAAA\n{PEM}END CERTIFICATE{PEM}"


def test_placeholder_private_sections_pass():
    skeleton = (
        "[Proxy]\n"
        "{{PROXY_NODES}}\n"
        "Home-Orca-WG = {{HOME_WG_NODE}}\n"
        "[MITM]\n"
        "enable = true\n"
        "hostname = {{MITM_HOSTNAMES}}\n"
        "ca-passphrase = {{CA_PASSPHRASE}}\n"
        "ca-p12 = {{CA_P12}}\n"
    )
    assert audit.private_section_leaks(skeleton) == []


def test_real_node_definition_is_flagged():
    leak = "[Proxy]\nMyNode = vless, 1.2.3.4, 443\n"
    assert audit.private_section_leaks(leak)


def test_real_ca_material_is_flagged():
    leak = "[MITM]\nca-p12 = MIIJRQIBAzCCCQ8\nca-passphrase = 24961EL2\n"
    assert len(audit.private_section_leaks(leak)) == 2


def test_mitm_public_keys_allowed_but_hostname_flagged():
    # enable / h2 are non-secret and may carry real values...
    assert audit.private_section_leaks("[MITM]\nenable = true\nh2 = true\n") == []
    # ...but a real MITM hostname is private (reveals intercepted apps) and must be a placeholder.
    assert audit.private_section_leaks("[MITM]\nhostname = *.paypal.com\n")


def test_hyphenated_placeholder_is_recognized():
    assert audit.private_section_leaks("[Proxy]\n{{US-NODES}}\n") == []


def test_public_sections_are_ignored():
    # A real value in [Proxy Group] (public wiring) is not a private-section leak.
    conf = "[Proxy Group]\nAI = select,链式代理链路,DIRECT\n"
    assert audit.private_section_leaks(conf) == []


# ---- SECRET_PATTERNS, one test per pattern ----


def test_pattern_private_key():
    assert any("private key" in p for p in audit.scan_text("f", FAKE_KEY))


def test_pattern_certificate():
    assert any("certificate" in p for p in audit.scan_text("f", FAKE_CERT))


@pytest.mark.parametrize(
    "scheme", ["ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "VMESS"]
)
def test_pattern_proxy_uri(scheme):
    assert audit.scan_text("f", f"node: {scheme}{SCHEME}eyJhbGci@host:443")


def test_pattern_proxy_uri_requires_word_boundary():
    # An https URL must not be mistaken for a proxy scheme whose name it merely ends with.
    assert audit.scan_text("f", f"https{SCHEME}example.com") == []


@pytest.mark.parametrize(
    "param", ["token", "key", "api_key", "access_token", "auth", "password", "passwd", "secret"]
)
def test_pattern_token_query_parameter(param):
    assert audit.scan_text("f", f"https{SCHEME}example.com/sub?{param}=abc123")


def test_clean_text_has_no_findings():
    assert audit.scan_text("f", "DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8\n") == []


# ---- index-mode scanning: the audit vouches for tracked ∪ staged, nothing else ----


def _git(repo, *argv):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *argv],
        check=True,
        capture_output=True,
    )


@pytest.fixture()
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "clean.list").write_text("DOMAIN-SUFFIX,example.com\n")
    _git(tmp_path, "add", "clean.list")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_index_scan_passes_on_clean_repo(repo, capsys):
    assert audit.main([str(repo)]) == 0
    assert "OK" in capsys.readouterr().out


def test_untracked_secret_is_not_noise(repo):
    # An untracked local file (backup, log) never enters a commit — index mode must ignore it.
    (repo / "backup.lcf").write_text(FAKE_KEY)
    assert audit.main([str(repo)]) == 0


def test_staged_secret_fails(repo, capsys):
    (repo / "leak.conf").write_text(FAKE_KEY)
    _git(repo, "add", "leak.conf")
    assert audit.main([str(repo)]) == 1
    assert "leak.conf" in capsys.readouterr().err


@pytest.mark.parametrize("scan_all", [False, True], ids=["index", "tree"])
def test_cli_reports_secret_locations_without_echoing_values(repo, capsys, scan_all):
    markers = [f"synthetic-private-{part}" for part in ("node", "ca", "pass", "host", "bare", "key")]
    text = (
        "[Proxy]\n"
        f"{markers[0]} = wireguard, {markers[0]}, 443\n"
        f"{markers[4]}\n"
        "[MITM]\n"
        f"ca-p12 = {markers[1]}\n"
        f"ca-passphrase = {markers[2]}\n"
        f"hostname = {markers[3]}\n"
        f"{markers[5]} = {markers[5]}\n"
    )
    (repo / "leak.conf").write_text(text)
    if not scan_all:
        _git(repo, "add", "leak.conf")

    assert audit.main([str(repo), *(["--all"] if scan_all else [])]) == 1

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "leak.conf" in output
    assert "line 2" in output
    assert "line 5" in output
    assert "ca-p12" in output
    assert "ca-passphrase" in output
    assert "non-placeholder" in output
    for marker in markers:
        assert marker not in output


def test_pattern_findings_report_line_number_without_echoing_uri():
    marker = "synthetic-private-uri"
    findings = audit.scan_text("leak.conf", f"# comment\nvless{SCHEME}{marker}@host:443\n")

    assert len(findings) == 1
    assert "line 2" in findings[0]
    assert "proxy uri" in findings[0]
    assert marker not in findings[0]


def test_pattern_findings_keep_one_location_per_category():
    text = f"# comment\nvless{SCHEME}one@host:443\nvless{SCHEME}two@host:443\n"

    assert audit.scan_text("leak.conf", text) == ["leak.conf: line 2: contains proxy uri"]


def test_staged_content_is_audited_not_worktree(repo):
    # The audited bytes are the index blob: cleaning the worktree copy after staging must not hide the leak.
    (repo / "leak.conf").write_text(FAKE_KEY)
    _git(repo, "add", "leak.conf")
    (repo / "leak.conf").write_text("clean now\n")
    assert audit.main([str(repo)]) == 1


def test_all_flag_scans_untracked_files(repo):
    (repo / "backup.lcf").write_text(FAKE_KEY)
    assert audit.main([str(repo), "--all"]) == 1


def test_non_git_dir_fails_closed(tmp_path):
    assert audit.main([str(tmp_path / "not-a-repo")]) == 2


# ---- secret-material file types: flagged by name, even when content can't be scanned ----


@pytest.mark.parametrize("suffix", [".p12", ".pfx", ".der", ".key", ".keystore", ".mobileconfig", ".ovpn"])
def test_secret_material_suffix_flagged(suffix):
    assert audit.secret_material_problem(f"certs/ca{suffix}") is not None


def test_ordinary_suffix_not_flagged():
    assert audit.secret_material_problem("rules/loon/generated/08-AI.list") is None


def test_staged_binary_ca_bundle_fails(repo, capsys):
    # A DER-encoded CA bundle is binary (would UnicodeDecodeError → skipped by content scan),
    # but its file type alone is a leak and must fail the audit by name.
    (repo / "ca.der").write_bytes(b"\x30\x82\x01\x0a\x00\xff\xfe")
    _git(repo, "add", "ca.der")
    assert audit.main([str(repo)]) == 1
    assert "ca.der" in capsys.readouterr().err


def test_staged_p12_with_image_suffix_still_text_clean(repo):
    # Guard against over-reach: a normal .png stays out of scope (name check is suffix-scoped).
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n")
    _git(repo, "add", "logo.png")
    assert audit.main([str(repo)]) == 0
