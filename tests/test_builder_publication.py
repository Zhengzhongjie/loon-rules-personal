"""A failed rebuild must preserve the previous generated snapshot for every client."""

from pathlib import Path

import pytest

import build_loon_rules as blr


def seed_build(tmp_path, monkeypatch, contents=None):
    rulesets = [blr.RuleSet("test.list", "Test", "DIRECT", sources=("source",))]
    monkeypatch.setattr(blr, "RULESETS", rulesets)
    monkeypatch.setattr(blr, "fetch_all", lambda: ({"source": "DOMAIN,new.example\n"} if contents is None else contents, []))
    for dialect in blr.DIALECTS:
        generated = tmp_path / dialect.subdir / "generated"
        generated.mkdir(parents=True)
        (generated / "stale.list").write_text("old rules\n")
        (generated / "MANIFEST.csv").write_text("old manifest\n")
        (generated / "keep.txt").write_text("retained\n")
    return snapshot(tmp_path)


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("strict", [False, True])
def test_bad_200_source_leaves_every_dialect_unchanged(tmp_path, monkeypatch, strict):
    before = seed_build(tmp_path, monkeypatch, {"source": "<html>upstream error</html>\n"})

    assert blr.build(tmp_path, strict=strict) == 1

    assert snapshot(tmp_path) == before


def test_allow_partial_publishes_only_valid_sources(tmp_path, monkeypatch):
    seed_build(tmp_path, monkeypatch, {"source": "DOMAIN,unsafe.example\ninvalid line\n"})
    monkeypatch.setattr(blr, "RULESETS", [blr.RuleSet("test.list", "Test", "DIRECT", sources=("source",), additions=("DOMAIN,local.example",))])

    assert blr.build(tmp_path, strict=False, allow_partial=True) == 0

    for dialect in blr.DIALECTS:
        generated = tmp_path / dialect.subdir / "generated"
        assert "DOMAIN,local.example\n" in (generated / "test.list").read_text()
        assert "unsafe.example" not in (generated / "test.list").read_text()
        assert (generated / "keep.txt").read_text() == "retained\n"
        assert not (generated / "stale.list").exists()


def test_staging_write_failure_preserves_all_dialects(tmp_path, monkeypatch):
    before = seed_build(tmp_path, monkeypatch)
    original_write = Path.write_text

    def fail_shadowrocket_write(path, text, *args, **kwargs):
        if path.name == "test.list" and path.parent.parent.name == "shadowrocket":
            raise OSError("disk full")
        return original_write(path, text, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_shadowrocket_write)

    assert blr.build(tmp_path, strict=True) == 1

    assert snapshot(tmp_path) == before


def test_staging_verification_failure_preserves_all_dialects(tmp_path, monkeypatch):
    before = seed_build(tmp_path, monkeypatch)
    original_write = Path.write_text

    def truncate_new_rules(path, text, *args, **kwargs):
        if path.name == "test.list":
            text = text[:20]
        return original_write(path, text, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", truncate_new_rules)

    assert blr.build(tmp_path, strict=True) == 1

    assert snapshot(tmp_path) == before


def test_publication_failure_rolls_back_already_published_dialects(tmp_path, monkeypatch):
    before = seed_build(tmp_path, monkeypatch)
    original_rename = Path.rename
    target = tmp_path / "surge" / "generated"

    def fail_last_publication(path, destination):
        if path.name.startswith(".generated-stage-") and Path(destination) == target:
            raise OSError("rename failed")
        return original_rename(path, destination)

    monkeypatch.setattr(Path, "rename", fail_last_publication)

    assert blr.build(tmp_path, strict=True) == 1

    assert snapshot(tmp_path) == before


def test_write_result_write_failure_preserves_previous_tree(tmp_path, monkeypatch):
    (tmp_path / "old.list").write_text("old\n")
    before = snapshot(tmp_path)
    original_write = Path.write_text

    def fail_new_write(path, text, *args, **kwargs):
        if path.name == "new.list":
            raise OSError("disk full")
        return original_write(path, text, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_new_write)

    with pytest.raises(OSError):
        blr.write_result(tmp_path, {"new.list": "new\n"})

    assert snapshot(tmp_path) == before


def test_successful_publication_preserves_existing_directory_permissions(tmp_path):
    output_dir = tmp_path / "generated"
    output_dir.mkdir(mode=0o750)
    output_dir.chmod(0o750)

    blr.write_result(output_dir, {"new.list": "fresh\n"})

    assert output_dir.stat().st_mode & 0o777 == 0o750
