"""Private configuration transformations must preserve nodes and two-hop roles."""
import optimize_loon_config as optimizer
import pytest


def sample():
    return "\n".join([
        '[General]',
        'mitm-on-wifi-access = true',
        'allow-wifi-access = true',
        'disconnect-on-policy-change = false',
        '[Proxy]',
        'Chosen = vless,SYNTHETIC_PRIVATE_VALUE',
        '[Remote Proxy]',
        'Sub = https://subscription.invalid/?SUB_QUERY,skip-cert-verify=true,enabled=true',
        '[Proxy Group]',
        '链式代理节点 = select,Chosen,Filter',
        '链式代理链路 = select,狮城链式代理,DIRECT,Filter',
        'AI = select,DIRECT,美国节点,链式代理链路,img-url = icon',
        'Google = select,DIRECT,链式代理链路',
        '美国节点 = url-test,US_Filter,url = http://test.invalid,interval = 300',
        '[Proxy Chain]',
        '狮城链式代理 = 美国节点,链式代理节点,udp=true',
        '[Rule]',
        'IP-CIDR,198.18.0.1/32,DIRECT,no-resolve',
        'DOMAIN-SUFFIX,zbrowser.cn,DIRECT',
        'FINAL,全局代理',
        '[Remote Rule]',
        '[Plugin]',
        'https://plugins.invalid/BiliBili.ADBlock.plugin,enabled=true',
        '[Mitm]',
        'skip-server-cert-verify = true',
        'ca-p12 = SYNTHETIC_CERT',
        '',
    ]).replace('SUB_QUERY', f"{'token'}=SYNTHETIC_TOKEN")


def test_chain_first_and_two_hop_structure_preserve_private_nodes():
    updated = optimizer.optimize_text(sample())
    assert 'AI = select,链式代理链路,DIRECT,美国节点,img-url = icon' in updated
    assert 'Google = select,链式代理链路,DIRECT' in updated
    assert '链式代理节点 = select,Chosen,Filter' in updated
    assert '链式代理链路 = select,狮城链式代理\n' in updated
    assert '狮城链式代理 = 美国节点,链式代理节点,udp=true' in updated
    assert 'Chosen = vless,SYNTHETIC_PRIVATE_VALUE' in updated
    assert 'ca-p12 = SYNTHETIC_CERT' in updated
    assert 'token=SYNTHETIC_TOKEN' in updated


def test_safety_updates_and_remote_catalogue_are_idempotent():
    updated = optimizer.optimize_text(sample())
    assert 'skip-server-cert-verify = false' in updated
    assert 'skip-cert-verify=false' in updated
    assert 'allow-wifi-access = false' in updated
    assert 'mitm-on-wifi-access = false' in updated
    assert 'disconnect-on-policy-change = true' in updated
    assert '198.18.0.1/32,DIRECT' not in updated
    assert 'BiliBili.ADBlock.plugin,enabled=false' in updated
    assert updated.count('DOMAIN-SUFFIX,zbrowser.cn,DIRECT') == 1
    assert '08-Gemini.list,policy=Google,tag=Gemini,enabled=true' in updated
    assert '27-Ads-Reject-Heavy.list,policy=广告分流,tag=Ads-Reject-Heavy,enabled=false' in updated
    assert optimizer.optimize_text(updated) == updated


def test_crlf_and_comment_preserved():
    original = '# keep this comment\r\n' + sample().replace('\n', '\r\n')
    updated = optimizer.optimize_text(original)
    assert updated.startswith('# keep this comment\r\n')
    assert '\n' not in updated.replace('\r\n', '')


def test_filter_only_terminal_prefers_existing_static_vless_node():
    text = sample().replace('链式代理节点 = select,Chosen,Filter', '链式代理节点 = select,Filter')
    assert '链式代理节点 = select,Chosen,Filter' in optimizer.optimize_text(text)


def test_quoted_option_commas_are_not_reclassified_as_candidates():
    original = sample().replace('img-url = icon', 'img-url="data:image/svg+xml,symbol"')
    result = optimizer.optimize_text(original)
    assert 'AI = select,链式代理链路,DIRECT,美国节点,img-url="data:image/svg+xml,symbol"' in result


def test_atomic_write_preserves_an_edit_during_temporary_file_preparation(tmp_path, monkeypatch):
    target = tmp_path / 'private.lcf'
    target.write_bytes(b'original')
    original_fsync = optimizer.os.fsync

    def edit_during_flush(fd):
        original_fsync(fd)
        target.write_bytes(b'external edit')

    monkeypatch.setattr(optimizer.os, 'fsync', edit_during_flush)
    with pytest.raises(ValueError, match='changed'):
        optimizer.atomic_write(target, b'optimized', expected=b'original', mode=0o600)
    assert target.read_bytes() == b'external edit'


def test_rollback_keeps_newer_external_content(tmp_path):
    target = tmp_path / 'private.lcf'
    target.write_bytes(b'external edit')
    backup = tmp_path / 'backup'
    backup.mkdir()
    (backup / target.name).write_bytes(b'original')
    optimizer.rollback_writes([(target, b'optimized')], backup)
    assert target.read_bytes() == b'external edit'


def test_rollback_restores_our_unchanged_write(tmp_path):
    target = tmp_path / 'private.lcf'
    target.write_bytes(b'optimized')
    backup = tmp_path / 'backup'
    backup.mkdir()
    (backup / target.name).write_bytes(b'original')
    assert optimizer.rollback_writes([(target, b'optimized')], backup) == []
    assert target.read_bytes() == b'original'


def test_rollback_preserves_deleted_target(tmp_path):
    target = tmp_path / 'private.lcf'
    backup = tmp_path / 'backup'
    backup.mkdir()
    (backup / target.name).write_bytes(b'original')
    assert optimizer.rollback_writes([(target, b'optimized')], backup) == [target]
    assert not target.exists()


def test_quoted_escaped_quotes_keep_the_comma_inside_option():
    fields = optimizer.split_fields(r'select,Route,img-url="data:escaped\",comma",interval=600')
    assert fields == ['select', 'Route', r'img-url="data:escaped\",comma"', 'interval=600']


def test_apostrophe_in_unquoted_member_or_url_is_literal():
    fields = optimizer.split_fields("select,John's route,img-url=https://icons.invalid/John's.svg")
    assert fields == ['select', "John's route", "img-url=https://icons.invalid/John's.svg"]
