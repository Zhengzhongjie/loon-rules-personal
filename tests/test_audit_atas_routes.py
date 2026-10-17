"""A post-login server must not disappear from the offline coverage audit."""
import json
from pathlib import Path

from audit_atas_routes import audit

ROOT = Path(__file__).resolve().parents[1]


def test_audit_reports_new_authenticated_server_without_reading_credentials(tmp_path):
    data = tmp_path / "data"
    (data / "Logs").mkdir(parents=True)
    (data / "AvaliableServers.cnf").write_text(json.dumps([
        {"EndPoint": "142.132.201.231:6450"},
        {"EndPoint": "auto.platform.atas.net:6214"},
    ]))
    (data / "Logs/app_fixture.log").write_text(
        "Crypto data: Connecting to 116.202.174.36:6452\n"
        "History: Connecting to 1.1.1.1:8450\n"
        "Malformed diagnostic: 999.1.1.1:8450\n"
    )
    # Reading these files as text or JSON would fail; neither is inventory input.
    (data / "Login.cnf").write_bytes(b"\xff\xfe")
    (data / "APIKeys.cnf").write_bytes(b"\xff\xfe")

    report = audit(data, tmp_path / "no-app", ROOT / "rules/loon/generated")

    assert report["missing"] == ["1.1.1.1:8450"]
    assert report["literal_ip_routes"]["116.202.174.36:6452"] == "金融加密"
    assert report["domain_routes"]["sntp.atas.net"] == "DIRECT"
    assert report["domain_routes"]["auto.platform.atas.net"] == "金融加密"


def test_localization_vendor_host_is_inventoried(tmp_path):
    data = tmp_path / "data"
    (data / "Logs").mkdir(parents=True)
    (data / "AvaliableServers.cnf").write_text("[]")
    app = tmp_path / "app"
    bundle = app / "Contents/MonoBundle"
    bundle.mkdir(parents=True)
    (bundle / "OFT.Localization.dll").write_bytes(
        "https://new-assets.atas.net/metadata.json".encode("utf-16-le")
    )

    report = audit(data, app, ROOT / "rules/loon/generated")

    assert report["domain_routes"]["new-assets.atas.net"] == "金融加密"
    assert report["missing"] == []
