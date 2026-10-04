"""Conditional-request cache tests for upstream rule fetching."""

from __future__ import annotations

import hashlib
import json
from urllib.error import HTTPError, URLError

import pytest

import build_loon_rules as blr


URL = "https://example.test/upstream.list"


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return self.body


class FakeOpener:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def cache_paths(cache_dir):
    cache_key = hashlib.sha256(URL.encode("utf-8")).hexdigest()
    return cache_dir / f"{cache_key}.json", cache_dir / f"{cache_key}.body"


def test_first_200_writes_response_body_and_validators(tmp_path):
    opener = FakeOpener(
        FakeResponse(
            200,
            b"DOMAIN,example.com\n",
            {"ETag": '"v1"', "Last-Modified": "Fri, 17 Jul 2026 12:00:00 GMT"},
        )
    )

    result = blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    metadata_path, body_path = cache_paths(tmp_path)
    assert result == "DOMAIN,example.com\n"
    assert body_path.read_bytes() == b"DOMAIN,example.com\n"
    assert json.loads(metadata_path.read_text()) == {
        "etag": '"v1"',
        "last_modified": "Fri, 17 Jul 2026 12:00:00 GMT",
    }


def test_304_sends_validators_and_returns_cached_body(tmp_path):
    opener = FakeOpener(
        FakeResponse(
            200,
            b"DOMAIN,cached.example\n",
            {"ETag": '"v2"', "Last-Modified": "Fri, 17 Jul 2026 13:00:00 GMT"},
        ),
        FakeResponse(304),
    )
    blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    result = blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    conditional_request = opener.requests[1]
    assert conditional_request.get_header("If-none-match") == '"v2"'
    assert conditional_request.get_header("If-modified-since") == "Fri, 17 Jul 2026 13:00:00 GMT"
    assert result == "DOMAIN,cached.example\n"


def test_real_304_path_raises_httperror_and_returns_cached_body(tmp_path):
    # The stdlib opener does NOT return a response with .status==304 — HTTPErrorProcessor
    # raises HTTPError for any non-2xx code. This exercises the production 304 path
    # (the except-branch HTTPError handler), not the in-block status check a fake opener hits.
    opener = FakeOpener(
        FakeResponse(200, b"DOMAIN,real304.example\n", {"ETag": '"v9"'}),
        HTTPError(URL, 304, "Not Modified", {}, None),
    )
    blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    result = blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    assert result == "DOMAIN,real304.example\n"
    assert opener.requests[1].get_header("If-none-match") == '"v9"'


def test_network_error_is_reported_as_fetch_all_failure_despite_cached_body(tmp_path, monkeypatch):
    seed_opener = FakeOpener(FakeResponse(200, b"DOMAIN,stale.example\n", {"ETag": '"stale"'}))
    blr.fetch(URL, opener=seed_opener, cache_dir=tmp_path)
    failing_opener = FakeOpener(URLError("offline"))
    monkeypatch.setattr(blr, "UPSTREAM_CACHE_DIR", tmp_path)
    monkeypatch.setattr(blr, "urlopen", failing_opener)
    monkeypatch.setattr(blr, "FETCH_RETRIES", 1)
    monkeypatch.setattr(blr, "RULESETS", [blr.RuleSet("test.list", "Test", "DIRECT", sources=(URL,))])

    contents, failures = blr.fetch_all()

    assert contents == {}
    assert len(failures) == 1
    assert URL in failures[0]
    assert "URLError" in failures[0]
    assert "offline" in failures[0]


@pytest.mark.parametrize(
    "response",
    [FakeResponse(200, b"<!doctype html><html>error</html>"), FakeResponse(200, b"\xff"), FakeResponse(200), FakeResponse(204)],
    ids=["html", "invalid-utf8", "empty", "unexpected-status"],
)
def test_invalid_response_does_not_replace_valid_cached_body(tmp_path, monkeypatch, response):
    blr.fetch(URL, opener=FakeOpener(FakeResponse(200, b"DOMAIN,safe.example\n", {"ETag": '"safe"'})), cache_dir=tmp_path)
    monkeypatch.setattr(blr, "FETCH_RETRIES", 1)
    metadata_path, body_path = cache_paths(tmp_path)
    previous_cache = (metadata_path.read_bytes(), body_path.read_bytes())

    with pytest.raises(URLError):
        blr.fetch(URL, opener=FakeOpener(response), cache_dir=tmp_path)

    assert (metadata_path.read_bytes(), body_path.read_bytes()) == previous_cache


def test_invalid_304_cache_is_rejected(tmp_path, monkeypatch):
    blr.fetch(URL, opener=FakeOpener(FakeResponse(200, b"DOMAIN,safe.example\n", {"ETag": '"safe"'})), cache_dir=tmp_path)
    _metadata_path, body_path = cache_paths(tmp_path)
    body_path.write_bytes(b"<html>corrupted cache</html>")
    monkeypatch.setattr(blr, "FETCH_RETRIES", 1)

    with pytest.raises(URLError):
        blr.fetch(URL, opener=FakeOpener(HTTPError(URL, 304, "Not Modified", {}, None)), cache_dir=tmp_path)


def test_invalid_utf8_cache_metadata_is_ignored_and_refetched(tmp_path):
    metadata_path, body_path = cache_paths(tmp_path)
    metadata_path.write_bytes(b"\xff")
    body_path.write_bytes(b"DOMAIN,old.example\n")
    opener = FakeOpener(FakeResponse(200, b"DOMAIN,new.example\n"))

    result = blr.fetch(URL, opener=opener, cache_dir=tmp_path)

    assert result == "DOMAIN,new.example\n"
    assert opener.requests[0].get_header("If-none-match") is None


def test_curl_fallback_rejects_invalid_utf8_as_a_fetch_error(tmp_path, monkeypatch):
    fake_curl = tmp_path / "curl"
    fake_curl.write_text("#!/bin/sh\nprintf '\\377'\n")
    fake_curl.chmod(0o755)
    monkeypatch.setattr(blr, "SYSTEM_CURL", fake_curl)

    with pytest.raises(URLError, match="UTF-8"):
        blr.fetch(URL, opener=FakeOpener(URLError("CERTIFICATE_VERIFY_FAILED")), cache_dir=tmp_path / "cache")
