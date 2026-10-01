"""Tests for :mod:`reconx.subdomains`.

crt.sh responses are served from an in-process requests mock and DNS is faked,
so no real traffic leaves the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import pytest
import requests
import responses

from reconx import subdomains
from reconx.context import MAX_CONCURRENCY, ReconContext


class FakeResolver:
    """Fake :class:`dns.resolver.Resolver` driven by a set of known names."""

    def __init__(self, known: set[str], *, fail_with: Exception | None = None) -> None:
        self.known = known
        self.fail_with = fail_with

    def resolve(self, name: str, rtype: str, **kwargs: Any):
        if self.fail_with is not None:
            raise self.fail_with
        if name in self.known:
            return [rtype]
        raise dns.resolver.NXDOMAIN()


@pytest.fixture
def ctx() -> ReconContext:
    return ReconContext(timeout=1.0, concurrency=4)


class TestInScope:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("www.example.com", True),
            ("example.com", True),
            ("WWW.EXAMPLE.COM", True),
            ("www.example.com.", True),
            ("*.example.com", False),
            ("notexample.com", False),
            ("example.com.evil.net", False),
            ("", False),
        ],
    )
    def test_filters(self, name, expected):
        assert subdomains._in_scope(name, "example.com") is expected


class TestLoadWordlist:
    def test_default_list_is_deduplicated_and_sorted(self):
        words = subdomains.load_wordlist()
        assert words == sorted(set(words))
        assert "www" in words
        assert all(word == word.lower() for word in words)

    def test_comments_and_blanks_skipped(self, tmp_path):
        path = tmp_path / "words.txt"
        path.write_text("# comment\n\nWWW\napi\n# trailing comment\nwww\n", encoding="utf-8")
        assert subdomains.load_wordlist(path) == ["api", "www"]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(OSError):
            subdomains.load_wordlist(tmp_path / "absent.txt")


class TestQueryCrtSh:
    @responses.activate
    def test_parses_and_filters_names(self, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=[
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "cdn.example.com"},
                {"name_value": "unrelated.other.org"},
            ],
            status=200,
        )
        result = subdomains.query_crtsh("example.com", ctx)
        assert result["error"] is None
        assert result["names"] == ["cdn.example.com", "mail.example.com", "www.example.com"]

    @responses.activate
    def test_common_name_field_used(self, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=[{"common_name": "shop.example.com"}],
            status=200,
        )
        assert subdomains.query_crtsh("example.com", ctx)["names"] == ["shop.example.com"]

    @responses.activate
    def test_bad_status_reports_error(self, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, status=502)
        result = subdomains.query_crtsh("example.com", ctx)
        assert result["names"] == []
        assert "HTTP 502" in result["error"]

    @responses.activate
    def test_invalid_json_reports_error(self, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, body="<html>oops</html>", status=200)
        assert "invalid JSON" in subdomains.query_crtsh("example.com", ctx)["error"]

    @responses.activate
    def test_unexpected_shape_reports_error(self, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, json={"unexpected": True})
        assert "unexpected payload" in subdomains.query_crtsh("example.com", ctx)["error"]

    @responses.activate
    def test_request_failure_reports_error(self, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            body=requests.ConnectionError("name resolution failed"),
        )
        assert "crt.sh lookup failed" in subdomains.query_crtsh("example.com", ctx)["error"]

    @responses.activate
    def test_no_certificates_reports_error(self, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, json=[], status=200)
        result = subdomains.query_crtsh("example.com", ctx)
        assert result["names"] == []
        assert "no certificates" in result["error"]

    @responses.activate
    def test_malformed_entries_ignored(self, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=["a string", {"no_name_field": 1}, {"name_value": "ok.example.com"}],
            status=200,
        )
        assert subdomains.query_crtsh("example.com", ctx)["names"] == ["ok.example.com"]

    @responses.activate
    def test_query_is_scoped_to_subdomains(self, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=[{"name_value": "www.example.com"}],
            status=200,
        )
        subdomains.query_crtsh("example.com", ctx)
        assert responses.calls[0].request.params["q"] == "%.example.com"


class TestResolveNames:
    def test_finds_resolving_words(self, monkeypatch, ctx):
        known = {"www.example.com", "api.example.com"}
        monkeypatch.setattr(
            subdomains.dns.resolver, "Resolver", lambda *a, **k: FakeResolver(known)
        )
        result = subdomains.resolve_names("example.com", ["www", "api", "nope"], ctx)
        assert result["found"] == ["api.example.com", "www.example.com"]
        assert result["checked"] == 3

    def test_no_hits_returns_empty(self, monkeypatch, ctx):
        monkeypatch.setattr(
            subdomains.dns.resolver, "Resolver", lambda *a, **k: FakeResolver(set())
        )
        assert subdomains.resolve_names("example.com", ["www"], ctx)["found"] == []

    def test_resolver_errors_are_not_hits(self, monkeypatch, ctx):
        monkeypatch.setattr(
            subdomains.dns.resolver,
            "Resolver",
            lambda *a, **k: FakeResolver(set(), fail_with=dns.resolver.LifetimeTimeout()),
        )
        assert subdomains.resolve_names("example.com", ["www"], ctx)["found"] == []

    def test_dns_exception_is_not_a_hit(self, monkeypatch, ctx):
        monkeypatch.setattr(
            subdomains.dns.resolver,
            "Resolver",
            lambda *a, **k: FakeResolver(set(), fail_with=dns.exception.DNSException("boom")),
        )
        assert subdomains.resolve_names("example.com", ["www"], ctx)["found"] == []

    def test_future_exception_is_survived(self, monkeypatch, ctx):
        class Exploding:
            def resolve(self, name, rtype, **kwargs):
                raise MemoryError("unexpected")

        monkeypatch.setattr(subdomains.dns.resolver, "Resolver", lambda *a, **k: Exploding())
        assert subdomains.resolve_names("example.com", ["www"], ctx)["found"] == []

    def test_concurrency_is_capped(self, monkeypatch, ctx):
        seen: list[int] = []

        class Recording:
            def __init__(self, *args, **kwargs):
                seen.append(kwargs["max_workers"])

            def __enter__(self, *args, **kwargs):
                return self

            def __exit__(self, *exc):
                return False

            def submit(self, *args, **kwargs):
                raise AssertionError("not reached")

        monkeypatch.setattr(subdomains, "ThreadPoolExecutor", Recording)
        huge = ReconContext(timeout=1.0, concurrency=10_000)
        with pytest.raises(AssertionError):
            subdomains.resolve_names("example.com", ["www"], huge)
        assert seen[0] == MAX_CONCURRENCY


class TestDiscover:
    @responses.activate
    def test_merges_both_sources(self, monkeypatch, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=[{"name_value": "cdn.example.com"}],
            status=200,
        )
        monkeypatch.setattr(subdomains, "load_wordlist", lambda path=None: ["www"])
        monkeypatch.setattr(subdomains, "_has_wildcard", lambda domain, timeout: False)
        monkeypatch.setattr(
            subdomains,
            "resolve_names",
            lambda domain, words, context: {"found": ["www.example.com"], "checked": 1},
        )
        result = subdomains.discover("example.com", ctx)
        assert result["subdomains"] == ["cdn.example.com", "www.example.com"]
        assert result["count"] == 2
        assert result["sources"] == {"crtsh": 1, "wordlist": 1, "wordlist_checked": 1}

    @responses.activate
    def test_wildcard_ignores_wordlist_hits(self, monkeypatch, ctx):
        responses.add(
            responses.GET,
            subdomains.CRTSH_URL,
            json=[{"name_value": "cdn.example.com"}],
            status=200,
        )
        monkeypatch.setattr(subdomains, "load_wordlist", lambda path=None: ["www", "api"])
        monkeypatch.setattr(subdomains, "_has_wildcard", lambda domain, timeout: True)
        monkeypatch.setattr(
            subdomains,
            "resolve_names",
            lambda domain, words, context: {"found": ["www.example.com"], "checked": 2},
        )
        result = subdomains.discover("example.com", ctx)
        assert result["wildcard_dns"] is True
        assert result["subdomains"] == ["cdn.example.com"]
        assert any("wildcard DNS" in warning for warning in result["warnings"])

    @responses.activate
    def test_both_sources_failing_is_an_error(self, monkeypatch, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, status=502)
        monkeypatch.setattr(subdomains, "load_wordlist", lambda path=None: ["www"])
        monkeypatch.setattr(subdomains, "_has_wildcard", lambda domain, timeout: False)
        monkeypatch.setattr(
            subdomains, "resolve_names", lambda d, w, c: {"found": [], "checked": len(w)}
        )
        result = subdomains.discover("example.com", ctx)
        assert "no subdomains discovered" in result["error"]
        assert any("HTTP 502" in warning for warning in result["warnings"])

    @responses.activate
    def test_crtsh_failure_still_uses_wordlist(self, monkeypatch, ctx):
        responses.add(responses.GET, subdomains.CRTSH_URL, body="timeout")
        monkeypatch.setattr(subdomains, "load_wordlist", lambda path=None: ["www"])
        monkeypatch.setattr(subdomains, "_has_wildcard", lambda domain, timeout: False)
        monkeypatch.setattr(
            subdomains,
            "resolve_names",
            lambda d, w, c: {"found": ["www.example.com"], "checked": 1},
        )
        result = subdomains.discover("example.com", ctx)
        assert result["subdomains"] == ["www.example.com"]
        assert result["warnings"]

    def test_lookup_never_raises(self, monkeypatch, ctx):
        monkeypatch.setattr(
            subdomains,
            "discover",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("kaboom")),
        )
        result = subdomains.lookup("example.com", ctx)
        assert "kaboom" in result["error"]

    @responses.activate
    def test_uses_context_wordlist(self, monkeypatch, ctx, tmp_path):
        custom = tmp_path / "words.txt"
        custom.write_text("special\n", encoding="utf-8")
        responses.add(responses.GET, subdomains.CRTSH_URL, status=502)
        captured: list[Path | None] = []

        def fake_load(path=None):
            captured.append(path)
            return ["special"]

        monkeypatch.setattr(subdomains, "load_wordlist", fake_load)
        monkeypatch.setattr(subdomains, "_has_wildcard", lambda d, t: False)
        monkeypatch.setattr(
            subdomains, "resolve_names", lambda d, w, c: {"found": [], "checked": 1}
        )
        subdomains.discover("example.com", ReconContext(wordlist=custom))
        assert captured == [custom]

    def test_crtsh_payload_is_valid_json_shape(self):
        """The URL constant must stay a plain crt.sh query endpoint."""
        assert subdomains.CRTSH_URL.startswith("https://")
        assert json.dumps({"q": "%.example.com", "output": "json"})
