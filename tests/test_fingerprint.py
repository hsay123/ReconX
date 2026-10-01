"""Tests for :mod:`reconx.fingerprint`.

HTTP responses come from the ``responses`` mock, so no real requests are made.
"""

from __future__ import annotations

from typing import Any

import pytest
import requests
import responses

from reconx import fingerprint
from reconx.context import ReconContext


@pytest.fixture
def ctx() -> ReconContext:
    return ReconContext(timeout=2.0)


def names(result: dict[str, Any]) -> set[str]:
    """Return the set of technology names detected."""
    return {item["name"] for item in result["technologies"]}


class TestGenerator:
    def test_normal_order(self):
        html = '<meta name="generator" content="WordPress 6.5">'
        assert fingerprint._generator(html) == "WordPress 6.5"

    def test_reversed_attribute_order(self):
        html = '<meta content="Drupal 10" name="generator">'
        assert fingerprint._generator(html) == "Drupal 10"

    def test_case_insensitive(self):
        assert fingerprint._generator('<META NAME="GENERATOR" CONTENT="Hugo 0.1">') == "Hugo 0.1"

    def test_absent(self):
        assert fingerprint._generator("<html><body>hi</body></html>") == ""

    def test_unrelated_meta_ignored(self):
        html = '<meta name="viewport" content="width=device-width">'
        assert fingerprint._generator(html) == ""


class TestIncludes:
    def test_collects_scripts_and_links(self):
        html = (
            '<script src="/static/jquery.min.js"></script>'
            '<link rel="stylesheet" href="/css/bootstrap.css">'
        )
        includes = fingerprint._includes(html)
        assert "/static/jquery.min.js" in includes
        assert "/css/bootstrap.css" in includes

    def test_deduplicates(self):
        html = '<script src="/a.js"></script><script src="/a.js"></script>'
        assert fingerprint._includes(html) == ["/a.js"]

    def test_respects_limit(self):
        html = "".join(f'<script src="/s{index}.js"></script>' for index in range(500))
        assert len(fingerprint._includes(html, limit=10)) == 10


class TestDetect:
    def test_detects_from_server_header(self):
        assert "nginx" in names(fingerprint.detect({"server": "nginx/1.24.0"}))

    def test_detects_cdn_from_header(self):
        assert "Cloudflare" in names(fingerprint.detect({"server": "cloudflare"}))

    def test_detects_powered_by(self):
        result = fingerprint.detect({"x-powered-by": "Express"})
        assert "Express" in names(result)

    def test_detects_cms_from_generator(self):
        html = '<meta name="generator" content="WordPress 6.5">'
        result = fingerprint.detect({}, html)
        assert "WordPress" in names(result)
        assert result["generator"] == "WordPress 6.5"

    def test_detects_library_from_script_src(self):
        html = '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>'
        assert "jQuery" in names(fingerprint.detect({}, html))

    def test_detects_analytics(self):
        html = '<script src="https://www.googletagmanager.com/gtm.js"></script>'
        assert "Google Tag Manager" in names(fingerprint.detect({}, html))

    def test_empty_input_detects_nothing(self):
        result = fingerprint.detect({}, "")
        assert result["technologies"] == []
        assert result["count"] == 0
        assert result["generator"] == ""

    def test_results_are_sorted_and_unique(self):
        html = '<script src="/jquery.js"></script><meta name="generator" content="WordPress">'
        result = fingerprint.detect({"server": "nginx"}, html)
        listed = [item["name"] for item in result["technologies"]]
        assert listed == sorted(listed, key=lambda name: name)
        assert len(listed) == len(set(listed))

    def test_high_confidence_overrides_low(self):
        # "wordpress" appears in an asset path (low) and the generator (high).
        html = (
            '<meta name="generator" content="WordPress 6.5">'
            '<script src="/wp-content/x.js"></script>'
        )
        entry = next(
            item
            for item in fingerprint.detect({}, html)["technologies"]
            if item["name"] == "WordPress"
        )
        assert entry["confidence"] == "high"

    def test_every_entry_has_evidence(self):
        for item in fingerprint.detect({"server": "nginx"}, "")["technologies"]:
            assert item["evidence"]
            assert item["category"]
            assert item["confidence"] in {"high", "low"}

    def test_large_body_is_truncated(self):
        html = "<p>x</p>" * 200_000
        result = fingerprint.detect({}, html)
        assert isinstance(result["count"], int)

    def test_signatures_are_well_formed(self):
        for entry in fingerprint.SIGNATURES:
            needle, name, category, confidence = entry
            assert needle == needle.lower()
            assert name and category
            assert confidence in {"high", "low"}


class TestLookup:
    @responses.activate
    def test_success(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            status=200,
            body='<meta name="generator" content="Hugo 0.140">',
            headers={"Server": "nginx"},
        )
        result = fingerprint.lookup("example.com", ctx)
        assert "nginx" in names(result)
        assert result["generator"] == "Hugo 0.140"

    @responses.activate
    def test_request_failure_reports_error(self, ctx):
        responses.add(responses.GET, "https://example.com", body=requests.ConnectionError("down"))
        assert "could not fetch" in fingerprint.lookup("example.com", ctx)["error"]

    @responses.activate
    def test_missing_text_falls_back_to_headers(self, ctx):
        responses.add(responses.GET, "https://example.com", status=204, headers={})
        assert "could not fetch" not in fingerprint.lookup("example.com", ctx).get("error", "")

    @responses.activate
    def test_non_html_body_is_tolerated(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            body=b"\xff\xfe\x00binary",
            headers={"Server": "Apache"},
        )
        assert "Apache" in names(fingerprint.lookup("example.com", ctx))

    @responses.activate
    def test_generator_alone_identifies_a_cms(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            body='<meta name="generator" content="PrestaShop 8.1">',
        )
        result = fingerprint.lookup("example.com", ctx)
        assert "PrestaShop" in names(result)
        assert result["generator"] == "PrestaShop 8.1"

    def test_matches_on_header_only(self):
        result = fingerprint.detect({"x-powered-by": "ASP.NET"})
        assert "ASP.NET" in names(result)
