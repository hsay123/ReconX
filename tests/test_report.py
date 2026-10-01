"""Tests for :mod:`reconx.report`.

Rendering is pure: a report dict goes in, formatted text comes out.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from reconx import report


@pytest.fixture
def sample_report() -> dict[str, Any]:
    """Return a report covering every module and the failure path."""
    return {
        "tool": "reconx",
        "version": "0.2.0",
        "target": "example.com",
        "generated_at": "2026-10-01T00:00:00Z",
        "duration_seconds": 1.5,
        "modules": ["dns", "http", "tls", "tech", "subdomains", "whois"],
        "results": {
            "dns": {
                "records": {
                    "A": ["93.184.216.34"],
                    "NS": ["a.iana-servers.net"],
                    "MX": [{"preference": 10, "exchange": "mail.example.com"}],
                },
                "warnings": [],
                "duration_seconds": 0.1,
            },
            "http": {
                "url": "https://www.example.com/",
                "final_url": "https://www.example.com/",
                "status_code": 200,
                "reason": "OK",
                "response_time_ms": 120.5,
                "redirect_count": 1,
                "headers": {"server": "nginx"},
                "security_headers": {
                    "present": ["Strict-Transport-Security"],
                    "missing": ["Content-Security-Policy", "X-Frame-Options"],
                    "score": 1,
                    "total": 6,
                    "grade": "D",
                },
                "attempts": [{"scheme": "https"}],
                "warnings": ["followed 1 redirect(s) to reach the final URL"],
                "duration_seconds": 0.4,
            },
            "tls": {
                "subject": "CN=example.com",
                "issuer": "CN=Example CA",
                "subject_alt_names": ["example.com", "www.example.com"],
                "not_after": "2026-12-25T22:56:35+00:00",
                "days_until_expiry": 85,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "warnings": [],
                "duration_seconds": 0.2,
            },
            "tech": {
                "technologies": [
                    {
                        "name": "nginx",
                        "category": "Web server",
                        "confidence": "high",
                        "evidence": "header matched 'nginx'",
                    }
                ],
                "count": 1,
                "generator": "Hugo 0.140",
                "warnings": [],
                "duration_seconds": 0.3,
            },
            "subdomains": {
                "subdomains": ["www.example.com"],
                "count": 1,
                "sources": {"crtsh": 1, "wordlist": 0, "wordlist_checked": 59},
                "wildcard_dns": False,
                "warnings": [],
                "duration_seconds": 0.4,
            },
            "whois": {
                "registrar": "Test Registrar",
                "country": "US",
                "created": "1995-08-14T04:00:00+00:00",
                "warnings": [],
                "duration_seconds": 0.1,
            },
        },
        "summary": {
            "modules_run": 6,
            "modules_failed": [],
            "warning_count": 1,
        },
    }


class TestToJson:
    def test_round_trips(self, sample_report):
        assert json.loads(report.to_json(sample_report)) == sample_report

    def test_keys_are_sorted(self, sample_report):
        text = report.to_json(sample_report)
        assert text.index('"duration_seconds"') < text.index('"generated_at"')

    def test_non_serializable_value_is_stringified(self, sample_report):
        sample_report["results"]["dns"]["records"]["odd"] = {1, 2}
        assert json.loads(report.to_json(sample_report))["results"]["dns"]["records"]["odd"]


class TestMarkdown:
    def test_includes_target_and_metadata(self, sample_report):
        text = report.markdown(sample_report)
        assert text.startswith("# ReconX report: example.com")
        assert "2026-10-01T00:00:00Z" in text
        assert "1.5" in text

    def test_has_a_section_per_module(self, sample_report):
        text = report.markdown(sample_report)
        for name in sample_report["modules"]:
            assert f"## {name}" in text

    def test_shows_dns_records(self, sample_report):
        assert "93.184.216.34" in report.markdown(sample_report)

    def test_shows_security_header_grade(self, sample_report):
        assert "grade D" in report.markdown(sample_report)

    def test_shows_subdomains(self, sample_report):
        assert "www.example.com" in report.markdown(sample_report)

    def test_includes_authorization_notice(self, sample_report):
        assert "authorized to test" in report.markdown(sample_report)

    def test_error_is_shown(self, sample_report):
        sample_report["results"]["dns"] = {"error": "NXDOMAIN"}
        assert "**Failed:** NXDOMAIN" in report.markdown(sample_report)

    def test_warnings_are_listed(self, sample_report):
        assert "followed 1 redirect" in report.markdown(sample_report)

    def test_module_without_warnings_renders(self, sample_report):
        del sample_report["results"]["dns"]["warnings"]
        assert "## dns" in report.markdown(sample_report)

    def test_module_with_empty_warnings_renders(self, sample_report):
        sample_report["results"]["dns"]["warnings"] = []
        assert "## dns" in report.markdown(sample_report)

    def test_module_with_no_lists_renders(self, sample_report):
        sample_report["results"]["whois"]["warnings"] = None
        assert "## whois" in report.markdown(sample_report)

    def test_empty_values_render_as_dash(self, sample_report):
        sample_report["results"]["tls"]["cipher"] = ""
        assert "- " in report.markdown(sample_report)

    def test_nested_records_are_flattened(self, sample_report):
        text = report.markdown(sample_report)
        # MX is a dict inside a list; a Python literal would leak into a
        # document meant to be pasted into a write-up.
        assert "preference=10" in text
        assert "{'preference'" not in text

    def test_missing_dns_records_still_render(self, sample_report):
        sample_report["results"]["dns"] = {"records": {}, "warnings": []}
        text = report.markdown(sample_report)
        assert "## dns" in text


class TestToHtml:
    def test_is_a_complete_document(self, sample_report):
        text = report.to_html(sample_report)
        assert text.startswith("<!DOCTYPE html>")
        assert text.rstrip().endswith("</html>")

    def test_styles_are_inline(self, sample_report):
        # No external stylesheet, so the file renders offline.
        assert "<style>" in report.to_html(sample_report)
        assert "<link" not in report.to_html(sample_report)

    def test_has_a_section_per_module(self, sample_report):
        text = report.to_html(sample_report)
        for name in sample_report["modules"]:
            assert f"<h2>{name}</h2>" in text

    def test_escapes_hostile_target(self, sample_report):
        sample_report["target"] = "<script>alert(1)</script>"
        text = report.to_html(sample_report)
        assert "<script>alert(1)</script>" not in text
        assert "&lt;script&gt;" in text

    def test_escapes_rendered_values(self, sample_report):
        sample_report["results"]["tls"]["subject"] = "<img src=x onerror=alert(1)>"
        text = report.to_html(sample_report)
        assert "<img src=x" not in text
        assert "&lt;img" in text

    def test_raw_header_dumps_are_not_embedded(self, sample_report):
        # The human formats show selected fields; the full header dict stays in
        # the JSON output, so arbitrary server values never reach the HTML.
        sample_report["results"]["http"]["headers"] = {"server": "<img src=x onerror=1>"}
        assert "<img" not in report.to_html(sample_report)

    def test_error_is_shown(self, sample_report):
        sample_report["results"]["dns"] = {"error": "boom"}
        assert "boom" in report.to_html(sample_report)

    def test_module_without_lists_renders(self, sample_report):
        del sample_report["results"]["dns"]["warnings"]
        assert "<h2>dns</h2>" in report.to_html(sample_report)

    def test_empty_records_render(self, sample_report):
        sample_report["results"]["dns"] = {"records": {}, "warnings": []}
        assert "<h2>dns</h2>" in report.to_html(sample_report)

    def test_summary_pills_present(self, sample_report):
        text = report.to_html(sample_report)
        assert "Modules" in text
        assert "Warnings" in text

    def test_missing_headers_listed(self, sample_report):
        assert "Missing security headers" in report.to_html(sample_report)


class TestConsole:
    def test_mentions_target_and_modules(self, sample_report):
        text = report.console(sample_report)
        assert "example.com" in text
        assert "dns" in text
        assert "93.184.216.34" in text

    def test_summary_is_not_printed_twice(self, sample_report):
        # Console rendering captures to a buffer; it must not also write to
        # stdout, or the CLI's print() would double the whole report.
        text = report.console(sample_report)
        assert text.count("ReconX 0.2.0") == 1

    def test_includes_authorization_notice(self, sample_report):
        assert "authorized to test" in report.console(sample_report)

    def test_error_shown(self, sample_report):
        sample_report["results"]["dns"] = {"error": "kaboom"}
        assert "kaboom" in report.console(sample_report)

    def test_plain_fallback_matches_content(self, sample_report, monkeypatch):
        def no_rich(*args, **kwargs):
            raise ImportError("no rich here")

        monkeypatch.setattr(report, "_console_rich", no_rich)
        text = report.console(sample_report)
        assert "example.com" in text
        assert "modules with errors" in text or "completed" in text

    def test_long_lists_are_truncated(self, sample_report):
        sample_report["results"]["subdomains"]["subdomains"] = [
            f"s{index}.example.com" for index in range(30)
        ]
        assert "more)" in report.console(sample_report)

    def test_empty_list_is_not_printed(self, sample_report):
        # An empty list is noise in the summary; the count row says "0".
        sample_report["results"]["subdomains"]["subdomains"] = []
        text = report.console(sample_report)
        assert "found" in text
        assert "subdomains:" not in text

    def test_console_value_handles_empty_and_missing(self):
        assert report._console_value([]) == "(none)"
        assert report._console_value(None) == "-"
        assert report._console_value("") == "-"
        assert report._console_value({}) == "-"
        assert report._console_value({"a": 1}) == "a=1"

    def test_console_flattens_nested_records(self, sample_report):
        assert "{'preference'" not in report.console(sample_report)


class TestRender:
    @pytest.mark.parametrize("fmt", ["text", "json", "md", "html"])
    def test_every_format_works(self, sample_report, fmt):
        assert report.render(sample_report, fmt).strip()

    def test_unknown_format_rejected(self, sample_report):
        with pytest.raises(ValueError, match="unknown format"):
            report.render(sample_report, "yaml")

    def test_formats_are_deterministic(self, sample_report):
        for fmt in ("json", "md", "html", "text"):
            first = report.render(sample_report, fmt)
            second = report.render(dict(sample_report), fmt)
            assert first == second

    def test_declared_formats(self):
        assert report.FORMATS == ("text", "json", "md", "html")


class TestSectionBody:
    def test_unknown_module_falls_back_to_pairs(self):
        body = report._section_body("mystery", {"alpha": "one", "beta": 2, "error": "x"})
        assert body["rows"] == [("alpha", "one"), ("beta", 2)]

    def test_whois_rows_exclude_internals(self):
        body = report._section_body("whois", {"registrar": "X", "duration_seconds": 1.0})
        assert body["rows"] == [("registrar", "X")]
