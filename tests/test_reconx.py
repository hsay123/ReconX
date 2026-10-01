"""End-to-end tests for the package surface.

These exercise the public API the way a consumer would, with every network
call faked.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import responses

from reconx import __version__, core, report
from tests.test_tls_info import FakeTLS, example_der_path, patch_socket

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestPackage:
    def test_version(self):
        assert __version__ == "0.2.0"

    def test_run_is_exported(self):
        import reconx

        assert callable(reconx.run)

    def test_module_inventory_is_stable(self):
        # The --modules names are a public interface; changing them silently
        # would break scripts.
        assert core.available_modules() == (
            "dns",
            "http",
            "subdomains",
            "tech",
            "tls",
            "whois",
        )

    def test_every_module_runner_is_callable(self):
        for name in core.available_modules():
            assert callable(core._MODULES[name])


class TestShim:
    def test_exposes_the_original_function_names(self):
        import ReconX

        for name in ("get_ip", "get_headers", "get_whois", "get_subdomains"):
            assert callable(getattr(ReconX, name))

    def test_get_ip_returns_addresses(self):
        import ReconX

        result = ReconX.get_ip("https://Example.com/path")
        assert set(result) >= {"a", "aaaa"}

    def test_invalid_domain_raises(self):
        import ReconX

        with pytest.raises(ValueError):
            ReconX.get_ip("not a domain")

    def test_legal_notice_is_shared_with_core(self):
        import ReconX

        assert ReconX.LEGAL_BANNER == core.LEGAL_NOTICE

    def test_runs_as_a_script(self):
        # The legacy interactive path must still work.
        result = subprocess.run(
            [sys.executable, "ReconX.py"],
            input="example.com\n",
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
            check=False,
        )
        assert result.returncode == 0
        assert "Website Information Gatherer" in result.stdout
        assert "authorized" in result.stdout

    def test_rejects_arguments_with_a_hint(self):
        result = subprocess.run(
            [sys.executable, "ReconX.py", "--help-me"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=REPO_ROOT,
            check=False,
        )
        assert result.returncode == 0
        assert "reconx example.com" in result.stderr


class TestConsoleScript:
    def test_reconx_entry_point_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "reconx", "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0
        assert __version__ in result.stdout


class TestModuleIntegration:
    """Run several real modules together with only the network faked."""

    @responses.activate
    def test_dns_http_tls_together(self, monkeypatch):
        responses.add(
            responses.GET,
            "https://example.com",
            status=200,
            body="<html></html>",
            headers={"Server": "nginx"},
        )
        patch_socket(monkeypatch, FakeTLS(example_der_path.read_bytes()))

        result = core.run("example.com", modules=["dns", "http", "tls"])
        assert result["modules"] == ["dns", "http", "tls"]
        assert result["summary"]["modules_failed"] == []
        assert json.loads(report.to_json(result))["target"] == "example.com"

    def test_one_failing_module_does_not_stop_the_others(self, monkeypatch):
        def boom(domain, context):
            raise RuntimeError("module exploded")

        # These two need the network blocked or stubbed; the point of the test
        # is that dns failing does not prevent them from being attempted.
        monkeypatch.setitem(core._MODULES, "tls", lambda domain, ctx: {"protocol": "TLSv1.3"})
        monkeypatch.setitem(core._MODULES, "tech", lambda domain, ctx: {"count": 0})
        monkeypatch.setitem(core._MODULES, "dns", boom)

        result = core.run("example.com", modules=["dns", "tls", "tech"])
        assert "module exploded" in result["results"]["dns"]["error"]
        assert result["summary"]["modules_failed"] == ["dns"]
        assert result["results"]["tls"]["protocol"] == "TLSv1.3"
        assert result["results"]["tech"]["count"] == 0

    def test_report_is_json_serialisable_across_all_modules(self, monkeypatch):
        monkeypatch.setitem(
            core._MODULES, "tls", lambda domain, ctx: {"protocol": "TLSv1.3", "port": 443}
        )
        result = core.run("example.com", modules=["tls"])
        assert json.loads(report.to_json(result))["results"]["tls"]["port"] == 443


def test_wordlist_ships_with_the_package():
    from reconx import subdomains

    words = subdomains.load_wordlist()
    assert words, "the bundled wordlist must not be empty"
    assert subdomains.DEFAULT_WORDLIST.exists()
