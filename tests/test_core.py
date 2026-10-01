"""Tests for :mod:`reconx.core` domain handling and orchestration.

No test here touches the network: every runner in the registry is replaced
with a stub, so the suite is deterministic and offline.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from reconx import core


@pytest.fixture(autouse=True)
def stub_registry() -> Iterator[dict[str, Any]]:
    """Replace every registered module with a deterministic stub.

    The whole registry is restored afterwards, so tests that register a module
    do not leak it into the next test.
    """
    stubs: dict[str, Any] = {
        "dns": lambda domain, context: {"records": {"A": ["93.184.216.34"]}},
        "http": lambda domain, context: {"status_code": 200, "headers": {}},
        "whois": lambda domain, context: {"registrar": "Test Registrar"},
    }
    original = dict(core._MODULES)
    core._MODULES.update(stubs)
    try:
        yield stubs
    finally:
        # Restore the whole mapping: monkeypatch.setitem only undoes the keys it
        # touched, so a module added via register_module would otherwise leak
        # into later tests.
        core._MODULES.clear()
        core._MODULES.update(original)


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("  example.com  ", "example.com"),
            ("https://example.com", "example.com"),
            ("http://example.com/path?a=1#frag", "example.com"),
            ("https://user:pass@example.com:8443/admin", "example.com"),
            ("example.com.", "example.com"),
            ("sub.example.co.uk", "sub.example.co.uk"),
        ],
    )
    def test_accepts_realistic_input(self, raw, expected):
        assert core.normalize_domain(raw) == expected

    def test_preserves_www(self):
        assert core.normalize_domain("www.example.com") == "www.example.com"

    @pytest.mark.parametrize(
        "raw",
        ["", "   ", "not a domain", "http://", "localhost", "-bad.example.com", "exa_mple.com"],
    )
    def test_rejects_invalid_input(self, raw):
        with pytest.raises(ValueError):
            core.normalize_domain(raw)

    def test_rejects_overlong_domain(self):
        long_label = "a" * 60
        domain = ".".join([long_label] * 5)
        with pytest.raises(ValueError, match="too long"):
            core.normalize_domain(domain)


class TestModuleRegistry:
    def test_available_modules_are_non_empty(self):
        assert "dns" in core.available_modules()

    def test_resolve_none_returns_all(self):
        assert core.resolve_modules(None) == list(core.available_modules())

    def test_resolve_is_order_independent(self):
        first = core.resolve_modules(["whois", "dns"])
        second = core.resolve_modules(["dns", "whois"])
        assert first == second

    def test_rejects_unknown_module(self):
        with pytest.raises(ValueError, match="unknown module"):
            core.resolve_modules(["dns", "nope"])

    def test_register_duplicate_rejected(self):
        with pytest.raises(ValueError, match="already registered"):
            core.register_module("dns", lambda domain, context: {})

    def test_register_adds_a_new_module(self):
        core.register_module("extra", lambda domain, context: {"ok": True})
        assert "extra" in core.available_modules()
        assert core.resolve_modules(["extra"]) == ["extra"]

    def test_new_module_runs(self):
        core.register_module("extra", lambda domain, context: {"ok": True})
        assert core.run("example.com", modules=["extra"])["results"]["extra"]["ok"] is True

    def test_registry_returns_a_tuple(self):
        assert isinstance(core.available_modules(), tuple)

    def test_summary_counts_warnings(self, monkeypatch):
        monkeypatch.setitem(
            core._MODULES,
            "dns",
            lambda domain, context: {"records": {}, "warnings": ["a", "b"]},
        )
        report = core.run("example.com", modules=["dns"])
        assert report["summary"]["warning_count"] == 2

    def test_summary_tolerates_non_dict_entries(self, monkeypatch):
        monkeypatch.setitem(core._MODULES, "dns", lambda domain, context: ["not", "a", "dict"])
        report = core.run("example.com", modules=["dns"])
        assert report["summary"]["modules_run"] == 1


class TestRun:
    def test_normalizes_target(self):
        report = core.run("https://Example.com/", modules=["dns"])
        assert report["target"] == "example.com"

    def test_report_shape(self):
        report = core.run("example.com", modules=["dns"])
        assert report["tool"] == "reconx"
        assert report["modules"] == ["dns"]
        assert "generated_at" in report
        assert report["results"]["dns"]["records"] == {"A": ["93.184.216.34"]}
        assert report["summary"]["modules_run"] == 1
        assert report["summary"]["modules_failed"] == []

    def test_module_failure_is_isolated(self, monkeypatch):
        def boom(domain: str, context: Any) -> dict[str, Any]:
            raise RuntimeError("kaboom")

        monkeypatch.setitem(core._MODULES, "dns", boom)
        report = core.run("example.com", modules=["dns", "whois"])

        assert "error" in report["results"]["dns"]
        assert "kaboom" in report["results"]["dns"]["error"]
        assert report["results"]["whois"]["registrar"] == "Test Registrar"
        assert report["summary"]["modules_failed"] == ["dns"]

    def test_non_dict_return_is_reported(self, monkeypatch):
        monkeypatch.setitem(core._MODULES, "dns", lambda domain, context: ["not", "a", "dict"])
        report = core.run("example.com", modules=["dns"])
        assert "expected dict" in report["results"]["dns"]["error"]

    def test_invalid_domain_raises(self):
        with pytest.raises(ValueError):
            core.run("not a domain")
