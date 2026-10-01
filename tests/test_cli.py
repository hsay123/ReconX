"""Tests for :mod:`reconx.cli` argument handling.

All module execution is stubbed, so nothing here touches the network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from reconx import cli, core


@pytest.fixture(autouse=True)
def stub_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every registered module with a deterministic stub."""
    stubs = {
        "dns": lambda domain, context: {"records": {"A": ["93.184.216.34"]}},
        "http": lambda domain, context: {"status_code": 200, "headers": {"server": "nginx"}},
        "whois": lambda domain, context: {"registrar": "Test Registrar"},
    }
    for name, runner in stubs.items():
        monkeypatch.setitem(core._MODULES, name, runner)


class TestParseModules:
    def test_none_means_all(self):
        assert cli.parse_modules(None) is None
        assert cli.parse_modules("  ") is None

    def test_all_means_all(self):
        assert cli.parse_modules("all") is None
        assert cli.parse_modules("dns,all") is None

    def test_splits_and_lowercases(self):
        assert cli.parse_modules(" DNS , HTTP ") == ["dns", "http"]

    def test_empty_selection_rejected(self):
        with pytest.raises(ValueError, match="selected no modules"):
            cli.parse_modules(", ,")


class TestBuildParser:
    def test_defaults(self):
        args = cli.build_parser().parse_args(["example.com"])
        assert args.domain == "example.com"
        assert args.format == "text"
        assert args.modules is None
        assert args.timeout == core.DEFAULT_TIMEOUT
        assert args.verbose is False

    def test_short_options(self):
        args = cli.build_parser().parse_args(
            ["example.com", "-m", "dns,http", "-f", "json", "-o", "out.json", "-v"]
        )
        assert args.modules == "dns,http"
        assert args.format == "json"
        assert args.output == "out.json"
        assert args.verbose is True

    def test_version_exits(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0
        assert "ReconX" in capsys.readouterr().out

    def test_unknown_format_rejected(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["example.com", "--format", "yaml"])


class TestMain:
    def test_json_to_stdout(self, capsys):
        assert cli.main(["example.com", "--format", "json", "--modules", "dns"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["target"] == "example.com"
        assert payload["results"]["dns"]["records"] == {"A": ["93.184.216.34"]}

    def test_domain_is_normalized(self, capsys):
        assert cli.main(["HTTPS://Example.com/path", "--format", "json"]) == 0
        assert json.loads(capsys.readouterr().out)["target"] == "example.com"

    def test_invalid_domain_exits_two(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["not a domain"])
        assert excinfo.value.code == cli.EXIT_USAGE
        assert "not a valid domain" in capsys.readouterr().err

    def test_unknown_module_exits_two(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["example.com", "--modules", "nope"])
        assert excinfo.value.code == cli.EXIT_USAGE
        assert "unknown module" in capsys.readouterr().err

    def test_non_positive_timeout_exits_two(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["example.com", "--timeout", "0"])
        assert excinfo.value.code == cli.EXIT_USAGE
        assert "--timeout" in capsys.readouterr().err

    def test_output_file(self, tmp_path, capsys):
        target = tmp_path / "report.json"
        assert cli.main(["example.com", "--format", "json", "-o", str(target)]) == 0
        assert capsys.readouterr().out == ""
        payload: dict[str, Any] = json.loads(target.read_text(encoding="utf-8"))
        assert payload["tool"] == "reconx"

    def test_text_output_mentions_target(self, capsys):
        assert cli.main(["example.com", "--modules", "dns"]) == 0
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "93.184.216.34" in out

    def test_verbose_prints_legal_notice(self, capsys):
        assert cli.main(["example.com", "--modules", "dns", "-v"]) == 0
        assert "authorized" in capsys.readouterr().err

    def test_all_modules_failing_returns_one(self, monkeypatch, capsys):
        def boom(domain: str, context: Any) -> dict[str, Any]:
            raise RuntimeError("nope")

        for name in core.available_modules():
            monkeypatch.setitem(core._MODULES, name, boom)
        assert cli.main(["example.com", "--format", "json"]) == 1
        assert "every module failed" in capsys.readouterr().err

    def test_partial_failure_is_only_reported_when_verbose(self, monkeypatch, capsys):
        def boom(domain: str, context: Any) -> dict[str, Any]:
            raise RuntimeError("nope")

        monkeypatch.setitem(core._MODULES, "dns", boom)
        assert cli.main(["example.com", "--format", "json"]) == 0
        assert "modules with errors" not in capsys.readouterr().err

        assert cli.main(["example.com", "--format", "json", "-v"]) == 0
        assert "modules with errors" in capsys.readouterr().err

    def test_markdown_output(self, capsys):
        assert cli.main(["example.com", "--modules", "dns", "--format", "md"]) == 0
        assert capsys.readouterr().out.startswith("# ReconX report: example.com")

    def test_html_output(self, capsys):
        assert cli.main(["example.com", "--modules", "dns", "--format", "html"]) == 0
        assert "<!DOCTYPE html>" in capsys.readouterr().out

    def test_file_output_gets_a_trailing_newline(self, tmp_path):
        target = tmp_path / "report.md"
        assert cli.main(["example.com", "--modules", "dns", "-f", "md", "-o", str(target)]) == 0
        assert target.read_text(encoding="utf-8").endswith("\n")
