"""Tests for :mod:`reconx.whois_info`.

`python-whois` is mocked, so no WHOIS server is contacted.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from reconx import whois_info
from reconx.context import ReconContext


@pytest.fixture
def ctx() -> ReconContext:
    return ReconContext(timeout=2.0)


class Obj(dict):
    """A whois result that exposes fields as attributes, as some TLDs return."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


class TestClean:
    def test_primitives_pass_through(self):
        assert whois_info._clean("x") == "x"
        assert whois_info._clean(5) == 5
        assert whois_info._clean(None) is None
        assert whois_info._clean(True) is True

    def test_datetime_becomes_isoformat(self):
        moment = dt.datetime(1995, 8, 14, 4, 0, tzinfo=dt.UTC)
        assert whois_info._clean(moment) == moment.isoformat()

    def test_nested_dict_is_cleaned(self):
        assert whois_info._clean({"a": dt.date(2020, 1, 1)}) == {"a": "2020-01-01"}

    def test_lists_are_cleaned(self):
        assert whois_info._clean([dt.date(2020, 1, 1), "x"]) == ["2020-01-01", "x"]

    def test_unknown_object_becomes_string(self):
        class Weird:
            def __str__(self) -> str:
                return "weird"

        assert whois_info._clean(Weird()) == "weird"


class TestNormalize:
    def test_single_keeps_one_value(self):
        assert whois_info._normalize(["only"], single=True) == "only"

    def test_single_of_empty_is_none(self):
        assert whois_info._normalize([], single=True) is None

    def test_multi_keeps_list(self):
        assert whois_info._normalize(["a", "b"], single=False) == ["a", "b"]


class TestParseWhoisData:
    def test_none_returns_empty(self):
        assert whois_info.parse_whois_data(None) == {}

    def test_dict_source(self):
        parsed = whois_info.parse_whois_data(
            {
                "registrar": "Registrar Inc",
                "creation_date": dt.datetime(2000, 1, 1, tzinfo=dt.UTC),
                "name_servers": ["a.ns.example.com.", "b.ns.example.com."],
                "unknown_field": "ignored",
            }
        )
        assert parsed["registrar"] == "Registrar Inc"
        assert parsed["created"] == "2000-01-01T00:00:00+00:00"
        assert parsed["name_servers"] == ["a.ns.example.com.", "b.ns.example.com."]
        assert "unknown_field" not in parsed

    def test_attribute_source(self):
        parsed = whois_info.parse_whois_data(
            Obj(registrar="Registrar Inc", registrant_country="US")
        )
        assert parsed["registrar"] == "Registrar Inc"
        assert parsed["country"] == "US"

    def test_empty_values_are_dropped(self):
        parsed = whois_info.parse_whois_data(
            {"registrar": "", "emails": [], "status": None, "dnssec": "signedDelegation"}
        )
        assert parsed == {"dnssec": "signedDelegation"}

    def test_first_of_list_used_for_single_fields(self):
        parsed = whois_info.parse_whois_data({"registrar": ["First", "Second"]})
        assert parsed["registrar"] == "First"

    def test_all_known_fields_round_trip(self):
        source = {field: f"value-{field}" for field in whois_info.REGISTRAR_FIELDS}
        parsed = whois_info.parse_whois_data(source)
        assert len(parsed) == len(whois_info.REGISTRAR_FIELDS)


class TestLookup:
    def test_success(self, monkeypatch, ctx):
        monkeypatch.setattr(
            whois_info.whois, "whois", lambda domain: {"registrar": "Registrar Inc"}
        )
        result = whois_info.lookup("example.com", ctx)
        assert result["registrar"] == "Registrar Inc"
        assert "error" not in result

    def test_exception_becomes_error(self, monkeypatch, ctx):
        def boom(domain: str) -> Any:
            raise ConnectionError("whois server unreachable")

        monkeypatch.setattr(whois_info.whois, "whois", boom)
        result = whois_info.lookup("example.com", ctx)
        assert "whois server unreachable" in result["error"]

    def test_empty_response_is_an_error(self, monkeypatch, ctx):
        monkeypatch.setattr(whois_info.whois, "whois", lambda domain: {})
        assert "no whois data" in whois_info.lookup("example.com", ctx)["error"]

    def test_unrecognised_fields_are_an_error(self, monkeypatch, ctx):
        monkeypatch.setattr(whois_info.whois, "whois", lambda domain: {"nonsense": "x"})
        assert "no known fields" in whois_info.lookup("example.com", ctx)["error"]

    def test_context_is_accepted_but_unused(self, monkeypatch):
        monkeypatch.setattr(whois_info.whois, "whois", lambda domain: {"registrar": "R"})
        # python-whois manages its own socket timeouts, so --timeout does not
        # apply here; the signature still has to accept it.
        assert whois_info.lookup("example.com", ReconContext(timeout=1.0))["registrar"] == "R"
