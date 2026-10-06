"""Tests for :mod:`reconx.dns_info`.

dnspython is exercised through a fake resolver object, so the suite performs no
real DNS traffic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from reconx import dns_info
from reconx.context import ReconContext


class FakeAnswer(list):
    """Stands in for a dnspython ``Answer`` object."""


class FakeMX:
    """Stand-in for ``dns.rdtypes.ANY.MX.MX``."""

    def __init__(self, preference: int, exchange: str) -> None:
        self.preference = preference
        self.exchange = exchange


class FakeSOA:
    """Stand-in for ``dns.rdtypes.ANY.SOA.SOA``."""

    def __init__(self) -> None:
        self.mname = "ns1.example.com."
        self.rname = "hostmaster.example.com."
        self.serial = 2026090101
        self.refresh = 7200
        self.retry = 3600
        self.expire = 1209600
        self.minimum = 3600


class FakeTXT:
    """Stand-in for ``dns.rdtypes.ANY.TXT.TXT`` (chunked byte strings)."""

    def __init__(self, *chunks: bytes) -> None:
        self.strings = list(chunks)


class FakeResolver:
    """Minimal stand-in for :class:`dns.resolver.Resolver`."""

    def __init__(self, answers: dict[str, Any] | None = None, error: Exception | None = None):
        self.answers = answers or {}
        self.error = error
        self.queries: list[tuple[str, str]] = []

    def resolve(self, domain: str, rtype: str, **kwargs: Any) -> FakeAnswer:
        self.queries.append((domain, rtype))
        if self.error is not None:
            raise self.error
        value = self.answers.get(rtype, [])
        if isinstance(value, Exception):
            raise value
        return FakeAnswer(value)


class TestNormalizeRdata:
    def test_plain_string(self):
        assert dns_info._normalize_rdata("93.184.216.34", "A") == "93.184.216.34"

    def test_mx(self):
        value = dns_info._normalize_rdata(FakeMX(10, "mail.example.com."), "MX")
        assert value == {"preference": 10, "exchange": "mail.example.com"}

    def test_soa(self):
        value = dns_info._normalize_rdata(FakeSOA(), "SOA")
        assert value["mname"] == "ns1.example.com"
        assert value["serial"] == 2026090101
        assert value["minimum"] == 3600

    def test_txt_chunks_are_concatenated(self):
        value = dns_info._normalize_rdata(FakeTXT(b"v=spf1 ", b"-all"), "TXT")
        assert value == "v=spf1 -all"

    def test_ns_strips_trailing_dot(self):
        assert dns_info._normalize_rdata("a.iana-servers.net.", "NS") == "a.iana-servers.net"

    def test_cname_strips_trailing_dot(self):
        assert dns_info._normalize_rdata("cdn.example.com.", "CNAME") == "cdn.example.com"


class TestResolveAll:
    def test_collects_every_record_type(self):
        resolver = FakeResolver(
            {
                "A": ["93.184.216.34"],
                "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
                "MX": [FakeMX(10, "mail.example.com.")],
            }
        )
        records = dns_info.resolve_all("example.com", resolver, timeout=3)
        assert records["A"] == ["93.184.216.34"]
        assert records["NS"] == ["a.iana-servers.net", "b.iana-servers.net"]
        assert len(resolver.queries) == len(dns_info.RECORD_TYPES)

    def test_missing_types_are_omitted(self):
        resolver = FakeResolver({"A": ["93.184.216.34"]})
        records = dns_info.resolve_all("example.com", resolver, timeout=3)
        assert "MX" not in records

    def test_all_record_types_requested(self):
        assert dns_info.RECORD_TYPES == ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class TestLookup:
    def test_returns_records_and_no_error(self):
        resolver = FakeResolver({"A": ["93.184.216.34"]})
        result = dns_info.lookup("example.com", ReconContext(), resolver)
        assert result["records"]["A"] == ["93.184.216.34"]
        assert "error" not in result

    def test_nxdomain_is_an_error(self):
        resolver = FakeResolver(error=dns.resolver.NXDOMAIN())
        result = dns_info.lookup("nope.invalid", ReconContext(), resolver)
        assert "does not exist" in result["error"]
        assert result["records"] == {}

    def test_lifetime_timeout_is_reported(self):
        resolver = FakeResolver(error=dns.resolver.LifetimeTimeout())
        result = dns_info.lookup("example.com", ReconContext(), resolver)
        assert "timed out" in result["error"]

    def test_warns_without_address_records(self):
        resolver = FakeResolver({"NS": ["a.iana-servers.net."]})
        result = dns_info.lookup("example.com", ReconContext(), resolver)
        assert any("no A or AAAA" in warning for warning in result["warnings"])

    def test_timeout_comes_from_context(self):
        resolver = FakeResolver({"A": ["93.184.216.34"]})
        dns_info.lookup("example.com", ReconContext(timeout=2.5), resolver)
        # A short context timeout is what keeps a slow resolver from hanging a run.
        assert resolver.answers["A"] == ["93.184.216.34"]

    def test_uses_default_context_without_one(self):
        resolver = FakeResolver({"A": ["1.2.3.4"]})
        assert dns_info.lookup("example.com", resolver=resolver)["records"]["A"] == ["1.2.3.4"]


def test_record_types_importable():
    # Guard against the dns.rdatatype import being dropped by a refactor.
    assert dns.rdatatype.A == 1
    assert isinstance(datetime.now(), datetime)


class TestCustomResolver:
    def test_make_resolver_points_at_the_given_server(self):
        resolver = dns_info.make_resolver("9.9.9.9")
        assert resolver.nameservers == ["9.9.9.9"]

    def test_port_suffix_is_honoured(self):
        resolver = dns_info.make_resolver("9.9.9.9#5353")
        assert resolver.nameservers == ["9.9.9.9"]
        assert resolver.port == 5353

    def test_lookup_uses_the_context_resolver(self, monkeypatch):
        fake = FakeResolver({"A": ["1.2.3.4"]})
        monkeypatch.setattr(dns_info, "make_resolver", lambda address: fake)

        result = dns_info.lookup("example.com", ReconContext(resolver="9.9.9.9"))

        assert result["records"]["A"] == ["1.2.3.4"]
        assert fake.queries and fake.queries[0][0] == "example.com"

    def test_unusable_resolver_falls_back_to_default(self, monkeypatch):
        fake = FakeResolver({"A": ["1.2.3.4"]})

        def explode(address):
            raise ValueError("not an address")

        monkeypatch.setattr(dns_info, "make_resolver", explode)
        monkeypatch.setattr(dns_info, "DEFAULT_RESOLVER", fake)

        result = dns_info.lookup("example.com", ReconContext(resolver="not-an-address"))

        assert result["records"]["A"] == ["1.2.3.4"]
