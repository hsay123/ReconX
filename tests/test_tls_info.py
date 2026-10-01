"""Tests for :mod:`reconx.x509` and :mod:`reconx.tls_info`.

The DER parser is fed a real certificate captured from example.com (checked in
as a fixture), and the socket layer is faked, so nothing here touches the
network.
"""

from __future__ import annotations

import datetime as dt
import ssl
from pathlib import Path
from typing import Any

import pytest

from reconx import tls_info, x509

FIXTURES = Path(__file__).parent / "fixtures"
example_der_path = FIXTURES / "example.com.der"


@pytest.fixture(scope="session")
def example_der() -> bytes:
    if not example_der_path.exists():  # pragma: no cover - fixture must ship
        pytest.skip("missing DER fixture")
    return example_der_path.read_bytes()


class FakeSocket:
    """Context manager standing in for a connected socket."""

    def __init__(self, tls: Any) -> None:
        self._tls = tls

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def close(self) -> None:
        """No-op."""


class FakeTLS:
    """Stand-in for the object returned by ``wrap_socket``."""

    def __init__(self, der: bytes, version: str = "TLSv1.3", cipher: tuple | None = None):
        self._der = der
        self._version = version
        self._cipher = cipher or ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def __enter__(self) -> FakeTLS:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cipher(self) -> tuple:
        return self._cipher

    def version(self) -> str:
        return self._version

    def getpeercert(self, binary_form: bool = False) -> bytes:
        return self._der if binary_form else {}


def patch_socket(
    monkeypatch: pytest.MonkeyPatch,
    tls: Any,
    error: Exception | None = None,
    record: list[Any] | None = None,
) -> None:
    """Point ``socket.create_connection`` and ``wrap_socket`` at fakes.

    Args:
        monkeypatch: The active pytest monkeypatch.
        tls: The fake TLS object to hand back, or ``None`` when ``error`` is set.
        error: Exception the fake connection should raise instead.
        record: Optional list that receives the ``timeout`` passed to
            ``create_connection``, so a test can assert on it.
    """

    def create_connection(address, timeout=None):
        if record is not None:
            record.append(timeout)
        if error is not None:
            raise error
        return FakeSocket(tls)

    # Patched on the class, so `self` arrives as the first argument; the
    # wrapped fake replaces the socket that was just connected.
    def wrap_socket(self, sock, server_hostname=None, **kwargs):
        return tls

    monkeypatch.setattr(tls_info.socket, "create_connection", create_connection)
    monkeypatch.setattr(tls_info.ssl.SSLContext, "wrap_socket", wrap_socket)


class TestReadTlv:
    def test_short_form_length(self):
        # Returned as (tag, content_start, content, next_offset).
        tag, content_start, content, end = x509._read_tlv(b"\x04\x03abc", 0)
        assert (tag, content_start, content, end) == (0x04, 2, b"abc", 5)

    def test_long_form_length(self):
        body = b"x" * 200
        data = b"\x04\x81" + bytes([200]) + body
        tag, _start, content, end = x509._read_tlv(data, 0)
        assert tag == 0x04
        assert content == body
        assert end == len(data)

    def test_indefinite_length_rejected(self):
        with pytest.raises(ValueError, match="indefinite"):
            x509._read_tlv(b"\x30\x80\x00\x00", 0)

    def test_truncated_content_rejected(self):
        with pytest.raises(ValueError, match="truncated"):
            x509._read_tlv(b"\x04\x05abc", 0)

    def test_truncated_tag_rejected(self):
        with pytest.raises(ValueError, match="truncated"):
            x509._read_tlv(b"\x04", 0)

    def test_truncated_length_rejected(self):
        with pytest.raises(ValueError, match="truncated"):
            x509._read_tlv(b"\x04\x82\x01", 0)


class TestDecodeOid:
    def test_common_name(self):
        assert x509._decode_oid(bytes([0x55, 0x04, 0x03])) == "2.5.4.3"

    def test_multi_byte(self):
        # 1.2.840.113549 uses multi-byte base-128 components.
        assert (
            x509._decode_oid(bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01]))
            == "1.2.840.113549.1"
        )

    def test_empty_is_empty(self):
        assert x509._decode_oid(b"") == ""


class TestParseTime:
    def test_utc_time(self):
        parsed = x509.parse_time(b"260101000000Z")
        assert parsed == dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

    def test_generalized_time(self):
        assert x509.parse_time(b"20260101000000Z") == dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

    def test_two_digit_year_window(self):
        assert x509.parse_time(b"990101000000Z").year == 1999

    def test_unparseable_returns_none(self):
        assert x509.parse_time(b"not a time") is None

    def test_non_ascii_returns_none(self):
        assert x509.parse_time(b"\xff\xfe") is None


class TestParseCertificate:
    def test_not_a_certificate(self):
        with pytest.raises(ValueError, match="top level"):
            x509.parse_certificate(b"\x02\x01\x05")

    def test_truncated_certificate(self):
        with pytest.raises(ValueError, match="truncated"):
            x509.parse_certificate(b"\x30\x03\x02\x01\x05")

    def test_reads_real_certificate(self, example_der):
        cert = x509.parse_certificate(example_der)
        assert cert.subject.get("CN")
        assert cert.issuer
        assert cert.not_after is not None
        assert cert.not_before is not None
        assert cert.not_after > dt.datetime.now(dt.UTC)

    def test_real_certificate_has_sans(self, example_der):
        cert = x509.parse_certificate(example_der)
        assert cert.subject_alt_names
        assert any("example.com" in san for san in cert.subject_alt_names)

    def test_serial_is_hex(self, example_der):
        cert = x509.parse_certificate(example_der)
        assert cert.serial
        int(cert.serial, 16)  # parses as hexadecimal

    def test_version_is_one_based(self, example_der):
        assert x509.parse_certificate(example_der).version == 3

    def test_as_dict_exposes_every_field(self, example_der):
        fields = x509.parse_certificate(example_der).as_dict()
        assert set(fields) == set(x509.Certificate.__slots__)


def der(tag: int, content: bytes) -> bytes:
    """Build one DER tag-length-value triple.

    Hand-written DER is easy to get subtly wrong, so the structural tests
    construct their input with this helper instead of counting hex bytes.
    """
    assert len(content) < 0x80, "long-form lengths are covered separately"
    return bytes([tag, len(content)]) + content


class TestIterChildren:
    def test_walks_every_tlv(self):
        inner = der(0x02, b"\x01") + der(0x02, b"\x02")
        assert list(x509._iter_children(inner)) == [(0x02, b"\x01"), (0x02, b"\x02")]

    def test_empty_content_yields_nothing(self):
        assert list(x509._iter_children(b"")) == []

    def test_first_child(self):
        content = der(0x04, b"ab") + der(0x04, b"cd")
        assert x509._first_child(content) == b"ab"

    def test_first_child_of_empty_is_empty(self):
        assert x509._first_child(b"") == b""


class TestParseName:
    @staticmethod
    def attribute(oid: bytes, value_tag: int, value: bytes) -> bytes:
        """Build one AttributeTypeAndValue."""
        return der(0x06, oid) + der(value_tag, value)

    @staticmethod
    def name(*attributes: bytes) -> bytes:
        """Build a Name wrapping the given attributes in one RDN."""
        return der(0x30, b"".join(der(0x31, attribute) for attribute in attributes))

    def test_parses_common_name(self):
        encoded = self.name(self.attribute(b"\x55\x04\x03", 0x0C, b"example.com"))
        assert x509.parse_name(encoded) == {"CN": "example.com"}

    def test_unknown_oid_is_kept_numeric(self):
        # OID 1.2.3.4 (1.2 encoded as 0x2a, then 0x03, 0x04).
        encoded = self.name(self.attribute(b"\x2a\x03\x04", 0x0C, b"value"))
        assert x509.parse_name(encoded) == {"1.2.3.4": "value"}

    def test_printable_string_is_decoded(self):
        encoded = self.name(self.attribute(b"\x55\x04\x0a", 0x13, b"Example Org"))
        assert x509.parse_name(encoded) == {"O": "Example Org"}

    def test_unknown_string_type_still_decodes(self):
        # IA5String (0x16) and anything else fall back to utf-8 rather than
        # being dropped, so a name is never silently lost.
        encoded = self.name(self.attribute(b"\x55\x04\x03", 0x16, b"example.com"))
        assert x509.parse_name(encoded) == {"CN": "example.com"}

    def test_bmp_string_is_decoded_as_utf16(self):
        encoded = self.name(
            self.attribute(b"\x55\x04\x03", 0x1E, "exämple.com".encode("utf-16-be"))
        )
        assert x509.parse_name(encoded) == {"CN": "exämple.com"}

    def test_attribute_with_missing_value_is_skipped(self):
        encoded = der(0x30, der(0x31, der(0x02, b"\x05")))
        assert x509.parse_name(encoded) == {}

    def test_non_oid_first_element_is_skipped(self):
        # An INTEGER where the OID should be: there is nothing to decode, so
        # it is skipped rather than raising.
        encoded = der(0x30, der(0x31, der(0x02, b"\x05") + der(0x02, b"\x06")))
        assert x509.parse_name(encoded) == {}


class TestExtractSans:
    @staticmethod
    def extension(oid: bytes, octets: bytes) -> bytes:
        """Build one Extension."""
        return der(0x30, der(0x06, oid) + der(0x04, octets))

    def test_no_san_extension_returns_empty(self):
        assert x509._extract_sans(b"") == []

    def test_extension_with_missing_value_is_skipped(self):
        assert x509._extract_sans(der(0x30, der(0x02, b"\x05"))) == []

    def test_other_extensions_are_ignored(self):
        # 2.5.29.19 is basicConstraints, not subjectAltName.
        extensions = self.extension(b"\x55\x1d\x13", der(0x30, der(0x82, b"example.com")))
        assert x509._extract_sans(extensions) == []

    def test_reads_dns_entries(self):
        names = der(0x82, b"a.example.com") + der(0x82, b"b.example.com")
        octets = der(0x30, names)
        assert x509._extract_sans(self.extension(b"\x55\x1d\x11", octets)) == [
            "a.example.com",
            "b.example.com",
        ]

    def test_reads_entries_without_a_sequence_wrapper(self):
        # Some encoders omit the GeneralNames SEQUENCE header entirely.
        names = der(0x82, b"a.example.com")
        assert x509._extract_sans(self.extension(b"\x55\x1d\x11", names)) == ["a.example.com"]

    def test_reads_email_and_uri_entries(self):
        names = der(0x81, b"admin@example.com") + der(0x86, b"https://example.com/")
        octets = der(0x30, names)
        assert x509._extract_sans(self.extension(b"\x55\x1d\x11", octets)) == [
            "admin:example.com",
            "https://example.com/",
        ]

    def test_reads_ip_entries(self):
        names = der(0x87, bytes([93, 184, 216, 34]))
        octets = der(0x30, names)
        assert x509._extract_sans(self.extension(b"\x55\x1d\x11", octets)) == ["93.184.216.34"]

    def test_truncated_general_names_do_not_raise(self):
        # A SAN body that ends mid-TLV must yield what was readable.
        octets = der(0x30, der(0x82, b"a.example.com") + b"\x82\x0bshort")
        found = x509._extract_sans(self.extension(b"\x55\x1d\x11", octets))
        assert found == ["a.example.com"]

    def test_unreadable_octets_are_skipped(self):
        # An empty extnValue is malformed but must not raise out of the parser.
        assert x509._extract_sans(self.extension(b"\x55\x1d\x11", b"")) == []


class TestFormatIp:
    def test_ipv4(self):
        assert x509._format_ip(bytes([93, 184, 216, 34])) == "93.184.216.34"

    def test_ipv6(self):
        raw = bytes(range(16))
        formatted = x509._format_ip(raw)
        assert formatted.count(":") == 7

    def test_unknown_length(self):
        assert x509._format_ip(b"\x01\x02\x03") == "010203"


class TestParseCertificateReport:
    def test_reports_fields(self, example_der):
        result = tls_info.parse_certificate(example_der)
        assert result["subject_common_name"]
        assert isinstance(result["days_until_expiry"], int)
        assert result["expired"] is False
        assert result["san_count"] == len(result["subject_alt_names"])
        assert result["not_after"].startswith("20")

    def test_expired_certificate(self, example_der, monkeypatch):
        # "now" is moved past notAfter, so the same bytes read as expired.
        after = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
        monkeypatch.setattr(tls_info.dt, "datetime", _fixed_datetime(after))
        result = tls_info.parse_certificate(example_der)
        assert result["expired"] is True
        assert result["days_until_expiry"] < 0


def _fixed_datetime(frozen: dt.datetime):
    """Return a datetime class whose ``now()`` is always ``frozen``.

    ``parse_time`` builds real datetimes from certificate bytes; only the
    comparison against "now" needs to move.
    """

    class FrozenDatetime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen if tz else frozen.replace(tzinfo=None)

    return FrozenDatetime


class TestReadCertificate:
    def test_success(self, monkeypatch, example_der):
        tls = FakeTLS(example_der)
        patch_socket(monkeypatch, tls)
        result = tls_info.read_certificate("example.com", 443, 5.0)
        assert result["hostname"] == "example.com"
        assert result["port"] == 443
        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["subject_common_name"]

    def test_timeout_reported(self, monkeypatch):
        # socket.timeout is an alias of the builtin TimeoutError on 3.10+.
        patch_socket(monkeypatch, None, error=TimeoutError("timed out"))
        result = tls_info.read_certificate("example.com", 443, 3.0)
        assert "timed out" in result["error"]

    def test_connection_refused_reported(self, monkeypatch):
        patch_socket(monkeypatch, None, error=ConnectionRefusedError("refused"))
        assert "could not connect" in tls_info.read_certificate("example.com")["error"]

    def test_ssl_error_reported(self, monkeypatch):
        patch_socket(monkeypatch, None, error=ssl.SSLError("bad handshake"))
        assert "handshake" in tls_info.read_certificate("example.com")["error"]

    def test_no_certificate_reported(self, monkeypatch):
        patch_socket(monkeypatch, FakeTLS(b""))
        assert "no certificate" in tls_info.read_certificate("example.com")["error"]

    def test_unparseable_certificate_reported(self, monkeypatch):
        patch_socket(monkeypatch, FakeTLS(b"\x02\x01\x05"))
        assert "could not parse" in tls_info.read_certificate("example.com")["error"]

    def test_timeout_uses_socket_timeout_value(self, monkeypatch, example_der):
        seen: list[Any] = []
        patch_socket(monkeypatch, FakeTLS(example_der), record=seen)
        tls_info.read_certificate("example.com", 443, 7.5)
        assert seen == [7.5]


class TestLookup:
    def test_success_adds_no_warnings(self, monkeypatch, example_der):
        from reconx.context import ReconContext

        patch_socket(monkeypatch, FakeTLS(example_der))
        result = tls_info.lookup("example.com", ReconContext(timeout=5.0))
        assert result["warnings"] == []

    def test_expired_warns(self, monkeypatch, example_der):
        patch_socket(monkeypatch, FakeTLS(example_der))
        after = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
        monkeypatch.setattr(tls_info.dt, "datetime", _fixed_datetime(after))
        result = tls_info.lookup("example.com")
        assert any("expired" in warning for warning in result["warnings"])

    def test_expiring_soon_warns(self, monkeypatch, example_der):
        patch_socket(monkeypatch, FakeTLS(example_der))
        expiry = x509.parse_certificate(example_der).not_after
        monkeypatch.setattr(tls_info.dt, "datetime", _fixed_datetime(expiry - dt.timedelta(days=5)))
        result = tls_info.lookup("example.com")
        assert any("expires in" in warning for warning in result["warnings"])

    def test_missing_sans_warns(self, monkeypatch, example_der):
        patch_socket(monkeypatch, FakeTLS(example_der))
        monkeypatch.setattr(tls_info, "parse_certificate", lambda der: {"subject_alt_names": []})
        result = tls_info.lookup("example.com")
        assert any("no subject alternative names" in w for w in result["warnings"])

    def test_error_passes_through(self, monkeypatch):
        patch_socket(monkeypatch, None, error=ConnectionRefusedError("refused"))
        assert "could not connect" in tls_info.lookup("example.com")["error"]

    def test_unexpected_exception_is_contained(self, monkeypatch, example_der):
        patch_socket(monkeypatch, FakeTLS(example_der))

        def explode(der: bytes) -> dict[str, Any]:
            raise MemoryError("unexpected")

        monkeypatch.setattr(tls_info, "parse_certificate", explode)
        result = tls_info.lookup("example.com")
        assert "TLS inspection failed" in result["error"]

    def test_only_https_port_is_contacted(self, monkeypatch, example_der):
        seen: list[tuple] = []

        def create_connection(address, timeout=None):
            seen.append(address)
            return FakeSocket(FakeTLS(example_der))

        monkeypatch.setattr(tls_info.socket, "create_connection", create_connection)
        monkeypatch.setattr(
            tls_info.ssl.SSLContext,
            "wrap_socket",
            lambda self, s, server_hostname=None, **k: s,
        )
        tls_info.lookup("example.com")
        # Exactly one connection, always to 443. This is not a port scanner.
        assert seen == [("example.com", 443)]
        assert tls_info.DEFAULT_PORT == 443
