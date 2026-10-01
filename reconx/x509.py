"""A minimal DER/X.509 reader.

ReconX needs certificate fields even when the certificate does *not* validate —
an expired, self-signed or mismatched certificate is exactly the kind of finding
worth reporting. Python's ``getpeercert()`` returns nothing under
``CERT_NONE`` and raises under a verifying handshake, so the bytes are parsed
here directly.

Scope is deliberately narrow: enough of ASN.1 to walk a certificate's
structure and read the fields ReconX reports. It is not a general ASN.1
library, and it never verifies signatures or chains.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator

__all__ = ["Certificate", "parse_certificate", "parse_name", "parse_time"]

# ASN.1 universal tags.
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OBJECT_IDENTIFIER = 0x06
_TAG_UTF8_STRING = 0x0C
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_PRINTABLE_STRING = 0x13
_TAG_BMP_STRING = 0x1E
_TAG_IA5_STRING = 0x16
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18

# Context-specific tags inside TBSCertificate.
_TAG_VERSION = 0xA0  # [0] EXPLICIT version
_TAG_EXTENSIONS = 0xA3  # [3] EXPLICIT extensions

#: TBSCertificate SEQUENCE fields, in their fixed order. The signature
#: AlgorithmIdentifier comes first, then issuer, validity and subject, so they
#: are told apart by position rather than by tag (all three are plain
#: SEQUENCEs, and so are the algorithm and the public key info).
_SEQUENCE_FIELDS = ("algorithm", "issuer", "validity", "subject", "spki")

# GeneralName context tags inside subjectAltName.
_SAN_DNS = 0x82
_SAN_EMAIL = 0x81
_SAN_URI = 0x86
_SAN_IP = 0x87

#: Object identifier of the subjectAltName extension.
_OID_SUBJECT_ALT_NAME = "2.5.29.17"

#: Object identifier short names for attributes worth showing in full.
_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
}


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
    """Read one tag-length-value triple.

    The identifier octet is returned whole, so a high-tag-number form stays
    visible to callers instead of being silently truncated to one byte.

    Args:
        data: The buffer to read from.
        offset: Where to start reading.

    Returns:
        A ``(tag, content_start, content, next_offset)`` tuple. Raises
        ``ValueError`` when the buffer is truncated or the length is
        indefinite, which BER permits but DER forbids.
    """
    if offset + 2 > len(data):
        raise ValueError("truncated DER: incomplete tag")
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1

    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise ValueError("indefinite lengths are not valid DER")
        if offset + count > len(data):
            raise ValueError("truncated DER: incomplete length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first

    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER: content shorter than declared length")
    return tag, offset, data[offset:end], end


def _first_child(content: bytes) -> bytes:
    """Return the content of the first TLV inside ``content``."""
    for _tag, inner in _iter_children(content):
        return inner
    return b""


def _iter_children(content: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(tag, content)`` for each TLV inside ``content``."""
    offset = 0
    while offset < len(content):
        tag, _start, inner, offset = _read_tlv(content, offset)
        yield tag, inner


def _decode_oid(content: bytes) -> str:
    """Decode an OBJECT IDENTIFIER body into dotted decimal form."""
    if not content:
        return ""
    values = [content[0] // 40, content[0] % 40]
    current = 0
    for byte in content[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(current)
            current = 0
    return ".".join(str(value) for value in values)


def parse_time(content: bytes) -> dt.datetime | None:
    """Decode a UTCTime or GeneralizedTime body.

    Both encodings are tried in turn, because which one a certificate uses
    depends on the year it was issued rather than anything we control.

    Args:
        content: The value bytes.

    Returns:
        An aware UTC datetime, or ``None`` if the value is unparseable.
    """
    try:
        text = content.decode("ascii").strip()
    except UnicodeDecodeError:
        return None

    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return dt.datetime.strptime(text, fmt).replace(tzinfo=dt.UTC)
        except ValueError:
            continue
    return None


def parse_name(content: bytes) -> dict[str, str]:
    """Decode a Name (RDNSequence) into a mapping of attribute to value.

    Short names (``CN``, ``O``, ``OU``…) are used when the OID is recognised,
    otherwise the dotted OID, so nothing is silently dropped.

    Args:
        content: The Name's DER content.

    Returns:
        A mapping such as ``{"CN": "example.com", "O": "..."}``.
    """
    result: dict[str, str] = {}
    for _tag, rdn in _iter_children(content):
        for _attr_tag, attribute in _iter_children(rdn):
            parts = list(_iter_children(attribute))
            if len(parts) < 2:
                continue
            oid_tag, oid_body = parts[0]
            value_tag, value_body = parts[1]
            if oid_tag != _TAG_OBJECT_IDENTIFIER:
                continue
            oid = _decode_oid(oid_body)
            if value_tag == _TAG_BMP_STRING:
                value = value_body.decode("utf-16-be", errors="replace")
            elif value_tag == _TAG_UTF8_STRING:
                value = value_body.decode("utf-8", errors="replace")
            elif value_tag == _TAG_PRINTABLE_STRING:
                value = value_body.decode("ascii", errors="replace")
            else:
                value = value_body.decode("utf-8", errors="replace")
            result[_OID_NAMES.get(oid, oid)] = value
    return result


def _extract_sans(extensions: bytes) -> list[str]:
    """Pull DNS/IP/email/URI entries out of the subjectAltName extension."""
    sans: list[str] = []
    for _tag, extension in _iter_children(extensions):
        parts = list(_iter_children(extension))
        if len(parts) < 2:
            continue
        oid = _decode_oid(parts[0][1])
        if oid != _OID_SUBJECT_ALT_NAME:
            continue
        # The extnValue is an OCTET STRING wrapping a GeneralNames SEQUENCE;
        # some encoders add the SEQUENCE header, some omit it.
        octet = parts[1][1]
        try:
            first_tag, _start, first_body, _next = _read_tlv(octet, 0)
        except ValueError:
            # Malformed or empty extnValue: nothing readable, so no SANs.
            continue
        if first_tag == _TAG_SEQUENCE:
            octet = first_body
        offset = 0
        while offset < len(octet):
            try:
                tag, _start, body, offset = _read_tlv(octet, offset)
            except ValueError:
                # Trailing bytes that do not form a TLV; keep what parsed.
                break
            if tag == _SAN_DNS:
                sans.append(body.decode("ascii", errors="replace"))
            elif tag == _SAN_IP:
                sans.append(_format_ip(body))
            elif tag == _SAN_EMAIL:
                # rfc822Name; '@' reads more clearly as ':' in a report line.
                sans.append(body.decode("ascii", errors="replace").replace("@", ":"))
            elif tag == _SAN_URI:
                sans.append(body.decode("ascii", errors="replace"))
    return sans


def _format_ip(raw: bytes) -> str:
    """Format a SAN iPAddress octet string as a readable address."""
    if len(raw) == 4:
        return ".".join(str(byte) for byte in raw)
    if len(raw) == 16:
        groups = [raw[index : index + 2].hex() for index in range(0, 16, 2)]
        return ":".join(groups)
    return raw.hex()


class Certificate:
    """The subset of X.509 fields ReconX reports."""

    __slots__ = (
        "issuer",
        "not_after",
        "not_before",
        "serial",
        "signature_algorithm",
        "subject",
        "subject_alt_names",
        "version",
    )

    def __init__(self, **fields: object) -> None:
        """Populate each slot from the keyword arguments given."""
        for name in self.__slots__:
            setattr(self, name, fields.get(name))

    def as_dict(self) -> dict[str, object]:
        """Return the certificate as a plain JSON-safe dict."""
        return {name: getattr(self, name) for name in self.__slots__}


def parse_certificate(der: bytes) -> Certificate:
    """Parse a DER-encoded X.509 certificate.

    Args:
        der: The raw certificate bytes.

    Returns:
        A :class:`Certificate` with whichever fields could be read.

    Raises:
        ValueError: If the buffer is not a well-formed certificate.
    """
    tag, _start, body, _end = _read_tlv(der, 0)
    if tag != _TAG_SEQUENCE:
        raise ValueError("not a certificate: top level is not a SEQUENCE")

    parts = list(_iter_children(body))
    if len(parts) < 3:
        raise ValueError("truncated certificate: expected tbsCertificate, algorithm and signature")

    tbs = parts[0][1]

    version = 0
    subject: dict[str, str] = {}
    issuer: dict[str, str] = {}
    serial: str = ""
    not_before: dt.datetime | None = None
    not_after: dt.datetime | None = None
    sans: list[str] = []

    sequence_index = 0
    for index, (tag, inner) in enumerate(_iter_children(tbs)):
        if tag == _TAG_VERSION and index == 0:  # [0] EXPLICIT version
            version_fields = list(_iter_children(inner))
            if version_fields:
                version = int.from_bytes(version_fields[0][1], "big") + 1
        elif tag == _TAG_INTEGER and not serial:
            serial = format(int.from_bytes(inner, "big"), "x")
        elif tag == _TAG_SEQUENCE:
            field = (
                _SEQUENCE_FIELDS[sequence_index] if sequence_index < len(_SEQUENCE_FIELDS) else ""
            )
            sequence_index += 1
            if field == "issuer":
                issuer = parse_name(inner)
            elif field == "subject":
                subject = parse_name(inner)
            elif field == "validity":
                for time_tag, time_body in _iter_children(inner):
                    if time_tag not in (_TAG_UTC_TIME, _TAG_GENERALIZED_TIME):
                        continue
                    if not_before is None:
                        not_before = parse_time(time_body)
                    else:
                        not_after = parse_time(time_body)
        elif tag == _TAG_EXTENSIONS:
            sans = _extract_sans(_first_child(inner))

    return Certificate(
        version=version,
        serial=serial,
        issuer=issuer,
        subject=subject,
        subject_alt_names=sans,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm="",
    )
