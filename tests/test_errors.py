"""Tests for UniKey error classes."""

from unikey_tp.errors import (
    UniKeyError, InvalidSignature, ExpiredRequest, MissingHeaders,
    DNSLookupFailed, UntrustedSigner, InvalidPacket, DNSInconsistency,
)


def test_all_inherit_from_unikey_error():
    assert issubclass(InvalidSignature, UniKeyError)
    assert issubclass(ExpiredRequest, UniKeyError)
    assert issubclass(MissingHeaders, UniKeyError)
    assert issubclass(DNSLookupFailed, UniKeyError)
    assert issubclass(UntrustedSigner, UniKeyError)
    assert issubclass(InvalidPacket, UniKeyError)
    assert issubclass(DNSInconsistency, UniKeyError)


def test_invalid_signature_default_message():
    err = InvalidSignature()
    assert str(err) == "Invalid UniKey signature"


def test_expired_request_default_message():
    err = ExpiredRequest()
    assert str(err) == "Request has expired"


def test_missing_headers_stores_list():
    err = MissingHeaders(["X-UniKey-Signature", "X-Agent-Email"])
    assert err.missing == ["X-UniKey-Signature", "X-Agent-Email"]
    assert "X-UniKey-Signature" in str(err)


def test_dns_lookup_failed_stores_domain():
    err = DNSLookupFailed("example.com")
    assert err.domain == "example.com"
    assert "example.com" in str(err)


def test_untrusted_signer_stores_signer():
    err = UntrustedSigner("evil.com")
    assert err.signer == "evil.com"
    assert "evil.com" in str(err)


def test_invalid_packet_stores_reason():
    err = InvalidPacket("Missing field: header")
    assert err.reason == "Missing field: header"


def test_dns_inconsistency_stores_details():
    err = DNSInconsistency("example.com", expected=2, got=1, total=3)
    assert err.domain == "example.com"
    assert err.expected == 2
    assert err.got == 1
    assert err.total == 3
    assert "1/3" in str(err)
