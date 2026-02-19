"""Tests for Trust Packet build, verify, verify_strict."""

import pytest

from unikey_tp import TrustPacket, KeyPair, configure, reset_configuration
from unikey_tp.errors import (
    InvalidPacket, ExpiredRequest, InvalidSignature, UntrustedSigner,
)
from unikey_tp.canonicalizer import canonicalize


kp = KeyPair.generate()
DOMAIN = "test.example.com"


def setup_function():
    reset_configuration()


def _build_test_packet(**overrides):
    return TrustPacket.build(
        subject=overrides.get("subject", "agent@user.example.com"),
        audience=overrides.get("audience", "orders@acme.com"),
        action=overrides.get("action", "purchase_item"),
        signing_key=overrides.get("signing_key", kp),
        signer_domain=overrides.get("signer_domain", DOMAIN),
        scope=overrides.get("scope", ["purchase:items"]),
        params=overrides.get("params", {"item": "blue purse", "callback_url": "https://device/cb/123"}),
        message=overrides.get("message", "Buy a blue purse."),
        ttl=overrides.get("ttl", 300),
        delegation_chain=overrides.get("delegation_chain"),
    )


# ── Build & serialize ────────────────────────────────────────

def test_build_signed_packet():
    pkt = _build_test_packet()
    assert pkt.header.version == "1.0"
    assert pkt.header.packet_type == "action_request"
    assert pkt.header.packet_id.startswith("pkt_")
    assert pkt.claims.subject == "agent@user.example.com"
    assert len(pkt.signatures) == 1
    assert pkt.signatures[0].algorithm == "ed25519"


def test_serialize_roundtrip():
    pkt = _build_test_packet()
    d = pkt.to_dict()
    restored = TrustPacket.from_dict(d)
    assert restored.header.packet_id == pkt.header.packet_id
    assert restored.claims.subject == pkt.claims.subject


def test_json_roundtrip():
    pkt = _build_test_packet()
    j = pkt.to_json(indent=2)
    restored = TrustPacket.from_json(j)
    assert restored.header.packet_id == pkt.header.packet_id


# ── verify (safe) ────────────────────────────────────────────

def test_verify_with_known_key():
    pkt = _build_test_packet()
    result = TrustPacket.verify(pkt.to_dict(), public_key_b64=kp.public_key_b64)
    assert result.valid is True
    assert result.subject == "agent@user.example.com"
    assert result.action == "purchase_item"
    assert result.callback_url == "https://device/cb/123"


def test_verify_fails_wrong_key():
    pkt = _build_test_packet()
    wrong = KeyPair.generate()
    result = TrustPacket.verify(pkt.to_dict(), public_key_b64=wrong.public_key_b64)
    assert result.valid is False
    assert result.error is not None


def test_verify_rejects_expired():
    pkt = _build_test_packet(ttl=-10)
    result = TrustPacket.verify(pkt.to_dict(), public_key_b64=kp.public_key_b64)
    assert result.valid is False
    assert "expired" in result.error.lower()


def test_verify_rejects_no_signatures():
    pkt = _build_test_packet()
    d = pkt.to_dict()
    d["signatures"] = []
    result = TrustPacket.verify(d, public_key_b64=kp.public_key_b64)
    assert result.valid is False


# ── verify_strict ────────────────────────────────────────────

def test_verify_strict_returns_result():
    pkt = _build_test_packet()
    result = TrustPacket.verify_strict(pkt.to_dict(), public_key_b64=kp.public_key_b64)
    assert result.valid is True
    assert result.subject == "agent@user.example.com"


def test_verify_strict_raises_expired():
    pkt = _build_test_packet(ttl=-10)
    with pytest.raises(ExpiredRequest):
        TrustPacket.verify_strict(pkt.to_dict(), public_key_b64=kp.public_key_b64)


def test_verify_strict_raises_invalid_signature():
    pkt = _build_test_packet()
    wrong = KeyPair.generate()
    with pytest.raises(InvalidSignature):
        TrustPacket.verify_strict(pkt.to_dict(), public_key_b64=wrong.public_key_b64)


def test_verify_strict_raises_invalid_packet():
    pkt = _build_test_packet()
    d = pkt.to_dict()
    d["signatures"] = []
    with pytest.raises(InvalidPacket):
        TrustPacket.verify_strict(d, public_key_b64=kp.public_key_b64)


# ── Trusted signers ──────────────────────────────────────────

def test_rejects_untrusted_signer():
    configure(trusted_signers=["trusted.com"])
    pkt = _build_test_packet()
    with pytest.raises(UntrustedSigner):
        TrustPacket.verify_strict(pkt.to_dict(), public_key_b64=kp.public_key_b64)


def test_allows_trusted_signer():
    configure(trusted_signers=[DOMAIN])
    pkt = _build_test_packet()
    result = TrustPacket.verify_strict(pkt.to_dict(), public_key_b64=kp.public_key_b64)
    assert result.valid is True


# ── Delegation chain ─────────────────────────────────────────

def test_delegation_chain_in_result():
    pkt = _build_test_packet(delegation_chain=["user@a.com -> agent@b.com"])
    result = TrustPacket.verify(pkt.to_dict(), public_key_b64=kp.public_key_b64)
    assert result.valid is True
    assert result.delegation_chain == ["user@a.com -> agent@b.com"]


def test_rejects_non_string_delegation_chain():
    pkt = _build_test_packet(delegation_chain=["valid-entry"])
    d = pkt.to_dict()
    d["claims"]["delegation_chain"] = [123]
    # Re-sign with tampered data
    unsigned = {"header": d["header"], "claims": d["claims"], "payload": d["payload"]}
    canonical = canonicalize(unsigned)
    d["signatures"][0]["signature"] = kp.sign_b64(canonical.encode())
    with pytest.raises(InvalidPacket):
        TrustPacket.verify_strict(d, public_key_b64=kp.public_key_b64)


# ── Other ────────────────────────────────────────────────────

def test_expired_property():
    pkt = _build_test_packet(ttl=-10)
    assert pkt.expired is True


def test_canonical_form_and_hash():
    pkt = _build_test_packet()
    canonical = pkt.canonical_form()
    assert canonical.startswith("{")
    assert "\n" not in canonical
    h = pkt.canonical_hash()
    assert len(h) == 44  # base64 SHA-256
