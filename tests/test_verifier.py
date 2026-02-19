"""Tests for HTTP Request Verifier."""

import base64
import hashlib
import time
from unittest.mock import patch

from unikey_tp import KeyPair, configure, reset_configuration
from unikey_tp.verifier import verify_request, verify_request_safe
from unikey_tp.errors import (
    InvalidSignature, ExpiredRequest, MissingHeaders, UntrustedSigner,
)


kp = KeyPair.generate()


def setup_function():
    reset_configuration()


def _build_signed_request(**overrides):
    method = overrides.get("method", "POST")
    url = overrides.get("url", "https://example.com/api/action")
    body = overrides.get("body", '{"action":"test"}')
    timestamp = overrides.get("timestamp", int(time.time()))
    agent_email = overrides.get("agent_email", "agent@test.com")

    body_hash = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
    canonical = "\n".join([method, url, body_hash, str(timestamp), agent_email])
    signature = kp.sign_b64(canonical.encode())

    return {
        "method": method,
        "url": url,
        "body": body,
        "headers": {
            "X-UniKey-Signature": overrides.get("signature", signature),
            "X-UniKey-Signer": overrides.get("signer", "test.example.com"),
            "X-UniKey-Timestamp": str(timestamp),
            "X-UniKey-Body-Hash": overrides.get("body_hash", body_hash),
            "X-Agent-Email": agent_email,
        },
    }


@patch("unikey_tp.dns.lookup_public_key")
def test_verifies_valid_request(mock_dns):
    mock_dns.return_value = kp.public_key_b64
    req = _build_signed_request()
    result = verify_request(req)
    assert result.signer == "test.example.com"
    assert result.agent_email == "agent@test.com"


def test_missing_headers():
    req = {"method": "POST", "url": "/", "body": "", "headers": {}}
    try:
        verify_request(req)
        assert False, "Should have raised"
    except MissingHeaders as e:
        assert len(e.missing) == 5


@patch("unikey_tp.dns.lookup_public_key")
def test_expired_timestamp(mock_dns):
    mock_dns.return_value = kp.public_key_b64
    req = _build_signed_request(timestamp=int(time.time()) - 600)
    try:
        verify_request(req)
        assert False, "Should have raised"
    except ExpiredRequest:
        pass


@patch("unikey_tp.dns.lookup_public_key")
def test_untrusted_signer(mock_dns):
    mock_dns.return_value = kp.public_key_b64
    configure(trusted_signers=["trusted.com"])
    req = _build_signed_request()
    try:
        verify_request(req)
        assert False, "Should have raised"
    except UntrustedSigner:
        pass


@patch("unikey_tp.dns.lookup_public_key")
def test_tampered_body(mock_dns):
    mock_dns.return_value = kp.public_key_b64
    req = _build_signed_request()
    req["body"] = '{"action":"tampered"}'
    try:
        verify_request(req)
        assert False, "Should have raised"
    except InvalidSignature:
        pass


@patch("unikey_tp.dns.lookup_public_key")
def test_wrong_key(mock_dns):
    wrong_key = KeyPair.generate()
    mock_dns.return_value = wrong_key.public_key_b64
    req = _build_signed_request()
    try:
        verify_request(req)
        assert False, "Should have raised"
    except InvalidSignature:
        pass


def test_verify_request_safe_returns_none():
    req = {"method": "POST", "url": "/", "body": "", "headers": {}}
    result = verify_request_safe(req)
    assert result is None


@patch("unikey_tp.dns.lookup_public_key")
def test_verify_request_safe_returns_result(mock_dns):
    mock_dns.return_value = kp.public_key_b64
    req = _build_signed_request()
    result = verify_request_safe(req)
    assert result is not None
    assert result.signer == "test.example.com"
