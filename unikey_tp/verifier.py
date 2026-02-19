"""HTTP Request Verifier — verify signed requests with X-UniKey-* headers.

Matches Ruby gem's UniKey::Verifier. Accepts dict-like request objects.
"""

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from .configuration import get_configuration
from .errors import (
    InvalidSignature, ExpiredRequest, MissingHeaders,
    DNSLookupFailed, UntrustedSigner, UniKeyError,
)

REQUIRED_HEADERS = [
    "X-UniKey-Signature",
    "X-UniKey-Signer",
    "X-UniKey-Timestamp",
    "X-UniKey-Body-Hash",
    "X-Agent-Email",
]


@dataclass
class VerifiedRequest:
    """Result of a successful HTTP request verification."""
    signer: str
    agent_email: str
    timestamp: datetime


def verify_request(request: dict) -> VerifiedRequest:
    """
    Verify a signed HTTP request (strict — raises on failure).

    Args:
        request: dict with keys: headers (dict), body (str), method (str), url (str).
            Also accepts WSGI environ dicts (HTTP_X_UNIKEY_SIGNATURE style).

    Returns: VerifiedRequest with signer, agent_email, timestamp.
    Raises: MissingHeaders, ExpiredRequest, UntrustedSigner, InvalidSignature, DNSLookupFailed
    """
    headers = _normalize_headers(request.get("headers", request))
    body = request.get("body", "")

    # Check required headers
    missing = [h for h in REQUIRED_HEADERS if not headers.get(h)]
    if missing:
        raise MissingHeaders(missing)

    signature = headers["X-UniKey-Signature"]
    signer = headers["X-UniKey-Signer"]
    timestamp = int(headers["X-UniKey-Timestamp"])
    body_hash = headers["X-UniKey-Body-Hash"]
    agent_email = headers["X-Agent-Email"]

    # Check timestamp freshness
    config = get_configuration()
    if int(time.time()) - timestamp > config.max_request_age:
        raise ExpiredRequest()

    # Check trusted signers
    if not config.trusted(signer):
        raise UntrustedSigner(signer)

    # Verify body hash (constant-time comparison)
    actual_body_hash = _hash_body(body)
    if not hmac.compare_digest(body_hash, actual_body_hash):
        raise InvalidSignature("Body hash mismatch")

    # Get public key from DNS
    from .dns import lookup_public_key, hardened_lookup
    try:
        if config.dns_hardening_enabled:
            public_key_b64 = hardened_lookup(
                signer,
                resolvers=config.dns_resolvers,
                min_consistent=config.dns_min_consistent,
            )
        else:
            public_key_b64 = lookup_public_key(signer)
    except Exception:
        raise DNSLookupFailed(signer)

    # Build canonical string
    method = request.get("method", "POST").upper()
    url = request.get("url", "")
    canonical = "\n".join([method, url, body_hash, str(timestamp), agent_email])

    # Verify Ed25519 signature
    try:
        from nacl.signing import VerifyKey
        vk = VerifyKey(base64.b64decode(public_key_b64))
        sig_bytes = base64.b64decode(signature)
        vk.verify(canonical.encode(), sig_bytes)
    except Exception:
        raise InvalidSignature()

    return VerifiedRequest(
        signer=signer,
        agent_email=agent_email,
        timestamp=datetime.fromtimestamp(timestamp),
    )


def verify_request_safe(request: dict) -> Optional[VerifiedRequest]:
    """
    Verify a signed HTTP request (safe — returns None on failure).
    """
    try:
        return verify_request(request)
    except UniKeyError:
        return None


def _normalize_headers(headers: dict) -> dict:
    """Normalize headers from WSGI (HTTP_X_*) or direct (X-*) formats."""
    normalized = {}
    for key, value in headers.items():
        key_str = str(key)
        if key_str.startswith("HTTP_"):
            # WSGI format: HTTP_X_UNIKEY_SIGNATURE -> X-UniKey-Signature
            parts = key_str[5:].split("_")
            normalized_key = "-".join(p.capitalize() for p in parts)
            normalized_key = normalized_key.replace("Unikey", "UniKey")
        else:
            normalized_key = key_str
        normalized[normalized_key] = str(value)
    return normalized


def _hash_body(body: Any) -> str:
    """SHA-256 hash of body, base64 encoded."""
    if isinstance(body, bytes):
        body_bytes = body
    else:
        body_bytes = str(body).encode("utf-8")
    return base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
