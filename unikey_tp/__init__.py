"""
UniKey Trust Packet Library - Python Implementation

Create, sign, verify, and parse RFC-001 Trust Packets.
Uses Ed25519 signatures with DNS-published public keys.

Usage:
    from unikey_tp import TrustPacket, KeyPair

    # Generate a keypair
    kp = KeyPair.generate()

    # Build and sign a packet
    packet = TrustPacket.build(
        subject="claude@user.example.com",
        audience="orders@acme-store.com",
        action="purchase_item",
        signing_key=kp,
        signer_domain="user.example.com",
    )

    # Verify a received packet
    result = TrustPacket.verify(packet.to_dict())

    # Verify a signed HTTP request
    result = verify_request(request_dict)
"""

from .packet import TrustPacket, VerifyResult
from .keypair import KeyPair
from .canonicalizer import canonicalize, compute_hash
from .dns import lookup_public_key, hardened_lookup
from .errors import (
    UniKeyError, InvalidSignature, ExpiredRequest, MissingHeaders,
    DNSLookupFailed, UntrustedSigner, InvalidPacket, DNSInconsistency,
)
from .configuration import Configuration, configure, get_configuration, reset_configuration
from .verifier import verify_request, verify_request_safe, VerifiedRequest

__all__ = [
    # Core
    "TrustPacket", "KeyPair", "VerifyResult",
    # Canonicalization
    "canonicalize", "compute_hash",
    # DNS
    "lookup_public_key", "hardened_lookup",
    # HTTP Request Verifier
    "verify_request", "verify_request_safe", "VerifiedRequest",
    # Configuration
    "Configuration", "configure", "get_configuration", "reset_configuration",
    # Errors
    "UniKeyError", "InvalidSignature", "ExpiredRequest", "MissingHeaders",
    "DNSLookupFailed", "UntrustedSigner", "InvalidPacket", "DNSInconsistency",
]
