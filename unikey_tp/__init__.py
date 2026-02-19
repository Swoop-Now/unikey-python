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
        scope=["purchase:items", "spend:150"],
        params={"item": "blue purse", "callback_url": "https://device/cb/123"},
        message="Please purchase a blue purse for my girlfriend.",
        signing_key=kp,
        signer_domain="user.example.com",
    )

    # Verify a received packet
    result = TrustPacket.verify(packet.to_dict())
"""

from .packet import TrustPacket
from .keypair import KeyPair
from .canonicalizer import canonicalize, compute_hash
from .dns import lookup_public_key, hardened_lookup

__all__ = [
    "TrustPacket",
    "KeyPair",
    "canonicalize",
    "compute_hash",
    "lookup_public_key",
    "hardened_lookup",
]
