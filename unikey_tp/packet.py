"""RFC-001 Trust Packet - create, sign, verify, parse."""

import time
import json
import secrets
import base64
from dataclasses import dataclass, asdict, field
from typing import Optional

from .canonicalizer import canonicalize, compute_hash
from .keypair import KeyPair


@dataclass
class Header:
    version: str = "1.0"
    packet_type: str = "action_request"
    packet_id: str = ""
    timestamp: int = 0
    expires: int = 0

    def __post_init__(self):
        if not self.packet_id:
            self.packet_id = f"pkt_{secrets.token_hex(16)}"
        if not self.timestamp:
            self.timestamp = int(time.time())
        if not self.expires:
            self.expires = self.timestamp + 300


@dataclass
class Claims:
    subject: str = ""
    issuer: str = ""
    audience: str = ""
    scope: list = field(default_factory=lambda: ["*"])
    delegation_chain: list = field(default_factory=list)


@dataclass
class Payload:
    action: str = ""
    params: dict = field(default_factory=dict)
    message: Optional[str] = None


@dataclass
class Signature:
    algorithm: str = "ed25519"
    signer: str = ""
    key_selector: str = "unikey"
    signature: str = ""
    signed_at: int = 0

    def __post_init__(self):
        if not self.signed_at:
            self.signed_at = int(time.time())


class TrustPacket:
    """RFC-001 Trust Packet."""

    def __init__(self, header: Header, claims: Claims, payload: Payload,
                 signatures: list[Signature] = None):
        self.header = header
        self.claims = claims
        self.payload = payload
        self.signatures = signatures or []

    @classmethod
    def build(cls, subject: str, audience: str, action: str,
              signing_key: KeyPair, signer_domain: str,
              scope: list = None, params: dict = None,
              message: str = None, packet_type: str = "action_request",
              delegation_chain: list = None, ttl: int = 300) -> "TrustPacket":
        """Build and sign a new Trust Packet."""
        now = int(time.time())

        header = Header(
            packet_type=packet_type,
            timestamp=now,
            expires=now + ttl,
        )
        claims = Claims(
            subject=subject,
            issuer=signer_domain,
            audience=audience,
            scope=scope or ["*"],
            delegation_chain=delegation_chain or [],
        )
        payload = Payload(
            action=action,
            params=params or {},
            message=message,
        )

        packet = cls(header=header, claims=claims, payload=payload)

        # Sign
        canonical = canonicalize(packet.unsigned_dict())
        sig_value = signing_key.sign_b64(canonical.encode())

        signature = Signature(
            signer=signer_domain,
            signature=sig_value,
            signed_at=now,
        )
        packet.signatures = [signature]
        return packet

    @classmethod
    def from_dict(cls, data: dict) -> "TrustPacket":
        """Parse from a dict (e.g., from JSON)."""
        header = Header(**data["header"])
        claims = Claims(**data["claims"])
        payload = Payload(**data["payload"])
        signatures = [Signature(**s) for s in data.get("signatures", [])]
        return cls(header=header, claims=claims, payload=payload, signatures=signatures)

    @classmethod
    def from_json(cls, json_string: str) -> "TrustPacket":
        """Parse from JSON string."""
        return cls.from_dict(json.loads(json_string))

    @classmethod
    def verify(cls, packet_data: dict, public_key_b64: str = None,
               dns_lookup: bool = True, hardened: bool = False) -> "VerifyResult":
        """
        Verify a Trust Packet.

        Args:
            packet_data: the full packet dict
            public_key_b64: provide key directly (skip DNS)
            dns_lookup: look up key from DNS (default True)
            hardened: use RFC-002 multi-resolver (default False)

        Returns: VerifyResult with .valid, .subject, .action, etc.
        """
        try:
            return cls._do_verify(packet_data, public_key_b64, dns_lookup, hardened)
        except Exception as e:
            return VerifyResult(valid=False, error=str(e))

    @classmethod
    def _do_verify(cls, data: dict, public_key_b64: str, dns_lookup: bool, hardened: bool):
        # Validate structure
        for field_name in ("header", "claims", "payload", "signatures"):
            if field_name not in data:
                raise ValueError(f"Missing field: {field_name}")

        if not data["signatures"]:
            raise ValueError("No signatures")

        header = data["header"]
        claims_data = data["claims"]
        payload_data = data["payload"]

        # Check expiration
        expires = header.get("expires", 0)
        if expires and int(time.time()) > expires:
            raise ValueError("Packet expired")

        # Build unsigned portion and canonicalize
        unsigned = {"header": header, "claims": claims_data, "payload": payload_data}
        canonical = canonicalize(unsigned)

        # Verify each signature
        for sig in data["signatures"]:
            signer_domain = sig.get("signer", "")
            signature_b64 = sig.get("signature", "")

            # Get public key
            if public_key_b64:
                pk = public_key_b64
            elif dns_lookup:
                from .dns import lookup_public_key, hardened_lookup
                if hardened:
                    pk = hardened_lookup(signer_domain)
                else:
                    pk = lookup_public_key(signer_domain)
            else:
                raise ValueError("No public key and dns_lookup disabled")

            # Verify
            from nacl.signing import VerifyKey
            vk = VerifyKey(base64.b64decode(pk))
            sig_bytes = base64.b64decode(signature_b64)
            vk.verify(canonical.encode(), sig_bytes)

        return VerifyResult(
            valid=True,
            packet_id=header.get("packet_id"),
            packet_type=header.get("packet_type"),
            subject=claims_data.get("subject"),
            issuer=claims_data.get("issuer"),
            audience=claims_data.get("audience"),
            scope=claims_data.get("scope", []),
            action=payload_data.get("action"),
            params=payload_data.get("params", {}),
            message=payload_data.get("message"),
            callback_url=payload_data.get("params", {}).get("callback_url"),
            signer=data["signatures"][0].get("signer"),
            delegation_chain=claims_data.get("delegation_chain", []),
        )

    def unsigned_dict(self) -> dict:
        """The unsigned portion for signing/verification."""
        return {
            "header": asdict(self.header),
            "claims": asdict(self.claims),
            "payload": asdict(self.payload),
        }

    def to_dict(self) -> dict:
        return {
            "header": asdict(self.header),
            "claims": asdict(self.claims),
            "payload": asdict(self.payload),
            "signatures": [asdict(s) for s in self.signatures],
        }

    def to_json(self, indent: int = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def canonical_form(self) -> str:
        return canonicalize(self.unsigned_dict())

    def canonical_hash(self) -> str:
        return compute_hash(self.unsigned_dict())

    @property
    def expired(self) -> bool:
        return self.header.expires > 0 and int(time.time()) > self.header.expires


@dataclass
class VerifyResult:
    valid: bool = False
    error: str = None
    packet_id: str = None
    packet_type: str = None
    subject: str = None
    issuer: str = None
    audience: str = None
    scope: list = field(default_factory=list)
    action: str = None
    params: dict = field(default_factory=dict)
    message: str = None
    callback_url: str = None
    signer: str = None
    delegation_chain: list = field(default_factory=list)
