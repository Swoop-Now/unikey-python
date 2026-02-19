"""Ed25519 keypair management for Trust Packet signing."""

import base64
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder


class KeyPair:
    """Ed25519 keypair for signing and verifying Trust Packets."""

    def __init__(self, private_key_b64: str | None = None):
        if private_key_b64:
            key_bytes = base64.b64decode(private_key_b64)
            if len(key_bytes) == 64:
                self._signing_key = SigningKey(key_bytes[:32])
            elif len(key_bytes) == 32:
                self._signing_key = SigningKey(key_bytes)
            else:
                raise ValueError(f"Invalid key length: {len(key_bytes)} bytes")
        else:
            self._signing_key = SigningKey.generate()

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new random keypair."""
        return cls()

    @property
    def private_key_b64(self) -> str:
        return base64.b64encode(
            bytes(self._signing_key) + bytes(self._signing_key.verify_key)
        ).decode()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self._signing_key.verify_key)).decode()

    @property
    def verify_key(self) -> VerifyKey:
        return self._signing_key.verify_key

    def sign(self, message: bytes) -> bytes:
        """Sign message, return 64-byte Ed25519 signature."""
        signed = self._signing_key.sign(message, encoder=RawEncoder)
        return signed.signature

    def sign_b64(self, message: bytes) -> str:
        """Sign message, return base64-encoded signature."""
        return base64.b64encode(self.sign(message)).decode()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True or raises."""
        self.verify_key.verify(message, signature)
        return True

    def verify_b64(self, message: bytes, signature_b64: str) -> bool:
        """Verify a base64-encoded signature."""
        sig_bytes = base64.b64decode(signature_b64)
        return self.verify(message, sig_bytes)

    def dns_record(self, selector: str = "unikey") -> str:
        """Get the DNS TXT record value for this public key."""
        return f"v=DKIM1; k=ed25519; p={self.public_key_b64}"
