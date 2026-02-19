"""UniKey error classes — matches Ruby gem error hierarchy."""


class UniKeyError(Exception):
    """Base error for all UniKey errors."""
    pass


class InvalidSignature(UniKeyError):
    """Raised when Ed25519 signature verification fails."""
    def __init__(self, message="Invalid UniKey signature"):
        super().__init__(message)


class ExpiredRequest(UniKeyError):
    """Raised when request or packet has expired (replay prevention)."""
    def __init__(self, message="Request has expired"):
        super().__init__(message)


class MissingHeaders(UniKeyError):
    """Raised when required HTTP headers are missing."""
    def __init__(self, missing: list):
        self.missing = missing
        super().__init__(f"Missing required headers: {', '.join(missing)}")


class DNSLookupFailed(UniKeyError):
    """Raised when DNS TXT record lookup fails."""
    def __init__(self, domain: str):
        self.domain = domain
        super().__init__(f"Failed to lookup public key for {domain}")


class UntrustedSigner(UniKeyError):
    """Raised when signer domain is not in trusted_signers list."""
    def __init__(self, signer: str):
        self.signer = signer
        super().__init__(f"Signer '{signer}' is not trusted")


class InvalidPacket(UniKeyError):
    """Raised when a Trust Packet has invalid structure."""
    def __init__(self, reason: str = "Invalid trust packet"):
        self.reason = reason
        super().__init__(reason)


class DNSInconsistency(UniKeyError):
    """Raised when RFC-002 hardened DNS resolvers disagree."""
    def __init__(self, domain: str, *, expected: int, got: int, total: int):
        self.domain = domain
        self.expected = expected
        self.got = got
        self.total = total
        super().__init__(
            f"DNS inconsistency for {domain}: "
            f"only {got}/{total} resolvers agree (need {expected})"
        )
