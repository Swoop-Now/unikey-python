"""Global configuration for UniKey — matches Ruby gem Configuration class."""

from typing import Optional


class Configuration:
    """UniKey configuration singleton."""

    def __init__(self):
        self.dns_cache_ttl: int = 3600
        self.max_request_age: int = 300
        self.trusted_signers: Optional[list] = None
        self.dns_hardening_enabled: bool = False
        self.dns_resolvers: Optional[list] = None
        self.dns_min_consistent: int = 2
        self.logger = None

    def trusted(self, signer_domain: str) -> bool:
        """Check if a signer domain is trusted. Returns True if no whitelist configured."""
        if self.trusted_signers is None:
            return True
        return signer_domain in self.trusted_signers


_configuration = Configuration()


def get_configuration() -> Configuration:
    """Get the global configuration."""
    return _configuration


def configure(fn=None, **kwargs):
    """Configure UniKey settings.

    Usage:
        configure(dns_cache_ttl=600, trusted_signers=["unikey.tech"])
        configure(lambda c: setattr(c, 'dns_cache_ttl', 600))
    """
    if fn is not None:
        fn(_configuration)
    for key, value in kwargs.items():
        if hasattr(_configuration, key):
            setattr(_configuration, key, value)


def reset_configuration():
    """Reset configuration to defaults (useful for tests)."""
    global _configuration
    _configuration = Configuration()
