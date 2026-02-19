"""Tests for UniKey configuration."""

from unikey_tp.configuration import (
    Configuration, configure, get_configuration, reset_configuration,
)


def setup_function():
    reset_configuration()


def test_defaults():
    config = get_configuration()
    assert config.dns_cache_ttl == 3600
    assert config.max_request_age == 300
    assert config.trusted_signers is None
    assert config.dns_hardening_enabled is False
    assert config.dns_resolvers is None
    assert config.dns_min_consistent == 2
    assert config.logger is None


def test_trusted_returns_true_when_no_whitelist():
    config = get_configuration()
    assert config.trusted("anything.com") is True


def test_trusted_checks_whitelist():
    config = get_configuration()
    config.trusted_signers = ["good.com", "also-good.com"]
    assert config.trusted("good.com") is True
    assert config.trusted("evil.com") is False


def test_configure_with_kwargs():
    configure(dns_cache_ttl=600, trusted_signers=["unikey.tech"])
    config = get_configuration()
    assert config.dns_cache_ttl == 600
    assert config.trusted_signers == ["unikey.tech"]


def test_configure_with_callback():
    configure(lambda c: setattr(c, "dns_cache_ttl", 42))
    assert get_configuration().dns_cache_ttl == 42


def test_reset_configuration():
    configure(dns_cache_ttl=1)
    reset_configuration()
    assert get_configuration().dns_cache_ttl == 3600
