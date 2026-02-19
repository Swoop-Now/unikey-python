"""DNS-based public key lookup for Trust Packet verification."""

import re
import time
import threading
from typing import Optional
import dns.resolver

from .errors import DNSLookupFailed, DNSInconsistency
from .configuration import get_configuration

# Backward-compatible aliases
DNSLookupError = DNSLookupFailed
DNSInconsistencyError = DNSInconsistency

# Simple TTL cache
_cache: dict[str, tuple[str, float]] = {}
_cache_lock = threading.Lock()

# RFC-002 default resolvers
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def configure(cache_ttl: int = 3600):
    """Configure DNS settings (writes to global configuration)."""
    get_configuration().dns_cache_ttl = cache_ttl


def clear_cache():
    """Clear the DNS cache."""
    global _cache
    with _cache_lock:
        _cache.clear()


def lookup_public_key(signer_domain: str, selector: str = "unikey") -> str:
    """
    Look up a signer's public key from DNS.

    Queries: {selector}._domainkey.{signer_domain} TXT record
    Returns: base64-encoded public key
    """
    config = get_configuration()
    cache_key = f"{selector}.{signer_domain}"

    with _cache_lock:
        if cache_key in _cache:
            value, expires = _cache[cache_key]
            if time.time() < expires:
                return value

    dns_name = f"{selector}._domainkey.{signer_domain}"

    try:
        answers = dns.resolver.resolve(dns_name, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            key = _parse_dkim_record(txt)
            if key:
                with _cache_lock:
                    _cache[cache_key] = (key, time.time() + config.dns_cache_ttl)
                return key
    except Exception:
        pass

    raise DNSLookupFailed(signer_domain)


def hardened_lookup(
    signer_domain: str,
    selector: str = "unikey",
    resolvers: list[str] | None = None,
    min_consistent: int = 2,
) -> str:
    """
    RFC-002 hardened DNS lookup - queries multiple resolvers and requires consistency.

    Args:
        signer_domain: domain to look up
        selector: DKIM selector (default: "unikey")
        resolvers: list of DNS resolver IPs (default: Google, Cloudflare, Quad9)
        min_consistent: minimum resolvers that must agree

    Returns: base64-encoded public key
    Raises: DNSLookupFailed if lookup fails, DNSInconsistency if resolvers disagree
    """
    config = get_configuration()
    cache_key = f"hardened.{selector}.{signer_domain}"

    with _cache_lock:
        if cache_key in _cache:
            value, expires = _cache[cache_key]
            if time.time() < expires:
                return value

    resolvers = resolvers or config.dns_resolvers or DEFAULT_RESOLVERS
    dns_name = f"{selector}._domainkey.{signer_domain}"

    results = {}
    for resolver_ip in resolvers:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.lifetime = 3  # 3 second timeout
            answers = r.resolve(dns_name, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                key = _parse_dkim_record(txt)
                if key:
                    results[resolver_ip] = key
                    break
        except Exception:
            continue

    if not results:
        raise DNSLookupFailed(signer_domain)

    # Check consistency
    key_counts: dict[str, int] = {}
    for key in results.values():
        key_counts[key] = key_counts.get(key, 0) + 1

    best_key = max(key_counts, key=key_counts.get)
    agreement = key_counts[best_key]

    if agreement < min_consistent:
        raise DNSInconsistency(
            signer_domain,
            expected=min_consistent,
            got=agreement,
            total=len(results),
        )

    with _cache_lock:
        _cache[cache_key] = (best_key, time.time() + config.dns_cache_ttl)

    return best_key


def _parse_dkim_record(txt: str) -> Optional[str]:
    """Parse public key from DKIM-style TXT record."""
    match = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
    return match.group(1) if match else None
