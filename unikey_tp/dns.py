"""DNS-based public key lookup for Trust Packet verification."""

import re
import base64
import time
import threading
from typing import Optional
import dns.resolver


# Simple TTL cache
_cache: dict[str, tuple[str, float]] = {}
_cache_lock = threading.Lock()
_cache_ttl = 3600  # 1 hour default

# RFC-002 default resolvers
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def configure(cache_ttl: int = 3600):
    """Configure DNS settings."""
    global _cache_ttl
    _cache_ttl = cache_ttl


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
                    _cache[cache_key] = (key, time.time() + _cache_ttl)
                return key
    except Exception:
        pass

    raise DNSLookupError(f"Failed to lookup public key for {signer_domain}")


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
    Raises: DNSLookupError if lookup fails or resolvers disagree
    """
    cache_key = f"hardened.{selector}.{signer_domain}"

    with _cache_lock:
        if cache_key in _cache:
            value, expires = _cache[cache_key]
            if time.time() < expires:
                return value

    resolvers = resolvers or DEFAULT_RESOLVERS
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
        raise DNSLookupError(f"All resolvers failed for {signer_domain}")

    # Check consistency
    key_counts: dict[str, int] = {}
    for key in results.values():
        key_counts[key] = key_counts.get(key, 0) + 1

    best_key = max(key_counts, key=key_counts.get)
    agreement = key_counts[best_key]

    if agreement < min_consistent:
        raise DNSInconsistencyError(
            f"DNS inconsistency for {signer_domain}: "
            f"only {agreement}/{len(results)} resolvers agree (need {min_consistent})"
        )

    with _cache_lock:
        _cache[cache_key] = (best_key, time.time() + _cache_ttl)

    return best_key


def _parse_dkim_record(txt: str) -> Optional[str]:
    """Parse public key from DKIM-style TXT record."""
    match = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
    return match.group(1) if match else None


class DNSLookupError(Exception):
    pass


class DNSInconsistencyError(DNSLookupError):
    pass
