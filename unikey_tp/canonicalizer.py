"""RFC-001 §4 Canonicalization - deterministic packet serialization."""

import json
import hashlib
import base64


def sort_recursive(obj):
    """Recursively sort dict keys lexicographically."""
    if isinstance(obj, dict):
        return {k: sort_recursive(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_recursive(item) for item in obj]
    return obj


def canonicalize(data: dict) -> str:
    """
    Canonicalize a dict into deterministic JSON.

    Rules (RFC-001 §4.1):
    - Lexicographic key ordering (recursive)
    - UTF-8 encoding
    - No whitespace between tokens
    """
    sorted_data = sort_recursive(data)
    return json.dumps(sorted_data, separators=(",", ":"), ensure_ascii=False)


def compute_hash(data: dict) -> str:
    """SHA-256 hash of canonical form, base64 encoded."""
    canonical = canonicalize(data)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.b64encode(digest).decode()
