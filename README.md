# unikey-tp

Trust Packet library for Python. Create, sign, verify, and send [Trust Packets](https://unikey.tech) using Ed25519 signatures with DNS-published public keys.

**UniKey is a Universal Trust Primitive for AI Agents** — it lets agents cryptographically prove their identity to any service, without shared secrets, API keys, or passwords. Public keys live in DNS (the same infrastructure that secures email via DKIM), so verification is fully decentralized.

This library is the **sender side**. Use it to build and sign Trust Packets from your agent, device, or service. The receiving service verifies the signature by looking up your public key from DNS — no pre-registration needed.

## Installation

```bash
pip install unikey-tp
```

Or from source:

```bash
pip install -e .
```

**Requirements:** Python >= 3.10 | **Dependencies:** `pynacl`, `dnspython`

## Quick Start

### 1. Generate a Keypair and Publish to DNS

```python
from unikey_tp import KeyPair

kp = KeyPair.generate()

# Save the private key securely
print(kp.private_key_b64)  # keep this secret

# Publish this as a DNS TXT record:
#   unikey._domainkey.yourdomain.com  TXT  "v=DKIM1; k=ed25519; p=<public_key>"
print(kp.dns_record())  # "v=DKIM1; k=ed25519; p=ABC123..."
```

### 2. Build and Sign a Trust Packet

```python
from unikey_tp import TrustPacket, KeyPair

kp = KeyPair(private_key_b64="<your saved private key>")

packet = TrustPacket.build(
    subject="isaiah.baca@gmail.com",        # who is making the request
    audience="login@yourservice.com",       # who should receive it
    action="login",                          # what you want done
    scope=["auth:login"],                    # permissions requested
    params={
        "callback_url": "https://mydevice/callback",
        "session_duration": 3600,
    },
    message="Please log me into my account.",
    signing_key=kp,
    signer_domain="gmail.com",               # domain where public key is in DNS
)

# Send it — via email, HTTP POST, or any transport
print(packet.to_json())
```

### 3. Send It

Trust Packets are transport-agnostic. Send them however you want:

```python
import urllib.request, json

# Option A: HTTP POST (direct)
req = urllib.request.Request(
    "https://yourservice.com/agent/inbound",
    data=packet.to_json().encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
urllib.request.urlopen(req)

# Option B: Email (SMTP)
# Put packet.to_json() in the email body, send to the audience address.
# Gmail/Outlook will DKIM-sign it, adding another layer of verification.
```

### 4. Verify a Received Packet

```python
from unikey_tp import TrustPacket

result = TrustPacket.verify(packet_data)

if result.valid:
    print(result.subject)       # "isaiah.baca@gmail.com"
    print(result.action)        # "login"
    print(result.params)        # {"callback_url": "...", "session_duration": 3600}
    print(result.signer)        # "gmail.com"
    print(result.callback_url)  # "https://mydevice/callback"
else:
    print(result.error)         # "Signature verification failed"
```

## What Is a Trust Packet?

A Trust Packet is a self-contained, cryptographically signed JSON container. It bundles identity, intent, and proof into one structure:

```json
{
  "header": {
    "version": "1.0",
    "packet_type": "action_request",
    "packet_id": "pkt_abc123",
    "timestamp": 1736784000,
    "expires": 1736784300
  },
  "claims": {
    "subject": "isaiah.baca@gmail.com",
    "issuer": "gmail.com",
    "audience": "login@yourservice.com",
    "scope": ["auth:login"],
    "delegation_chain": []
  },
  "payload": {
    "action": "login",
    "params": { "callback_url": "https://device/cb/123", "session_duration": 3600 },
    "message": "Please log me into my account."
  },
  "signatures": [{
    "algorithm": "ed25519",
    "signer": "gmail.com",
    "key_selector": "unikey",
    "signature": "<base64 Ed25519 signature>",
    "signed_at": 1736784000
  }]
}
```

The verifier checks the signature by looking up `unikey._domainkey.gmail.com` in DNS — no shared secrets, no pre-registration.

## API Reference

### KeyPair

Manage Ed25519 signing keys.

```python
from unikey_tp import KeyPair

# Generate a new keypair
kp = KeyPair.generate()

# Load from a saved private key
kp = KeyPair(private_key_b64="<base64 private key>")

# Properties
kp.public_key_b64    # base64 public key (share this / publish to DNS)
kp.private_key_b64   # base64 private key (keep secret!)
kp.verify_key        # NaCl VerifyKey object

# Sign
sig = kp.sign(b"message")            # 64-byte Ed25519 signature
sig_b64 = kp.sign_b64(b"message")    # base64-encoded signature

# Verify
kp.verify(b"message", sig)           # True or raises
kp.verify_b64(b"message", sig_b64)   # True or raises

# DNS record content for your domain's TXT record
kp.dns_record()            # "v=DKIM1; k=ed25519; p=<public_key>"
kp.dns_record("custom")    # custom selector instead of "unikey"
```

### TrustPacket

Build, sign, parse, and verify Trust Packets.

#### Building

```python
packet = TrustPacket.build(
    subject="agent@example.com",       # who is making the request
    audience="service@target.com",     # who should receive it
    action="do_something",             # what action to perform
    signing_key=kp,                    # KeyPair instance
    signer_domain="example.com",       # domain with public key in DNS
    scope=["read", "write"],           # permissions (default: ["*"])
    params={"key": "value"},           # action parameters (optional)
    message="Human-readable note",     # optional message
    packet_type="action_request",      # packet type (default)
    delegation_chain=None,             # delegation chain (optional)
    ttl=300,                           # seconds until expiration (default: 300)
)
```

#### Serialization

```python
packet.to_dict()            # full packet as dict (includes signatures)
packet.to_json()            # compact JSON string
packet.to_json(indent=2)    # pretty-printed JSON
packet.unsigned_dict()      # header + claims + payload only (no signatures)
packet.canonical_form()     # deterministic JSON used for signing
packet.canonical_hash()     # SHA-256 of canonical form (base64)
packet.expired              # True if packet has expired
```

#### Parsing

```python
packet = TrustPacket.from_dict(data)        # from dict
packet = TrustPacket.from_json(json_str)    # from JSON string
```

#### Verification

```python
# Standard: looks up public key from DNS
result = TrustPacket.verify(packet_dict)

# With hardened DNS (RFC-002, multi-resolver consensus)
result = TrustPacket.verify(packet_dict, hardened=True)

# With a known public key (skip DNS lookup)
result = TrustPacket.verify(packet_dict, public_key_b64="<key>", dns_lookup=False)
```

The `VerifyResult` object (never raises — check `.valid`):

| Field | Description |
|-------|-------------|
| `result.valid` | `True` if signature verified |
| `result.error` | Error message if invalid, else `None` |
| `result.packet_id` | Unique packet ID |
| `result.packet_type` | `"action_request"` or `"action_response"` |
| `result.subject` | Who made the request (email) |
| `result.issuer` | Domain that vouches for the subject |
| `result.audience` | Intended recipient |
| `result.scope` | Permission list |
| `result.action` | Requested action name |
| `result.params` | Action parameters dict |
| `result.message` | Human-readable message |
| `result.callback_url` | Extracted from params (if present) |
| `result.signer` | Domain that signed the packet |
| `result.delegation_chain` | Delegation chain (if delegated) |

### DNS Lookup

Look up Ed25519 public keys from DNS TXT records.

```python
from unikey_tp import lookup_public_key, hardened_lookup

# Standard: queries unikey._domainkey.example.com
key = lookup_public_key("example.com")
key = lookup_public_key("example.com", selector="custom")

# RFC-002 hardened: queries 3 resolvers, requires 2 to agree
key = hardened_lookup("example.com")
key = hardened_lookup(
    "example.com",
    resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    min_consistent=2,
)
```

Configure caching:

```python
from unikey_tp.dns import configure, clear_cache

configure(cache_ttl=3600)  # cache DNS lookups for 1 hour (default)
clear_cache()              # purge cached lookups
```

### Canonicalization

Trust Packets use deterministic JSON canonicalization so that the same packet always produces the same bytes for signing, regardless of key ordering.

```python
from unikey_tp import canonicalize, compute_hash

canonicalize({"z": 1, "a": 2})  # '{"a":2,"z":1}'
compute_hash({"z": 1, "a": 2})  # base64 SHA-256 of canonical form
```

Rules (RFC-001 Section 4):
- Keys sorted lexicographically (recursive)
- UTF-8 encoding
- No whitespace between tokens

## Cross-Language Compatibility

Trust Packets are designed to work across languages. The canonicalization rules ensure that a packet signed in Python produces the exact same bytes as one signed in Ruby, Go, or any other implementation.

Tested flow: **Python signs, Ruby verifies** (and vice versa).

```python
# Python: build and sign
packet = TrustPacket.build(
    subject="agent@example.com",
    audience="service@target.com",
    action="login",
    signing_key=kp,
    signer_domain="example.com",
)
# Send packet.to_json() to a Ruby service...
```

```ruby
# Ruby: verify
result = UniKey.verify_packet!(JSON.parse(packet_json))
result.subject  # => "agent@example.com"
result.valid    # => true
```

## DNS Record Setup

Publish your public key as a DNS TXT record:

```
unikey._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=<base64 public key>"
```

Generate the record content:

```python
kp = KeyPair.generate()
print(kp.dns_record())  # "v=DKIM1; k=ed25519; p=ABC123..."
# Add this as a TXT record for unikey._domainkey.yourdomain.com
```

This is the same format used by DKIM email signatures. The `unikey` selector distinguishes it from email DKIM records.

## How It Works

```
Agent (you)                         Service (verifier)
  |                                    |
  |  1. Build Trust Packet             |
  |  2. Sign with Ed25519 private key  |
  |  3. Send (email / HTTPS / any)  -->|
  |                                    |  4. Validate structure & expiration
  |                                    |  5. Canonicalize to deterministic JSON
  |                                    |  6. Look up public key from DNS:
  |                                    |     unikey._domainkey.{signer}
  |                                    |  7. Verify Ed25519 signature
  |                                    |  8. Process the action
  |                                    |
  |  9. Signed response <--------------| (optional: response Trust Packet)
```

No shared secrets. No API keys. The public key lives in DNS — the same infrastructure that already secures billions of emails daily via DKIM.

## Errors

```python
from unikey_tp.dns import DNSLookupError, DNSInconsistencyError

# DNSLookupError        - public key not found in DNS
# DNSInconsistencyError - hardened lookup: resolvers disagree (fail-closed)
```

`TrustPacket.verify()` never raises — it returns a `VerifyResult` with `valid=False` and an `error` message. DNS functions raise on failure.

## License

MIT
