# UniKey Python

Trust Packet creation, signing, and verification for Python. Build and verify [Trust Packets](https://unikey.tech) and signed HTTP requests from AI agents using Ed25519 + DNS-published public keys.

**UniKey is a Universal Trust Primitive for AI Agents** — it lets any service verify that a request genuinely came from a specific agent, without shared secrets, API keys, or passwords. Public keys live in DNS (the same infrastructure that secures email via DKIM), so verification is fully decentralized.

This library is a **full sender + verifier implementation**. Use it to build and sign Trust Packets, or to verify incoming packets and HTTP requests. Works with any language on either side (companion libraries in [Ruby](https://github.com/Swoop-Now/unikey-ruby) and [Node.js](https://github.com/Swoop-Now/unikey-node)).

## Installation

```bash
pip install unikey-tp
```

**Requirements:** Python >= 3.9 | **Dependencies:** `pynacl`, `dnspython`

## Quick Start

### 1. Build and Sign a Trust Packet

```python
from unikey_tp import TrustPacket, KeyPair

# Generate an Ed25519 keypair (or load from saved key)
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

packet.to_json(indent=2)  # serialize
```

### 2. Verify a Trust Packet

```python
from unikey_tp import TrustPacket

# Raises on failure: InvalidSignature, InvalidPacket, ExpiredRequest, etc.
result = TrustPacket.verify_strict(packet_data, public_key_b64=kp.public_key_b64)

# Returns VerifyResult with valid=False on failure (no exception)
result = TrustPacket.verify(packet_data)

result.valid        # True
result.subject      # "claude@user.example.com"
result.action       # "purchase_item"
result.callback_url # "https://device/cb/123"
result.signer       # "user.example.com"
```

Behind the scenes, the library:
1. Validates the packet structure and expiration
2. Looks up the signer's Ed25519 public key from DNS (`unikey._domainkey.user.example.com`)
3. Verifies the signature over the canonicalized packet
4. Returns the verified claims

No API keys. No shared secrets. Just DNS + cryptography.

### 3. Verify Signed HTTP Requests

```python
from unikey_tp import verify_request

result = verify_request({
    "method": "POST",
    "url": "https://example.com/api/action",
    "body": '{"action":"purchase"}',
    "headers": {
        "X-UniKey-Signature": "...",
        "X-UniKey-Signer": "unikey.tech",
        "X-UniKey-Timestamp": "1736784000",
        "X-UniKey-Body-Hash": "...",
        "X-Agent-Email": "agent@example.com",
    },
})

result.signer       # "unikey.tech"
result.agent_email  # "agent@example.com"
result.timestamp    # datetime object
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
    "subject": "claude@user.example.com",
    "issuer": "user.example.com",
    "audience": "orders@acme-store.com",
    "scope": ["purchase:items"],
    "delegation_chain": []
  },
  "payload": {
    "action": "purchase_item",
    "params": { "item": "blue purse", "callback_url": "https://device/cb/123" },
    "message": "Please purchase a blue purse."
  },
  "signatures": [{
    "algorithm": "ed25519",
    "signer": "user.example.com",
    "key_selector": "unikey",
    "signature": "<base64 Ed25519 signature>",
    "signed_at": 1736784000
  }]
}
```

**Transport-agnostic.** Trust Packets can travel over email (SMTP + DKIM), HTTPS POST, WebSocket, or any channel. The signature makes them self-verifying regardless of how they arrive.

## Configuration

```python
from unikey_tp import configure

configure(
    # How long to cache DNS lookups (default: 3600s / 1 hour)
    dns_cache_ttl=3600,

    # Reject packets/requests older than this (default: 300s / 5 minutes)
    max_request_age=300,

    # Restrict to specific signer domains (None = trust any valid signer)
    trusted_signers=["gmail.com", "unikey.tech"],

    # RFC-002: DNS hardening with multi-resolver consensus
    dns_hardening_enabled=True,
    dns_resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    dns_min_consistent=2,  # at least 2 of 3 resolvers must agree
)
```

## Trust Packet API

### Building

```python
packet = TrustPacket.build(
    subject="agent@example.com",       # who is making the request
    audience="service@target.com",     # who should receive it
    action="do_something",             # what action to perform
    signing_key=kp,                    # KeyPair instance
    signer_domain="example.com",       # domain publishing the public key in DNS
    scope=["read", "write"],           # permissions (default: ["*"])
    params={"key": "value"},           # action parameters (optional)
    message="Human-readable note",     # optional message
    ttl=300,                           # seconds until expiration (default: 300)
)

packet.to_dict()                       # full packet as dict
packet.to_json(indent=2)              # JSON string
packet.canonical_form()               # deterministic JSON (for debugging)
packet.expired                        # True if TTL has passed
```

### Verification

```python
# Raises on failure: InvalidSignature, InvalidPacket, ExpiredRequest, etc.
result = TrustPacket.verify_strict(packet_data)

# Returns VerifyResult with valid=False on failure (no exception)
result = TrustPacket.verify(packet_data)
```

The result object:

| Field | Description |
|-------|-------------|
| `result.valid` | Whether verification succeeded |
| `result.error` | Error message (if invalid) |
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

### Parsing (without verification)

```python
packet = TrustPacket.from_dict(data)    # from dict
packet = TrustPacket.from_json(string)  # from JSON string
packet.header.packet_id
packet.claims.subject
packet.payload.action
```

## HTTP Request Verification

For the header-based signature flow (DKIM-over-HTTPS), the agent signs each HTTP request directly:

### Expected Headers

| Header | Description |
|--------|-------------|
| `X-UniKey-Signature` | Base64 Ed25519 signature |
| `X-UniKey-Signer` | Domain that signed the request |
| `X-UniKey-Timestamp` | Unix timestamp (replay prevention) |
| `X-UniKey-Body-Hash` | Base64 SHA-256 of request body |
| `X-Agent-Email` | The agent's verified email |

### Canonical String (What Gets Signed)

```
POST
https://example.com/api/action
<sha256-body-hash>
1736784000
agent@example.com
```

### Verification

```python
from unikey_tp import verify_request, verify_request_safe

# Raises on failure
result = verify_request(request_dict)
result.signer       # "unikey.tech"
result.agent_email  # "user@gmail.com"
result.timestamp    # datetime object

# Returns None on failure (no exception)
result = verify_request_safe(request_dict)
```

Accepts a dict with `headers`, `body`, `method`, `url` keys. Also handles WSGI environ dicts (`HTTP_X_UNIKEY_SIGNATURE` format).

## DNS Hardening (RFC-002)

Standard DNS queries trust a single resolver. DNS hardening queries multiple independent resolvers and requires consensus. If resolvers disagree on the public key, verification fails closed — protecting against DNS poisoning.

```python
from unikey_tp import configure

configure(
    dns_hardening_enabled=True,
    dns_resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    dns_min_consistent=2,
)
```

Default resolvers: Google (`8.8.8.8`), Cloudflare (`1.1.1.1`), Quad9 (`9.9.9.9`).

## DNS Record Setup

Publish your Ed25519 public key as a DNS TXT record:

```
unikey._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=<base64 public key>"
```

This is the same format used by DKIM email signatures. The `unikey` selector distinguishes it from email DKIM records.

Generate the record value:

```python
kp = KeyPair.generate()
print(kp.dns_record())
# v=DKIM1; k=ed25519; p=abc123...
```

## Error Handling

All errors inherit from `UniKeyError`:

| Error | Meaning |
|-------|---------|
| `InvalidSignature` | Ed25519 signature verification failed |
| `ExpiredRequest` | Packet/request is older than `max_request_age` |
| `InvalidPacket` | Trust Packet structure is malformed |
| `MissingHeaders` | Required HTTP headers absent |
| `DNSLookupFailed` | Public key not found in DNS |
| `UntrustedSigner` | Signer not in `trusted_signers` whitelist |
| `DNSInconsistency` | Hardened DNS: resolvers disagree (fail-closed) |

## How It Works

```
Agent (sender)                      Your Service (verifier)
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

## Cross-Language Compatibility

Trust Packets are interoperable across all UniKey libraries:

| Language | Package | Install |
|----------|---------|---------|
| **Python** | `unikey-tp` | `pip install unikey-tp` |
| **Ruby** | `unikey` | `gem 'unikey'` |
| **Node.js** | `unikey-tp` | `npm install unikey-tp` |

A packet built in any language can be verified by any other — the canonical JSON serialization and Ed25519 signatures are identical across implementations.

## Running Tests

```bash
pip install -e ".[dev]"
pytest   # 39 specs
```

## License

MIT
