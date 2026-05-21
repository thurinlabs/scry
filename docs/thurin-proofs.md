# Thurin Proofs

Thurin Proofs are a decentralized identity verification system that links your PGP key to your online accounts. By adding cryptographic proofs to your PGP key and publishing verification posts on supported platforms, you create a verifiable chain of identity that anyone can check using [Scry](https://thurin.id).

## How It Works

Thurin Proofs use a **bidirectional linking** model:

1. **Your PGP key points to your account** — A `proof@thurin.id` notation in your PGP key contains a URL to a proof post on a platform (e.g., a GitHub gist, a Farcaster cast, a DNS record).

2. **Your account points back to your key** — The proof post contains your PGP fingerprint in the standard `openpgp4fpr:FINGERPRINT` format.

Anyone can independently verify both directions, confirming that the same person controls both the PGP key and the account.

```
┌──────────────┐     proof@thurin.id notation      ┌──────────────────┐
│              │ ──────────────────────────────────→│                  │
│   PGP Key    │     (URL to proof post)            │  GitHub / DNS /  │
│              │                                    │  Farcaster / ... │
│              │←────────────────────────────────── │                  │
└──────────────┘     openpgp4fpr:FINGERPRINT        └──────────────────┘
```

## Prerequisites

1. **A PGP key** registered on [Signet](https://thurin.id/signet) (on-chain identity claim)
2. **GPG** installed locally to edit your key
3. **An account on keys.openpgp.org** — after adding proof notations, you must upload your updated key to the keyserver so Scry can read the new notations

## Notation Format

Thurin Proofs use the PGP notation namespace `proof@thurin.id`. The notation value is a URI pointing to your proof on a supported platform.

```
proof@thurin.id=<proof-uri>
```

### Adding a notation to your key

```bash
# Open your key for editing
gpg --edit-key YOUR_KEY_ID

# Select your user ID
uid 1

# Add a notation
notation proof@thurin.id=https://gist.github.com/yourusername/gist_id

# Save and quit
save
```

You can add multiple `proof@thurin.id` notations for different platforms.

### Uploading your updated key

After adding notations, upload your key to the keyserver:

```bash
gpg --export --armor YOUR_KEY_ID | curl -T - https://keys.openpgp.org
```

Or use the web upload at [keys.openpgp.org/upload](https://keys.openpgp.org/upload).

## Proof Content Format

All proof posts must contain your PGP fingerprint using the [openpgp4fpr](https://www.iana.org/assignments/uri-schemes/prov/openpgp4fpr) URI scheme (IANA-registered, RFC 9116):

```
openpgp4fpr:FINGERPRINT
```

Where `FINGERPRINT` is your 40-character hex PGP fingerprint (case-insensitive).

Example:
```
openpgp4fpr:653909A2F0E37C106F5FAF546C8857E0D8E8F074
```

The proof post may contain additional text — Scry only checks for the presence of the `openpgp4fpr:` string followed by a matching fingerprint.

## Verification Flow

When Scry looks up an identity:

1. Fetches the PGP public key from `keys.openpgp.org` (by fingerprint from the on-chain attestation)
2. Parses `proof@thurin.id` notations from the key
3. For each notation, identifies the platform and fetches the proof content
4. Checks that the proof contains `openpgp4fpr:FINGERPRINT` matching the key
5. Displays verification status for each proof
