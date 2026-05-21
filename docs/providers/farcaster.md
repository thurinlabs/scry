# Farcaster Proof

Verify your Farcaster identity by publishing a cast containing your PGP fingerprint.

## Setup

### 1. Publish a proof cast

Post a cast on Farcaster (via Warpcast or any Farcaster client) containing your fingerprint:

```
Verifying my Thurin identity

openpgp4fpr:653909A2F0E37C106F5FAF546C8857E0D8E8F074

https://thurin.id
```

The cast can contain any additional text — Scry only looks for the `openpgp4fpr:` string.

### 2. Get the cast URL

Copy the URL of your proof cast. On Warpcast, this looks like:

```
https://warpcast.com/username/0xabcdef12
```

### 3. Add the notation to your PGP key

```bash
gpg --edit-key YOUR_KEY_ID
uid 1
notation proof@thurin.id=https://warpcast.com/username/0xabcdef12
save
```

### 4. Upload your updated key

```bash
gpg --export --armor YOUR_KEY_ID | curl -T - https://keys.openpgp.org
```

## How Scry Verifies

1. Parses the Warpcast URL from the `proof@thurin.id` notation
2. Extracts the cast hash from the URL
3. Fetches the cast via a Farcaster Hub REST API
4. Searches the cast text for `openpgp4fpr:FINGERPRINT`
5. Confirms the fingerprint matches the PGP key

## Requirements

- The cast must be public (not in a direct cast / channel-restricted)
- The cast URL must be in the format `https://warpcast.com/:username/0x:hash`
- The cast must contain `openpgp4fpr:` followed by your 40-character fingerprint
- Do not delete the cast — Scry re-verifies on each lookup

## CORS

Farcaster Hub APIs are public and free (no API key). CORS availability depends on the hub endpoint used. Scry uses publicly available hub endpoints for verification.

## Notes

- Your proof cast is permanent and public on the Farcaster protocol — even if deleted from a client, it may persist on hubs
- You can include a link to your Scry profile in the cast for discoverability
- The cast hash in the Warpcast URL is sufficient to locate the cast across any hub
