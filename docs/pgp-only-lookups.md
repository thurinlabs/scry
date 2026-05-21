# PGP-Only Lookups (Future Consideration)

## The Idea

Allow Scry to look up any PGP fingerprint directly from `keys.openpgp.org` — without requiring an on-chain Signet registration. This would show key info and verify `proof@thurin.id` notations for anyone with a PGP key, even if they've never touched Ethereum.

## Why Consider It

- The overlap of ETH users and PGP key users is very small
- Requiring Signet registration creates a high barrier to entry
- PGP-only lookups could serve as a discovery funnel: user sees their proofs on Scry, then learns about on-chain identity claims via Signet
- Expands the potential user base significantly

## Why Wait

- This is essentially what Keyoxide already does — need a clear differentiator
- Scry's unique value is the on-chain identity layer (ETH address + PGP key binding)
- Adding PGP-only lookups changes the product positioning
- Should validate the core on-chain flow first before broadening scope
- Risk of diluting the message: "prove your identity on-chain" vs "another PGP key viewer"

## Two-Tier Model (If Implemented)

1. **PGP tier** — Key info, user IDs, proof verification (works for anyone with a PGP key)
2. **On-chain tier** — ETH address binding, attestation status, signature verification, SBT status (requires Signet)

For unclaimed keys, the on-chain section would show a CTA: "Link this key to your ETH address on Signet."

## What Would Change

- `FingerprintDetail` would need to fetch keys from `keys.openpgp.org` independently of contract events
- New fallback UI when no on-chain claims exist but the key is valid
- Search input would need to handle bare fingerprints that aren't on-chain
- Proof verification already works independently — no changes needed there

## ~~Key ID Shorthand~~ (Shipped)

Implemented via Option 1 (keyserver resolve). Scry detects 16-char hex input, resolves the key ID to a full fingerprint via `keys.openpgp.org/vks/v1/by-keyid/`, and then proceeds with the standard lookup flow. URLs like `thurin.id/#/pgp/CD3D0D7F0C9E5FB8` work.

## WKD Integration (Related)

Fetch PGP keys from a user's own domain via Web Key Directory instead of (or in addition to) a keyserver. If the WKD server sets CORS headers, Scry can fetch directly from the browser.

- Extract email domain from PGP key UIDs, derive WKD URL (direct/advanced method)
- If key matches the on-chain fingerprint, show as an additional proof: "WKD: verified on example.com"
- openpgp.js has built-in WKD support
- Only works when the server sets `Access-Control-Allow-Origin` — progressive enhancement, not a requirement
- Reference: [Your Key, Your Domain](https://benwoodall.eth.limo/blog/your-key-your-domain-setting-up-wkd-for-pgp-discovery/) blog post recommends CORS-friendly nginx config

## Decision

Key ID shorthand is shipped. Parking PGP-only lookups and WKD for now. Focus on getting traction with Scry + Signet as-is before broadening scope.
