# Scry

Look up any Ethereum address, ENS name, or PGP fingerprint to view on-chain identity claims and verified proofs.

A [Thurin Labs](https://thurin.id) project.

## What it does

Scry is Thurin's identity lookup tool. It reads from the `PGPRegistry` contract on Ethereum mainnet and verifies identity proofs linked to PGP keys.

1. **Look up an identity** — enter an ETH address, ENS name, or PGP fingerprint
2. **View on-chain claims** — see which PGP keys are attested to which addresses via [Signet](https://thurin.id/signet)
3. **Verify proofs** — `proof@thurin.id` notations in PGP keys are checked against GitHub, DNS, and Farcaster

## Setup

```bash
npm install
npm run dev
```

Requires a `.env` file:

```
VITE_ALCHEMY_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
VITE_NEYNAR_API_KEY=YOUR_NEYNAR_KEY
```

## How it works

Scry fetches attestation events from the `PGPRegistry` contract, retrieves the associated PGP public key from `keys.openpgp.org`, and parses `proof@thurin.id` notations. Each proof is verified client-side:

- **GitHub** — fetches the gist via GitHub API, checks for `openpgp4fpr:FINGERPRINT`
- **DNS** — queries TXT records via Cloudflare DNS-over-HTTPS, checks for `openpgp4fpr:FINGERPRINT`
- **Farcaster** — resolves the user's FID, scans recent casts via Neynar Hub API, checks for `openpgp4fpr:FINGERPRINT`

## IPFS

The build output (`npm run build`) is a static `dist/` folder with relative asset paths — pin it to IPFS directly.
