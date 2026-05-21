# GitHub Proof

Verify your GitHub identity by creating a public gist containing your PGP fingerprint.

## Setup

### 1. Create a proof gist

Go to [gist.github.com](https://gist.github.com) and create a **public** gist:

- **Filename:** `thurin-proof.md` (or any name)
- **Content:** Must contain your fingerprint in `openpgp4fpr:` format

Example gist content:

```markdown
This is a Thurin identity proof.

openpgp4fpr:653909A2F0E37C106F5FAF546C8857E0D8E8F074

This gist links my GitHub account to my PGP key registered on Signet (https://thurin.id/signet).
```

### 2. Add the notation to your PGP key

Copy the gist URL (e.g., `https://gist.github.com/yourusername/abc123def456`) and add it as a notation:

```bash
gpg --edit-key YOUR_KEY_ID
uid 1
notation proof@thurin.id=https://gist.github.com/yourusername/abc123def456
save
```

### 3. Upload your updated key

```bash
gpg --export --armor YOUR_KEY_ID | curl -T - https://keys.openpgp.org
```

## How Scry Verifies

1. Parses the gist URL from the `proof@thurin.id` notation
2. Extracts the gist ID from the URL
3. Fetches the gist content via the GitHub API (`api.github.com/gists/:id`)
4. Searches the gist file contents for `openpgp4fpr:FINGERPRINT`
5. Confirms the fingerprint matches the PGP key

## Requirements

- The gist must be **public**
- The gist URL must be in the format `https://gist.github.com/:username/:gist_id`
- The gist must contain `openpgp4fpr:` followed by your 40-character fingerprint

## CORS

GitHub's API (`api.github.com`) returns CORS headers, so verification happens entirely client-side in the browser. No proxy or backend is needed.
