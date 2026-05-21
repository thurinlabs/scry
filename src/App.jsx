import { useState, useEffect, useCallback, useMemo } from 'react'
import { useReadContract, useReadContracts, useEnsAddress, useEnsName, useEnsAvatar } from 'wagmi'
import { createPublicClient, http, parseAbiItem, getAddress } from 'viem'
import { mainnet } from 'wagmi/chains'
import { normalize } from 'viem/ens'
import { readKey, readCleartextMessage, verify } from 'openpgp'
import { REGISTRY_ADDRESS, REGISTRY_ABI, RPC_URL } from './wagmiConfig'
import { identifyProof, verifyProof, displayUrl, proofHref, proofSecondaryHref } from './proofs'
import { ScryCard, IdentityKitProvider } from '@thurinlabs/identity-kit'
import '@thurinlabs/identity-kit/styles'
import Signet from './components/Signet'

async function parsePgpKey(armoredKey) {
  try {
    const key = await readKey({ armoredKey })
    const fingerprint = key.getFingerprint().toUpperCase()
    const userIDs = key.users.map(u => u.userID?.userID).filter(Boolean)
    const algorithm = key.keyPacket.algorithm
    const created = key.keyPacket.created?.toISOString() ?? null
    const expiration = await key.getExpirationTime()
    const expires = expiration && expiration !== Infinity
      ? new Date(expiration).toISOString() : null

    // Extract notations (keyoxide proofs, etc.)
    const notations = []
    const seen = new Set()
    for (const user of key.users) {
      if (!user.selfCertifications) continue
      for (const cert of user.selfCertifications) {
        if (cert.rawNotations) {
          for (const n of cert.rawNotations) {
            const name = typeof n.name === 'string' ? n.name : new TextDecoder().decode(n.name)
            const value = n.value instanceof Uint8Array
              ? new TextDecoder().decode(n.value)
              : typeof n.value === 'string' ? n.value : null
            if (value) {
              const key = `${name}:${value}`
              if (!seen.has(key)) {
                seen.add(key)
                notations.push({ name, value })
              }
            }
          }
        }
      }
    }

    const subkeys = key.subkeys.map(sk => ({
      algorithm: sk.keyPacket.algorithm,
      created: sk.keyPacket.created?.toISOString() ?? null,
      fingerprint: sk.getFingerprint().toUpperCase(),
    }))

    return { fingerprint, userIDs, algorithm, created, expires, notations, subkeys }
  } catch {
    return null
  }
}

/**
 * Verify an attestation's PGP proofs:
 * 1. Public key fingerprint matches claimed fingerprint
 * 2. PGP signature is valid against the public key
 * 3. Signed message contains the ETH address
 *
 * Returns { verified: true } or { verified: false, reason: string }
 */
async function verifyAttestation({ pgpPublicKey, pgpSignature, fingerprint, ethAddress }) {
  try {
    if (!pgpPublicKey || !pgpSignature) {
      return { verified: false, reason: 'Missing PGP data' }
    }

    // 1. Parse public key and check fingerprint
    const publicKey = await readKey({ armoredKey: pgpPublicKey })
    const keyFingerprint = publicKey.getFingerprint().toUpperCase()
    if (keyFingerprint !== fingerprint.toUpperCase()) {
      return { verified: false, reason: 'Key fingerprint mismatch' }
    }

    // 2. Parse and verify the PGP signature
    const message = await readCleartextMessage({ cleartextMessage: pgpSignature })
    const { signatures } = await verify({ message, verificationKeys: publicKey })
    await signatures[0].verified // throws if invalid

    // 3. Check the signed message contains the ETH address
    const signedText = message.getText()
    if (!signedText.toLowerCase().includes(ethAddress.toLowerCase())) {
      return { verified: false, reason: 'Signed message does not contain ETH address' }
    }

    return { verified: true }
  } catch {
    return { verified: false, reason: 'Signature verification failed' }
  }
}

const mainnetClient = createPublicClient({
  chain: mainnet,
  transport: http(import.meta.env.VITE_ALCHEMY_RPC_URL),
})

const CONTRACT_DEPLOY_BLOCK = 24515891n
const LOG_CHUNK_SIZE = 999999n

async function getLogsChunked(params) {
  const latest = await mainnetClient.getBlockNumber()
  const fromBlock = params.fromBlock ?? CONTRACT_DEPLOY_BLOCK
  const toBlock = params.toBlock === 'latest' ? latest : (params.toBlock ?? latest)
  const allLogs = []

  for (let start = fromBlock; start <= toBlock; start += LOG_CHUNK_SIZE) {
    const end = start + LOG_CHUNK_SIZE - 1n > toBlock ? toBlock : start + LOG_CHUNK_SIZE - 1n
    const logs = await mainnetClient.getLogs({ ...params, fromBlock: start, toBlock: end })
    allLogs.push(...logs)
  }

  return allLogs
}

// ─── helpers ────────────────────────────────────────────────────────────────

function detectInputType(value) {
  const trimmed = value.trim()
  if (/^0x[0-9a-fA-F]{40}$/.test(trimmed)) return 'address'
  if (/^[0-9a-fA-F]{40}$/.test(trimmed)) return 'fingerprint'
  if (/^[0-9a-fA-F]{16}$/.test(trimmed)) return 'keyId'
  if (trimmed.includes('.') && trimmed.length > 3) return 'ens'
  return null
}

function safeNormalize(name) {
  try { return normalize(name) } catch { return null }
}

function formatDate(unixTimestamp) {
  if (!unixTimestamp) return '—'
  return new Date(unixTimestamp * 1000).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  })
}

function copyToClipboard(text, e) {
  navigator.clipboard.writeText(text)
  if (e?.target) {
    const btn = e.target
    const original = btn.textContent
    btn.textContent = 'copied'
    btn.classList.add('copied')
    setTimeout(() => {
      btn.textContent = original
      btn.classList.remove('copied')
    }, 1200)
  }
}

// ─── Path routing ───────────────────────────────────────────────────────────

function parseRoute() {
  // Check for legacy hash routes — redirect to path on thurin.id, keep hash elsewhere (IPFS/ENS)
  const hash = window.location.hash.replace(/^#\/?/, '')
  if (hash) {
    const slash = hash.indexOf('/')
    if (slash !== -1) {
      const prefix = hash.slice(0, slash).toLowerCase()
      const value = decodeURIComponent(hash.slice(slash + 1))
      if (value && (prefix === 'eth' || prefix === 'pgp' || prefix === 'ens')) {
        if (window.location.hostname === 'thurin.id') {
          window.history.replaceState(null, '', `/${prefix}/${encodeURIComponent(value)}`)
        } else {
          // On IPFS/ENS, parse the hash route directly
          return { type: prefix === 'eth' ? 'address' : prefix === 'pgp' ? (/^[0-9a-fA-F]{16}$/i.test(value) ? 'keyId' : 'fingerprint') : 'ens', value }
        }
      }
    }
  }

  const path = window.location.pathname.replace(/^\/?/, '')
  if (!path) return null

  const slash = path.indexOf('/')
  if (slash === -1) return null

  const prefix = path.slice(0, slash).toLowerCase()
  const value = decodeURIComponent(path.slice(slash + 1))
  if (!value) return null

  if (prefix === 'eth' && /^0x[0-9a-fA-F]{40}$/.test(value)) return { type: 'address', value }
  if (prefix === 'pgp' && /^[0-9a-fA-F]{40}$/i.test(value)) return { type: 'fingerprint', value }
  if (prefix === 'pgp' && /^[0-9a-fA-F]{16}$/i.test(value)) return { type: 'keyId', value }
  if (prefix === 'ens') return { type: 'ens', value }

  return null
}

function pushRoute(type, value) {
  const prefix = type === 'address' ? 'eth' : (type === 'fingerprint' || type === 'keyId') ? 'pgp' : 'ens'
  if (window.location.hostname === 'thurin.id') {
    const newPath = `/${prefix}/${encodeURIComponent(value)}`
    if (window.location.pathname !== newPath) {
      window.history.pushState(null, '', newPath)
    }
  } else {
    // IPFS/ENS — use hash routing
    const newHash = `#/${prefix}/${encodeURIComponent(value)}`
    if (window.location.hash !== newHash) {
      window.location.hash = newHash
    }
  }
}

// ─── Topbar ─────────────────────────────────────────────────────────────────

function ThemeSelect({ storageKey }) {
  const [theme, setTheme] = useState(
    () => localStorage.getItem(storageKey) || 'thurin'
  )

  const handleChange = (e) => {
    const id = e.target.value
    setTheme(id)
    document.documentElement.dataset.theme = id
    localStorage.setItem(storageKey, id)
  }

  return (
    <select className="theme-select" value={theme} onChange={handleChange}>
      <option value="thurin">Thurin</option>
      <option value="dark">Dark</option>
      <option value="light">Light</option>
    </select>
  )
}

function Topbar() {
  return (
    <nav className="topbar">
      <a href="/" className="topbar-title" onClick={(e) => { e.preventDefault(); window.history.pushState(null, '', '/'); window.dispatchEvent(new PopStateEvent('popstate')); }}
         style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <svg viewBox="20 20 76 76" xmlns="http://www.w3.org/2000/svg" width="36" height="36">
          <path d="M25 80 Q25 25 50 25 Q75 25 75 50" fill="none" stroke="#7c9a3e" strokeWidth="4" strokeLinecap="round"/>
          <path d="M33 75 Q33 35 50 35 Q67 35 67 52" fill="none" stroke="#7c9a3e" strokeWidth="4" strokeLinecap="round"/>
          <path d="M41 70 Q41 45 50 45 Q59 45 59 55" fill="none" stroke="#c9a227" strokeWidth="4" strokeLinecap="round"/>
          <path d="M50 65 L50 53" fill="none" stroke="#c9a227" strokeWidth="4" strokeLinecap="round"/>
          <circle cx="72" cy="72" r="12" fill="none" stroke="#c9a227" strokeWidth="3.5"/>
          <line x1="81" y1="81" x2="92" y2="92" stroke="#c9a227" strokeWidth="3.5" strokeLinecap="round"/>
        </svg>
        Scry
      </a>
      <div className="topbar-right">
        <a href="/signet" className="topbar-signet-link" target="_blank" rel="noopener noreferrer">
          Create identity claim
        </a>
        <ThemeSelect storageKey="thurin-scry-theme" />
      </div>
    </nav>
  )
}

// ─── PGP Key Info ──────────────────────────────────────────────────────────

function PgpKeyInfo({ armoredKey }) {
  const [keyInfo, setKeyInfo] = useState(null)
  const [keySource, setKeySource] = useState(null) // 'keyserver' | 'on-chain'
  const [showKey, setShowKey] = useState(false)
  const [proofResults, setProofResults] = useState({})

  useEffect(() => {
    if (!armoredKey) return
    let cancelled = false

    async function load() {
      // Parse the stored key first
      const stored = await parsePgpKey(armoredKey)
      if (cancelled || !stored) return

      setKeyInfo(stored)
      setKeySource('on-chain')

      // Try to fetch a fresher version from keyserver
      try {
        const resp = await fetch(`https://keys.openpgp.org/vks/v1/by-fingerprint/${stored.fingerprint}`)
        if (!resp.ok) return
        const fresh = await parsePgpKey(await resp.text())
        if (cancelled || !fresh) return
        setKeyInfo(fresh)
        setKeySource('keyserver')
      } catch {
        // Keyserver unavailable, keep stored key
      }
    }

    load()
    return () => { cancelled = true }
  }, [armoredKey])

  // Verify identity proofs
  useEffect(() => {
    if (!keyInfo) return
    let cancelled = false

    const proofs = keyInfo.notations
      .map((n, i) => ({ ...identifyProof(n), index: i }))
      .filter(p => p && p.provider !== 'unknown')

    if (proofs.length === 0) return

    // Set all to pending
    const pending = {}
    for (const p of proofs) pending[p.index] = { status: 'pending' }
    setProofResults(pending)

    Promise.all(
      proofs.map(p =>
        verifyProof(p, keyInfo.fingerprint).then(result => ({ index: p.index, result }))
      )
    ).then(results => {
      if (cancelled) return
      const next = {}
      for (const { index, result } of results) {
        next[index] = { status: result.verified ? 'verified' : 'unverified', reason: result.reason }
      }
      setProofResults(next)
    })

    return () => { cancelled = true }
  }, [keyInfo])

  if (!keyInfo) return null

  return (
    <div className="detail-history">
      <div className="detail-label">
        PGP Key Details
        {keySource && (
          <span style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginLeft: 8, fontWeight: 'normal' }}>
            via {keySource === 'keyserver' ? 'keys.openpgp.org' : 'on-chain event log'}
          </span>
        )}
      </div>

      {keyInfo.userIDs.length > 0 && (
        <div className="mono-box" style={{ marginBottom: 2 }}>
          <div className="label">User IDs</div>
          {keyInfo.userIDs.map((uid, i) => (
            <div key={i} className="value">{uid}</div>
          ))}
          {keySource === 'keyserver' ? (
            <div style={{ marginTop: 6 }}>
              <span
                className="status-badge verified"
                title="keys.openpgp.org verified the email address associated with this key — the key owner proved control of this email"
              >
                email verified
              </span>
            </div>
          ) : keySource === 'on-chain' ? (
            <div style={{ marginTop: 6 }}>
              <span
                className="status-badge"
                style={{ opacity: 0.4, borderColor: 'var(--color-text-muted)', color: 'var(--color-text-muted)' }}
                title="User IDs are from the on-chain key data — not independently verified by a keyserver"
              >
                self-declared
              </span>
            </div>
          ) : null}
        </div>
      )}

      {(() => {
        const thurinProofs = keyInfo.notations
          .map((n, i) => ({ notation: n, index: i, proof: identifyProof(n) }))
          .filter(p => p.proof)
        return (
          <div className="mono-box" style={{ marginBottom: 2 }}>
            <div className="label">Identity Proofs</div>
            {thurinProofs.length === 0 ? (
              <div className="value" style={{ color: 'var(--color-text-muted)' }}>No proofs found</div>
            ) : thurinProofs.map(({ index, proof }) => {
              const result = proofResults[index]
              const clean = displayUrl(proof)
              const href = proofHref(proof)
              const secondary = proofSecondaryHref(proof)
              return (
                <div key={index} className="proof-row">
                  {result ? (
                    result.status === 'pending' ? (
                      <span className="proof-icon pending" title="Checking...">&#8943;</span>
                    ) : result.status === 'verified' ? (
                      <span className="proof-icon verified" title="Proof verified: target contains openpgp4fpr token matching this key">&#10003;</span>
                    ) : (
                      <span className="proof-icon unverified" title={result.reason}>&#10007;</span>
                    )
                  ) : null}
                  <span className="proof-provider">{proof.label}</span>
                  {href ? (
                    <a href={href} className="proof-link" target="_blank" rel="noopener noreferrer">{clean}</a>
                  ) : (
                    <span className="proof-link">{clean}</span>
                  )}
                  {secondary && (
                    <a href={secondary} className="proof-secondary" target="_blank" rel="noopener noreferrer">proof</a>
                  )}
                </div>
              )
            })}
            <div className="proof-docs-footer">
              <a href="https://docs.thurin.id/#/scry/proofs" target="_blank" rel="noopener noreferrer">how to add proofs</a>
            </div>
          </div>
        )
      })()}

      <div className="mono-box" style={{ marginBottom: 2 }}>
        <div className="label">Key Info</div>
        <div className="value">{typeof keyInfo.algorithm === 'number' ? ({
          1: 'RSA', 2: 'RSA (encrypt)', 3: 'RSA (sign)',
          16: 'Elgamal', 17: 'DSA', 18: 'ECDH',
          19: 'ECDSA', 22: 'EdDSA (Ed25519)',
        }[keyInfo.algorithm] || `Algorithm ${keyInfo.algorithm}`) : keyInfo.algorithm}</div>
        <div style={{ marginTop: 4 }}>
          <span style={{ color: 'var(--color-text-muted)' }}>Created: </span>
          <span className="value">{keyInfo.created ? new Date(keyInfo.created).toLocaleDateString() : '—'}</span>
        </div>
        {keyInfo.expires && (
          <div>
            <span style={{ color: 'var(--color-text-muted)' }}>Expires: </span>
            <span className="value">{new Date(keyInfo.expires).toLocaleDateString()}</span>
          </div>
        )}
        {keyInfo.subkeys.length > 0 && (
          <div>
            <span style={{ color: 'var(--color-text-muted)' }}>Subkeys: </span>
            <span className="value">{keyInfo.subkeys.length}</span>
          </div>
        )}
      </div>

      <div className="mono-box">
        <button
          className="pubkey-toggle"
          onClick={() => setShowKey(v => !v)}
        >
          {showKey ? 'Hide' : 'Show'} Public Key
        </button>
        {showKey && (
          <>
            <pre className="pubkey-block">{armoredKey}</pre>
            <div className="pubkey-actions">
              <button className="copy-btn" onClick={(e) => copyToClipboard(armoredKey, e)}>copy</button>
              <button className="copy-btn" onClick={() => {
                const blob = new Blob([armoredKey], { type: 'application/pgp-keys' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `${keyInfo.fingerprint}.asc`
                a.click()
                URL.revokeObjectURL(url)
              }}>download .asc</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ─── Address Detail ─────────────────────────────────────────────────────────

function AddressDetail({ address, ensName, ensAvatar, attestations, count, isLoading, error }) {
  const activeCount = attestations.filter(a => !a.revoked).length
  const latest = attestations[0] // newest first

  if (isLoading) {
    return <div className="status info" style={{ marginTop: 24 }}>Querying registry...</div>
  }

  if (error) {
    return <div className="status err" style={{ marginTop: 24 }}>Query failed: {error.shortMessage || error.message}</div>
  }

  return (
    <div className="detail-page fade-in">
      <div className="detail-header">
        <div className="detail-header-content">
          {ensAvatar && <img src={ensAvatar} alt="" className="ens-avatar" />}
          <div>
            <div className="detail-label">Address</div>
            <div className="detail-address-row">
              <span className="detail-address">{address}</span>
              <button className="copy-btn" onClick={(e) => copyToClipboard(address, e)}>copy</button>
              <a
                className="detail-link"
                href={`https://etherscan.io/address/${address}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                etherscan
              </a>
            </div>
            {ensName && <div className="detail-ens">{ensName}</div>}
          </div>
        </div>
      </div>

      <div className="detail-summary">
        <div className="detail-label">Summary</div>
        <div className="summary-grid">
          <div className="summary-item">
            <span className="summary-value">{count}</span>
            <span className="summary-key">Total</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{activeCount}</span>
            <span className="summary-key">Active</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{count - activeCount}</span>
            <span className="summary-key">Revoked</span>
          </div>
        </div>
        {latest && !latest.revoked && (
          <div className="mono-box" style={{ marginTop: 12 }}>
            <div className="label">current fingerprint</div>
            <div className="value">{latest.fingerprint.toUpperCase()}</div>
            {latest.verification && (
              <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className={`status-badge ${latest.verification.verified ? 'verified' : 'unverified'}`}
                  title={latest.verification.verified ? 'PGP signature verified: the clearsign block in the event log is valid for this key and binds it to this address' : latest.verification.reason}>
                  {latest.verification.verified ? 'pgp verified' : 'unverified'}
                </span>
                <span
                  className="status-badge"
                  style={{ opacity: 0.35, cursor: 'default', borderColor: 'var(--color-text-muted)', color: 'var(--color-text-muted)' }}
                  title="Thurin SBT verification coming soon"
                >
                  thurin verified
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {latest && latest.pgpPublicKey ? (
        <PgpKeyInfo armoredKey={latest.pgpPublicKey} />
      ) : attestations.length > 0 && (
        <div className="detail-history">
          <div className="mono-box" style={{ marginBottom: 2 }}>
            <div className="label">Identity Proofs</div>
            <div className="value" style={{ color: 'var(--color-text-muted)' }}>No proofs found</div>
            <div className="proof-docs-footer">
              <a href="https://docs.thurin.id/#/scry/proofs" target="_blank" rel="noopener noreferrer">how to add proofs</a>
            </div>
          </div>
        </div>
      )}

      <EfpSection address={address} />

      {attestations.length > 0 && (
        <div className="detail-history">
          <div className="detail-label">Seal History</div>
          <div className="attestation-table-wrap">
            <table className="attestation-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Fingerprint</th>
                  <th>Date</th>
                  <th>Status <span className="info-icon" title="Active: identity claim is live on-chain. Revoked: owner has revoked this seal.">?</span></th>
                  <th>PGP <span className="info-icon" title="Verified: the PGP clearsign block stored in the event log is cryptographically valid for this key and binds it to this address. Unverified: signature check failed or PGP data is missing.">?</span></th>
                </tr>
              </thead>
              <tbody>
                {attestations.map(a => (
                  <tr key={a.index}>
                    <td className="att-index">{a.index}</td>
                    <td>
                      <a href={`/pgp/${a.fingerprint.toUpperCase()}`} className="fingerprint-link">
                        {a.fingerprint.toUpperCase().slice(0, 8)}...{a.fingerprint.toUpperCase().slice(-8)}
                      </a>
                    </td>
                    <td className="att-date">{formatDate(a.createdAt)}</td>
                    <td>
                      <span className={`status-badge ${a.revoked ? 'revoked' : 'active'}`}>
                        {a.revoked ? 'revoked' : 'active'}
                      </span>
                    </td>
                    <td>
                      {a.verification ? (
                        <span className={`status-badge ${a.verification.verified ? 'verified' : 'unverified'}`}>
                          {a.verification.verified ? 'verified' : 'unverified'}
                        </span>
                      ) : (
                        <span className="status-badge" style={{ opacity: 0.4 }}>...</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {attestations.length === 0 && (
        <div className="status info" style={{ marginTop: 2 }}>
          No identity claims found for this address.
          <div style={{ marginTop: 8 }}>
            <a href="/signet" className="fingerprint-link" target="_blank" rel="noopener noreferrer">
              Create an identity claim on Signet →
            </a>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── EFP (Ethereum Follow Protocol) ─────────────────────────────────────────

const EFP_API = 'https://api.ethfollow.xyz/api/v1'

function EfpSection({ address }) {
  const [followers, setFollowers] = useState(0)
  const [followingList, setFollowingList] = useState([])
  const [top8, setTop8] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [hasEfp, setHasEfp] = useState(false)

  useEffect(() => {
    if (!address) return
    let cancelled = false
    setIsLoading(true)

    async function load() {
      try {
        // Get primary list ID
        const listsResp = await fetch(`${EFP_API}/users/${address}/lists`)
        if (!listsResp.ok) { setIsLoading(false); return }
        const listsData = await listsResp.json()
        const listId = listsData.primary_list
        if (!listId) { setIsLoading(false); return }
        if (cancelled) return

        setHasEfp(true)

        // Fetch following and top8 via list ID, followers via stats endpoint
        const [followingResp, statsResp, top8Resp] = await Promise.all([
          fetch(`${EFP_API}/lists/${listId}/following?limit=100`),
          fetch(`${EFP_API}/users/${address}/stats`),
          fetch(`${EFP_API}/lists/${listId}/following?limit=8&tags=top8`),
        ])

        if (cancelled) return

        const followingData = followingResp.ok ? await followingResp.json() : { following: [] }
        const statsData = statsResp.ok ? await statsResp.json() : {}
        const top8Data = top8Resp.ok ? await top8Resp.json() : { following: [] }

        setFollowingList(followingData.following || [])
        setFollowers(parseInt(statsData.followers_count) || 0)
        setTop8(top8Data.following || [])
      } catch {
        // silently fail — EFP is supplementary
      }
      if (!cancelled) setIsLoading(false)
    }

    load()
    return () => { cancelled = true }
  }, [address])

  if (!isLoading && !hasEfp) return null
  if (isLoading) return (
    <div className="detail-history">
      <div className="detail-label">Social Graph</div>
      <div className="mono-box" style={{ marginBottom: 2 }}>
        <div className="value" style={{ color: 'var(--color-text-muted)' }}>Loading EFP data...</div>
      </div>
    </div>
  )

  const followingCount = followingList.length

  return (
    <div className="detail-history">
      <div className="detail-label">
        Social Graph
        <span style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginLeft: 8, fontWeight: 'normal' }}>
          via <a href="https://efp.app" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit' }}>EFP</a>
        </span>
      </div>
      <div className="mono-box" style={{ marginBottom: 2 }}>
        <div className="summary-grid" style={{ marginBottom: top8.length > 0 ? 12 : 0 }}>
          <div className="summary-item">
            <span className="summary-value">{followers}</span>
            <span className="summary-key">Followers</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{followingCount}</span>
            <span className="summary-key">Following</span>
          </div>
        </div>
        {top8.length > 0 && (
          <>
            <div className="label">Top 8</div>
            <div className="efp-top8">
              {top8.map((f, i) => (
                <EfpFollowItem key={i} address={f.data} />
              ))}
            </div>
          </>
        )}
      </div>
      <div style={{ textAlign: 'right', marginTop: 4 }}>
        <a
          href={`https://efp.app/${address}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}
        >
          view full profile on efp.app
        </a>
      </div>
    </div>
  )
}

function EfpFollowItem({ address }) {
  const { data: ensName } = useEnsName({
    address,
    chainId: mainnet.id,
    query: { enabled: !!address },
  })
  return (
    <a href={`/eth/${address}`} className="efp-top8-item" title={address}>
      {ensName || `${address.slice(0, 8)}...${address.slice(-4)}`}
    </a>
  )
}

function ClaimAddressCell({ address }) {
  const { data: ensName } = useEnsName({
    address,
    chainId: mainnet.id,
    query: { enabled: !!address },
  })
  const { data: ensAvatar } = useEnsAvatar({
    name: ensName ? safeNormalize(ensName) : undefined,
    chainId: mainnet.id,
    query: { enabled: !!ensName },
  })
  return (
    <div className="claim-address-cell">
      {ensAvatar && <img src={ensAvatar} alt="" className="ens-avatar-sm" />}
      <div>
        <a href={`/eth/${address}`} className="address-link">
          {ensName || `${address.slice(0, 8)}...${address.slice(-6)}`}
        </a>
      </div>
    </div>
  )
}

// ─── Fingerprint Detail ─────────────────────────────────────────────────────

function FingerprintDetail({ fingerprint }) {
  const [claims, setClaims] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [verifications, setVerifications] = useState({})

  // Fetch all Attested events for this fingerprint via indexed fingerprintHash
  useEffect(() => {
    if (!REGISTRY_ADDRESS || !fingerprint) return
    let cancelled = false
    setIsLoading(true)
    setError(null)

    async function load() {
      try {
        // fingerprintHash is indexed as keccak256 of the lowercase fingerprint
        const logs = await getLogsChunked({
          address: REGISTRY_ADDRESS,
          event: parseAbiItem('event Attested(address indexed ethAddress, string indexed fingerprintHash, string fingerprint, string pgpSignature, string pgpPublicKey, uint256 index, uint256 timestamp)'),
          fromBlock: CONTRACT_DEPLOY_BLOCK,
          toBlock: 'latest',
        })

        if (cancelled) return

        // Filter to matching fingerprint (case-insensitive) and check revocation status
        const matching = []
        for (const log of logs) {
          if (log.args.fingerprint.toUpperCase() !== fingerprint.toUpperCase()) continue
          const addr = log.args.ethAddress
          const idx = Number(log.args.index)

          // Check if this attestation is still active
          let revoked = false
          try {
            const [, , isRevoked] = await mainnetClient.readContract({
              address: REGISTRY_ADDRESS,
              abi: REGISTRY_ABI,
              functionName: 'getAttestation',
              args: [addr, BigInt(idx)],
            })
            revoked = isRevoked
          } catch {}

          matching.push({
            address: addr,
            index: idx,
            fingerprint: log.args.fingerprint,
            pgpSignature: log.args.pgpSignature,
            pgpPublicKey: log.args.pgpPublicKey,
            timestamp: Number(log.args.timestamp),
            txHash: log.transactionHash,
            revoked,
          })
        }

        if (!cancelled) {
          setClaims(matching)
          setIsLoading(false)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err)
          setIsLoading(false)
        }
      }
    }

    load()
    return () => { cancelled = true }
  }, [fingerprint])

  // Verify PGP proofs for each claim
  useEffect(() => {
    if (claims.length === 0) return
    let cancelled = false
    async function run() {
      const results = {}
      for (const claim of claims) {
        const key = `${claim.address}-${claim.index}`
        if (claim.pgpPublicKey && claim.pgpSignature) {
          results[key] = await verifyAttestation({
            pgpPublicKey: claim.pgpPublicKey,
            pgpSignature: claim.pgpSignature,
            fingerprint: claim.fingerprint,
            ethAddress: claim.address,
          })
        } else {
          results[key] = { verified: false, reason: 'No PGP data' }
        }
      }
      if (!cancelled) setVerifications(results)
    }
    run()
    return () => { cancelled = true }
  }, [claims])

  // Find the first verified, non-revoked claim for PGP key display
  const bestClaim = useMemo(() => {
    for (const claim of claims) {
      const key = `${claim.address}-${claim.index}`
      if (!claim.revoked && verifications[key]?.verified) return claim
    }
    // Fall back to first non-revoked claim
    return claims.find(c => !c.revoked) || null
  }, [claims, verifications])

  if (isLoading) {
    return <div className="status info" style={{ marginTop: 24 }}>Querying registry...</div>
  }

  if (error) {
    return <div className="status err" style={{ marginTop: 24 }}>Query failed: {error.message}</div>
  }

  const activeClaims = claims.filter(c => !c.revoked)
  const revokedClaims = claims.filter(c => c.revoked)

  return (
    <div className="detail-page fade-in">
      <div className="detail-header">
        <div className="detail-label">PGP Fingerprint</div>
        <div className="detail-address-row">
          <span className="detail-address">{fingerprint.toUpperCase()}</span>
          <button className="copy-btn" onClick={(e) => copyToClipboard(fingerprint.toUpperCase(), e)}>copy</button>
        </div>
      </div>

      <div className="detail-summary">
        <div className="detail-label">Claims ({claims.length})</div>
        {activeClaims.length > 0 ? (
          <div className="attestation-table-wrap">
            <table className="attestation-table">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Date</th>
                  <th>Status <span className="info-icon" title="Active: identity claim is live on-chain. Revoked: owner has revoked this seal.">?</span></th>
                  <th>PGP <span className="info-icon" title="Verified: the PGP clearsign block stored in the event log is cryptographically valid for this key and binds it to this address. Unverified: signature check failed or PGP data is missing.">?</span></th>
                </tr>
              </thead>
              <tbody>
                {activeClaims.map(claim => {
                  const key = `${claim.address}-${claim.index}`
                  const v = verifications[key]
                  return (
                    <tr key={key}>
                      <td><ClaimAddressCell address={claim.address} /></td>
                      <td className="att-date">{formatDate(claim.timestamp)}</td>
                      <td><span className="status-badge active">active</span></td>
                      <td>
                        {v ? (
                          <span className={`status-badge ${v.verified ? 'verified' : 'unverified'}`}
                            title={v.verified ? 'PGP signature verified' : v.reason}>
                            {v.verified ? 'verified' : 'unverified'}
                          </span>
                        ) : (
                          <span className="status-badge" style={{ opacity: 0.4 }}>...</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
                {revokedClaims.map(claim => {
                  const key = `${claim.address}-${claim.index}`
                  return (
                    <tr key={key} style={{ opacity: 0.5 }}>
                      <td><ClaimAddressCell address={claim.address} /></td>
                      <td className="att-date">{formatDate(claim.timestamp)}</td>
                      <td><span className="status-badge revoked">revoked</span></td>
                      <td></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="status info" style={{ marginTop: 0 }}>
            No active claims found for this fingerprint.
            <div style={{ marginTop: 8 }}>
              <a href="/signet" className="fingerprint-link" target="_blank" rel="noopener noreferrer">
                Create an identity claim on Signet →
              </a>
            </div>
          </div>
        )}
      </div>

      {bestClaim?.pgpPublicKey ? (
        <PgpKeyInfo armoredKey={bestClaim.pgpPublicKey} />
      ) : claims.length > 0 && (
        <div className="detail-history">
          <div className="mono-box" style={{ marginBottom: 2 }}>
            <div className="label">Identity Proofs</div>
            <div className="value" style={{ color: 'var(--color-text-muted)' }}>No proofs found</div>
            <div className="proof-docs-footer">
              <a href="https://docs.thurin.id/#/scry/proofs" target="_blank" rel="noopener noreferrer">how to add proofs</a>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Scry ───────────────────────────────────────────────────────────────────

function Scry() {
  const [query, setQuery] = useState(() => parseRoute()?.value || '')
  const [submitted, setSubmitted] = useState(() => parseRoute())
  const [cardTheme, setCardTheme] = useState(
    () => document.documentElement.dataset.theme || 'thurin'
  )

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setCardTheme(document.documentElement.dataset.theme || 'thurin')
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => observer.disconnect()
  }, [])

  const inputType = detectInputType(query)

  // On mount + popstate, parse route and auto-submit
  useEffect(() => {
    function onRoute() {
      const route = parseRoute()
      if (route) {
        setQuery(route.value)
        setSubmitted(route)
      } else if (window.location.pathname === '/') {
        setQuery('')
        setSubmitted(null)
      }
    }
    onRoute()
    window.addEventListener('popstate', onRoute)
    window.addEventListener('hashchange', onRoute)
    return () => {
      window.removeEventListener('popstate', onRoute)
      window.removeEventListener('hashchange', onRoute)
    }
  }, [])

  // Resolve key ID (16 hex chars) → full fingerprint via keyserver
  const [keyIdResolving, setKeyIdResolving] = useState(false)
  const [keyIdError, setKeyIdError] = useState(null)
  useEffect(() => {
    if (submitted?.type !== 'keyId') return
    let cancelled = false
    setKeyIdResolving(true)
    setKeyIdError(null)

    fetch(`https://keys.openpgp.org/vks/v1/by-keyid/${submitted.value}`)
      .then(resp => {
        if (!resp.ok) throw new Error('Key ID not found on keyserver')
        return resp.text()
      })
      .then(armored => readKey({ armoredKey: armored }))
      .then(key => {
        if (cancelled) return
        const fullFingerprint = key.getFingerprint().toUpperCase()
        setQuery(fullFingerprint)
        setSubmitted({ type: 'fingerprint', value: fullFingerprint })
        pushRoute('fingerprint', fullFingerprint)
        setKeyIdResolving(false)
      })
      .catch(err => {
        if (cancelled) return
        setKeyIdError(err.message)
        setKeyIdResolving(false)
      })

    return () => { cancelled = true }
  }, [submitted?.type, submitted?.value])

  const handleLookup = useCallback(() => {
    if (!inputType) return
    const value = query.trim()
    if (inputType === 'keyId') {
      setSubmitted({ type: 'keyId', value })
      pushRoute('keyId', value)
    } else {
      setSubmitted({ type: inputType, value })
      pushRoute(inputType, value)
    }
  }, [query, inputType])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleLookup()
  }

  // ─── ENS resolution ─────────────────────────────────────────────────────

  const normalizedEns = submitted?.type === 'ens' ? safeNormalize(submitted.value) : null
  const {
    data: ensResolvedAddress,
    isLoading: ensLoading,
    error: ensError,
  } = useEnsAddress({
    name: normalizedEns,
    chainId: mainnet.id,
    query: { enabled: !!normalizedEns },
  })

  const lookupAddress = submitted?.type === 'address' ? submitted.value
    : submitted?.type === 'ens' ? ensResolvedAddress
    : null

  const {
    data: reverseEns,
  } = useEnsName({
    address: submitted?.type === 'address' ? submitted.value : undefined,
    chainId: mainnet.id,
    query: { enabled: submitted?.type === 'address' },
  })

  // ─── Contract reads ─────────────────────────────────────────────────────

  // Step 1: Get attestation count
  const {
    data: attestationCount,
    isLoading: countLoading,
    error: countError,
  } = useReadContract({
    address: REGISTRY_ADDRESS,
    abi: REGISTRY_ABI,
    functionName: 'attestationCount',
    args: lookupAddress ? [lookupAddress] : undefined,
    chainId: mainnet.id,
    query: { enabled: !!REGISTRY_ADDRESS && !!lookupAddress },
  })

  // Step 2: Multicall all attestations
  const count = attestationCount !== undefined ? Number(attestationCount) : 0
  const attestationContracts = useMemo(() => {
    if (!lookupAddress || !REGISTRY_ADDRESS || count === 0) return []
    return Array.from({ length: count }, (_, i) => ({
      address: REGISTRY_ADDRESS,
      abi: REGISTRY_ABI,
      functionName: 'getAttestation',
      args: [lookupAddress, BigInt(i)],
      chainId: mainnet.id,
    }))
  }, [lookupAddress, count])

  const {
    data: allAttestations,
    isLoading: attestationsLoading,
    error: attestationsError,
  } = useReadContracts({
    contracts: attestationContracts,
    query: { enabled: attestationContracts.length > 0 },
  })

  // Step 3: Fetch event logs for rich data (pgpSignature, pgpPublicKey)
  const [eventLogs, setEventLogs] = useState({})
  useEffect(() => {
    if (!lookupAddress || !REGISTRY_ADDRESS || count === 0) return
    let checksummed
    try { checksummed = getAddress(lookupAddress) } catch { return }
    getLogsChunked({
      address: REGISTRY_ADDRESS,
      event: parseAbiItem('event Attested(address indexed ethAddress, string indexed fingerprintHash, string fingerprint, string pgpSignature, string pgpPublicKey, uint256 index, uint256 timestamp)'),
      args: { ethAddress: checksummed },
      fromBlock: CONTRACT_DEPLOY_BLOCK,
      toBlock: 'latest',
    }).then(logs => {
      const byIndex = {}
      for (const log of logs) {
        const idx = Number(log.args.index)
        byIndex[idx] = {
          pgpSignature: log.args.pgpSignature,
          pgpPublicKey: log.args.pgpPublicKey,
          txHash: log.transactionHash,
        }
      }
      setEventLogs(byIndex)
    }).catch(() => {})
  }, [lookupAddress, count])

  // Step 4: Post-process into display-ready data (newest first)
  const attestationsRaw = useMemo(() => {
    if (!allAttestations) return []
    return allAttestations
      .map((item, index) => {
        if (item.status !== 'success') return null
        const [fingerprint, createdAt, revoked] = item.result
        const event = eventLogs[index] || {}
        return {
          index,
          fingerprint,
          createdAt: Number(createdAt),
          revoked,
          pgpSignature: event.pgpSignature || null,
          pgpPublicKey: event.pgpPublicKey || null,
          txHash: event.txHash || null,
        }
      })
      .filter(Boolean)
      .reverse()
  }, [allAttestations, eventLogs])

  // Step 5: Verify PGP proofs for each attestation
  const [verifications, setVerifications] = useState({})
  useEffect(() => {
    if (attestationsRaw.length === 0 || !lookupAddress) return
    let cancelled = false
    async function run() {
      const results = {}
      for (const att of attestationsRaw) {
        if (att.pgpPublicKey && att.pgpSignature) {
          results[att.index] = await verifyAttestation({
            pgpPublicKey: att.pgpPublicKey,
            pgpSignature: att.pgpSignature,
            fingerprint: att.fingerprint,
            ethAddress: lookupAddress,
          })
        } else {
          results[att.index] = { verified: false, reason: 'No PGP data in event logs' }
        }
      }
      if (!cancelled) setVerifications(results)
    }
    run()
    return () => { cancelled = true }
  }, [attestationsRaw, lookupAddress])

  // Merge verification results into attestations
  const attestations = useMemo(() => {
    return attestationsRaw.map(a => ({
      ...a,
      verification: verifications[a.index] || null,
    }))
  }, [attestationsRaw, verifications])

  const isAddressLookup = submitted?.type === 'address' || submitted?.type === 'ens'
  const isLoading = (isAddressLookup && (countLoading || attestationsLoading)) || ensLoading
  const error = countError || attestationsError
  const noContract = !REGISTRY_ADDRESS

  // Derive ENS name for display
  const displayEns = submitted?.type === 'ens' ? submitted.value
    : submitted?.type === 'address' ? reverseEns
    : null

  const { data: ensAvatar } = useEnsAvatar({
    name: displayEns ? safeNormalize(displayEns) : undefined,
    chainId: mainnet.id,
    query: { enabled: !!displayEns },
  })

  return (
    <>
      <div className="search-section">
        <div className="scry-input-row">
          <input
            className="text-input"
            placeholder="0x address, ENS name, or PGP fingerprint"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            spellCheck={false}
          />
          <button
            className="btn btn-primary"
            onClick={handleLookup}
            disabled={!inputType}
          >
            Lookup
          </button>
        </div>

        {query.trim() && !inputType && (
          <div className="status info" style={{ marginTop: 12 }}>
            Enter a valid ETH address (0x, 42 chars), ENS name (e.g. vitalik.eth), PGP fingerprint (40 hex chars), or key ID (16 hex chars).
          </div>
        )}

        {query.trim() && inputType && (
          <div className="scry-detected" style={{ marginTop: 8 }}>
            Detected: <span className="scry-type">{inputType === 'keyId' ? 'key ID' : inputType}</span>
          </div>
        )}
        {!submitted && (
          <>
            <p className="helper" style={{ marginTop: 16, marginBottom: 0, textAlign: 'center' }}>
              Don't have an identity claim yet? <a href="/signet" target="_blank" rel="noopener noreferrer">Create one on Signet</a>.
            </p>
            <h2 className="homepage-headline">See the full picture behind any Ethereum identity.</h2>
            <div className="homepage-cards">
              <IdentityKitProvider neynarApiKey={import.meta.env.VITE_NEYNAR_API_KEY}>
                <ScryCard ens="vitalik.eth" theme={cardTheme} />
                <ScryCard ens="bendoubleu.eth" theme={cardTheme} />
              </IdentityKitProvider>
            </div>
            <p className="homepage-cta">
              Add your identity to any website. <a href="https://docs.thurin.id/#/sdk" target="_blank" rel="noopener noreferrer">Get the embed</a>.
            </p>
          </>
        )}
      </div>

      <div className="scry-results">
        {/* Key ID resolving */}
        {keyIdResolving && (
          <div className="status info" style={{ marginTop: 24 }}>
            Resolving key ID {submitted?.value}...
          </div>
        )}
        {keyIdError && (
          <div className="status err" style={{ marginTop: 24 }}>
            Could not resolve key ID: {keyIdError}
          </div>
        )}

        {/* ENS resolving */}
        {submitted?.type === 'ens' && ensLoading && (
          <div className="status info" style={{ marginTop: 24 }}>
            Resolving {submitted.value}...
          </div>
        )}

        {/* ENS resolution failed */}
        {submitted?.type === 'ens' && !ensLoading && ensError && (
          <div className="status err" style={{ marginTop: 24 }}>
            Could not resolve ENS name: {ensError.shortMessage || ensError.message}
          </div>
        )}

        {/* ENS resolved but no address found */}
        {submitted?.type === 'ens' && !ensLoading && !ensError && !ensResolvedAddress && (
          <div className="status err" style={{ marginTop: 24 }}>
            No address found for {submitted.value}
          </div>
        )}

        {/* Contract not deployed — fallback with whatever data we have */}
        {noContract && submitted && (submitted.type !== 'ens' || ensResolvedAddress) && (
          <div className="result-card fade-in" style={{ marginTop: 24 }}>
            <div className="result-card-header">
              <span className="result-card-label">Registry Status</span>
            </div>
            <div className="result-card-body">
              <div className="status info">
                The PGPRegistry contract is not yet deployed. Once deployed to Sepolia, lookups will query on-chain data.
                <div style={{ marginTop: 8 }}>
                  <a href="/signet" className="fingerprint-link" target="_blank" rel="noopener noreferrer">
                    Create an identity claim on Signet →
                  </a>
                </div>
              </div>
              {submitted.type === 'ens' && ensResolvedAddress && (
                <>
                  <div className="mono-box" style={{ marginTop: 16 }}>
                    <div className="label">ens name</div>
                    <div className="value">{submitted.value}</div>
                  </div>
                  <div className="mono-box" style={{ marginTop: 8 }}>
                    <div className="label">resolved address</div>
                    <div className="value">{ensResolvedAddress}</div>
                  </div>
                </>
              )}
              {submitted.type === 'address' && (
                <div className="mono-box" style={{ marginTop: 16 }}>
                  <div className="label">queried address</div>
                  <div className="value">
                    {submitted.value}
                    {reverseEns && <span className="ens-reverse"> ({reverseEns})</span>}
                  </div>
                </div>
              )}
              {submitted.type === 'fingerprint' && (
                <div className="mono-box" style={{ marginTop: 16 }}>
                  <div className="label">queried fingerprint</div>
                  <div className="value">{submitted.value}</div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Address/ENS detail page */}
        {!noContract && isAddressLookup && lookupAddress && attestationCount !== undefined && (
          <AddressDetail
            address={lookupAddress}
            ensName={displayEns}
            ensAvatar={ensAvatar}
            attestations={attestations}
            count={count}
            isLoading={attestationsLoading}
            error={attestationsError}
          />
        )}

        {/* Fingerprint detail page */}
        {!noContract && submitted?.type === 'fingerprint' && (
          <FingerprintDetail fingerprint={submitted.value} />
        )}

        {/* Loading (contract reads) */}
        {!noContract && isLoading && submitted && !ensLoading && (
          <div className="status info" style={{ marginTop: 24 }}>
            Querying registry...
          </div>
        )}
      </div>
    </>
  )
}

// ─── Root App ───────────────────────────────────────────────────────────────

export default function App() {
  const isSignet = typeof window !== 'undefined' && window.location.pathname.startsWith('/signet')

  return (
    <div className="app">
      <Topbar />

      {isSignet ? <Signet /> : <Scry />}

      <footer className="footer">
        <span className="footer-version">scry v0.4.1</span>
        <div className="footer-columns">
          <div className="footer-col">
            <span className="footer-col-label">Home</span>
            <a href="https://thurinlabs.id" target="_blank" rel="noopener noreferrer">Thurin Labs</a>
            <a href="/signet">Signet</a>
            <a href="https://thurinlabs.id/privacy/" target="_blank" rel="noopener noreferrer">Privacy</a>
          </div>
          <div className="footer-col">
            <span className="footer-col-label">Social</span>
            <a href="https://x.com/thurinlabs" target="_blank" rel="noopener noreferrer">X</a>
            <a href="https://farcaster.xyz/thurinlabs.eth" target="_blank" rel="noopener noreferrer">Farcaster</a>
            <a href="https://www.linkedin.com/company/thurin-labs/" target="_blank" rel="noopener noreferrer">LinkedIn</a>
          </div>
          <div className="footer-col">
            <span className="footer-col-label">Dev</span>
            <a href="https://codeberg.org/thurinlabs" target="_blank" rel="noopener noreferrer">Codeberg</a>
            <a href="https://github.com/thurinlabs" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://docs.thurin.id" target="_blank" rel="noopener noreferrer">Docs</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
