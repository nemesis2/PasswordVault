# Security Policy

## Reporting a vulnerability

If you believe you've found a security issue, please report it privately rather
than opening a public issue:

- Email the maintainer (see the repository owner's profile), subject line
  prefixed `[vault-security]`.
- Include a description, affected file(s)/version, and a proof-of-concept if you
  have one.
- Please give a reasonable window to respond before any public disclosure.

This is a personal, self-hosted project maintained on a best-effort basis — there
is no bug bounty, but credible reports are taken seriously and credited if you wish.

## What this project protects

All encryption and decryption happen **in the browser**; the server only stores
and serves ciphertext and never sees a plaintext password or a master key.

- **At rest** every record is protected by a four-cipher cascade
  (ChaCha20-Poly1305 → AES-256-GCM → Twofish-256-CTR → Serpent-256-CTR) under two
  independent master keys, each derived with memory-hard **Argon2id**. Entry
  **names are encrypted** too — the plaintext appears nowhere in storage.
- **Two passwords** are required to derive any record's keys; omitting the second
  fails closed.
- **Length-hiding padding** pads each payload to a 256-byte bucket so ciphertext
  length doesn't leak secret length.
- **Vault integrity** is signed by a keyed HMAC manifest (`vm2`) that only a
  password holder can forge — it detects tampering, corruption, and rollback of
  the whole record set, which per-record authentication alone cannot.
- **Transport / access**: writes are HTTP Basic-Auth + CSRF gated and
  brute-force throttled; a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`,
  no inline scripts) and sensitive-file deny rules protect the served app.
- **Passkeys**: the browser extensions can act as a WebAuthn authenticator. The
  passkey's ECDSA P-256 private key is stored inside a record's encrypted payload —
  protected by the same cascade and master keys as every other secret — and is never
  persisted in extension storage. Creating one is the extensions' only write and is
  Basic-Auth gated; signing in is read-only (`signCount` 0). The PWA can only display
  and delete passkeys.

See **[THREAT_MODEL.md](THREAT_MODEL.md)** for the assumptions, the explicit
non-goals, and where the protections stop.

## Scope notes for reporters

The following are **known, documented design choices**, not vulnerabilities — please
read [THREAT_MODEL.md](THREAT_MODEL.md) before reporting them:

- The default `pass` / `word` Basic-Auth credentials are placeholders meant to be
  changed per deployment.
- A fully compromised server that can rewrite the served `javascript.js` defeats
  in-page integrity checks (in-band limitation — addressed out-of-band by the
  browser-extension code-pinning approach on the roadmap).
- The encrypted KeePass `.kdbx` binary format is not importable by design (export
  to KeePass XML / CSV first).
