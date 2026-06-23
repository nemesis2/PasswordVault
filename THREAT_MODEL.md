# Threat Model

This document states what the vault defends against, what it deliberately does
**not**, and why. It is the reference for "is this a bug?" questions.

## Deployment assumptions

The reference deployment is a **self-hosted, LAN-only** instance reached over:

- a private LAN, optionally via **VPN** for remote access, and
- **HTTPS/TLS** end-to-end.

Under those assumptions, **server compromise is out of scope** (router/host
compromise = game over). This is an intentional boundary for a personal,
self-hosted tool, not an oversight.

## What is in scope (and defended)

| Threat | Defense |
|--------|---------|
| Theft of the stored ciphertext (`lines`, backups) | Four-cipher cascade under two Argon2id-derived master keys; encrypted entry names; length-hiding padding |
| Offline brute force of a stolen vault | Memory-hard Argon2id (default m=128 MiB, t=3; tunable up to 1 GiB / t=10) over per-record salts |
| Tampering / corruption / rollback of the record set | Keyed `vm1` HMAC integrity manifest (only a password holder can forge); monotonic revision with a per-device high-water mark |
| Unauthorized writes | HTTP Basic-Auth + same-origin/CSRF check, constant-time credential compare |
| Online password guessing against the write endpoint | Per-IP sliding-window rate limit (5 fails / 15 min) |
| Passive data exposure of the served files | CSP (no inline scripts), sensitive-file deny rules, `no-store`, COOP/CORP/HSTS |
| A single weak cipher or a future cryptanalytic break | Defense-in-depth cascade — all four layers must fall |
| Clipboard secret lingering | 45-second auto-clear of copied secrets; immediate wipe on lock |
| Walk-away exposure | 5-minute inactivity auto-lock that wipes the key cache and re-locks names |

## Explicit non-goals (NOT defended) — by design

- **A compromised server.** Anything that can rewrite the served `javascript.js`
  can exfiltrate plaintext as you type. The `vm1` manifest protects vault **data**
  integrity, **not the code** — this is an in-band limitation acknowledged up
  front. The roadmap's strongest mitigation is **out-of-band**: a browser
  extension that pins the SHA-256 of `javascript.js`. The bundled service worker
  (`sw.js`) is a first step (it can report the running bundle's hash) but does
  **not** itself defeat a compromised server.
- **A brand-new device with no history.** It trusts the first vault state it sees
  (no prior revision to compare against) — trust-on-first-use.
- **Endpoint compromise / malware / hardware keyloggers** on the client device.
- **Metadata about *when* you use the vault** (request timing) beyond what TLS hides.
- **The default placeholder credentials.** `pass`/`word` are meant to be changed
  per deployment; they are kept as-is only on the maintainer's LAN-only dev box.
- **Recovery from a forgotten master password.** There is intentionally no
  backdoor — losing both passwords means losing the vault. (A recovery mechanism
  is a roadmap item; see [suggestions.md](suggestions.md).)

## Cryptographic construction (summary)

- **KDF:** `MK1 = Argon2id(pw1, salt1)`, `MK2 = Argon2id(pw2, salt2)` per record;
  `HKDF-SHA-256` expands each into independent per-cipher subkeys. Cost is
  vault-wide and tunable (`kdfparams`).
- **Payload:** `ChaCha20-Poly1305 → AES-256-GCM → Twofish-256-CTR →
  Serpent-256-CTR`. The two inner AEAD layers provide authentication; the outer
  CTR layers add cipher diversity.
- **Names:** `AES-256-GCM(pw1) → ChaCha20-Poly1305(pw2)`.
- **Integrity:** `vm1` = `HMAC-SHA-256(vaultKey, header + "\n" +
  sortedRecords.join("\n"))`, `vaultKey = HKDF(Argon2id(pw1,s1) ‖
  Argon2id(pw2,s2))`.
- **Passkeys (extension authenticator):** WebAuthn credentials are **ECDSA
  P-256 (ES256)**. The private key (`privateKeyJwk`) is stored inside an ordinary
  record's encrypted payload, so it is protected by the same cascade + KDF as every
  other secret — the server never sees it in the clear. Attestation is `fmt:"none"`
  (no device attestation), and `signCount` stays `0`, so using a passkey to sign in
  is a read-only operation. Only the browser extensions create or sign passkeys; the
  PWA can only display and delete them.

All primitives are WebCrypto (AES-GCM, HKDF, HMAC) plus audited inlined bundles
(ChaCha20-Poly1305 from `@noble/ciphers`, Twofish from `twofish-ts`, Argon2id from
`hash-wasm`) and a vector-verified Serpent implementation. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how the bundles are built and verified.
