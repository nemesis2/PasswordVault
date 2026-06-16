# Password Vault

A self-hosted, zero-knowledge password manager that runs entirely in your browser. Every entry — including its **name** — is encrypted on your device with a four-cipher cascade and a memory-hard key-derivation function before it is sent anywhere. The server stores and serves ciphertext only; it never sees a master key or a single plaintext byte.

No accounts, no cloud, no JavaScript framework, no database server, no runtime dependencies fetched from a CDN. One directory, one flat file, one PHP script. [MIT-licensed](LICENSE).

---

## Screen Shots

### Main Body
![Screenshot](/images/vault-screenshot-1.jpg "Vault Screenshot")

### New Entry 
![Screenshot](/images/vault-screenshot-2.jpg "Vault Screenshot")

### About
![Screenshot](/images/vault-screenshot-3.jpg "Vault Screenshot")

---

## Vault Architecture

![Screenshot](/images/vault-architecture.jpg "Architecture Layout Screenshot")

---

## Overview

The vault is a single page served by any PHP-capable web server. Unlocking it takes **two independent master passwords** — both are required to decrypt anything; either one alone reveals nothing, not even entry names.

**At a glance:**

- 🔐 **Client-side encryption only** — AES-256-GCM, ChaCha20-Poly1305, Twofish-256-CTR, and Serpent-256-CTR layered in series, with keys derived by Argon2id (64 MiB memory-hard) and expanded via HKDF-SHA-256
- 🕶 **Encrypted entry names** — the stored database leaks no metadata; the entry grid shows 🔒 placeholders until both passwords are entered
- 🔢 **Built-in 2FA (TOTP)** — stores authenticator secrets and shows live 6-digit codes with a countdown ring; import secrets by scanning a QR code
- 🎲 **Password generator** — configurable character sets, length- or entropy-targeted, with a live strength meter
- 📊 **Vault-key strength indicator** — a combined strength bar for both master passwords updates live as you type; the ＋ New button is disabled (labeled **"Too Weak"**) until the combined entropy exceeds 45 bits, blocking new entries under trivially guessable keys
- 🧰 **Vault tools** — one-click encrypted export, a local-only password audit (reused / weak / empty), whole-vault master-password rotation, and integrity signing
- 🔏 **Integrity manifest** — a keyed HMAC-SHA-256 over the entire record set (signed under both master passwords) is verified on every unlock; tampering, corruption, and rolled-back copies are detected with a badge above the entry list
- 🔍 **Live search**, ✏ **edit**, 🗑 **delete**, and instant in-place grid updates — no page reloads
- ⏱ **Auto-lock** after 5 minutes idle (with a 60-second warning), instant lock on double-Escape, and **clipboard auto-clear** 45 seconds after copying a secret
- 🧪 **Runtime self-test** — every cipher and the Argon2id WASM are verified on every page load; failures raise a warning before you type a password
- 🤝 **Concurrency-safe writes** — entries are deleted/edited by content (never by position), the whole read-modify-write runs under an exclusive lock, and every write is preceded by an automatic backup
- 📱 Responsive single-column layout that works on mobile, including camera QR scanning

**Requirements:** a web server with PHP (Apache, nginx + PHP-FPM, or just `php -S`). PHP must be able to write `lines`, `bak/`, and `index.html` in the vault directory. Everything else happens in the browser.

---

## How it works

```
plaintext JSON ──▶ ChaCha20-Poly1305 ──▶ AES-256-GCM ──▶ Twofish-256-CTR ──▶ Serpent-256-CTR ──▶ stored hex
                   (password 1, AEAD)     (password 1, AEAD)  (password 2)        (password 2)
```

- Each record carries two random 32-byte salts. From these, **Argon2id** (m = 128 MiB, t = 3, p = 1 by default) derives one master key per password, and **HKDF-SHA-256** expands each into independent per-cipher subkeys — so the expensive memory-hard step runs only twice per record while every layer still gets its own key. The Argon2id cost is **vault-wide and tunable** (see [*Vault tools*](#vault-tools)): it lives in the `kdfparams` file (and is embedded in the page), so changing it re-encrypts the whole vault atomically and the read-only/offline copy still derives keys at the right cost.
- **Length-hiding padding:** the plaintext is padded up to the next 256-byte boundary (with trailing spaces) before encryption, so the stored ciphertext length reveals only the 256-byte bucket an entry falls in — not the true length of a password or note. The pad is trailing JSON whitespace, discarded automatically on decrypt.
- The two inner layers are AEAD: a wrong password or a tampered byte produces a hard authentication failure, never garbled output or partial plaintext.
- The entry **name** is separately double-encrypted (AES-256-GCM under password 1, wrapped by ChaCha20-Poly1305 under password 2), so the database file exposes no plaintext at all.
- The four ciphers span three unrelated design lineages (ARX stream cipher, AES, and two AES finalists). Breaking one does not weaken the others.
- Argon2id derivations run on a pool of **Web Workers** (own WASM instance each), sized at the reported CPU core count (capped at 16 on desktop, 2 on phones/tablets) and further bounded by device memory, so unlocking a large vault stays responsive and peak memory stays bounded. A transient derivation failure is retried (falling back to the main thread) so no entry is silently dropped.

Records live one-per-line in a flat file (`lines`), sorted alphabetically:

```
encName | v6 | recSalt1 | recSalt2 | nameNonce1 | nameNonce2 | iv1 | nonce2 | nonce3 | nonce4 | ciphertext
```

The page itself (`index.html`) is generated server-side from two template fragments plus one button per record, and is rebuilt automatically on every save/delete.

---

## Quick start

1. Copy the vault directory onto a PHP-capable web server.
2. Set your write credentials: edit the `VAULT_AUTH_USER` / `VAULT_AUTH_PASS` constants at the top of `post.php`. **The shipped values are placeholders — change them.** They gate all writes (add/edit/delete) behind HTTP Basic Auth; reading the page needs no login.
3. Make sure the web-server user can write `lines`, `bak/`, and `index.html`.
4. On **Apache**, the bundled `.htaccess` files already block direct HTTP access to the data file, templates, and backups, and set the security headers. On **nginx**, `.htaccess` is ignored — apply the rules under [*Deploying behind nginx*](#deploying-behind-nginx) before going live.
5. Open the page, pick two strong master passwords, and add your first entry.

> ⚠️ **If you fork or publish this repository:** never commit your own `lines` file or `bak/` directory. They contain your (encrypted) password database — ciphertext, but still nothing you want public. Add them to `.gitignore`.

To test locally with no web server installed:

```bash
php -S localhost:8080
```

---

## User guide

### Unlocking

The two key fields at the top of the page take your master passwords:

- **Primary key** — used by the two inner encryption layers
- **Secondary key** — an independent password used by the two outer layers

Both are required. Enter them once per session; the eye button (👁) toggles visibility, Tab jumps from the first field to the second.

Entry buttons are hidden on page load because names are encrypted. When both passwords are entered and you tab or click away from the second field, all names decrypt in parallel (across the Web Worker pool) and the grid reveals in alphabetical order.

A **vault-key strength bar** (six segments) sits below the key fields and shows the combined entropy of both passwords while you type. The estimate uses character-class pool size × length, summed across both keys:

| Label | Combined entropy |
|-------|-----------------|
| Weak | < 45 bits |
| Fair | 45 – 79 bits |
| Strong | 80 – 114 bits |
| Very Strong | 115 – 149 bits |
| Exceptional | 150 – 184 bits |
| Paranoid | ≥ 185 bits |

While the combined total is below **45 bits**, the **＋ New** button is replaced with **"Too Weak"** and adding entries is blocked — this prevents encrypting new secrets under easily guessable master passwords. The bar is hidden when both fields are empty or after the integrity lock engages (see below).

Once both passwords decrypt the vault and the integrity check passes (**✓ Integrity verified**), both key fields and their visibility toggles are **disabled** for the rest of the session. This prevents accidentally editing a master password after names are revealed. Typing in either field immediately re-enables the inputs, re-hides all decrypted names, and clears the integrity badge — a full re-unlock (tab away from the second field) is required.

### Viewing an entry

Click any entry button. The fixed panel at the top fills in with the decrypted fields:

| Field | How to copy |
|-------|-------------|
| Username | Click the username area |
| Password | Click the password area |
| 2FA token | Click the token area |

A brief flash confirms the copy. If the entry's URL starts with `https://`, the name becomes a link that opens in a new tab. A wrong key or corrupted record shows **"Wrong key or corrupted entry"** — nothing partial is ever displayed.

**Copied secrets are auto-cleared from the clipboard after 45 seconds**, and immediately on any lock.

### 2FA / TOTP codes

If an entry stores a TOTP secret, the six-digit code appears automatically with a countdown ring showing the seconds left in the 30-second window. Clicking the token area copies the current code.

### Searching

Press 🔍 to open the search overlay and type — the list filters live. Click a result to decrypt it; **Escape** dismisses.

### Adding an entry

Click **＋ New** and fill in any combination of:

- **Name** (required) — the label on the entry button; cannot contain `|`
- **URL** — used as a clickable link after decryption
- **Username**
- **Password** — type one or generate one
- **2FA Token** — paste a Base32 TOTP secret, or click **📷 Scan QR** to read it from a QR code image (mobile opens the rear camera; desktop opens a file picker). Issuer and account from the QR pre-fill Name/Username if empty. Requires Chrome 83+, Edge 83+, or Safari 17.4+.
- **Notes** — free-form text; the field grows as you type

**Save Entry** updates the grid instantly without a reload.

#### Password generator

**Generate** fills the password field; **⚙️ Generator** opens its settings: toggle Uppercase / Lowercase / Digits / Symbols, add custom characters, and target either a fixed **length** (default 16) or a number of **entropy bits** (the generator computes the required length). The statistics line shows the actual entropy of the current settings; 📋 copies the generated password without saving.

#### Strength meter

A six-segment bar estimates the typed **entry password**'s entropy from its character classes × length:

| Label | Entropy |
|-------|---------|
| Weak | < 40 bits |
| Fair | 40 – 79 bits |
| Strong | 80 – 119 bits |
| Very Strong | 120 – 159 bits |
| Exceptional | 160 – 199 bits |
| Paranoid | ≥ 200 bits |

This bar measures only the entry's stored password field. The separate **vault-key strength bar** above the entry list measures the combined master-password strength — see [*Unlocking*](#unlocking).

### Editing and deleting

Decrypt an entry, then use the ✏ (edit) or 🗑 (delete, with confirmation) buttons in the decode panel. Edits are an atomic replace; deletes reference the record **by content**, so a change made meanwhile in another tab or on another device can never cause the wrong entry to be removed — if the entry changed under you, the vault answers "Entry was changed elsewhere" and refreshes instead.

### Vault tools

In the About panel (ℹ), the **Vault Tools** section offers five whole-vault operations:

- **⬇ Export** — downloads the encrypted database as `vault-export-YYYY-MM-DD.lines`, built entirely in the browser and byte-identical to the server's data file. Ciphertext only, safe to store as an offline backup.
- **⬆ Import / Restore** — replaces the entire vault from an exported `.lines` file. The file is validated, then **every record is decrypted with the passwords currently in the key fields before anything is sent** — so an import that doesn't match those passwords is refused and nothing changes, and a successful import is guaranteed to be fully readable. Committed as one atomic replace (the server keeps a backup of the previous vault first, so a restore is itself reversible), then re-signed at a fresh revision. Replace-only — it does not merge.
- **🔎 Audit** — decrypts every entry locally (both passwords required) and reports **reused**, **weak** (< 40 bits), and **empty** passwords. Only entry names are shown, and nothing leaves the device — there are no breach-check API calls by design (the CSP forbids all outbound connections).
- **🔑 Change Passwords** — rotates both master passwords: every entry is decrypted with the current passwords and re-encrypted under the new ones (fresh salts and nonces) in the browser, then committed to the server as **one atomic replace**. All-or-nothing: if any record fails to decrypt, or the vault changed mid-run from another device, nothing is modified. On success the session switches to the new passwords seamlessly (and the vault is re-signed under them).
- **✍ Sign** — manually re-signs the **integrity manifest** (see below). Only needed to accept a deliberate manual edit of the data file or a backup restore as the new baseline; normal saves re-sign automatically.

A separate **⚙ Change KDF Parameters** section directly below Vault Tools adjusts the Argon2id work factor (memory and iterations) for the whole vault. The passwords stay the same: every entry is decrypted at the current cost and re-encrypted at the new one, committed via the same all-or-nothing atomic replace as *Change Passwords*, with the new `kdfparams` written atomically alongside the records. Memory is bounded 64 MiB – 1 GiB and iterations 2 – 10 (parallelism fixed at 1); a preset slider and a per-device-class suggestion table help pick a value, and a no-op or out-of-range entry is refused. On success the new cost takes effect immediately, the worker pool re-sizes for the new memory budget, and the vault is re-signed — so a later attempt to downgrade the cost out-of-band is integrity-detectable.

### Vault integrity manifest

The vault carries a **keyed signature over the entire record set** — an HMAC-SHA-256 whose key is derived from *both master passwords* (Argon2id + HKDF). The server stores it but can never compute it, so only a password holder can produce a valid signature.

- **Verified on every unlock:** after the entry names are revealed, the browser recomputes the signature over the records it received and compares. A mismatch — an entry added, modified, or removed behind your back, or silent corruption — shows a red **integrity failure** badge instead of passing unnoticed. Per-record encryption alone can't catch this: each record authenticates itself, but nothing else binds the *set* together.
- **Rollback detection:** the manifest embeds a monotonically increasing **revision number**, and each device remembers the highest revision it has seen (in browser storage). Being served an older — validly signed — copy of the vault raises a rollback alarm.
- **Automatic re-signing:** every save, edit, delete, and password change re-signs the vault (revision +1). If another device wrote concurrently, the client resyncs and signs the merged state.
- **Status badge:** a line above the entry list (and in Vault Tools) shows ✓ verified with revision and timestamp, ⚠ unsigned, or a red failure/rollback alert.
- **Key-field lock:** a passing integrity check also *disables* both master-password input fields and their visibility toggles for the rest of the session. This prevents accidentally changing a master password after the vault has been verified and names are revealed. Typing in either key field re-enables them, clears the badge, and re-hides all decrypted names — a full re-unlock is required.
- **Honest limits:** this is tamper *detection* for the data file, in-band. It protects against corruption, botched restores, manual-edit mistakes, and tampering by anything that can't also rewrite the served JavaScript. An attacker who fully controls the server (and can serve modified code) defeats it — no in-band scheme can prevent that.

### Locking

- **Manual:** the ✕ button clears both keys and all decoded data (stored entries are untouched). **Escape twice** does the same instantly.
- **Auto-lock:** after **5 minutes** of inactivity a warning banner counts down from 60 seconds; click **Stay** to keep the session, or let it lock. Locking wipes the key fields, the derived-key cache, the worker pool, decoded data, audit results, and the clipboard (if it holds a copied secret).

### About panel & self-test

The ℹ button opens the About panel: record format, key-derivation parameters, the full encryption pipeline, the cipher-selection rationale, TOTP details, the Vault Tools, standards alignment, and library credits.

A **runtime self-test** (WebCrypto, all four ciphers round-trip, Argon2id known-answer) runs on **every page load** — a failure raises a warning dialog naming the failed check before you enter any password — and again each time the About panel opens, with a ↻ Retest button.

### Tooltips

Hover any button or interactive field for a brief description of what it does.

---

## Data safety & concurrency

- **Backups before every write:** the current database is copied to `bak/` (timestamped to the microsecond, so rapid writes can't collide) before any modification; the newest 50 are retained. A failed backup aborts the write.
- **Exclusive locking:** the entire read-modify-write — including the `index.html` rebuild — holds an exclusive `flock` on the database, so overlapping saves cannot lose each other's changes.
- **Content-addressed writes:** deletes and edits identify the record by its full ciphertext string (unique per record thanks to random salts), never by line position. A stale reference is refused with HTTP `409` and nothing is modified.
- **Atomic password rotation:** the bulk replace used by *Change Passwords* sends a hash of the exact snapshot that was re-encrypted; the server verifies it under the lock and refuses (`409`, untouched) if the vault changed in between.
- **Clear failure modes:** the UI distinguishes wrong write-credentials (401), rate-limit lockout (429, with the wait time), stale records (409), and blocked origins (403).

---

## Security notes

- **All encryption and decryption happens in your browser.** The server never sees your master keys or plaintext.
- **Writes require a separate login.** `post.php` is protected by HTTP Basic Auth (`VAULT_AUTH_USER` / `VAULT_AUTH_PASS` at the top of the file — set your own; the shipped values are placeholders). Your browser prompts the first time you save in a session. Only meaningful over HTTPS.
- **Write logins are rate-limited.** After 5 failed Basic-Auth attempts from one IP within 15 minutes, further attempts get `429` until the window clears. Blocked attempts don't extend the lockout; a success clears the history. The limiter fails open if its temp-dir state can't be written, so a misconfiguration can't lock you out of your own server.
- **Wrong keys fail hard.** The AEAD layers authenticate the ciphertext — there is no partial or garbled decryption.
- **The database leaks nothing.** Entries are ciphertext in a flat text file; names are encrypted too. Read access to the file is useless without both master passwords.
- **The record set is signed on every write.** A keyed HMAC (HMAC-SHA-256, key derived from both master passwords via Argon2id + HKDF) covers the entire sorted record set and is re-stored after every save. Verified on every unlock — tampering, silent deletion, corruption, and rolled-back copies are caught before you act on the data. The server stores the signature opaquely and cannot forge or verify it.
- **Key derivation is memory-hard.** Argon2id at 128 MiB per guess (the default; tunable up to 1 GiB) reduces a GPU farm that tests billions of fast hashes per second to a few thousand guesses per second per card.
- **Sessions are containable.** Auto-lock, double-Escape lock, clipboard auto-clear, and teardown of the worker pool (whose WASM heaps hold residual key material) all bound how long secrets stay in memory.
- **Server files are blocked from HTTP access** by the bundled `.htaccess` files — **on Apache only**. nginx ignores `.htaccess` entirely; apply the rules under [*Deploying behind nginx*](#deploying-behind-nginx) or the database file, templates, and backups are downloadable (ciphertext, but block them regardless).
- **No outbound connections.** The CSP's `connect-src 'self'` means the page can talk only to its own origin — no telemetry, no CDN, no breach-check APIs, no exfiltration channel.

### Standards alignment

| Standard | Status | Notes |
|---|---|---|
| Argon2 (RFC 9106) | Met | Argon2id key derivation, m = 128 MiB, t = 3, p = 1 by default (exceeds the RFC 9106 second-recommended option); tunable per vault up to m = 1 GiB, t = 10 |
| RFC 6238 | Met | TOTP with 30-second window and 6-digit codes |
| OWASP ASVS L1/L2 | Met | Client-side crypto, CSRF protection, Basic-Auth rate limiting, full security-header suite (CSP, HSTS, COOP/CORP, Permissions-Policy) |
| OWASP ASVS L3 | Partial | `style-src 'unsafe-inline'` still required by inline `style` attributes; `script-src` is `'self' 'wasm-unsafe-eval'` (latter only to compile the Argon2id WASM). Key derivation is memory-hard Argon2id |
| OWASP Secure Headers | Met | CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP all set |
| FIPS 140 | Partial | AES-256-GCM and HKDF-SHA-256 are FIPS-approved; ChaCha20, Twofish, Serpent and Argon2id are not |

---

## Architecture

| File | Role |
|------|------|
| `index.html` | The served page — **auto-generated**; rebuilt on every save/delete and via `post?regen=1` |
| `javascript.js` | All client logic and the inlined cipher bundles — the readable, editable source |
| `argon2-worker.js` | The Argon2id Web Worker (hash-wasm bundle + a small message handler) |
| `part1` / `part2` | HTML template fragments; `post.php` splices the entry buttons between them |
| `lines` | The flat-file ciphertext database, one record per line, sorted |
| `manifest` | The vault integrity manifest — a client-computed HMAC stored opaquely by the server; absent until the vault is first signed |
| `kdfparams` | The vault-wide Argon2id cost (`a2id\|memKiB\|t\|p`), written by *Change KDF Parameters* and embedded in the page; absent ⇒ the 128 MiB / t = 3 default |
| `post.php` | The only server-side code: validates, locks, backs up, writes, and rebuilds the page |
| `bak/` | Automatic pre-write backups of `lines` (newest 50 kept) |
| `.htaccess` | Apache-only access rules and security headers |

The server-side write API is deliberately tiny: `data=` (add), `delete_rec=` (delete by content), both together (atomic edit), `bulk=1` (atomic whole-vault replace for password rotation — optionally carrying a `kdf=` field so the records and the Argon2id cost change together), `restore=1` (atomic whole-vault replace for import — like `bulk` but the entry count may change), `sign=1` (store an integrity manifest without touching records), and `regen=1` (rebuild the page without touching data). Everything is validated against the strict v6 record shape before a byte is written.

---

## Deploying behind nginx

> ⚠️ **nginx does not read `.htaccess` files.** The bundled `.htaccess` files (which block the
> data files, templates, and backups, and set security headers) have **no effect** under nginx.
> Without the rules below, `lines`, `part1`, `part2`, and every file in `bak/` are served as
> plain downloads. Because the stored data is ciphertext this does not leak your passwords, but
> it does expose salts and the full encrypted database. Block the files regardless.

Add these to the **`server` block whose `root` actually serves the vault files** — not just any
server block. If you host the app under a sub-path (e.g. `/pass/<user>/`) and/or run several
instances, put the rules in the vhost that maps that URL to disk. (A real-world trap: deny rules
placed in a different vhost — one whose `root` doesn't contain `pass/` — validate fine and look
correct but protect nothing.)

The rules below assume a `/pass/<instance>/` sub-path layout and cover **every** instance at
once via `[^/]+`. If you serve a single vault at the site root, drop the `/pass/[^/]+` prefix
(e.g. `location ~ /(lines|manifest|kdfparams|part1|part2)$`).

```nginx
# Block the flat-file DB, KDF params, manifest, and HTML templates for every
# vault instance. (kdfparams is not secret — it is also embedded in index.html —
# but is denied for consistency with the manifest.)
location ~ /pass/[^/]+/(lines|manifest|kdfparams|part1|part2)$ {
    deny all;
}

# Block backups AND any legacy working directory (old DB copies, migration
# tooling) that may exist alongside an instance.
location ~ /pass/[^/]+/(bak|moved)/ {
    deny all;
}

# Block Apache leftovers (.htaccess etc.) from being served.
location ~ /\.ht {
    deny all;
}

# Security headers — the nginx equivalent of the bundled .htaccess CSP block.
# Apply at the server level so all responses (including PHP) inherit them.
# script-src is 'self' with NO 'unsafe-inline' (the HTML carries no inline handlers
# or <script>). 'wasm-unsafe-eval' is required ONLY so the inlined Argon2id WASM
# can compile (WASM compilation is blocked without it, even when embedded same-origin);
# it does not re-enable JS eval/inline scripts. worker-src 'self' permits the
# same-origin argon2-worker.js (the Argon2id Web Worker pool); applying these
# headers server-wide means that worker response carries the same CSP, so
# 'wasm-unsafe-eval' lets it compile its WASM too. style-src keeps 'unsafe-inline'
# for the inline style="" attributes.
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
# Force HTTPS. Add 'includeSubDomains; preload' only once EVERY subdomain is
# confirmed HTTPS-only — those tokens are hard to walk back.
add_header Strict-Transport-Security "max-age=63072000" always;
# Disable APIs the vault never uses; camera stays on for QR scanning.
add_header Permissions-Policy "camera=(self), geolocation=(), microphone=(), payment=(), usb=()" always;
# Cross-origin isolation — detach this context from openers/embedders.
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
# The vault HTML embeds the ciphertext DB — keep it out of on-disk caches.
# Scope this to the vault host only; do NOT set it globally on a host that also
# serves cache-friendly static content.
add_header Cache-Control "no-store" always;
```

> **nginx `add_header` gotcha:** if any `location` block defines its own `add_header`, it
> **replaces** (does not merge) the ones inherited from the server level. Keep all the
> `add_header` lines at the `server` level and avoid per-location `add_header` so they apply
> everywhere, including the `post` (PHP) endpoint and error responses.

After editing, validate and reload: `nginx -t && systemctl reload nginx`. Confirm the blocks
work against the **vhost that serves the vault** — requests to `…/pass/<user>/lines`, `/part1`,
`/part2`, `/bak/<anything>`, and `/moved/<anything>` should return `403`, while
`…/pass/<user>/index.html` and `/javascript.js` still return `200` with the headers present.
If nginx binds to a specific IP rather than `127.0.0.1`, point curl at it with `--resolve` so
both SNI and `Host` are correct:

```bash
H=your.host; IP=203.0.113.10
curl -sko /dev/null -w '%{http_code}\n' --resolve "$H:443:$IP" "https://$H/pass/master/lines"        # 403
curl -skI --resolve "$H:443:$IP" "https://$H/pass/master/index.html" | grep -i content-security      # header present, 200
```

---

## Libraries & attribution

The cryptographic primitives are third-party open-source implementations, bundled **inline** in `javascript.js` (and in `argon2-worker.js`). No external requests are made at runtime — the Argon2id WebAssembly is embedded as base64 rather than fetched. Each library is used under its own license, and the upstream license/attribution notices are retained inside the bundles. With gratitude to the authors:

| Library | Version | Author | License | Source | Used for |
|---------|---------|--------|---------|--------|----------|
| `@noble/ciphers` | — | Paul Miller ([paulmillr.com](https://paulmillr.com)) | MIT | [github.com/paulmillr/noble-ciphers](https://github.com/paulmillr/noble-ciphers) · [npm](https://www.npmjs.com/package/@noble/ciphers) | ChaCha20-Poly1305 |
| `twofish-ts` | 1.0.2 | Logan R. Kearsley | MIT | [github.com/gliese1337/twofish](https://github.com/gliese1337/twofish) · [npm](https://www.npmjs.com/package/twofish-ts) | Twofish-256 |
| `hash-wasm` | 4.12.0 | Dani Biró ([danibiro.com](https://danibiro.com)) | MIT | [github.com/Daninet/hash-wasm](https://github.com/Daninet/hash-wasm) · [npm](https://www.npmjs.com/package/hash-wasm) | Argon2id (WebAssembly) |

**Serpent-256** is **not** an npm dependency — no maintained package exists. It is a hand-written bitslice implementation of the forward block cipher (inlined into `javascript.js`), verified against [Bouncy Castle](https://www.bouncycastle.org/)'s 256-bit ECB test vectors. The Serpent cipher itself is in the public domain, designed by [Ross Anderson, Eli Biham, and Lars Knudsen](https://www.cl.cam.ac.uk/~rja14/serpent.html).

**AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256 (vault signing), and HMAC-SHA-1 (TOTP)** use the browser's native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — no third-party code.

**Build tooling (not shipped at runtime):** the npm bundles are produced with [esbuild](https://github.com/evanw/esbuild) (MIT — Evan Wallace). It is a development dependency only; no part of esbuild is served to the browser.

---

## License

This project is released under the [MIT License](LICENSE). The bundled third-party libraries are MIT-licensed as credited above; the Serpent cipher implementation is public domain.
