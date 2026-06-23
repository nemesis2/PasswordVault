# Password Vault

A self-hosted, zero-knowledge password manager that runs entirely in your browser. Every entry — including its **name** — is encrypted on your device with a four-cipher cascade and a memory-hard key-derivation function before it is sent anywhere. The server stores and serves ciphertext only; it never sees a master key or a single plaintext byte.

No accounts, no cloud, no database server, no runtime dependencies fetched from a CDN. One directory, one flat file, and your choice of backend — a single PHP script or the bundled dependency-free Node server ([`server.js`](#running-without-php-standalone-node-server)). [MIT-licensed](LICENSE).


Full disclosure: This originally started a simple custom built/hacked together AES vault that the author used for years.  
Then Claude was used to audit the code and slowly expand it.  

---

## Screen Shots

### Main Body
![Screenshot](/images/vault-screenshot-1.jpg "Vault Screenshot")

### New Entry 
![Screenshot](/images/vault-screenshot-2.jpg "Vault Screenshot")

### About
![Screenshot](/images/vault-screenshot-3.jpg "Vault Screenshot")

---

## Overview

The vault is a single page served by any PHP-capable web server — or by the bundled, dependency-free Node server ([`server.js`](#running-without-php-standalone-node-server)), with no PHP required. Unlocking it takes **two independent master passwords** — both are required to decrypt anything; either one alone reveals nothing, not even entry names.

**At a glance:**

- 🔐 **Client-side encryption only** — AES-256-GCM, ChaCha20-Poly1305, Twofish-256-CTR, and Serpent-256-CTR layered in series, with keys derived by Argon2id (memory-hard; 128 MiB default, tunable per vault) and expanded via HKDF-SHA-256; payloads are length-padded so ciphertext size doesn't leak secret length
- 🕶 **Encrypted entry names** — the stored database leaks no metadata; the entry grid shows 🔒 placeholders until both passwords are entered
- 🔢 **Built-in 2FA (TOTP)** — stores authenticator secrets and shows live codes with a countdown ring; supports the full `otpauth://` spec (custom digits / period / SHA-1·256·512) and **Steam Guard** codes, importable by scanning a QR code
- 🎨 **Light / dark theme** — a one-click toggle, remembered per vault
- 🖼 **Entry avatars** — each entry gets a colored monogram "favicon" derived locally from its name (no third-party favicon requests)
- 🎲 **Password generator** — configurable character sets, length- or entropy-targeted, with a live strength meter
- 📊 **Vault-key strength indicator** — a combined strength bar for both master passwords updates live as you type; the ＋ New button is disabled (labeled **"Too Weak"**) until the combined entropy exceeds 45 bits, blocking new entries under trivially guessable keys
- 🧰 **Vault tools** — one-click encrypted export and import/restore (atomic whole-vault replace, verified-readable before commit), **migration in** from CSV, **KeePass 2 XML**, and **1Password `.1pux`**, a local-only password audit (reused / weak / fair / empty / stale), a **trash bin** for restoring deleted entries, whole-vault master-password rotation, a tunable Argon2id work factor with a one-click **Calibrate** benchmark, and integrity signing
- 🔏 **Integrity manifest** — a keyed HMAC-SHA-256 over the entire record set (signed under both master passwords) is verified on every unlock; tampering, corruption, and rolled-back copies are detected with a badge above the entry list
- 🏷 **Tags, favorites & organization** — tag entries with a comma-separated list (encrypted in the payload like every other field), filter by **`#tag`**, **`@note`**, or **`!field`** with scoped live search, ⭐ **favorite** entries to pin them to the top, and group the entry grid under sticky **A–Z** headers
- 🧩 **Custom fields, password history & age** — add arbitrary labelled fields per entry (optionally masked as *secret*), all encrypted in the payload; editing an entry automatically archives the previous password (with a date) so you can recover an old one; a **Modified** column shows when the password last changed, with a hover tooltip giving the entry's creation date and age
- 📝 **Secure notes** — an entry type toggle for a title + encrypted body with no URL/username/password/2FA, for things that aren't logins
- ☑ **Multi-select & bulk operations** — a grid select mode to favorite, tag, or delete many entries at once in a single atomic write, with an Undo for bulk delete
- 🔍 **Live search**, ✏ **edit**, 🗑 **delete** (soft — recoverable from the trash), and instant in-place grid updates — no page reloads
- ⏱ **Auto-lock** after 5 minutes idle (with a 60-second warning), instant lock on double-Escape, and **clipboard auto-clear** 45 seconds after copying a secret
- 🧪 **Runtime self-test** — every cipher and the Argon2id WASM are verified on every page load; failures raise a warning before you type a password
- 🤝 **Concurrency-safe writes** — entries are deleted/edited by content (never by position), the whole read-modify-write runs under an exclusive lock, and every write is preceded by an automatic backup
- 🧩 **Browser autofill** — optional Firefox and Chrome/Edge extensions unlock the vault from the toolbar and autofill logins, decrypting locally with the vault's exact cipher code (see [*Browser extensions*](#browser-extensions-autofill-companion))
- 🔐 **Passkeys (WebAuthn)** — the extensions act as an authenticator, storing passkeys encrypted inside the vault and using them to sign in; the web app shows that a passkey is stored and can delete it (see [*Passkeys*](#passkeys))
- ⌨️ **Terminal client** — an optional Node.js TUI reads and writes the same `lines` file with the same v6 crypto, fully interoperable with the web app (see [*Terminal client*](#terminal-client-tui))
- 📱 Responsive single-column layout that works on mobile, including camera QR scanning

**Requirements:** a web server with PHP (Apache, nginx + PHP-FPM, or just `php -S`) **or** Node.js — the bundled [`server.js`](#running-without-php-standalone-node-server) runs the whole vault with no PHP and no external web server. The server (PHP or Node) must be able to write `lines`, `bak/`, and `index.html` in the vault directory. Everything else happens in the browser.

---

## How it works

```
plaintext JSON ──▶ pad to 256 B ──▶ ChaCha20-Poly1305 ──▶ AES-256-GCM ──▶ Twofish-256-CTR ──▶ Serpent-256-CTR ──▶ stored hex
                                     (password 1, AEAD)     (password 1, AEAD)  (password 2)        (password 2)
```

- Each record carries two random 32-byte salts. From these, **Argon2id** (m = 128 MiB, t = 3, p = 1 by default) derives one master key per password, and **HKDF-SHA-256** expands each into independent per-cipher subkeys — so the expensive memory-hard step runs only twice per record while every layer still gets its own key. The Argon2id cost is **vault-wide and tunable** (see [*Vault tools*](#vault-tools)): it lives in the `kdfparams` file (and is embedded in the page), so changing it re-encrypts the whole vault atomically and the read-only/offline copy still derives keys at the right cost.
- **Length-hiding padding:** the plaintext is padded up to the next 256-byte boundary (with trailing spaces) before encryption, so the stored ciphertext length reveals only the 256-byte bucket an entry falls in — not the true length of a password or note. The pad is trailing JSON whitespace, discarded automatically on decrypt.
- The two inner layers are AEAD: a wrong password or a tampered byte produces a hard authentication failure, never garbled output or partial plaintext.
- The entry **name** is separately double-encrypted (AES-256-GCM under password 1, wrapped by ChaCha20-Poly1305 under password 2), so the database file exposes no plaintext at all.
- The four ciphers span three unrelated design lineages (ARX stream cipher, AES, and two AES finalists). Breaking one does not weaken the others.
- Argon2id derivations run on a pool of **Web Workers** (own WASM instance each), sized at the reported CPU core count (capped at 24 on desktop, 2 on phones/tablets) and further bounded by device memory, so unlocking a large vault stays responsive and peak memory stays bounded. A transient derivation failure is retried (falling back to the main thread) so no entry is silently dropped.

Records live one-per-line in a flat file (`lines`), sorted lexically by the full (encrypted) record string — since the entry name is itself encrypted, this is **not** alphabetical by name; the on-screen grid is what gets re-sorted alphabetically, client-side, after the names are decrypted:

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

Prefer not to install PHP at all? The bundled [Node server](#running-without-php-standalone-node-server) runs the same vault with `node server.js` — see that section for the (very short) setup.

---

## Running without PHP (standalone Node server)

The vault ships with **`server.js`** — a single, dependency-free Node script (Node built-ins only) that replaces *both* `post.php` **and** the web-server config. It lets you run the whole vault locally with nothing but Node installed, and install it as a Progressive Web App.

```bash
node server.js                       # local mode → http://127.0.0.1:8787
node server.js --mode web --port 8080  # web mode (front with TLS)
```

It serves one vault directory (the current directory by default; `--dir` to point elsewhere) and reproduces the entire write protocol of `post.php` **byte-for-byte** — same `lines`, same generated `index.html`, same integrity `manifest`. That equivalence is enforced by **`parity-test.js`** (`node parity-test.js`, needs `php` on PATH), which runs the real `post.php` and `server.js` over the same operations and diffs the results; it must stay green because the same vault may be opened under either backend and the integrity signature covers the exact record set.

**Two modes:**

| Mode | Bind | Auth / CSRF / rate-limit | Use |
|------|------|--------------------------|-----|
| `local` *(default)* | `127.0.0.1` | none (no network exposure) | Run it on your own machine and open the page; the "standalone app" case. |
| `web` | `0.0.0.0` | Basic-Auth + CSRF same-origin + per-IP rate-limit + HSTS | A drop-in PHP-free web deployment. Front it with TLS, like the PHP host. |

Both modes serve the same security headers as the `.htaccess` / nginx config — the full CSP (with `'wasm-unsafe-eval'` for the Argon2id WASM and `worker-src 'self'` for the worker pool), the deny rules that block `lines` / `trash` / `manifest` / `kdfparams` / templates / `bak/`, and `Cache-Control: no-store` on the page. Configurable via flags (`--mode`, `--port`, `--host`, `--dir`) or env (`VAULT_MODE`, `PORT`, `VAULT_HOST`, `VAULT_DIR`, `VAULT_AUTH_USER`, `VAULT_AUTH_PASS`, plus the backup-retention `VAULT_BAK_KEEP` / `VAULT_BAK_MAX_AGE_DAYS`).

> The original PHP path is unchanged and remains the canonical way to deploy behind Apache/nginx. `server.js` is an alternative runtime, not a replacement — pick whichever fits the host. Multi-instance `/pass/<user>/` hosting still belongs to nginx; `server.js` serves a single vault directory.

### Installing as a PWA

The app is an installable PWA (web-app manifest + icon, linked from the page). In a supported browser — Chromium-based or recent WebKit/Firefox — open the vault and use the browser's **Install** action (address-bar install icon, or ⋮ → *Install*). It then runs in its own window with a home-screen / launcher icon. Served over `http://localhost`, which counts as a secure context, install and all the in-browser crypto work **without TLS**.

A small **service worker** (`sw.js`) speeds up repeat loads by caching the heavy *non-secret* code assets (the JavaScript bundle and the Argon2id worker) and shows a graceful offline page if the network drops. It is **not** offline vault access: the page that embeds your live encrypted database is never cached (the server sends `Cache-Control: no-store`, and the worker honors that), so the encrypted data is never written to disk and the **server still has to be running** when you launch the app. Offline read of the vault data is intentionally out of scope — it would mean persisting ciphertext to the browser's cache.

---

## Browser extensions (autofill companion)

Two optional **browser extensions** unlock the vault from the toolbar and **autofill logins** into web pages, so you don't have to open the vault page and copy-paste. They are read-only for ordinary entries — add and edit those in the vault web app as usual — with one exception: they act as a **WebAuthn authenticator** for [**passkeys**](#passkeys), which they create (a per-write prompt) and use to sign in.

| Extension | Directory | Browsers |
|-----------|-----------|----------|
| Firefox (Manifest V2) | [`firefox-extension/`](firefox-extension/) | Firefox |
| Chrome / Edge (Manifest V3) | [`chrome-extension/`](chrome-extension/) | Chrome, Edge (any Chromium) |

Both are functionally identical and share the same crypto, content script, popup UI, and icons; only the background layer differs to fit each browser's extension model.

**How they work** — you enter the vault URL (e.g. `https://host/pass/<instance>/`) and both master passwords in the toolbar popup. The extension fetches the same `index.html` the vault already serves — an unauthenticated read; only *writes* need Basic Auth — parses every encrypted v6 record from the page and runs the **exact v6 decrypt cascade** locally (the crypto files are a verbatim slice of the vault's `javascript.js`, parallelised across the same Argon2id Web Worker pool). Decrypted entries live **only in the extension's memory** — passwords are never stored; only the vault URL is saved. Because it only does a plain HTTP `GET` of `index.html`, it works against a vault served by **either backend** — PHP (`post.php`) or the standalone [Node server](#running-without-php-standalone-node-server) (`server.js`), which emit a byte-identical page.

The popup lists entries, surfacing ones whose URL matches the current tab. **Fill** types the username + password into the page's login form (origin-gated per frame so a third-party iframe can't capture it); **📋** copies the password; **OTP** copies the live TOTP code; clicking a name expands an inline panel (URL / username / masked password / live TOTP / notes), every value click-to-copy. The session **auto-locks after 5 minutes of true system idle** (or screen lock) or instantly via **Lock**; locking wipes the decrypted entries, the key cache, and the worker pool, and clears any copied secret from the clipboard. The toolbar icon is monochrome while locked, full color once unlocked, animated during decrypt, and gains a red stopwatch when auto-lock is disabled; a green ✓ badge marks tabs whose site matches a stored entry.

> The Chrome/Edge build is a Manifest V3 port: because an MV3 service worker is ephemeral (and can't spawn Web Workers), the unlocked session, the Argon2id worker pool, `DOMParser`, and clipboard wiping live in a persistent **offscreen document**, while the service worker owns the toolbar icon, idle auto-lock, tab autofill injection, and message routing. See [`chrome-extension/README.md`](chrome-extension/README.md) for the architecture.

**Install (development):**

- **Firefox** — `about:debugging` → *This Firefox* → *Load Temporary Add-on* → pick `firefox-extension/manifest.json` (or load the signed `.xpi`). Build a package with `firefox-extension/build-xpi.sh`.
- **Chrome / Edge** — `chrome://extensions` (or `edge://extensions`) → enable *Developer mode* → *Load unpacked* → select the `chrome-extension/` directory. Build a store zip with `chrome-extension/build-zip.sh`.

Each extension's `selftest.js` (`node selftest.js`) verifies its decrypt path against the bundled ciphers.

### Passkeys

The extensions can also act as a **WebAuthn authenticator**, storing passkeys (resident credentials) inside the vault. They override `navigator.credentials.create/get` on every site: **create** generates an ECDSA P-256 key pair, encrypts it into a new vault entry, and saves it; **get** signs the site's challenge with the stored key. A passkey lives inside an entry's encrypted payload (`fields.passkey`, `url: passkey://<rpId>`) — no record-format change — so the private key is protected by the same four-cipher cascade as every other secret.

Because creating a passkey is a *write*, the extension prompts **per creation** for the two master passwords (to encrypt the new entry) and the vault's Basic-Auth write password (to POST it); nothing is persisted. Signing in with a stored passkey is **read-only** (`signCount` stays `0`, no write or prompt per login).

The **web app only displays** that an entry has a passkey (a 🔐 row in the decode panel and a Vault Tools → **Passkeys** inventory) and can **delete** it (strips the passkey and re-saves, or removes the whole entry if nothing else remains) — it never creates or signs passkeys. Scope/limits (`fmt:"none"` attestation, no OS credential-picker, RP libraries that test `instanceof PublicKeyCredential`) are documented in the extension READMEs.

---

## Terminal client (TUI)

For a keyboard-only / headless workflow, [`tui.node/`](tui.node/) is an optional **Node.js terminal UI** — a full read **and write** client, unlike the read-only browser extensions. It operates **directly on the vault files** (`lines` / `manifest` / `kdfparams` / `bak/`), not over HTTP, so it runs on the same machine as the vault (or any copy of the directory) with no web server at all.

It is **fully interoperable** with the web app: it reuses the **identical** v6 crypto — the ChaCha20-Poly1305 / Twofish-256 / Serpent-256 bundles are loaded straight out of `javascript.js` and the Argon2id WASM out of `argon2-worker.js`, so nothing is re-implemented — reads the vault-wide Argon2id cost from `kdfparams`, applies the same length-hiding padding, and **re-signs the integrity manifest after every write** so the browser still shows `✓ Integrity verified`. Entries created or edited in one show up cleanly in the other (including tags, custom fields, password history, and password age, which the TUI preserves on edit).

```bash
cd tui.node
node vault-tui.js
# or target another instance / a copy of the directory:
VAULT_DIR=/var/www/html_n2/pass/<instance> node vault-tui.js
```

No build step and no `npm install` — pure Node ≥ 18 (WebCrypto is built in). It needs an interactive terminal; the UI reflows to fit the window and re-lays-out live on resize. Unlock fans the memory-hard Argon2id derivations across a **`worker_threads` pool (one per core)** for the same multi-core speed as the browser; cap it with `VAULT_TUI_THREADS=<n>` on a many-core box. TOTP codes render with a live countdown, and the session auto-locks after 5 minutes idle. Clipboard copy uses `pbcopy` / `wl-copy` / `xclip` / `xsel` when available.

> **Ownership caveat:** the web server writes these files as `www-data`. Run the TUI as the same user (`sudo -u www-data node vault-tui.js`) or `chown www-data:www-data` the files it rewrites (`lines`, `manifest`, `bak/*`) afterward, or php-fpm's next save can fail. See [`tui.node/README.md`](tui.node/README.md) for keys and details.

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

Each copyable field shows a dimmed **⧉ copy glyph** on its right; the glyph brightens when you hover the row, marking the whole area as click-to-copy (the glyph itself is just a cue — clicking anywhere on the row copies, which also works on touch where there is no hover). A brief flash confirms the copy. If the entry's URL starts with `https://`, the name becomes a link that opens in a new tab. Any **tags** on the entry show in a 🏷 Tags row, and notes appear below. A wrong key or corrupted record shows **"Wrong key or corrupted entry"** — nothing partial is ever displayed.

Next to the password, a **📝 Modified** column shows the date the password was last changed — or the creation date, if it never has. Hovering it shows a tooltip with the entry's **creation date** and **age**. Entries saved before this tracking existed show a best-effort, upper-bound creation date (prefixed `≤`), inferred from the oldest password-history entry or the modified date when there's no history.

**Copied secrets are auto-cleared from the clipboard after 45 seconds**, and immediately on any lock.

### 2FA / TOTP codes

If an entry stores a TOTP secret, the code appears automatically with a countdown ring showing the seconds left in the current window. Clicking the token area copies the current code. Plain Base32 secrets use the standard 6-digit / 30-second / SHA-1 settings; if you store a full `otpauth://` URI instead, its `digits`, `period`, and `algorithm` (SHA-1 / SHA-256 / SHA-512) are honored, and **Steam Guard** secrets render as their 5-character codes — the countdown ring follows the entry's period in every case.

### Searching

Press 🔍 to open the search overlay and type — the list filters live. Click a result to decrypt it; **Escape** dismisses. Searches are **scoped by a leading character**:

- *(no prefix)* — match the entry **name** (the default)
- **`#`** — match **tags** (e.g. `#work`)
- **`@`** — match **notes** (e.g. `@recovery`)
- **`!`** — match **custom fields**, both labels and values (e.g. `!PIN`)

The count line shows which scope is active ("Searching custom fields…"). Tag, note, and custom-field search look inside the encrypted payload, so they cover every entry whose name has already been revealed this session (i.e. once both passwords are entered and all names decrypt).

### Grouping & sorting

The entry grid is always sorted alphabetically. A **Group A–Z** toggle (next to the entry count, shown once the vault is unlocked) adds sticky first-letter headers above each run of entries — names that don't start with a letter are bucketed under **#**. The choice is remembered per vault in your browser (on by default).

**Favorites:** decrypt an entry and click the ☆ star in the decode panel (or press **F**) to favorite it. Favorites pin to the top of the grid — under a **★ Favorites** header when grouping is on — and show a ★ on their button. The set is remembered per vault in your browser, stored as a one-way hash of each name (never the name itself), so it survives edits and reveals nothing if browser storage is read.

### Adding an entry

Click **＋ New** and fill in any combination of:

- **Name** (required) — the label on the entry button; cannot contain `|`
- **URL** — used as a clickable link after decryption
- **Username**
- **Password** — type one or generate one
- **2FA Token** — paste a Base32 TOTP secret or a full `otpauth://` URI (which carries custom digits / period / algorithm, and Steam Guard), or click **📷 Scan QR** to read it from a QR code image (mobile opens the rear camera; desktop opens a file picker). Issuer and account from the QR pre-fill Name/Username if empty; a non-default or Steam QR is stored as its full URI so those settings survive. Requires Chrome 83+, Edge 83+, or Safari 17.4+.
- **Tags** — a comma-separated list (e.g. `work, email, personal`); normalized on save (lowercased, trimmed, de-duplicated) and searchable with `#tag`. Stored encrypted in the payload like every other field.
- **Notes** — free-form text; the field grows as you type. Searchable with `@note`.
- **Custom fields** — click **➕ Add field** to add any number of labelled values (e.g. *Recovery code*, *PIN*, *Security question*). Tick **secret** to mask a value in the decode panel (it stays click-to-copy). Custom fields are stored encrypted in the payload like every other field.

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

**Password history:** whenever you edit an entry and change its password, the previous one is automatically archived (with the date it was replaced) inside the encrypted payload. The decode panel shows a collapsible **⏱ Password history** row listing past passwords, each click-to-copy. The newest 20 are kept.

**Soft delete:** a delete moves the entry to the **trash** rather than erasing it — see *Vault tools → Trash* to restore it or remove it permanently. (A brief **Undo** also appears in the toast right after deleting.)

### Vault tools

In the About panel (ℹ), the **Vault Tools** section offers seven whole-vault operations:

- **⬇ Export** — downloads the encrypted database as `vault-export-YYYY-MM-DD.lines`, built entirely in the browser and byte-identical to the server's data file. Ciphertext only, safe to store as an offline backup.
- **⬆ Import / Restore** — replaces the entire vault from an exported `.lines` file. The file is validated, then **every record is decrypted with the passwords currently in the key fields before anything is sent** — so an import that doesn't match those passwords is refused and nothing changes, and a successful import is guaranteed to be fully readable. Committed as one atomic replace (the server keeps a backup of the previous vault first, so a restore is itself reversible), then re-signed at a fresh revision. Replace-only — it does not merge.
- **🔎 Audit** — decrypts every entry locally (both passwords required) and reports **reused**, **weak** (< 40 bits), **fair** (40 – 80 bits), **empty**, and **stale** (password unchanged in over a year) passwords. Only entry names are shown, and nothing leaves the device — there are no breach-check API calls by design (the CSP forbids all outbound connections).
- **🗑 Trash** — lists entries you have deleted (decrypting each name locally), each with the date it was deleted. **Restore** puts an entry back into the vault; **Delete** removes it permanently; **Empty Trash** clears everything. Deleted entries are kept server-side for 30 days (ciphertext only, the same as the live database) and pruned automatically. Restoring re-signs the vault at a fresh revision.
- **🔑 Change Passwords** — rotates both master passwords: every entry is decrypted with the current passwords and re-encrypted under the new ones (fresh salts and nonces) in the browser, then committed to the server as **one atomic replace**. All-or-nothing: if any record fails to decrypt, or the vault changed mid-run from another device, nothing is modified. On success the session switches to the new passwords seamlessly (and the vault is re-signed under them).
- **🔐 Passkeys** — lists every entry that stores a WebAuthn passkey (name + relying-party domain), decrypting locally. This is a read-only inventory: the web app cannot create or sign passkeys (the browser extensions do that — see [*Passkeys*](#passkeys)). To remove one, open the entry and use the **Delete passkey** button in the decode panel, which strips the passkey but keeps the rest of the entry.
- **✍ Sign** — manually re-signs the **integrity manifest** (see below). Only needed to accept a deliberate manual edit of the data file or a backup restore as the new baseline; normal saves re-sign automatically.

A separate **⚙ Change KDF Parameters** section directly below Vault Tools adjusts the Argon2id work factor (memory and iterations) for the whole vault. The passwords stay the same: every entry is decrypted at the current cost and re-encrypted at the new one, committed via the same all-or-nothing atomic replace as *Change Passwords*, with the new `kdfparams` written atomically alongside the records. Memory is bounded 64 MiB – 1 GiB and iterations 2 – 10 (parallelism fixed at 1); a preset slider, a per-device-class suggestion table, and a one-click **Calibrate** button (which benchmarks Argon2id on your device and proposes an iteration count for a target time, default 500 ms) help pick a value, and a no-op or out-of-range entry is refused. On success the new cost takes effect immediately, the worker pool re-sizes for the new memory budget, and the vault is re-signed — so a later attempt to downgrade the cost out-of-band is integrity-detectable.

**Migrating in from another manager.** Alongside the encrypted `.lines` import, the Backup section can import three plaintext formats and **merge** their entries into the current vault (your existing entries are kept; each imported row is re-encrypted with the passwords in the key fields):

- **CSV** — header aliases cover Bitwarden, Chrome, 1Password, and others.
- **KeePass 2 XML** — the unencrypted *File → Export → KeePass XML (2.x)* output from KeePass / KeePassXC, including TOTP, custom strings, and group/tag mapping.
- **1Password `.1pux`** — read entirely in the browser (the ZIP is unpacked with the native `DecompressionStream`; no library).

The encrypted KeePass `.kdbx` binary is intentionally **not** supported — its format requires a full binary-crypto parser that can't be loaded under the page's strict CSP. Export to KeePass XML or CSV first.

### Vault integrity manifest

The vault carries a **keyed signature over the entire record set** — an HMAC-SHA-256 whose key is derived from *both master passwords* (Argon2id + HKDF). The server stores it but can never compute it, so only a password holder can produce a valid signature.

- **Verified on every unlock:** after the entry names are revealed, the browser recomputes the signature over the records it received and compares. A mismatch — an entry added, modified, or removed behind your back, or silent corruption — shows a red **integrity failure** badge instead of passing unnoticed. Per-record encryption alone can't catch this: each record authenticates itself, but nothing else binds the *set* together.
- **Rollback detection:** the manifest embeds a monotonically increasing **revision number**, and each device remembers the highest revision it has seen (in browser storage). Being served an older — validly signed — copy of the vault raises a rollback alarm.
- **Automatic re-signing:** every save, edit, delete, and password change re-signs the vault (revision +1). If another device wrote concurrently, the client resyncs and signs the merged state.
- **Status badge:** a line above the entry list (and in Vault Tools) shows ✓ verified with revision and timestamp, ⚠ unsigned, or a red failure/rollback alert.
- **Key-field lock:** a passing integrity check also *disables* both master-password input fields and their visibility toggles for the rest of the session, so a verified master password can't be edited by accident — see [*Unlocking*](#unlocking) for the full behavior.
- **Honest limits:** this is tamper *detection* for the data file, in-band. It protects against corruption, botched restores, manual-edit mistakes, and tampering by anything that can't also rewrite the served JavaScript. An attacker who fully controls the server (and can serve modified code) defeats it — no in-band scheme can prevent that.

### Keyboard shortcuts

Single-key shortcuts work whenever you are not typing in a field (`Shift`+`Enter` works inside the entry form):

| Key | Action |
|-----|--------|
| `Shift`+`Enter` | Save the entry being added or edited (from any field in the form — except **Notes**, where it inserts a newline) |
| `?` | Open / close search |
| `N` | New entry (when the ＋ New button is enabled) |
| `E` | Edit the selected entry (when one is displayed) |
| `Shift`+`D` | Delete the selected entry, with confirmation |
| `F` | Toggle favorite on the selected entry |
| `C` | Clear the displayed entry |
| `A` / `I` | Open / close the About panel |
| `X` | Lock the vault |
| `Esc` | Close dialog / clear displayed entry |
| `Esc` `Esc` | Lock the vault (press twice quickly) |

### Locking

- **Manual:** the ✕ button clears both keys and all decoded data (stored entries are untouched). **Escape twice** does the same instantly.
- **Auto-lock:** after **5 minutes** of inactivity a warning banner counts down from 60 seconds; click **Stay** to keep the session, or let it lock. Locking wipes the key fields, the derived-key cache, the worker pool, decoded data, audit results, and the clipboard (if it holds a copied secret).

### About panel & self-test

The ℹ button opens the About panel: record format, key-derivation parameters, the full encryption pipeline, the cipher-selection rationale, TOTP details, the Vault Tools, viewing/organizing guidance, the keyboard-shortcut reference, standards alignment, and library credits.

A **runtime self-test** (WebCrypto, all four ciphers round-trip, Argon2id known-answer) runs on **every page load** — a failure raises a warning dialog naming the failed check before you enter any password — and again each time the About panel opens, with a ↻ Retest button.

### Tooltips

Hover any button or interactive field for a brief description of what it does.

---

## Data safety & concurrency

- **Backups before every write:** the current database is copied to `bak/` (timestamped to the microsecond, so rapid writes can't collide) before any modification; a failed backup aborts the write. Backups are pruned on every write — first dropping any older than 60 days, then keeping only the newest 100 (oldest removed first). Both limits default sensibly and can be overridden per-deployment via the `VAULT_BAK_KEEP` and `VAULT_BAK_MAX_AGE_DAYS` environment variables (`0` disables that limit); all three write clients — `post.php`, `server.js`, and the TUI — honor them.
- **Soft delete:** deleted records are moved to a `trash` file (ciphertext only, like the database) rather than discarded, so they can be restored from *Vault Tools → Trash*. Trash is pruned to the newest 100 entries and entries younger than 30 days on every change. All trash writes happen under the same exclusive lock as the database.
- **Exclusive locking:** the entire read-modify-write — including the `index.html` rebuild — holds an exclusive `flock` on the database (the single-process Node server runs the same critical section synchronously instead, which is equivalent), so overlapping saves cannot lose each other's changes.
- **Content-addressed writes:** deletes and edits identify the record by its full ciphertext string (unique per record thanks to random salts), never by line position. A stale reference is refused with HTTP `409` and nothing is modified.
- **Atomic password rotation:** the bulk replace used by *Change Passwords* sends a hash of the exact snapshot that was re-encrypted; the server verifies it under the lock and refuses (`409`, untouched) if the vault changed in between.
- **Clear failure modes:** the UI distinguishes wrong write-credentials (401), rate-limit lockout (429, with the wait time), stale records (409), and blocked origins (403).

---

## Security notes

- **All encryption and decryption happens in your browser.** The server never sees your master keys or plaintext.
- **Writes require a separate login.** Writes are protected by HTTP Basic Auth — `VAULT_AUTH_USER` / `VAULT_AUTH_PASS`, set at the top of `post.php` (or, for the Node server's `web` mode, supplied as environment variables). Set your own; the shipped values are placeholders. Your browser prompts the first time you save in a session. Only meaningful over HTTPS.
- **Write logins are rate-limited.** After 5 failed Basic-Auth attempts from one IP within 15 minutes, further attempts get `429` until the window clears. Blocked attempts don't extend the lockout; a success clears the history. Under PHP the per-IP window is tracked in a temp-dir file and the limiter **fails open** if that state can't be written, so a misconfiguration can't lock you out of your own server; the Node server's `web` mode keeps the same window in memory.
- **Wrong keys fail hard.** The AEAD layers authenticate the ciphertext — there is no partial or garbled decryption.
- **The database leaks nothing.** Entries are ciphertext in a flat text file; names are encrypted too. Read access to the file (or the `trash` file, which holds deleted entries in the same form) is useless without both master passwords.
- **Browser storage stays metadata-free.** The only per-vault state kept in the browser is UI preferences (the Group A–Z toggle, the integrity revision high-water mark) and the favorites set — and favorites are stored as a one-way hash of each entry name, never the name itself, so reading local storage reveals nothing about your entries.
- **The record set is signed on every write.** A keyed HMAC (HMAC-SHA-256, key derived from both master passwords via Argon2id + HKDF) covers the entire sorted record set and is re-stored after every save. Verified on every unlock — tampering, silent deletion, corruption, and rolled-back copies are caught before you act on the data. The server stores the signature opaquely and cannot forge or verify it.
- **Key derivation is memory-hard.** Argon2id at 128 MiB per guess (the default; tunable up to 1 GiB) reduces a GPU farm that tests billions of fast hashes per second to a few thousand guesses per second per card.
- **Sessions are containable.** Auto-lock, double-Escape lock, clipboard auto-clear, and teardown of the worker pool (whose WASM heaps hold residual key material) all bound how long secrets stay in memory.
- **Server files are blocked from HTTP access** by the bundled `.htaccess` files — **on Apache only**. nginx ignores `.htaccess` entirely; apply the rules under [*Deploying behind nginx*](#deploying-behind-nginx) or the database file, trash, templates, and backups are downloadable (ciphertext, but block them regardless).
- **No outbound connections.** The CSP's `connect-src 'self'` means the page can talk only to its own origin — no telemetry, no CDN, no breach-check APIs, no exfiltration channel.

### Standards alignment

| Standard | Status | Notes |
|---|---|---|
| Argon2 (RFC 9106) | Met | Argon2id key derivation, m = 128 MiB, t = 3, p = 1 by default (exceeds the RFC 9106 second-recommended option); tunable per vault up to m = 1 GiB, t = 10, then HKDF-SHA-256 subkeys |
| RFC 6238 / 4226 | Met | TOTP with configurable period, digit count, and SHA-1/256/512 (plus Steam Guard); defaults to 30 s / 6 digits / SHA-1 |
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
| `sw.js` | Optional service worker — caches the non-secret code assets + offline fallback; never caches the vault document ([*Installing as a PWA*](#installing-as-a-pwa)) |
| `part1` / `part2` | HTML template fragments; `post.php` splices the entry buttons between them |
| `lines` | The flat-file ciphertext database, one record per line, sorted |
| `trash` | Soft-deleted records (ciphertext only, like `lines`); pruned to the newest 100 / 30 days, restorable from *Vault Tools → Trash* |
| `manifest` | The vault integrity manifest — a client-computed HMAC stored opaquely by the server; absent until the vault is first signed |
| `kdfparams` | The vault-wide Argon2id cost (`a2id\|memKiB\|t\|p`), written by *Change KDF Parameters* and embedded in the page; absent ⇒ the 128 MiB / t = 3 default |
| `post.php` | The PHP server-side code: validates, locks, backs up, writes, and rebuilds the page |
| `server.js` | Optional **standalone Node server** — a byte-faithful, dependency-free port of `post.php` + the web-server config, with `local`/`web` modes ([*Running without PHP*](#running-without-php-standalone-node-server)) |
| `parity-test.js` | Proves `server.js` is byte-identical to `post.php` (`node parity-test.js`, needs `php`) |
| `manifest.json` / `icon.png` | PWA web-app manifest + icon, making the page installable |
| `bak/` | Automatic pre-write backups of `lines` (newest 100 / younger than 60 days kept; override via `VAULT_BAK_KEEP` / `VAULT_BAK_MAX_AGE_DAYS`) |
| `.htaccess` | Apache-only access rules and security headers (Node mode applies the same rules in `server.js`) |
| `firefox-extension/` | Optional Firefox autofill companion (MV2) — unlocks the vault and autofills logins ([*Browser extensions*](#browser-extensions-autofill-companion)) |
| `chrome-extension/` | Optional Chrome/Edge autofill companion (MV3 port of the Firefox one) |
| `tui.node/` | Optional Node.js terminal client — read/write, operates directly on the vault files with the same v6 crypto ([*Terminal client*](#terminal-client-tui)) |

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
(e.g. `location ~ /(lines|trash|manifest|kdfparams|part1|part2)$`).

```nginx
# Block the flat-file DB, KDF params, manifest, and HTML templates for every
# vault instance. (kdfparams is not secret — it is also embedded in index.html —
# but is denied for consistency with the manifest.)
location ~ /pass/[^/]+/(lines|trash|manifest|kdfparams|part1|part2)$ {
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

### Or skip the web server: the standalone Node server

If you'd rather not run Apache or nginx at all, the bundled [`server.js`](#running-without-php-standalone-node-server)
**builds every rule above into the runtime** — the deny rules for `lines`/`trash`/`manifest`/`kdfparams`/`part1`/`part2`,
the `bak/` and `moved/` directory blocks, the full security-header suite (same CSP, HSTS, COOP/CORP, `no-store`), and the
complete `post.php` write protocol — so no `.htaccess` and no `location` config is needed. It is a faithful, dependency-free
port of both `post.php` *and* the config on this page; `node parity-test.js` proves the two backends emit a byte-identical
`lines`/`index.html`/`manifest`.

```bash
node server.js                         # local mode → http://127.0.0.1:8787 (no auth; localhost is a secure context)
node server.js --mode web --port 8080  # web mode: Basic-Auth + CSRF + rate-limit + HSTS — front with TLS
```

Use whichever fits the host: keep PHP behind Apache/nginx (the canonical multi-instance path), or run the self-contained
Node server for a single vault. Either way the served page is byte-identical, so a vault can be opened under either backend
without tripping the integrity manifest. In `web` mode terminate TLS in front of it (a reverse proxy or a TLS-terminating
load balancer) exactly as you would for the PHP host.

---

## Libraries & attribution

The cryptographic primitives are third-party open-source implementations, bundled **inline** in `javascript.js` (and in `argon2-worker.js`). No external requests are made at runtime — the Argon2id WebAssembly is embedded as base64 rather than fetched. Each library is used under its own license, and the upstream license/attribution notices are retained inside the bundles. With gratitude to the authors:

| Library | Version | Author | License | Source | Used for |
|---------|---------|--------|---------|--------|----------|
| `@noble/ciphers` | — | Paul Miller ([paulmillr.com](https://paulmillr.com)) | MIT | [github.com/paulmillr/noble-ciphers](https://github.com/paulmillr/noble-ciphers) · [npm](https://www.npmjs.com/package/@noble/ciphers) | ChaCha20-Poly1305 |
| `twofish-ts` | 1.0.2 | Logan R. Kearsley | MIT | [github.com/gliese1337/twofish](https://github.com/gliese1337/twofish) · [npm](https://www.npmjs.com/package/twofish-ts) | Twofish-256 |
| `hash-wasm` | 4.12.0 | Dani Biró ([danibiro.com](https://danibiro.com)) | MIT | [github.com/Daninet/hash-wasm](https://github.com/Daninet/hash-wasm) · [npm](https://www.npmjs.com/package/hash-wasm) | Argon2id (WebAssembly) |

**Serpent-256** is **not** an npm dependency — no maintained package exists. It is a hand-written bitslice implementation of the forward block cipher (inlined into `javascript.js`), verified against [Bouncy Castle](https://www.bouncycastle.org/)'s 256-bit ECB test vectors. The Serpent cipher itself is in the public domain, designed by [Ross Anderson, Eli Biham, and Lars Knudsen](https://www.cl.cam.ac.uk/~rja14/serpent.html).

**AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256 (vault signing), and HMAC-SHA-1/256/512 (TOTP)** use the browser's native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — no third-party code.

**Build tooling (not shipped at runtime):** the npm bundles are produced with [esbuild](https://github.com/evanw/esbuild) (MIT — Evan Wallace). It is a development dependency only; no part of esbuild is served to the browser.

---

## License

This project is released under the [MIT License](LICENSE). The bundled third-party libraries are MIT-licensed as credited above; the Serpent cipher implementation is public domain.
