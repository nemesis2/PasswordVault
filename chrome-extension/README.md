# Vault Autofill Companion (Chrome / Edge)

A Chromium (Chrome + Edge) **Manifest V3** port of the Firefox companion. It
unlocks your self-hosted, client-side-encrypted vault and autofills logins into
web pages. **All decryption happens locally in the browser** — the extension only
ever fetches the same ciphertext the vault already serves, and your passwords are
never stored or sent anywhere.

It is functionally identical to the [`../firefox-extension`](../firefox-extension)
build and reuses its crypto, content script, popup UI, and icons **verbatim**.
Only the background layer differs, because MV3 changes how it must run.

## MV3 architecture (why it differs from Firefox)

Firefox runs the whole add-on in one **persistent background page**. Chrome MV3
replaces that with an **ephemeral service worker** that has no DOM, cannot spawn
Web Workers, and is killed when idle. None of those work for us (the worker pool,
DOMParser, the long-lived decrypted session). So the work is split across two
contexts:

| Context | File(s) | Responsibility |
|---|---|---|
| **Offscreen document** (persistent) | `offscreen.html` / `offscreen.js` | Holds the unlocked **session** (decrypted entries) in memory, runs the **Argon2id Web Worker pool** (`crypto-vault.js` + `argon2-worker.js`), parses the vault `index.html` with **DOMParser**, computes TOTP, and wipes the **clipboard**. This is the MV3 stand-in for Firefox's persistent background page — created once and kept alive, so the session survives the popup *and* the service worker closing. |
| **Service worker** | `background.js` | Owns the chrome.* UI APIs the offscreen page can't touch: the toolbar **action icon/badge** (drawn with `OffscreenCanvas`), **idle** auto-lock, **tabs + scripting** (autofill injection), and **routing** popup commands to the offscreen document. Mirrors the lock state in `chrome.storage.session` so the icon/badges are correct after a service-worker respawn. |
| **Popup** | `popup.html` / `popup.js` / `popup.css` | Unchanged from Firefox — sends plain messages to the service worker and renders results. |
| **Content script** | `content.js` | Unchanged from Firefox — injected on demand to fill credentials, with a per-frame origin gate. |
| **Passkey interceptor** | `content_passkey_main.js` (MAIN world) + `content_passkey_bridge.js` (ISOLATED) | Overrides `navigator.credentials.create/get` on every site. MAIN world replaces the API (no `chrome.*` there); the ISOLATED bridge relays requests to the service worker over a long-lived port. **Conditional/silent `get()`** (passkey autofill) and RP requests for a **cross-platform** authenticator pass straight through to the browser's native handling — they never raise extension UI. |
| **Passkey crypto** | `webauthn.js` + `crypto-vault.js` | ECDSA P-256 keygen/signing, the encrypt path that writes passkey records, and the WebAuthn byte builders (CBOR COSE key, attestationObject, authenticatorData, DER signatures). Runs in the offscreen document. |
| **Approval window** | `approve.html` / `approve.js` | Per-ceremony prompt that always shows the **validated requesting origin** (not just the RP-supplied name). Creating a passkey asks for the two master passwords (to encrypt) + the vault write password (to POST), and offers **Use this device instead** (fall back to the browser's native authenticator instead of failing the ceremony). Once both master passwords are entered it **unlocks the vault and lists existing entries** so the passkey can be **attached to one** (site-matching entries first) instead of always creating a new entry — default is **Create new entry**. Using a passkey requires a per-assertion **confirm** (the WebAuthn user-presence gesture) even when the vault is unlocked; if it's locked, the prompt asks for the master passwords to unlock first. Nothing is persisted. |

Passkeys are stored as normal encrypted vault entries (`url: passkey://<rpId>`, the
private key inside the encrypted payload). `signCount` stays `0`, so authenticating
is read-only. The web app shows that a passkey is stored and can delete it, but
never creates or signs one. **Attach-to-existing:** when the create approval picks
an existing entry, the extension decrypts that entry's *full* record (preserving its
tags / custom fields / history / url that the in-memory session copy drops), injects
the `passkey` sub-object, and commits an **atomic replace** (`delete_rec=<old>&data=<new>`)
instead of adding a second record — so a passkey for a site you already have a login
for lands on that login. Entries that already hold a passkey are shown disabled (no
clobbering). After writing the record the extension also **re-signs the vault
integrity manifest** (`vm1`) — like the PWA does after its own writes — so the new
record doesn't trip the PWA's tamper check; this is best-effort (the PWA's Sign
button can re-baseline if it fails).

This keeps full multi-core Argon2id parallelism (Approach B in
`../firefox-extension/CHROME-PORT-PLAN.md`), so unlock speed matches Firefox.

### What changed vs. Firefox

- `manifest.json`: `manifest_version: 3`, `action` (was `browser_action`),
  `background.service_worker` (was a persistent scripts list), `host_permissions`
  (was `<all_urls>` in `permissions`), CSP **object** (`extension_pages`), plus
  the `scripting` + `offscreen` permissions. The Firefox-only
  `browser_specific_settings` / `data_collection_permissions` are dropped.
- `background.js`: rewritten as the service worker described above. Icon
  compositing uses `OffscreenCanvas` + `createImageBitmap` instead of
  `new Image()` + `<canvas>`; `browserAction.*` → `action.*`;
  `tabs.executeScript` → `chrome.scripting.executeScript`.
- `offscreen.html` / `offscreen.js`: **new** — the session/crypto half lifted
  out of the Firefox `background.js`, with DOMParser and the worker pool intact.

Everything else (`crypto-ciphers.js`, `crypto-vault.js`, `argon2-worker.js`,
`content.js`, `popup.*`, `icons/`, `selftest.js`) is copied byte-for-byte from
the Firefox build.

## Install (development)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** on.
3. **Load unpacked** → select this `chrome-extension/` directory.

The same package installs on both Chrome and Edge.

## Build a store zip

```bash
./build-zip.sh
```

Produces `web-ext-artifacts/vault-autofill-companion-chrome-<version>.zip` with
`manifest.json` at the root — upload that to the Chrome Web Store ($5 one-time
developer fee) or the (free) Edge Add-ons dashboard.

## Test the crypto path

```bash
node selftest.js
```

Builds a v6 record with the bundled ciphers and decrypts it back through
`VaultCrypto` (correct + wrong passwords, TOTP shape), cross-checks the new
`VaultCrypto.buildRecord` encrypt path, and round-trips a passkey sub-object plus
the ECDSA sign→verify and CBOR/DER builders. Identical to the Firefox build's
selftest since the crypto files are shared.

## How it works (same as Firefox)

1. Enter the vault URL (e.g. `https://host/pass/<instance>/`) and both master
   passwords in the toolbar popup.
2. The offscreen document fetches the vault's `index.html` — an unauthenticated
   read (only *writes* need Basic Auth) — parses every encrypted v6 record from
   the `data-row` attributes plus the Argon2id cost from the `#vault-kdf` span,
   and runs the exact v6 decrypt cascade (Serpent → Twofish → AES-GCM → ChaCha20
   for payloads; ChaCha20 → AES-GCM for names) across the worker pool. Decrypted
   entries live **only in the offscreen document's memory**. The fetch is a plain
   HTTP `GET`, so it works whether the vault is served by the **PHP** backend
   (`post.php`) or the **standalone Node server** (`server.js`) — both emit a
   byte-identical `index.html`.
3. The popup lists entries, surfacing ones whose `url` matches the current tab.
   **Fill** types the username + password into the page; **📋** copies the
   password; **OTP** copies the live TOTP code; clicking a name expands an inline
   panel (URL / username / masked password / live TOTP / notes), every value
   click-to-copy.
4. The session auto-locks after 5 minutes of true system idle (or screen lock),
   or immediately via **Lock**. Auto-lock can be turned off in the About modal.
   Locking wipes the decrypted entries, the master-key cache, and the worker
   pool, and clears any copied secret from the clipboard.

The toolbar icon is **monochrome while locked**, **full color once unlocked**,
**animated during decrypt**, and gains a **red stopwatch** when auto-lock is
disabled. A green **✓** badge marks tabs whose site matches a stored entry.
Passwords are **never stored** — only the vault URL is saved.
