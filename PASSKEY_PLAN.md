# Passkey Support Plan for the Password Vault

> **Status: IMPLEMENTED (2026-06-21).** Passkey support shipped, with the
> architecture reshaped from this original draft: the **browser extensions are the
> authenticator** (they create + sign passkeys), and the **PWA only displays a
> stored passkey and can delete it** — it never does passkey crypto. Part 3
> (classic username/password/TOTP inline-dropdown autofill) was **not** built
> (out of scope). For the as-built design see the *Passkeys* section in
> `README.md` and the two extension READMEs.

## Context

The vault is a self-hosted PWA that stores encrypted credentials client-side. The goal is to store and use passkeys (WebAuthn credentials) from this vault — meaning the vault acts as the authenticator rather than the OS or a hardware key. A PWA cannot intercept the browser's `navigator.credentials.create()` / `navigator.credentials.get()` calls on other sites, so a companion browser extension is required. This is exactly the same architecture used by Bitwarden and 1Password. There is no stable, cross-browser API for a PWA to register itself as a system authenticator — content script injection in an extension is the only viable path.

---

## Two-Component Architecture

```
┌─────────────────────────────────────┐     ┌────────────────────────────────────┐
│  Vault PWA (existing)               │     │  Companion Browser Extension       │
│  ─ Stores encrypted passkey entries │◄───►│  ─ Intercepts navigator.credentials│
│  ─ Generates ECDSA P-256 key pairs  │     │  ─ Talks to vault for key ops      │
│  ─ Signs challenges when unlocked   │     │  ─ Presents approval UI            │
│  ─ All crypto stays client-side     │     │  ─ Returns synthetic credential    │
└─────────────────────────────────────┘     └────────────────────────────────────┘
```

The PWA handles everything cryptographic. The extension handles only the browser API surface — it is a thin relay that presents the vault's keys to relying-party sites.

---

## Existing Vault Architecture (relevant constraints)

- **Record format**: 11-field pipe-separated v6 records; `post.php` enforces exactly 11 fields — adding fields would require a format bump and server-side change.
- **Opaque payload**: The 11th field (`encHEX`) is the ciphertext of a JSON object `{url, username, password, token, notes}`. The server never inspects the plaintext — it is safe to add new JSON keys without any server changes.
- **No asymmetric crypto currently**: All existing WebCrypto usage is AES-GCM, HKDF, HMAC-SHA-1 (TOTP), ChaCha20-Poly1305, Twofish-CTR, Serpent-CTR, and Argon2id. ECDSA P-256 is not used.
- **CSP**: `script-src 'self' 'wasm-unsafe-eval'` — no `unsafe-inline`. All JS must be in `javascript.js`.
- **Event binding**: All UI uses `data-action` delegation or explicit `addEventListener`. No `onclick=` attributes.

---

## Part 1: Vault-Side Changes (`javascript.js` only, no server changes)

### 1a. Extend the JSON payload schema

The encrypted `encHEX` field stores a JSON object. The server never sees the plaintext. Add a `passkey` sub-object:

```json
{
  "url": "passkey://example.com",
  "username": "alice@example.com",
  "password": "",
  "token": "",
  "notes": "",
  "passkey": {
    "credentialId": "<base64url string>",
    "rpId": "example.com",
    "rpName": "Example Site",
    "userId": "<base64url string>",
    "userHandle": "<base64url string>",
    "privateKeyJwk": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." },
    "publicKeyJwk":  { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
    "signCount": 0,
    "createdAt": "2026-06-10T12:00:00Z"
  }
}
```

**No server changes needed.** Passkey entries are regular vault entries with the `passkey` sub-object populated. A URL prefix convention (`passkey://rpid`) lets the UI distinguish them (key icon instead of lock icon).

### 1b. Key generation — `generatePasskeyPair()`

New function in `javascript.js`:

```javascript
async function generatePasskeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,   // extractable: must be true to export for vault storage
    ['sign', 'verify']
  );
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicKeyJwk  = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const credentialId  = crypto.getRandomValues(new Uint8Array(32)); // 32 random bytes
  return { privateKeyJwk, publicKeyJwk, credentialId };
}
```

The private key is stored as JWK inside the encrypted JSON — only ever exposed in plaintext in browser memory after vault unlock, same as any password field.

### 1c. Signing — `signPasskeyChallenge()`

New function used by the extension communication path:

```javascript
async function signPasskeyChallenge(privateKeyJwk, authenticatorDataBytes, clientDataHashBytes) {
  const privateKey = await crypto.subtle.importKey(
    'jwk', privateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
  // WebAuthn: signature is over authenticatorData || SHA-256(clientDataJSON)
  const payload = new Uint8Array(authenticatorDataBytes.length + clientDataHashBytes.length);
  payload.set(authenticatorDataBytes, 0);
  payload.set(clientDataHashBytes, authenticatorDataBytes.length);
  return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, payload);
}
```

### 1d. Vault UI additions

- **Decoded entry view**: Extend `decodeLine()` to detect `fields.passkey` and render a passkey section showing `rpId`, `rpName`, creation date, credential ID (truncated). No private key JWK in UI.
- **Vault Tools (About modal)**: Add a "Passkeys" inventory list (`#passkey-list`) that iterates `_allEntries`, decrypts, and lists all passkey entries (entry name + rpId). Follows existing `auditVault()` pattern using `_forEachRecordDecrypt()`.

### 1e. Extension communication — postMessage API

The vault page needs to accept messages from the extension when it is open and unlocked:

```javascript
// In javascript.js — add to the DOMContentLoaded init block
const EXTENSION_ORIGIN = 'chrome-extension://YOUR_EXTENSION_ID'; // configurable constant

window.addEventListener('message', async (event) => {
  if (event.origin !== EXTENSION_ORIGIN) return;
  const { type, requestId } = event.data;

  if (type === 'passkey-get-credentials') {
    // Return list of passkey entries (decrypted names + credentialIds + rpIds, NO private keys)
    // Returns error if vault is locked (key fields empty)
    const list = await _listPasskeyEntries();
    event.source.postMessage({ type: 'passkey-credentials', requestId, list }, EXTENSION_ORIGIN);
  }

  if (type === 'passkey-sign') {
    const { credentialId, authenticatorDataHex, clientDataHashHex, requestId } = event.data;
    // Find entry by credentialId, decrypt, sign, return signature hex
    const sig = await _signWithStoredPasskey(credentialId, authenticatorDataHex, clientDataHashHex);
    event.source.postMessage({ type: 'passkey-signature', requestId, signatureHex: sig }, EXTENSION_ORIGIN);
  }
});
```

**Security note**: EXTENSION_ORIGIN must be the exact `chrome-extension://ID` origin of the installed extension. This origin is stable for a given extension (determined by its key in `manifest.json`). Messages from any other origin are silently dropped.

---

## Part 2: Browser Extension Architecture

### 2a. Manifest V3 structure

```
passkey-extension/
  manifest.json
  background.js          ← service worker
  content_script.js      ← injected into every page at document_start (MAIN world)
  popup.html / popup.js  ← vault URL config + approval UI
  lib/cbor.js            ← bundled CBOR library (cbor-x or cbor-web, ~15 KB)
  icons/
```

**manifest.json:**
```json
{
  "manifest_version": 3,
  "name": "Vault Passkey Bridge",
  "version": "1.0",
  "permissions": ["storage", "tabs", "activeTab", "scripting"],
  "host_permissions": ["*://*/*"],
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["*://*/*"],
    "js": ["content_script.js"],
    "run_at": "document_start",
    "world": "MAIN"
  }],
  "action": { "default_popup": "popup.html" }
}
```

`world: "MAIN"` is required — the content script must share the page's JS context to replace `navigator.credentials`. A content script in the default ISOLATED world cannot touch the page's `navigator`.

### 2b. Content script: WebAuthn interception

```javascript
// content_script.js — runs in MAIN world at document_start
const _nativeCreate = navigator.credentials.create.bind(navigator.credentials);
const _nativeGet    = navigator.credentials.get.bind(navigator.credentials);

Object.defineProperty(navigator.credentials, 'create', {
  configurable: false,   // non-configurable: page scripts cannot clobber it (1Password's hardening)
  enumerable: true,
  get: () => (options) => _interceptCreate(options, _nativeCreate),
});
Object.defineProperty(navigator.credentials, 'get', {
  configurable: false,
  enumerable: true,
  get: () => (options) => _interceptGet(options, _nativeGet),
});

async function _interceptCreate(options, native) {
  if (!options?.publicKey) return native(options); // not a passkey request
  return new Promise((resolve, reject) => {
    // Send to background service worker; receive synthetic attestation response
    chrome.runtime.sendMessage({ type: 'passkey-create', options: _serializeOptions(options) },
      (response) => response.error ? reject(new DOMException(response.error)) : resolve(_deserializeCredential(response)));
  });
}

async function _interceptGet(options, native) {
  if (!options?.publicKey) return native(options);
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'passkey-get', options: _serializeOptions(options) },
      (response) => {
        if (response.passthrough) return native(options).then(resolve, reject);
        response.error ? reject(new DOMException(response.error)) : resolve(_deserializeCredential(response));
      });
  });
}
```

### 2c. Background service worker

**Create flow:**
1. Find or open vault tab (configurable URL, stored in `chrome.storage.local`)
2. Send `passkey-get-credentials` via `chrome.tabs.sendMessage` to vault tab to confirm vault is unlocked
3. If vault is locked: open popup or new tab prompting user to unlock vault
4. Generate credential ID (32 random bytes) — key pair generation happens in background
5. Show approval UI in popup: "example.com wants to create a passkey — allow?"
6. On approval: send `passkey-save` to vault tab (vault saves a new encrypted entry)
7. Construct synthetic attestation object (see §2d) and return to content script

**Get flow:**
1. Query vault for all stored passkey entries (via `passkey-get-credentials`)
2. Match against `options.publicKey.allowCredentials` (if present) or `rpId`
3. If no match: return `{passthrough: true}` (fall through to native browser implementation)
4. Show approval UI: "example.com wants to sign in using your passkey — allow?"
5. Construct `authenticatorData` bytes (rpIdHash + flags + signCount)
6. Hash `clientDataJSON` (SHA-256)
7. Send `passkey-sign` to vault tab with authenticatorData + clientDataHash
8. Receive signature, construct assertion response, return to content script

### 2d. Synthetic credential construction (the hard part)

The relying party validates these cryptographically, so they must be byte-perfect.

**Registration — attestation object structure:**
```
attestationObject (CBOR map):
  "fmt"      → "none"
  "attStmt"  → {} (empty map)
  "authData" → <authenticatorData bytes>

authenticatorData bytes:
  [0..31]  rpIdHash = SHA-256(rpId as UTF-8)          32 bytes
  [32]     flags = 0x45 (UP=1, UV=1, AT=1)             1 byte
  [33..36] signCount = 0 (big-endian uint32)            4 bytes
  [37..]   attestedCredentialData:
             aaguid = 16 zero bytes
             credentialIdLength (big-endian uint16)
             credentialId bytes
             credentialPublicKey (CBOR COSE_Key):
               {1: 2, 3: -7, -1: 1, -2: x_bytes(32), -3: y_bytes(32)}
               (kty=EC2, alg=ES256, crv=P-256, x, y from publicKeyJwk)
```

**clientDataJSON** (UTF-8 bytes, hash is verified by RP):
```json
{"type":"webauthn.create","challenge":"<base64url of original challenge>","origin":"https://example.com","crossOrigin":false}
```

**Authentication — assertion response:**
```
authenticatorData bytes:
  [0..31]  rpIdHash = SHA-256(rpId)
  [32]     flags = 0x05 (UP=1, UV=1)
  [33..36] signCount (big-endian uint32, incremented from stored value)

clientDataJSON: {"type":"webauthn.get","challenge":"<base64url>","origin":"https://example.com","crossOrigin":false}

signature: ECDSA-P256-SHA256 over (authenticatorData || SHA-256(clientDataJSON))
           The ECDSA signature is DER-encoded (not raw r||s)
           WebCrypto's subtle.sign returns IEEE P1363 format (raw r||s, 64 bytes)
           → must convert to DER before sending to RP

userHandle: stored userId bytes from the passkey entry
```

**CBOR dependency**: Use `cbor-x` or `cbor-web` bundled into the extension. This is the only non-WebCrypto dependency. It handles the `attestationObject` and COSE public key encoding. Bundle it so no CDN request is made.

**ECDSA format conversion**: WebCrypto returns IEEE P1363 (64 bytes: r||s). WebAuthn expects DER. A small conversion function:
```javascript
function p1363ToDer(sig) {
  const r = sig.slice(0, 32), s = sig.slice(32);
  const pad = (b) => (b[0] & 0x80) ? new Uint8Array([0, ...b]) : b; // prepend 0x00 if high bit set
  const rp = pad(r), sp = pad(s);
  const body = new Uint8Array([0x02, rp.length, ...rp, 0x02, sp.length, ...sp]);
  return new Uint8Array([0x30, body.length, ...body]);
}
```

### 2e. Extension-to-vault communication details

The background service worker cannot directly call `window.postMessage` into a tab. The flow is:

```
Background SW
  → chrome.tabs.sendMessage(vaultTabId, msg)         [extension messaging]
  → Vault tab's content script (ISOLATED world)
  → content script calls window.postMessage(msg, vaultOrigin)
  → Vault page's message listener in javascript.js
  → Vault page replies via window.postMessage
  → Content script relays reply via chrome.runtime.sendMessage
  → Background SW resolves its Promise
```

This requires a second, **ISOLATED-world** content script running in the vault tab — separate from the MAIN-world content script that intercepts `navigator.credentials` on relying-party sites. The vault tab's isolated content script acts as the bridge between extension messaging and the vault page's postMessage API.

Alternatively: the vault page URL serves as the extension popup itself (opening the vault URL in the extension popup window), removing the need for the relay. This is simpler but requires the vault to be online.

---

## Part 3: Credential Autofill (username / password / TOTP)

The same two-component infrastructure that serves passkeys also serves classic
credential autofill. Autofill reuses: the MV3 extension, the ISOLATED-world
bridge content script in the vault tab (§2e), the background service worker, and
the vault page's origin-gated `postMessage` listener (§1e). Nothing in `post.php`
changes — autofill saves ride the existing `saveEntry()` write path and the
payload stays opaque.

**UX decision:** inline dropdown (a shadow-DOM overlay anchored to the focused
field), plus a popup "Fill on this page" fallback. **Capabilities:** username +
password fill, TOTP autofill, a save/update prompt on form submit, a registrable-
domain matcher, and a manual entry picker for any field/site.

### 3a. Vault-side postMessage handlers (extends the §1e listener)

Add these message `type`s to the **same** `window` message listener from §1e.
Every request is gated on `event.origin === EXTENSION_ORIGIN` and is refused
when the vault is locked (key fields empty). Transport reuses the §2e
ISOLATED-world bridge — only new message types, no new transport.

```javascript
// (added to the §1e window 'message' handler)

if (type === 'vault-get-logins') {
  // event.data: { requestId, host }   host === '*' (or absent) ⇒ all entries (manual picker)
  // Returns a NON-SECRET match list — no password — to drive the dropdown.
  const list = await _listLoginsForHost(event.data.host);
  // list: [{ recordKey, entryName, username, host, hasTotp }]
  event.source.postMessage({ type: 'vault-logins', requestId, list }, EXTENSION_ORIGIN);
}

if (type === 'vault-get-secret') {
  // event.data: { requestId, recordKey }  — the ONE entry the user chose in the dropdown
  // The only message that returns a password, and only for a single explicit choice.
  const secret = await _getLoginSecret(event.data.recordKey); // { username, password, totp }
  event.source.postMessage({ type: 'vault-secret', requestId, secret }, EXTENSION_ORIGIN);
}

if (type === 'vault-save-login') {
  // event.data: { requestId, name, url, username, password }
  // Routes through the existing saveEntry() path: de-dupe, CSRF/Basic-Auth, manifest re-sign.
  const ok = await _saveLoginFromExtension(event.data);
  event.source.postMessage({ type: 'vault-save-result', requestId, ok }, EXTENSION_ORIGIN);
}
```

**Supporting additions in `javascript.js`:**

- **Domain matcher** — `_loginHost(url)` (parse hostname) and
  `_registrableDomain(host)`: match on the registrable domain via a small
  public-suffix **heuristic** (compare the last two labels, with a short
  multi-part-TLD exception list, e.g. `co.uk`, `com.au`). So `login.example.com`
  matches an entry stored as `example.com` or `www.example.com`. This is a
  deliberate heuristic, **not** a full Public Suffix List — kept small to avoid
  bundling the PSL; the trade-off is rare mismatches on exotic TLDs.

- **Session host index** — `_loginHostIndex: Map<host, recordKey[]>`, seeded
  inside the existing `_revealAllV5Names` decrypt callback (the `url` is already
  in the decrypted `fields` there, so the index costs no extra Argon2id — keys
  are hot in `_mkCache`). Cleared alongside `_v5Names` / `_searchText` on lock.
  `_listLoginsForHost()` consults this index (cheap); `_getLoginSecret()`
  decrypts the single chosen record on demand via `decryptFields()`.

- **TOTP** — `_getLoginSecret()` returns a **freshly computed 6-digit code**
  (reusing the existing RFC-6238 path: `base32ToBytes()` + HMAC-SHA-1), never the
  raw `token` secret.

- **Save** — `_saveLoginFromExtension()` finds an existing entry for the host
  (update) or creates one, then calls the existing `saveEntry()` flow.

### 3b. Extension — autofill content script (`content_script_autofill.js`, ISOLATED world, all sites)

ISOLATED world is sufficient (DOM access only — unlike the MAIN-world WebAuthn
script it needs no page-JS context) and safer.

- **Field detection:** `autocomplete` tokens (`username`, `email`,
  `current-password`, `new-password`, `one-time-code`),
  `input[type=password|email]`, and name/id regexes; group a password field with
  its nearest preceding username/email field.
- **Inline dropdown:** a shadow-DOM overlay anchored to the focused field
  (isolated from page CSS), populated from `autofill-get-logins`. Selecting a row
  → `autofill-get-secret`, then fill username + password and **dispatch
  `input` / `change` / `keyup` events** so React/Vue/Angular forms register the
  change. A small vault icon in the field reopens the picker; an empty match list
  offers the **manual picker** (`host:'*'` → all entries).
- **TOTP autofill:** when a `one-time-code` field is present (or right after
  submit), fill the `totp` value from the secret response.
- **Save/update prompt:** on form submit (capture phase), if the submitted
  username/password don't match a stored entry for the host, show a non-blocking
  banner offering **Save** (new) or **Update** (existing `recordKey`) →
  `autofill-save`.

### 3c. Extension — background service worker additions

Handlers paralleling the passkey flows, each relaying to the vault tab via the
§2e bridge and reusing the §2c vault-discovery / "unlock vault first" path:
`autofill-get-logins` → `vault-get-logins`; `autofill-get-secret` →
`vault-get-secret` (after the in-page selection, optionally a popup approval
toggle); `autofill-save` → `vault-save-login`.

### 3d. Extension — popup additions

- "Fill on this page" manual trigger (fallback when in-page detection misses).
- Per-site enable/disable and an "ask before filling" approval toggle, stored in
  `chrome.storage.local`.

### 3e. Security notes

- A password leaves the vault page only via `vault-get-secret`, only for a single
  user-chosen entry, only to the verified `EXTENSION_ORIGIN`, only while unlocked.
- The TOTP **secret** never leaves the vault — only the derived code does.
- Filled secrets necessarily live in the page DOM (unavoidable for autofill);
  the overlay and any cached secret reference are cleared immediately after fill.
- Consistent with the existing threat model (LAN + VPN + HTTPS; server/host
  compromise out of scope).

---

## What This Does NOT Cover (Scope Boundaries)

- **iOS/Safari**: No extension support in mobile Safari. Not feasible without a native app.
- **OS passkey picker integration**: These passkeys won't appear in Chrome's/Windows's/macOS's native credential chooser — they only work when the extension is active.
- **iCloud Keychain / Google Password Manager sync**: Deliberately excluded — the point is self-hosted control.
- **Attestation**: Using `fmt: "none"` (no attestation statement). Enterprise sites requiring attestation will reject these. Acceptable for personal use.
- **Cross-origin iframes**: Out of scope for initial implementation.
- **Firefox**: Architecture is compatible but Firefox has a known bug (popup closes during WebAuthn flow). Workaround: open vault in a tab instead of popup. Cross-browser polish is a follow-up.

---

## Critical Files

| File | What Changes |
|------|-------------|
| `javascript.js` | Add `generatePasskeyPair()`, `signPasskeyChallenge()`, extend `decodeLine()` to render passkey fields, add `passkey-get-credentials` / `passkey-sign` postMessage handler, add passkey inventory to Vault Tools. **Autofill:** add `vault-get-logins` / `vault-get-secret` / `vault-save-login` handlers, `_loginHost()` / `_registrableDomain()` matcher, `_loginHostIndex` (seeded in `_revealAllV5Names`), `_listLoginsForHost()` / `_getLoginSecret()` / `_saveLoginFromExtension()` (reuses `decryptFields`, existing TOTP path, `saveEntry`) |
| `part2` | Add `#passkey-list` div to About modal Vault Tools section |
| `post.php` | **No changes** — passkey data is opaque inside encHEX; autofill saves ride the existing `saveEntry` write path |
| `passkey-extension/manifest.json` | New — Manifest V3 (autofill adds `content_script_autofill.js` to `content_scripts`) |
| `passkey-extension/content_script.js` | New — MAIN world, overrides navigator.credentials |
| `passkey-extension/content_script_isolated.js` | New — ISOLATED world in vault tab, relays messages (passkey **and** autofill) |
| `passkey-extension/content_script_autofill.js` | New — ISOLATED world, all sites: field detection, inline shadow-DOM dropdown, manual picker, TOTP fill, save/update prompt |
| `passkey-extension/background.js` | New — service worker, orchestrates create/get **and** `autofill-get-logins` / `autofill-get-secret` / `autofill-save` flows |
| `passkey-extension/popup.html` + `popup.js` | New — vault URL config, approval UI, "Fill on this page" + per-site toggles |
| `passkey-extension/lib/cbor.js` | New — bundled CBOR library, no CDN |

---

## Implementation Phases (recommended order)

1. **Vault data model**: extend `decodeLine`/`saveEntry` to handle `passkey` sub-object; add `generatePasskeyPair()` and `signPasskeyChallenge()`. Verify: save a passkey entry manually, decrypt, confirm JWK round-trips.

2. **Vault postMessage API**: add `message` event listener. Verify: `window.postMessage({type:'passkey-get-credentials'}, location.origin)` in browser console returns list.

3. **Extension scaffold**: manifest, popup (vault URL config), background skeleton, content script skeleton. Verify: extension loads, no console errors.

4. **Content script interception**: override `navigator.credentials`, log intercepted calls. Verify: navigate to webauthn.io, confirm extension sees `create`/`get` calls.

5. **Create flow end-to-end**: generate key pair, save via vault postMessage, construct attestation object. Verify: complete passkey registration on webauthn.io; confirm entry stored in vault.

6. **Get flow end-to-end**: retrieve private key, sign, return assertion. Verify: authenticate on webauthn.io using stored passkey; confirm signCount increments.

7. **Vault autofill API**: add `vault-get-logins` / `vault-get-secret` / `vault-save-login` handlers, the `_loginHost`/`_registrableDomain` matcher, and the `_loginHostIndex` (seeded in `_revealAllV5Names`). Verify: from the vault console, `postMessage` queries return the right matches and a single secret; a locked vault refuses.

8. **Extension autofill UI**: `content_script_autofill.js` field detection + inline shadow-DOM dropdown + manual picker, wired through the background relay. Verify: on a login page, the dropdown lists matching entries and fills username/password with framework `input`/`change` events firing.

9. **Save/update prompt + TOTP autofill**: capture-phase submit detection → save/update banner; `one-time-code` fields filled with the derived code. Verify: a new login is offered for save and lands in the vault; a TOTP field auto-fills the current code.

---

## Verification Test Sites

- `webauthn.io` — public passkey test site, no account needed, full create + authenticate flow
- `passkeys.io` — alternative test site
- A self-hosted/static login form (and common provider login pages) — exercise username/password autofill, the manual picker, save/update prompt, and TOTP fill
- Browser DevTools → Application → Session Storage can confirm no private key material leaks to storage
