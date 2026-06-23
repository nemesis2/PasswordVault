# Vault Autofill Companion (Firefox)

A Firefox extension that unlocks your self-hosted, client-side-encrypted vault and
autofills logins into web pages. **All decryption happens locally in the browser** —
the extension only ever fetches the same ciphertext the vault already serves, and
your passwords are never stored or sent anywhere.

## How it works

1. You enter the vault URL (e.g. `https://host/pass/<instance>/`) and both master
   passwords in the toolbar popup.
2. The background page fetches the vault's `index.html` — an unauthenticated read
   (only *writes* require Basic Auth) — and parses every encrypted v6 record out
   of the `data-row` attributes, plus the Argon2id cost from the `#vault-kdf`
   span. It is a plain HTTP `GET`, so it works the same whether the vault is
   served by the **PHP** backend (`post.php`) or the **standalone Node server**
   (`server.js`, in either `local` or `web` mode) — both emit a byte-identical
   `index.html`.
3. It derives the two Argon2id master keys per record and runs the exact v6
   decrypt cascade (Serpent → Twofish → AES-GCM → ChaCha20 for payloads;
   ChaCha20 → AES-GCM for names). The decrypted entries live **only in the
   background page's memory**.
4. The popup lists entries, surfacing ones whose `url` matches the current tab at
   the top. **Fill** types the username + password into the page's login form;
   **📋** copies the password; **OTP** copies the live TOTP code. **Clicking an
   entry's name** expands an inline panel (Display-Panel-style) showing its URL,
   username, password (masked, with 👁 reveal), live TOTP with countdown, notes,
   tags, and custom fields — every value click-to-copy. Field values are fetched
   from the background only when an entry is expanded.
5. The session auto-locks after 5 minutes of **true system idle** (via the
   `idle` API — no keyboard/mouse activity anywhere, or the screen locks), or
   immediately via **Lock**. Auto-lock can be turned off in the About modal
   (persisted in `storage.local`). Locking wipes the decrypted entries and the
   master-key cache from memory.

The toolbar icon is **monochrome (grayscale) while locked** and switches to
**full color once unlocked** (set from the background via `browserAction.setIcon`,
reset on lock/idle). The password inputs each have an **👁 / 🙈 show-hide toggle**.
During unlock, a **progress bar with a travelling 🔑** fills as each record is
decrypted (the background streams per-record progress to the popup).

The cryptography is not reimplemented: `crypto-ciphers.js` is a byte-for-byte
slice of the vault's `javascript.js` (the ChaCha20-Poly1305, Twofish-256,
Serpent-256, and Argon2id-WASM bundles + the CTR helpers), so the extension
decrypts with the identical code path the web app uses. `crypto-vault.js` is the
thin, DOM-free orchestration (key derivation, HKDF, the v6 flows, TOTP, record
parsing).

## Install (temporary, for development)

1. Open `about:debugging#/runtime/this-firefox` in Firefox.
2. Click **Load Temporary Add-on…** and select `manifest.json` in this folder.
3. The 🔒 toolbar button appears — click it to unlock.

Temporary add-ons are removed when Firefox restarts. To install permanently you
must package and sign it — see below.

## Build & sign (.xpi)

An `.xpi` is just a zip with `manifest.json` at its root. Firefox refuses to
*permanently* install one unless it's **signed by Mozilla** (release/Beta builds;
Developer Edition / Nightly / ESR can disable this with
`xpinstall.signatures.required=false`). Two paths:

### Quick unsigned package (no dependencies)

```bash
./build-xpi.sh        # or: npm run build:zip
```

Produces `web-ext-artifacts/vault-autofill-companion-<version>.xpi` containing
only the runtime files (a whitelist — dev files like `selftest.js`, `README.md`,
and the build tooling are excluded). Install it temporarily via `about:debugging`,
or upload it to AMO for signing.

### Signed package via `web-ext` (recommended)

[`web-ext`](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/)
is Mozilla's official tool. Install the dev dependency once:

```bash
npm install
```

Then:

```bash
npm run lint          # validate the manifest/sources (do this first)
npm run build         # → web-ext-artifacts/*.zip (unsigned, web-ext's packager)
npm run sign          # self-distribution: returns a signed .xpi you host yourself
npm run sign:listed   # submit to AMO for review + public listing instead
```

Signing needs **AMO API credentials** — generate a key/secret at
<https://addons.mozilla.org/developers/addon/api/key/> and pass them via env:

```bash
export WEB_EXT_API_KEY="user:XXXXXX:XXX"     # the AMO "JWT issuer"
export WEB_EXT_API_SECRET="…"                # the AMO "JWT secret"
npm run sign
```

The add-on id and `strict_min_version` already live in
`manifest.json → browser_specific_settings.gecko`, which signing/self-distribution
require. `npm run sign` (channel `unlisted`) returns a Mozilla-signed `.xpi` in
`web-ext-artifacts/` that installs permanently and self-updates if you host an
update manifest; `sign:listed` puts it through AMO review for the public store.

> **Chrome/Edge:** a Manifest V3 port exists in [`../chrome-extension`](../chrome-extension)
> (`action` instead of `browser_action`, the `scripting` API instead of
> `tabs.executeScript`, and a persistent offscreen document hosting the session +
> worker pool). It shares this extension's crypto, content script, popup, and
> icons verbatim.

## Files

| File | Role |
|------|------|
| `manifest.json` | MV2 manifest. CSP includes `'wasm-unsafe-eval'` so the Argon2id WASM compiles. |
| `crypto-ciphers.js` | Verbatim cipher bundles + `twofishCTR`/`serpentCTR` from the vault's `javascript.js` (lines 1–1641). **Regenerate** if those change: `sed -n '1,1641p' ../javascript.js > crypto-ciphers.js`. |
| `crypto-vault.js` | Standalone decrypt **and encrypt** orchestration → `globalThis.VaultCrypto` (adds `encryptName`/`encryptFields`/`buildRecord` for passkey writes + `generatePasskeyPair`/`signPasskeyChallenge` ECDSA P-256 helpers). |
| `background.js` | Holds the unlocked session, fetches + decrypts the vault, matches by hostname, auto-locks. Also handles the **passkey** create/get ceremonies, the approval window, the authenticated POST that stores a new passkey, and the follow-up **re-sign of the vault integrity manifest** (`vm1`, via `_resignVault`) so the new record doesn't trip the PWA's tamper check — best-effort, mirroring the PWA's auto-re-sign after its own writes. |
| `content.js` | Injected on demand by **Fill** to set username/password fields (framework-safe via the native value setter + input/change events). |
| `webauthn.js` | WebAuthn byte builders → `globalThis.WebAuthnKit`: a minimal CBOR encoder, COSE public key, `authenticatorData`, `attestationObject`, `p1363ToDer` (assertion signature), base64url helpers. Shared verbatim with the Chrome build. |
| `content_passkey_bridge.js` | Content script: injects `passkey-inpage.js` into the page (MV2 has no `world:"MAIN"`) and relays passkey ceremonies between the page and the background over a long-lived port. |
| `passkey-inpage.js` | Page-injected (`web_accessible_resources`) override of `navigator.credentials.create/get` — the MAIN-world equivalent of Chrome's `content_passkey_main.js`. Passes through to the native authenticator when no stored passkey matches. |
| `approve.html` / `approve.js` | Per-ceremony approval window, always showing the **validated requesting origin** (not just the RP-supplied name). Creating a passkey prompts for the two master passwords (to encrypt) + the vault write password (to POST) and offers **Use this device instead** (fall back to the native authenticator rather than failing). Once both master passwords are entered it **unlocks the vault and lists existing entries** so the passkey can be **attached to one** (site-matching entries first; entries that already hold a passkey are disabled) instead of always creating a new entry — default is **Create new entry**. Attaching decrypts the chosen entry's *full* record, injects the `passkey` sub-object, and commits an **atomic replace** (`delete_rec=<old>&data=<new>`) so the passkey lands on your existing login. Using a passkey requires a per-assertion **confirm** (user-presence gesture) even when unlocked; if locked, it prompts for the master passwords first. Conditional/silent `get()` and cross-platform requests pass through to the browser natively. Nothing persisted. |
| `popup.html` / `popup.css` / `popup.js` | Toolbar UI. |
| `selftest.js` | `node selftest.js` — builds a v6 record with the bundled ciphers and round-trips it through `VaultCrypto` (name/fields/TOTP/wrong-password), cross-checks the `buildRecord` encrypt path, and verifies the passkey round-trip + ECDSA sign/verify + CBOR/DER builders. |
| `build-xpi.sh` | Zero-dependency unsigned `.xpi` builder (whitelist zip). |
| `package.json` / `web-ext-config.cjs` | `web-ext` lint/build/sign tooling + the package denylist. Not shipped in the `.xpi`. |

## Keeping crypto in sync

If the vault's `javascript.js` cipher bundles or the v6 format change, re-slice
`crypto-ciphers.js` (command above) and re-run `node selftest.js`. The HKDF info
labels, cipher order, and KDF bounds in `crypto-vault.js` mirror `javascript.js`
and `post.php`'s `is_valid_kdf()` — update them together if they ever change.

## Security notes / limits

- **Mostly read-only.** This companion decrypts and fills logins; for ordinary
  entries it does not add, edit, or delete — use the web app for those writes. The
  one exception is **passkeys** (WebAuthn): the extension acts as the authenticator
  and *creates* passkey entries, prompting per-write for the two master passwords
  (to encrypt) and the vault write password (to save) — nothing is persisted.
  Using a stored passkey to sign in is read-only.
- **Passwords are never persisted.** Only the vault *URL* is saved (in
  `storage.local`) for convenience. The decrypted vault exists solely in the
  background page's RAM and is wiped on lock/idle.
- **`<all_urls>` host permission** is required to (a) fetch your vault from
  whatever host you point it at and (b) fill credentials into login pages.
- The decrypt cost is real: at the vault's default Argon2id parameters, unlocking
  derives two memory-hard keys per entry. The first unlock of a large vault can
  take several seconds; the popup can be closed while it runs.
- Same threat model as the vault itself: this protects ciphertext confidentiality
  in the browser. A compromised machine or a malicious page you fill into is out
  of scope.
