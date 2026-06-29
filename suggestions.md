# Feature Suggestions & Roadmap

A running list of feature ideas and improvements for the vault, grouped by
theme. Items marked **✅ done** have been implemented; the rest are proposals.

## Highest-leverage (given the threat model)

The `vm1` integrity manifest protects *data* integrity but **not the served
code** — a compromised server can ship a malicious `javascript.js` and defeat
everything. The locally-installed pieces are the trust anchor for closing that gap.

- **Code-integrity pinning in the browser extensions.** The Chrome/Firefox
  extensions are locally-installed code the server can't rewrite. Have them
  fetch `javascript.js` and compare against a known-good SHA-256 (pinned in the
  extension, bumped on release), warning on mismatch. The one addition that
  raises the "server compromise = game over" ceiling.
- **✅ Service worker as a verifying shell.** A SW gives offline read *and* a
  hash-pinned `javascript.js` / `argon2-worker.js`. The SW is the small trusted
  root that validates the big app bundle. *(Implemented — see `sw.js`.)*

## Authentication & key derivation

- **✅ KDF auto-tune / benchmark.** "Calibrate" control that runs Argon2id and
  picks the highest `m`/`t` hitting a target time on the current device.
- **WebAuthn PRF as one of the two factors.** Derive one master key from a
  hardware key via the WebAuthn `prf` extension. (Distinct from the shipped
  passkey-*storage* feature — the extensions storing/signing passkeys; this would
  instead use a hardware key to *unlock the vault*. See `PASSKEY_PLAN.md`.)
- **Recovery path.** Shamir secret-sharing of a recovery key, or a printed
  recovery code wrapping the vault key. Today a forgotten password = total loss.
- **Duress / decoy password.** A second password pair that decrypts a decoy set.

## Entry features

- **Passphrase (diceware) generator.** Charset generator only today; add an
  EFF-wordlist passphrase mode.
- **❌ Encrypted attachments (rejected).** Per-entry encrypted file blobs.
  The no-server-change option — blobs inside the encrypted payload JSON (like
  `tags`/`extra`/`passkey`) — bloats the served `index.html` (which embeds every
  record's ciphertext in a `data-row` and is `no-store`, re-downloaded every
  load) by ~2× the file size in hex on **every** page load. The clean
  alternative (metadata in payload + a separate on-demand blob store, new
  `post.php`/`server.js` modes + parity + deny rules + orphan GC) was judged not
  worth the added complexity. Not building it.
- **✅ Secure notes as a first-class type.** A `note` entry type (vs `login`) —
  just a title + encrypted body (Notes), tags, and custom fields, with the
  credential/2FA/password machinery hidden. Stored as `fields.type` inside the
  encrypted payload JSON (no v6 format change; `login` is the absent-key default).
- **✅ Bulk operations** — multi-select delete/tag/favorite. A grid select mode
  with a bulk-action bar; delete/tag commit in one atomic count-flexible `restore`
  write (delete is Undo-able), favorite is localStorage-only.
- **Expiry & reminders.** Surface `pwModified` staleness proactively.

## TOTP

- **✅ Full `otpauth://` spec.** Parse `digits`, `period`, `algorithm`
  (SHA-1/256/512) and **Steam Guard** alphabet from the URI.

## Import / export & interop

- **✅ KeePass 2 XML + 1Password `.1pux` import.** Native-format migration.
  (Encrypted `.kdbx` binary is intentionally out of scope — it needs a full
  binary-crypto parser that can't be loaded under the CSP; export to XML/CSV
  from KeePass first. `.1pux` is a ZIP+JSON, read client-side via
  `DecompressionStream`.)
- **Encrypted backup export** wrapped under a single backup password.

## UX

- **✅ Command palette** (`Ctrl-K`) — fuzzy jump/copy/edit. Opens with **Ctrl/⌘-K**,
  **?**, or the 🔍 button; **Enter** opens the highlighted entry, **Ctrl-C/U/E** copy
  its password / username or open it for editing, and a leading **`>`** switches to a
  fuzzy command list (New, Lock, Export/Import, Audit, Passkeys, Trash, Change
  Passwords/KDF, theme toggle, …). Scoped prefixes (`#tag`, `@note`, `!field`) apply.
- **✅ Light theme toggle.** Persisted per-instance.
- **✅ Favicons for entries.** CSP-safe local letter/color avatars derived from
  the entry URL domain (no third-party favicon fetch — `connect-src 'self'`).

## Project health

- **CI via GitHub Actions** running `parity-test.js` + lint on every push.
- **✅ `SECURITY.md` / `THREAT_MODEL.md` / `CONTRIBUTING.md`** as standalone
  docs for the public repo.
- **✅ `verify-bundles.sh`** to rebuild each inlined crypto bundle and diff it
  against the committed copy.
- **✅ README screenshots.** Three in-app screenshots embedded at the top of the
  README (`images/`). A demo GIF, status badges, and issue templates are still open.
- **✅ A real test suite.** `run-tests.sh` drives the suites — Node crypto/logic
  round-trips (`test-client.js`, `test-client-extras.js`), server protocol +
  HTTP-layer (`test-server.js`, `test-http.js`), both extension passkey selftests,
  a Playwright browser E2E (`test-browser/`), and the `post.php` ↔ `server.js`
  byte-parity check (`parity-test.js`).
