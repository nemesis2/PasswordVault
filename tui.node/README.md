# vault-tui

A Node.js **terminal UI** for the same client-side-encrypted password vault the
web app serves. It reads and writes the **identical** `lines` / `manifest` files
using the **identical** v6 crypto, so the browser and the TUI are fully
interoperable — entries created in one decrypt cleanly in the other, and the TUI
re-signs the integrity manifest after every write so the web UI still shows
`✓ Integrity verified`.

No build step, no npm install — it reuses the cipher bundles already shipped in
`../javascript.js` (ChaCha20-Poly1305, Twofish-256, Serpent-256) and
`../argon2-worker.js` (Argon2id WASM). Pure Node ≥ 18 (WebCrypto built in).

It tracks the vault's current v6 scheme exactly: it reads the **vault-wide
Argon2id cost** from the `kdfparams` file (default 128 MiB / t = 3 when absent,
the same fallback as `post.php`), so it decrypts at whatever cost the vault was
last (re-)encrypted with; it applies the same **length-hiding padding** (256-byte
buckets) when it writes a record; and on **edit** it preserves every payload
field the UI doesn't surface — tags, custom fields, password history, and the
password-age stamp — archiving the old password (and restamping the age) when the
password changes, just like the web app.

## Run

```bash
cd tui.node
node vault-tui.js
# or target another instance / a copy:
VAULT_DIR=/var/www/html_n2/pass/<instance> node vault-tui.js
```

It must run in an interactive terminal. The UI **dynamically fits and fills**
the screen: the entry list reflows into as many columns as fit, and everything
re-lays-out live on terminal resize.

## Keys

| Screen | Keys |
|--------|------|
| **Unlock** | type both master passwords · `Tab`/`↑↓` switch · `Ctrl-R` reveal · `Enter` unlock · `Esc` quit |
| **List** | `↑↓←→` / `hjkl` move · `Enter` view · `a` add · `e` edit · `d` delete · `/` search · `l` lock · `q` quit |
| **Detail** | `c` copy password · `u` copy username · `t` copy TOTP · `o` open URL · `e` edit · `d` delete · `Esc` back |
| **Add/Edit** | `Tab`/`↑↓` fields · `Ctrl-R` reveal pw/token · `Ctrl-G` generate password · `Ctrl-S` save · `Esc` cancel |

- **TOTP** codes render live with a 30-second countdown bar (RFC 6238).
- **Clipboard** uses `pbcopy` (macOS) or `wl-copy` / `xclip` / `xsel` (Linux);
  if none is installed, copy degrades to a warning.
- **Auto-lock** after 5 minutes idle, mirroring the web app.

## Layout

| File | Role |
|------|------|
| `vault-tui.js` | App: screens, key handling, responsive rendering |
| `lib/crypto.js` | v6 cascade — loads the cipher/Argon2id bundles from the parent app, mirrors the browser KDF / encrypt / decrypt / TOTP / manifest helpers (incl. the vault-wide KDF cost + length-hiding padding) |
| `lib/vault.js` | `lines` / `bak/` / `manifest` / `kdfparams` storage, byte-compatible with `post.php` (same backup retention — newest 100 / younger than 60 days, override via `VAULT_BAK_KEEP` / `VAULT_BAK_MAX_AGE_DAYS`) |
| `lib/model.js` | in-memory vault: unlock, decrypt, add/edit/delete, re-sign |
| `lib/argon-pool.js` | `worker_threads` pool (one worker per core) for Argon2id |
| `lib/argon-thread.js` | worker entry — loads the Argon2id WASM bundle, hashes on demand |
| `lib/ui.js` | ANSI primitives, diffed screen buffer, raw-mode key parser |

## Unlock is multi-threaded

Unlock decrypts every entry name, and each name needs two memory-hard Argon2id
derivations (128 MiB each at the vault's default cost, up to 1 GiB if raised) —
the dominant cost. hash-wasm runs Argon2id
synchronously on one WASM instance, so a plain loop pins it to a single core.
Instead `model.unlock()` spins up a pool of **worker threads, one per CPU core**
(`lib/argon-pool.js`) and decrypts names with matching concurrency, fanning the
derivations across all cores; the pool is torn down as soon as unlock finishes,
so its memory (≈ cores × the vault's Argon2id memory cost) is held only during unlock. Single-entry views
afterwards derive in-process. Set `VAULT_TUI_THREADS=<n>` to cap the worker count
(e.g. to bound memory on a many-core box). If `worker_threads` is unavailable it
falls back to in-process derivation automatically.

Like the PHP / Node backends, the TUI prunes `bak/` on every write — first dropping
backups older than 60 days, then keeping only the newest 100 (oldest first). Override
either limit with `VAULT_BAK_KEEP` / `VAULT_BAK_MAX_AGE_DAYS` (`0` disables that limit).

## Ownership caveat

The web server writes these files as `www-data`. If you run the TUI as another
user (e.g. `root`), the files it rewrites (`lines`, `manifest`, `bak/*`) become
owned by that user and php-fpm's next save can fail. Run it as `www-data`
(`sudo -u www-data node vault-tui.js`) or `chown www-data:www-data lines manifest bak/*`
afterward.
