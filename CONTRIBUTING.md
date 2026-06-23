# Contributing

Thanks for your interest. This is a self-hosted, client-side-encrypted password
manager; correctness and the security model matter more than feature volume.
Please read [THREAT_MODEL.md](THREAT_MODEL.md) before proposing changes that touch
crypto, storage, or the server.

## Repository layout

| Path | Role |
|------|------|
| `javascript.js` | The readable front-end source — **edit this directly** (no build/minify step). |
| `part1` / `part2` | HTML template fragments spliced around the entry buttons. |
| `index.html` | **Build artifact** — regenerated from `part1` + records + `part2`. Do not edit by hand. |
| `post.php` | PHP backend: write protocol, `index.html` regeneration, auth, rate limiting. |
| `server.js` | Dependency-free Node backend — a byte-faithful port of `post.php` + the static/header layer. |
| `parity-test.js` | Proves `server.js` is byte-identical to `post.php`. |
| `sw.js` | Service worker (asset caching + offline fallback; never caches the vault document). |
| `argon2-worker.js` | Argon2id Web Worker (the `hash-wasm` bundle + a message tail). |
| `chrome-extension/`, `firefox-extension/`, `tui.node/` | Companion clients. |
| `moved/` | Offline re-encryption tooling and cipher-bundle build inputs (private repo only). |

A fuller architecture reference lives in [CLAUDE.md](CLAUDE.md).

## Local development

Serve the directory from any PHP-capable web server so `post.php` can write
`lines`, `bak/`, and `index.html`:

```bash
php -S localhost:8080      # then open http://localhost:8080/
```

Or run the standalone Node backend (no PHP needed):

```bash
node server.js             # local mode → http://127.0.0.1:8787
```

### After editing `part1` / `part2`

`index.html` is generated. Rebuild it without changing any record:

```bash
./regen.sh                                   # local CLI shortcut, or
curl -u user:pass "http://localhost:8080/post?regen=1"
```

If you edit templates as a non-`www-data` user, `chown www-data:www-data` the
files afterward so php-fpm can still rewrite them.

## Required checks before a PR

1. **JS syntax:** `node --check javascript.js && node --check sw.js`
2. **Backend parity** (after any change to `post.php` *or* `server.js`):
   ```bash
   node parity-test.js          # needs `php` on PATH; must report 12/12 byte-identical
   ```
3. **Crypto self-test:** open the About modal in a browser and confirm the
   self-test banner is green (WebCrypto, ChaCha, AES, Twofish, Serpent, Argon2id).
4. **Bundle integrity** (only if you touched an inlined cipher):
   ```bash
   ./verify-bundles.sh
   ```

## Conventions

- **No inline scripts or `on*=` handlers.** The CSP forbids them. Wire behavior in
  `javascript.js`: add a `data-action="…"` attribute and a matching entry in the
  `_clickActions` map (the two must stay in sync).
- **Match the surrounding style** — the codebase uses `var`, ES5-ish function
  style, and dense explanatory comments. Follow it rather than introducing a new
  idiom.
- **Storage format is v6.** Don't add legacy decode branches. New per-entry data
  goes *inside* the encrypted payload JSON (like `tags`/`extra`/`history`), never
  as a new plaintext record field.
- **Keep the two backends in lockstep.** `post.php` is canonical; mirror any
  protocol change in `server.js` and re-run `parity-test.js`.

## Rebuilding the inlined cipher bundles

The ciphers are vendored as IIFE bundles spliced into `javascript.js`. They are
built once with `esbuild` from small entry files (in `moved/`):

```bash
npm install @noble/ciphers twofish-ts hash-wasm
npx esbuild moved/chacha_entry.js  --bundle --format=iife --platform=browser --outfile=moved/chacha_bundle.js
npx esbuild moved/twofish_entry.js --bundle --format=iife --platform=browser --outfile=moved/twofish_bundle.js
npx esbuild moved/argon2_entry.js  --bundle --format=iife --platform=browser --outfile=moved/argon2_bundle.js
# Serpent is a hand-written, vector-verified bundle (no npm package): moved/serpent_bundle.js
# The served worker is the argon2 bundle + a message tail:
cat moved/argon2_bundle.js moved/argon2_worker_tail.js > argon2-worker.js
```

`./verify-bundles.sh` automates rebuilding and diffing these against what's
committed. See [CLAUDE.md](CLAUDE.md) → *Inlined Cipher Bundles* for details.

## Roadmap

Open ideas and their status are tracked in [suggestions.md](suggestions.md).
