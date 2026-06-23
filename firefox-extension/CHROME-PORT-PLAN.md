# Chrome / Edge Port Plan (MV3)

Status: **DONE** (2026-06-20) — built in [`../chrome-extension/`](../chrome-extension)
using **Approach B** (offscreen document hosting the worker pool + session). The
offscreen document was needed regardless of the perf goal, because an MV3 service
worker is ephemeral and would lose the decrypted session on idle — so it doubles as
the persistent state holder. Firefox MV2 (`manifest.json` here) is untouched. The
notes below are kept as the original plan / rationale.

## Why it's non-trivial

Chrome/Edge require **Manifest V3**, where the background runs as a **service worker
with no DOM**. The current `background.js` / `crypto-vault.js` depend on four things
that don't exist in an MV3 service worker:

| Current usage | MV3 problem | Fix |
|---|---|---|
| `new Worker("argon2-worker.js")` — the Argon2id pool (`crypto-vault.js`) | a Chrome MV3 service worker **cannot spawn Web Workers** | the fork in the road — see Approaches |
| `new Image()` + `document.createElement("canvas")` + `getContext`/`getImageData` — icon compositing & animation (`background.js`) | no `document` / `Image` in a SW | `OffscreenCanvas` + `createImageBitmap(blob)` (both available in a SW) |
| `new DOMParser().parseFromString(html)` — parsing the vault `index.html` (`background.js`) | no `DOMParser` in a SW | regex-extract the `data-row="…"` attrs + the `#vault-kdf data-kdf` span — small, self-contained |
| `tabs.executeScript`, `browserAction.*` | renamed in MV3 | `scripting.executeScript({target:{tabId,allFrames}, files:["content.js"]})`, `action.*` |
| manifest: `browser_action`, persistent background, `<all_urls>`, string CSP | MV3 shape changed | `action`, `background.service_worker`, `host_permissions`, CSP **object** (`{extension_pages: "…"}`; `'wasm-unsafe-eval'` still allowed) |

## Two approaches (the worker pool decides the effort)

### Approach A — get it working, slower unlock (~1–1.5 days)
`_argonDerive` (in `crypto-vault.js`) **already falls back to in-process Argon2id**
when workers are unavailable, so the SW can run it single-threaded. Everything
functions, but a large-vault unlock loses multi-core parallelism and gets noticeably
slower (and briefly blocks the SW). Includes the mechanical manifest/API swaps,
OffscreenCanvas icons, and regex index parsing.

### Approach B — performance parity (~2.5–3.5 days)
Add a Chrome **offscreen document** (`chrome.offscreen` API + `offscreen` permission)
that hosts the Argon2id worker pool (and can also host `DOMParser`/canvas), with the
service worker as a thin message router. Keeps full multi-core Argon2id like Firefox.
Well-trodden pattern but the real chunk of work: an `offscreen.html` / `offscreen.js`
bridge, lifecycle management, and plumbing the crypto through it.

**Recommendation:** do **A first** (validates the whole MV3 path and yields a working
Chrome/Edge build fast), then upgrade to B only if unlock speed on big vaults matters.

## Task checklist (Approach A)

- [ ] Add `manifest.chrome.json` (MV3): `manifest_version:3`, `action`,
      `background.service_worker` (single file — combine `crypto-ciphers.js` +
      `crypto-vault.js` + `background.js` via `importScripts`, or `type:"module"`),
      `host_permissions:["<all_urls>"]`, `permissions:["storage","activeTab","tabs",
      "idle","clipboardWrite","scripting"]`, CSP object with `'wasm-unsafe-eval'` +
      `worker-src 'self'`, and the same `data_collection_permissions` idea is
      Firefox-only (drop it for Chrome).
- [ ] Keep **one shared source tree**; Firefox MV2 (`manifest.json`) stays as-is and
      signed — do not disturb it.
- [ ] `browserAction.*` → `action.*` (setIcon / setBadgeText / setBadgeBackgroundColor
      / setBadgeTextColor — all exist in Chrome MV3; transparent `[0,0,0,0]` badge bg
      works in Chrome too).
- [ ] Icons: replace `new Image()` + `<canvas>` with `OffscreenCanvas` +
      `createImageBitmap(await (await fetch(iconURL)).blob())`. Re-verify the decode
      **animation** under the SW lifecycle (SW can be killed when idle — it stays alive
      during an active decode, but the `setInterval` animation is the fragile part).
- [ ] `tabs.executeScript` → `chrome.scripting.executeScript`. `content.js` itself is
      DOM code in the page and needs no change.
- [ ] Replace `DOMParser` with regex extraction of `data-row` + `#vault-kdf`.
- [ ] `browser` vs `chrome`: the `api = browser||chrome` shim mostly holds (Chrome MV3
      returns promises on most APIs); only `scripting`/`action` names differ. Consider
      `webextension-polyfill` if it gets messy.
- [ ] Build: extend `build-xpi.sh` / `package.json` to also emit a Chrome zip
      (`web-ext` can target Chromium, or a plain `zip`).
- [ ] Test matrix: Chrome + Edge (same MV3 zip) + confirm Firefox MV2 still works.

## Distribution notes
- **Edge is free** and Chromium-based — the same MV3 package installs there; only the
  store listing differs (Edge Add-ons is a separate, free portal).
- **No Firefox-style signing hoop** — Chrome loads unpacked for dev; the Chrome Web
  Store has a one-time **$5** developer fee + review for public distribution.
