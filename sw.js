/* sw.js — Password Vault service worker.
 *
 * Purpose (deliberately NARROW, to respect the vault's security model):
 *   1. Speed up repeat loads of the heavy, NON-SECRET code assets
 *      (javascript.js ~300 KB, argon2-worker.js ~42 KB) via a cache.
 *   2. Make the app a well-behaved installable PWA with a graceful OFFLINE
 *      fallback page.
 *   3. Expose a hash-reporting hook (GET_ASSET_HASHES) so a future
 *      code-integrity check (e.g. the browser extension) can read the
 *      SHA-256 of the running app bundle.
 *
 * What it intentionally does NOT do:
 *   - It NEVER caches the navigation document (index.html). That document
 *     embeds the ciphertext DB, and the server sends `Cache-Control: no-store`
 *     precisely so the encrypted vault is not persisted to disk. Caching it in
 *     Cache Storage would undo that. The document is therefore network-only,
 *     with a synthesized offline page when the network is unreachable — so the
 *     vault data is never served stale and never written to the SW cache.
 *   - It never touches `post`, `lines`, `kdfparams`, `manifest`, `trash`,
 *     `part1`/`part2`, or anything under `bak/`,`moved/` — those pass straight
 *     through to the network.
 *
 * Scope: registered from the instance root (/pass/<inst>/), so it controls only
 * that one vault instance.
 */
'use strict';

var CACHE = 'vault-shell-v1';

// Non-secret code/asset files worth precaching. Relative to the SW scope.
var ASSETS = ['javascript.js', 'argon2-worker.js', 'manifest.json', 'icon.png'];

// Request paths the SW must never cache or intercept (always go to network).
var SENSITIVE = /(^|\/)(post|lines|kdfparams|manifest|trash|part1|part2)(\/|$|\?)/i;
var SENSITIVE_DIR = /(^|\/)(bak|moved)\//i;

function isAsset(url) {
    var path = url.pathname;
    for (var i = 0; i < ASSETS.length; i++) {
        if (path === self.registration.scope.replace(self.location.origin, '') + ASSETS[i]
            || path.endsWith('/' + ASSETS[i])) return true;
    }
    return false;
}

self.addEventListener('install', function(e) {
    e.waitUntil(
        caches.open(CACHE).then(function(c) {
            // Best-effort precache: a single 404 must not fail the whole install.
            return Promise.all(ASSETS.map(function(a) {
                return c.add(new Request(a, { cache: 'reload' })).catch(function() {});
            }));
        }).then(function() { return self.skipWaiting(); })
    );
});

self.addEventListener('activate', function(e) {
    e.waitUntil(
        caches.keys().then(function(keys) {
            return Promise.all(keys.map(function(k) {
                if (k !== CACHE) return caches.delete(k);
            }));
        }).then(function() { return self.clients.claim(); })
    );
});

// Minimal offline page (no vault data) — shown only when a navigation can't
// reach the network. Kept tiny and self-contained (CSP-clean: no inline JS).
function offlinePage() {
    var html = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width,initial-scale=1">'
        + '<title>Offline — Password Vault</title>'
        + '<style>body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;'
        + 'background:#111318;color:#dde1f0;margin:0;min-height:100vh;display:flex;'
        + 'align-items:center;justify-content:center;text-align:center}'
        + '.box{max-width:340px;padding:24px}h1{font-size:18px;color:#3fcf8e}'
        + 'p{font-size:14px;color:#8b90a8;line-height:1.5}</style></head><body>'
        + '<div class="box"><h1>You’re offline</h1>'
        + '<p>The vault needs a connection to load its latest encrypted data. '
        + 'Reconnect and reload to unlock.</p></div></body></html>';
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

self.addEventListener('fetch', function(e) {
    var req = e.request;
    if (req.method !== 'GET') return;                       // writes pass through
    var url;
    try { url = new URL(req.url); } catch (_) { return; }
    if (url.origin !== self.location.origin) return;        // third-party: ignore
    if (SENSITIVE.test(url.pathname) || SENSITIVE_DIR.test(url.pathname)) return;

    // Navigation (the index.html document): network-only, offline fallback.
    // Never cached — it embeds the ciphertext DB.
    if (req.mode === 'navigate') {
        e.respondWith(fetch(req).catch(function() { return offlinePage(); }));
        return;
    }

    // Code assets: stale-while-revalidate — serve cached instantly, refresh in
    // the background so a deployed update is picked up on the next load.
    if (isAsset(url)) {
        e.respondWith(
            caches.open(CACHE).then(function(c) {
                return c.match(req).then(function(hit) {
                    var net = fetch(req).then(function(resp) {
                        if (resp && resp.ok) c.put(req, resp.clone());
                        return resp;
                    }).catch(function() { return hit; });
                    return hit || net;
                });
            })
        );
        return;
    }
    // Everything else: default network handling.
});

// Message API. SKIP_WAITING lets a freshly-installed SW take over immediately;
// GET_ASSET_HASHES returns the SHA-256 of each cached core asset so a client
// (or the companion extension) can verify the running code hasn't been swapped.
self.addEventListener('message', function(e) {
    var data = e.data || {};
    if (data.type === 'SKIP_WAITING') { self.skipWaiting(); return; }
    if (data.type === 'GET_ASSET_HASHES') {
        e.waitUntil(assetHashes().then(function(hashes) {
            if (e.source && e.source.postMessage) {
                e.source.postMessage({ type: 'ASSET_HASHES', hashes: hashes });
            }
        }));
    }
});

function hex(buf) {
    var b = new Uint8Array(buf), s = '';
    for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
}
async function assetHashes() {
    var c = await caches.open(CACHE);
    var out = {};
    for (var i = 0; i < ASSETS.length; i++) {
        try {
            var resp = await c.match(ASSETS[i]) || await fetch(ASSETS[i]);
            var buf  = await resp.clone().arrayBuffer();
            out[ASSETS[i]] = hex(await crypto.subtle.digest('SHA-256', buf));
        } catch (_) { out[ASSETS[i]] = null; }
    }
    return out;
}
