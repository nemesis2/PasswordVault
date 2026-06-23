#!/usr/bin/env node
'use strict';

// =============================================================================
// server.js — Node.js replacement for post.php + the nginx/apache static layer.
//
// One server, two modes (set with --mode or VAULT_MODE):
//   local (default)  127.0.0.1-bound, single-user. No Basic-Auth / CSRF / rate
//                    limit (no network exposure). Still applies the CSP, the
//                    sensitive-file deny rules, and Cache-Control: no-store.
//   web              0.0.0.0-bound, full nginx+php parity: Basic-Auth, the CSRF
//                    same-origin check, the brute-force rate limiter, and HSTS,
//                    on top of everything local mode does. (Front it with TLS,
//                    as the existing PHP host does.)
//
// The write protocol is a faithful port of post.php — it must produce
// byte-identical `lines` / `index.html` / `manifest` / `kdfparams`, because the
// same vault can be served by either backend and the vm1 integrity manifest
// signs an exact, sorted record set. See CLAUDE.md → Write Protocol.
//
// Serves ONE vault directory (default: cwd). Multi-instance /pass/<inst>/ web
// hosting stays with nginx for now (out of scope for v1).
//
// Run:   node server.js                 # local mode, http://127.0.0.1:8787
//        node server.js --mode web --port 8080
// Module: require('./server.js') exposes the internals for the parity test.
// =============================================================================

const VERSION = '1.1.3';

const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const url      = require('url');
const querystring = require('querystring');

// ---- Constants (mirror post.php) ----
// Backup retention: pruned on every write — drop backups older than BAK_MAX_AGE,
// then keep only the newest BAK_KEEP (oldest removed first). Both can be overridden
// per-deployment via VAULT_BAK_KEEP / VAULT_BAK_MAX_AGE_DAYS; 0 disables that limit.
const envUint = (name, def) => {
    const v = process.env[name];
    return v !== undefined && /^\d+$/.test(v) ? parseInt(v, 10) : def;
};
const BAK_KEEP       = envUint('VAULT_BAK_KEEP', 100);                 // newest N kept
const BAK_MAX_AGE    = envUint('VAULT_BAK_MAX_AGE_DAYS', 60) * 86400;  // seconds
const TRASH_FILE     = 'trash';
const TRASH_KEEP     = 100;
const TRASH_MAX_AGE  = 2592000;     // 30 days
const BULK_MAX_BYTES = 4194304;     // 4 MiB
const KDF_DEFAULT    = 'a2id|131072|3|1';
const KDF_MEM_MIN    = 65536;
const KDF_MEM_MAX    = 1048576;
const KDF_TIME_MIN   = 2;
const KDF_TIME_MAX   = 10;
const RL_WINDOW      = 900;          // 15 min
const RL_MAX_FAIL    = 5;

const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
    "worker-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; " +
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// =============================================================================
// Validation helpers — exact ports of post.php's is_valid_* functions.
// =============================================================================
const isHex   = (s) => typeof s === 'string' && /^[0-9a-fA-F]+$/.test(s);
const isDigit = (s) => typeof s === 'string' && /^[0-9]+$/.test(s);

function isValidRecord(s) {
    if (typeof s !== 'string') return false;
    if (Buffer.byteLength(s, 'utf8') > 65536) return false;
    const p = s.split('|');
    if (p.length === 11 && p[1] === 'v6') {
        if (p[0] === '' || p[0].length % 2 !== 0 || !isHex(p[0])) return false;
        const hexlens = { 2: 64, 3: 64, 4: 24, 5: 24, 6: 24, 7: 24, 8: 32, 9: 32 };
        for (const i of Object.keys(hexlens)) {
            if (p[i].length !== hexlens[i] || !isHex(p[i])) return false;
        }
        if (p[10] === '' || p[10].length % 2 !== 0 || !isHex(p[10])) return false;
        return true;
    }
    return false;
}

function isValidManifest(s) {
    if (typeof s !== 'string' || s.length > 512) return false;
    const p = s.split('|');
    if (p.length !== 6 || p[0] !== 'vm1') return false;
    for (const i of [1, 2, 5]) if (p[i].length !== 64 || !isHex(p[i])) return false;
    for (const i of [3, 4]) if (p[i] === '' || p[i].length > 15 || !isDigit(p[i])) return false;
    return true;
}

function isValidKdf(s) {
    if (typeof s !== 'string' || s.length > 64) return false;
    const p = s.split('|');
    if (p.length !== 4 || p[0] !== 'a2id') return false;
    for (let i = 1; i <= 3; i++) if (p[i] === '' || p[i].length > 10 || !isDigit(p[i])) return false;
    const m = parseInt(p[1], 10), t = parseInt(p[2], 10), pp = parseInt(p[3], 10);
    if (m < KDF_MEM_MIN || m > KDF_MEM_MAX) return false;
    if (t < KDF_TIME_MIN || t > KDF_TIME_MAX) return false;
    if (pp !== 1) return false;
    return true;
}

// htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8'). For v6 records (hex +
// pipes + digits) this is a no-op, but kept faithful for the legacy name branch.
function htmlspecialchars(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');   // ENT_HTML5 ⇒ &apos; (not &#039;)
}

// PHP sort($a, SORT_STRING) == byte-wise strcmp. Buffer.compare matches it
// exactly (JS default string sort is UTF-16-code-unit, which would diverge on
// multibyte content; records are ASCII but be correct anyway).
const byteCmp = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
const sortRecords = (arr) => arr.slice().sort(byteCmp);

const sha256hex = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

// Split on any line ending, dropping empty segments (PHP preg_split '/\R/' + NO_EMPTY).
const splitLines = (s) => (s === '' ? [] : s.split(/\r\n|\r|\n/).filter((x) => x !== ''));

// =============================================================================
// Trash helpers (mirror post.php trash_read / trash_write).
// =============================================================================
function trashRead(dir) {
    const out = [];
    let raw;
    try { raw = fs.readFileSync(path.join(dir, TRASH_FILE), 'utf8'); } catch (_) { return out; }
    if (!raw) return out;
    for (const ln of splitLines(raw)) {
        const tab = ln.indexOf('\t');
        if (tab === -1) continue;
        const ts = parseInt(ln.slice(0, tab), 10);
        const rec = ln.slice(tab + 1);
        if (!(ts > 0) || !isValidRecord(rec)) continue;
        out.push({ ts, rec });
    }
    return out;
}

function trashWrite(dir, items) {
    const now = Math.floor(Date.now() / 1000);
    items = items.filter((it) => (now - it.ts) <= TRASH_MAX_AGE);
    items.sort((a, b) => b.ts - a.ts);                 // newest first
    if (items.length > TRASH_KEEP) items = items.slice(0, TRASH_KEEP);
    let buf = '';
    for (const it of items) buf += it.ts + '\t' + it.rec + '\n';
    try { fs.writeFileSync(path.join(dir, TRASH_FILE), buf); } catch (_) { return false; }
    try { fs.chmodSync(path.join(dir, TRASH_FILE), 0o600); } catch (_) {}
    return true;
}

// =============================================================================
// Backups (mirror post.php prune_backups + the pre-write backup).
// =============================================================================
function pruneBackups(dir, keep, maxAge) {
    const bakdir = path.join(dir, 'bak');
    let files;
    try { files = fs.readdirSync(bakdir).filter((f) => f.startsWith('lines.')); } catch (_) { return; }
    files.sort();                                       // lexical == chronological (oldest first)
    if (maxAge > 0) {
        const cutoff = Date.now() - maxAge * 1000;
        files = files.filter((f) => {
            const p = path.join(bakdir, f);
            let mt;
            try { mt = fs.statSync(p).mtimeMs; } catch (_) { return false; }
            if (mt < cutoff) { try { fs.unlinkSync(p); } catch (_) {} return false; }
            return true;
        });
    }
    if (keep > 0 && files.length > keep) {
        for (const f of files.slice(0, files.length - keep)) {
            try { fs.unlinkSync(path.join(bakdir, f)); } catch (_) {}
        }
    }
}

function backupLines(dir, current) {
    const bakdir = path.join(dir, 'bak');
    if (!fs.existsSync(bakdir)) { try { fs.mkdirSync(bakdir, 0o700); } catch (_) {} }
    const d = new Date();
    const z = (n, w = 2) => String(n).padStart(w, '0');
    const micro = Number(process.hrtime.bigint() % 1000000n);
    const dt = `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}_` +
        `${z(d.getHours())}.${z(d.getMinutes())}.${z(d.getSeconds())}.${z(micro, 6)}`;
    const bakfile = path.join(bakdir, 'lines.' + dt);
    try { fs.writeFileSync(bakfile, current); } catch (_) { return false; }
    try { fs.chmodSync(bakfile, 0o600); } catch (_) {}
    pruneBackups(dir, BAK_KEEP, BAK_MAX_AGE);
    return true;
}

// =============================================================================
// index.html rebuild — byte-faithful to post.php's splice.
//   file('part1') keeps newlines, so a string/Buffer concat is exactly
//   equivalent: part1 bytes + ASCII buttons/spans + part2 bytes.
// =============================================================================
function buildIndex(dir, sortedArray, manifestOut, kdfOut) {
    const part1 = fs.readFileSync(path.join(dir, 'part1'));   // Buffer (preserve bytes)
    const part2 = fs.readFileSync(path.join(dir, 'part2'));
    let mid = '';
    for (let x = 0; x < sortedArray.length; x++) {
        const row = sortedArray[x].trim();
        const parts = row.split('|');
        const ver = parts[1] !== undefined ? parts[1] : '';
        const dataRow = htmlspecialchars(row + '|' + x);
        if (ver === 'v6') {
            mid += `<button class="entry-btn v5-locked" style="display:none" data-row="${dataRow}">&#x1F512;</button>\n`;
        } else {
            const dn = htmlspecialchars(parts[0]);
            mid += `<button class="entry-btn" title="${dn}" data-row="${dataRow}">${dn}</button>\n`;
        }
    }
    mid += `<span id="vault-manifest" hidden data-manifest="${htmlspecialchars(manifestOut === null ? '' : manifestOut)}"></span>\n`;
    mid += `<span id="vault-kdf" hidden data-kdf="${htmlspecialchars(kdfOut)}"></span>\n`;
    return Buffer.concat([part1, Buffer.from(mid, 'utf8'), part2]);
}

// =============================================================================
// Core write handler — the post.php critical section, run synchronously so two
// requests can never interleave (the single-process equivalent of its flock).
// `params` is the parsed POST body (object of strings); `isRegen` is the merged
// GET/POST regen flag. Returns { code, json } | { code, text }.
// =============================================================================
function handleWrite(dir, params, isRegen) {
    const P = (f) => path.join(dir, f);
    const has = (k) => Object.prototype.hasOwnProperty.call(params, k);
    const bad = () => ({ code: 400, text: 'Invalid data' });

    // ---- Templates must exist (post.php aborts 500 before touching anything) ----
    if (!fs.existsSync(P('part1')) || !fs.existsSync(P('part2'))) {
        return { code: 500, text: 'Template missing' };
    }

    // ---- Input validation (skipped entirely in regen mode) ----
    let data = null, de = -1, deleteRec = null;
    let bulk = false, restore = false, bulkLines = null, expectHash = '';
    let sign = false, manifestIn = null, kdfIn = null;
    let trashList = false, purgeTrash = null, untrashRec = null, untrash = false;

    if (!isRegen) {
        trashList  = has('trash');
        purgeTrash = has('purge_trash') ? params['purge_trash'] : null;
        untrashRec = has('untrash_rec') ? params['untrash_rec'] : null;

        if (purgeTrash !== null) {
            if (purgeTrash !== '__all__' && !isValidRecord(purgeTrash)) return bad();
        } else if (trashList) {
            // handled after the read below
        } else {
            restore = has('restore');
            bulk = has('bulk') || restore;
            sign = has('sign');
            if (sign) {
                if (bulk || has('data') || has('delete') || has('delete_rec') || has('kdf')) return bad();
                manifestIn = has('manifest') ? params['manifest'] : '';
                expectHash = has('expect_hash') ? params['expect_hash'] : '';
                if (!/^[0-9a-f]{64}$/.test(expectHash) || !isValidManifest(manifestIn)) return bad();
            } else if (bulk) {
                if (has('data') || has('delete') || has('delete_rec')) return bad();
                const bulkData = has('bulk_data') ? params['bulk_data'] : '';
                expectHash = has('expect_hash') ? params['expect_hash'] : '';
                if (!/^[0-9a-f]{64}$/.test(expectHash)) return bad();
                if (bulkData === '' || Buffer.byteLength(bulkData, 'utf8') > BULK_MAX_BYTES) return bad();
                bulkLines = splitLines(bulkData);
                if (bulkLines.length === 0) return bad();
                for (const bl of bulkLines) if (!isValidRecord(bl)) return bad();
                if (has('kdf')) {
                    kdfIn = params['kdf'];
                    if (!isValidKdf(kdfIn)) return bad();
                }
            } else {
                data      = has('data') ? params['data'] : null;
                de        = has('delete') ? parseInt(params['delete'], 10) : -1;
                deleteRec = has('delete_rec') ? params['delete_rec'] : null;
                if (!(de >= -1) || isNaN(de)) de = -1;
                if (deleteRec !== null && !isValidRecord(deleteRec)) return bad();
                if (data !== null && (data.indexOf('\n') !== -1 || data.indexOf('\r') !== -1)) return bad();
                if (data !== null && !isValidRecord(data)) return bad();
                if (has('kdf')) return bad();
                if (untrashRec !== null) {
                    if (!isValidRecord(untrashRec)) return bad();
                    data = untrashRec;
                    untrash = true;
                }
            }
        }
    }

    // ---- Read the current lines snapshot (critical section start) ----
    let current = '';
    try { current = fs.readFileSync(P('lines'), 'utf8'); } catch (_) { current = ''; }
    let array = splitLines(current);

    // ---- Trash list / purge: handled here, never touch lines/index.html ----
    if (trashList) {
        const items = trashRead(dir);
        items.sort((a, b) => b.ts - a.ts);
        const rows = items.map((it) => ({ ts: it.ts, record: it.rec }));
        return { code: 200, json: { ok: true, trash: rows } };
    }
    if (purgeTrash !== null) {
        let items;
        if (purgeTrash === '__all__') items = [];
        else items = trashRead(dir).filter((it) => it.rec !== purgeTrash);
        if (trashWrite(dir, items) === false) return { code: 500, text: 'Write failed' };
        return { code: 200, json: { ok: true, purged: true, count: items.length } };
    }

    // ---- Staleness checks (before any backup/mutation) ----
    if (!isRegen) {
        if (sign) {
            if (sha256hex(array.join('\n')) !== expectHash) return { code: 409, json: { ok: false, error: 'stale' } };
        } else if (bulk) {
            if (sha256hex(array.join('\n')) !== expectHash ||
                (!restore && bulkLines.length !== array.length)) {
                return { code: 409, json: { ok: false, error: 'stale' } };
            }
        } else if (deleteRec !== null) {
            const idx = array.indexOf(deleteRec);
            if (idx === -1) return { code: 409, json: { ok: false, error: 'stale' } };
            de = idx;
        }
    }

    // ---- Backup before modifying (skip regen/sign and empty files) ----
    if (!isRegen && !sign && current !== '') {
        if (backupLines(dir, current) === false) return { code: 500, text: 'Backup failed' };
    }

    // ---- Update lines ----
    if (isRegen || sign) {
        array = sortRecords(array);                      // order for the rebuild only
        if (sign) {
            try { fs.writeFileSync(P('manifest'), manifestIn + '\n'); } catch (_) { return { code: 500, text: 'Write failed' }; }
            try { fs.chmodSync(P('manifest'), 0o600); } catch (_) {}
        }
    } else {
        if (bulk) {
            array = bulkLines;
        } else {
            if (de >= 0 && de < array.length) {
                const removed = array[de];
                array.splice(de, 1);
                if (isValidRecord(removed)) {
                    const titems = trashRead(dir);
                    titems.push({ ts: Math.floor(Date.now() / 1000), rec: removed });
                    trashWrite(dir, titems);
                }
            }
            if (data !== null && array.indexOf(data) === -1) array.push(data);
            if (untrash) {
                const titems = trashRead(dir).filter((it) => it.rec !== untrashRec);
                trashWrite(dir, titems);
            }
        }
        array = sortRecords(array);
        const out = array.length ? array.join('\n') + '\n' : '';
        try { fs.writeFileSync(P('lines'), out); } catch (_) { return { code: 500, text: 'Write failed' }; }
        if (bulk && kdfIn !== null) {
            try { fs.writeFileSync(P('kdfparams'), kdfIn + '\n'); } catch (_) { return { code: 500, text: 'Write failed' }; }
            try { fs.chmodSync(P('kdfparams'), 0o600); } catch (_) {}
        }
    }

    // ---- Resolve manifest_out / kdf_out for the embed + response ----
    let manifestOut = sign ? manifestIn : null;
    if (manifestOut === null) {
        try {
            const m = fs.readFileSync(P('manifest'), 'utf8').trim();
            if (isValidManifest(m)) manifestOut = m;
        } catch (_) {}
    }
    let kdfOut = (bulk && kdfIn !== null) ? kdfIn : null;
    if (kdfOut === null) {
        try {
            const k = fs.readFileSync(P('kdfparams'), 'utf8').trim();
            if (isValidKdf(k)) kdfOut = k;
        } catch (_) {}
    }
    if (kdfOut === null) kdfOut = KDF_DEFAULT;

    // ---- Rebuild index.html ----
    try {
        fs.writeFileSync(P('index.html'), buildIndex(dir, array, manifestOut, kdfOut));
    } catch (_) { return { code: 500, text: 'Write failed' }; }

    const entries = [];
    array.forEach((line, i) => { const row = line.trim(); if (row !== '') entries.push(row + '|' + i); });
    return { code: 200, json: { ok: true, regen: isRegen, sign, manifest: manifestOut, kdf: kdfOut, entries } };
}

// =============================================================================
// HTTP layer: static serving + the /post endpoint, with mode-gated auth.
// =============================================================================
const MIME = {
    '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8', '.png': 'image/png',
    '.svg': 'image/svg+xml', '.css': 'text/css; charset=utf-8',
    '.md': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
    '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json',
};
const DENY_EXACT = new Set(['lines', 'trash', 'manifest', 'kdfparams', 'part1', 'part2']);
const DENY_DIRS  = new Set(['bak', 'moved']);

function securityHeaders(cfg, isIndex) {
    const h = {
        'Content-Security-Policy': CSP,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=(self), geolocation=(), microphone=(), payment=(), usb=()',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cache-Control': 'no-store',
    };
    if (cfg.mode === 'web') h['Strict-Transport-Security'] = 'max-age=63072000';
    return h;
}

function safeEq(a, b) {
    const ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
    if (ab.length !== bb.length) { crypto.timingSafeEqual(ab, ab); return false; }
    return crypto.timingSafeEqual(ab, bb);
}

// In-memory per-IP sliding-window rate limiter (web mode). Single process, so a
// Map replaces post.php's temp-file state. Same window/threshold semantics.
const rlState = new Map();
function rlCheck(ip) {
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - RL_WINDOW;
    const fails = (rlState.get(ip) || []).filter((t) => t >= cutoff);
    rlState.set(ip, fails);
    return fails;
}
function rlFail(ip)  { const f = rlCheck(ip); f.push(Math.floor(Date.now() / 1000)); rlState.set(ip, f); }
function rlClear(ip) { rlState.delete(ip); }

function requireBasicAuth(req, res, cfg) {
    const ip = req.socket.remoteAddress || 'unknown';
    const fails = rlCheck(ip);
    if (fails.length >= RL_MAX_FAIL) {
        let retry = RL_WINDOW - (Math.floor(Date.now() / 1000) - Math.min(...fails));
        if (retry < 1) retry = 1;
        res.writeHead(429, { 'Retry-After': String(retry) });
        res.end('Too many authentication attempts. Try again later.');
        return false;
    }
    let u = '', p = '';
    const hdr = req.headers['authorization'] || '';
    if (/^Basic /i.test(hdr)) {
        // Strict base64: Node's Buffer.from(.., 'base64') is lenient and silently
        // drops invalid chars, so validate the charset/padding first to match
        // post.php's base64_decode(.., true). Reject anything malformed (fail closed).
        const b64 = hdr.slice(6).trim();
        if (/^[A-Za-z0-9+/]*={0,2}$/.test(b64) && b64.length % 4 === 0) {
            const dec = Buffer.from(b64, 'base64').toString('utf8');
            const i = dec.indexOf(':');
            if (i !== -1) { u = dec.slice(0, i); p = dec.slice(i + 1); }
        }
    }
    if (safeEq(cfg.user, u) && safeEq(cfg.pass, p)) { rlClear(ip); return true; }
    rlFail(ip);
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Password Vault", charset="UTF-8"' });
    res.end('Authentication required');
    return false;
}

function isSameOrigin(req) {
    const host = req.headers['host'] || '';
    if (host === '') return false;
    if (String(req.headers['x-requested-with'] || '').toLowerCase() !== 'xmlhttprequest') return false;
    const check = (v) => {
        try {
            const u = new url.URL(v);
            // The passkey companion extension POSTs from its own unspoofable
            // chrome-extension:// / moz-extension:// origin; writes stay Basic-Auth
            // gated, so accept those alongside the same-origin web app.
            if (u.protocol === 'chrome-extension:' || u.protocol === 'moz-extension:') return true;
            return u.host === host;
        } catch (_) { return false; }
    };
    if (req.headers['origin']) return check(req.headers['origin']);
    if (req.headers['referer']) return check(req.headers['referer']);
    return false;
}

function serveStatic(req, res, cfg) {
    let pathname;
    try { pathname = decodeURIComponent(url.parse(req.url).pathname); } catch (_) { res.writeHead(400); return res.end('Bad request'); }
    if (pathname === '/') pathname = '/index.html';
    const rel = pathname.replace(/^\/+/, '');
    const segments = rel.split('/');
    // Traversal / dotfile / deny-list guards.
    if (segments.some((s) => s === '..' || s.startsWith('.'))) { res.writeHead(403); return res.end('Forbidden'); }
    if (DENY_DIRS.has(segments[0]) || DENY_EXACT.has(segments[segments.length - 1])) { res.writeHead(403); return res.end('Forbidden'); }
    const full = path.join(cfg.dir, rel);
    if (!full.startsWith(path.resolve(cfg.dir))) { res.writeHead(403); return res.end('Forbidden'); }
    fs.readFile(full, (err, buf) => {
        if (err) { res.writeHead(404); return res.end('Not found'); }
        const ext = path.extname(full).toLowerCase();
        const isIndex = path.basename(full) === 'index.html';
        const headers = Object.assign({ 'Content-Type': MIME[ext] || 'application/octet-stream' }, securityHeaders(cfg, isIndex));
        // index.html embeds the ciphertext DB → never cache. Static assets may cache.
        if (!isIndex) delete headers['Cache-Control'];
        res.writeHead(200, headers);
        res.end(buf);
    });
}

function handlePost(req, res, cfg, isRegen) {
    if (cfg.mode === 'web') {
        if (!requireBasicAuth(req, res, cfg)) return;
        if (!isRegen && (req.method !== 'POST' || !isSameOrigin(req))) { res.writeHead(403); return res.end('Forbidden'); }
    }
    // Regen with no body (GET) is fine; otherwise collect the urlencoded body.
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
        size += c.length;
        if (size > BULK_MAX_BYTES + 65536) { res.writeHead(413); res.end('Payload too large'); req.destroy(); return; }
        chunks.push(c);
    });
    req.on('end', () => {
        if (res.writableEnded) return;
        const body = Buffer.concat(chunks).toString('utf8');
        const params = body ? querystring.parse(body) : {};
        // querystring may yield arrays on duplicate keys; flatten to the first (PHP $_POST keeps the last — but our client never duplicates).
        for (const k of Object.keys(params)) if (Array.isArray(params[k])) params[k] = params[k][params[k].length - 1];
        const result = handleWrite(cfg.dir, params, isRegen);
        const headers = securityHeaders(cfg, false);
        if (result.json !== undefined) {
            headers['Content-Type'] = 'application/json; charset=utf-8';
            res.writeHead(result.code, headers);
            res.end(JSON.stringify(result.json));
        } else {
            headers['Content-Type'] = 'text/plain; charset=utf-8';
            res.writeHead(result.code, headers);
            res.end(result.text || '');
        }
    });
}

function createServer(cfg) {
    return http.createServer((req, res) => {
        const parsed = url.parse(req.url, true);
        const pathname = parsed.pathname || '/';
        const isPostEndpoint = pathname === '/post' || pathname === '/post.php';
        const isRegen = ('regen' in (parsed.query || {}));
        if (isPostEndpoint || (req.method === 'POST')) {
            // Only the post endpoint accepts writes; a POST elsewhere is 404.
            if (!isPostEndpoint) { res.writeHead(404); return res.end('Not found'); }
            return handlePost(req, res, cfg, isRegen || req.method === 'GET' && isRegen);
        }
        if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end('Method not allowed'); }
        return serveStatic(req, res, cfg);
    });
}

// =============================================================================
// CLI entry.
// =============================================================================
function parseConfig(argv, env) {
    const get = (flag) => { const i = argv.indexOf(flag); return i !== -1 && argv[i + 1] ? argv[i + 1] : null; };
    const mode = get('--mode') || env.VAULT_MODE || 'local';
    const cfg = {
        mode: mode === 'web' ? 'web' : 'local',
        port: parseInt(get('--port') || env.PORT || '8787', 10),
        host: get('--host') || env.VAULT_HOST || (mode === 'web' ? '0.0.0.0' : '127.0.0.1'),
        dir:  path.resolve(get('--dir') || env.VAULT_DIR || process.cwd()),
        user: env.VAULT_AUTH_USER || 'pass',
        pass: env.VAULT_AUTH_PASS || 'word',
    };
    return cfg;
}

function main() {
    const cfg = parseConfig(process.argv.slice(2), process.env);
    createServer(cfg).listen(cfg.port, cfg.host, () => {
        console.log(`vault server v${VERSION} [${cfg.mode}] → http://${cfg.host}:${cfg.port}  (dir: ${cfg.dir})`);
        if (cfg.mode === 'local') console.log('  local mode: no auth / CSRF / rate-limit (127.0.0.1 only).');
        else console.log('  web mode: Basic-Auth + CSRF + rate-limit + HSTS. Front with TLS.');
    });
}

if (require.main === module) main();

module.exports = {
    handleWrite, buildIndex, isValidRecord, isValidManifest, isValidKdf,
    htmlspecialchars, sortRecords, sha256hex, trashRead, trashWrite, parseConfig, createServer,
};
