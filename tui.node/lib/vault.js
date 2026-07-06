'use strict';
// ============================================================
// vault.js — storage layer for the `lines` flat-file DB.
//
// Reads/writes the SAME files the PHP app uses, byte-compatibly:
//   - `lines`    : one 11-field v6 record per line, sorted SORT_STRING, '\n'-joined + trailing '\n'
//   - `bak/`     : timestamped pre-write backups, pruned to BAK_KEEP newest and
//                  BAK_MAX_AGE old (overridable via VAULT_BAK_KEEP / VAULT_BAK_MAX_AGE_DAYS)
//   - `manifest` : single `vm2|…` (or legacy `vm1|…`) integrity line + trailing '\n'
//
// Records are all-ASCII (hex + 'v6' + '|'), so JS default sort == PHP SORT_STRING.
// ============================================================

const fs = require('fs');
const path = require('path');

// Vault directory: $VAULT_DIR if set, else the app root (parent of tui/).
const ROOT = process.env.VAULT_DIR
    ? path.resolve(process.env.VAULT_DIR)
    : path.resolve(__dirname, '..', '..');
const LINES = path.join(ROOT, 'lines');
const MANIFEST = path.join(ROOT, 'manifest');
const KDFPARAMS = path.join(ROOT, 'kdfparams');
const BAK = path.join(ROOT, 'bak');
// Backup retention (mirrors post.php / server.js): on every write, drop backups
// older than BAK_MAX_AGE, then keep only the newest BAK_KEEP (oldest removed
// first). Both default sensibly and are overridable via the VAULT_BAK_KEEP /
// VAULT_BAK_MAX_AGE_DAYS env vars; 0 disables that limit.
const _bakUint = (name, def) => {
    const v = process.env[name];
    return v !== undefined && /^\d+$/.test(v) ? parseInt(v, 10) : def;
};
const BAK_KEEP = _bakUint('VAULT_BAK_KEEP', 100);
const BAK_MAX_AGE = _bakUint('VAULT_BAK_MAX_AGE_DAYS', 60) * 86400;  // seconds

const FIELD_NAMES = ['encName', 'version', 'recSalt1', 'recSalt2',
    'nameNonce1', 'nameNonce2', 'iv1', 'nonce2', 'nonce3', 'nonce4', 'enc'];

function readRecords() {
    let raw;
    try { raw = fs.readFileSync(LINES, 'utf8'); }
    catch (e) { if (e.code === 'ENOENT') return []; throw e; }
    return raw.split('\n').map(s => s.trim()).filter(Boolean);
}

// Split a record string into named fields. Throws on a non-v6 / malformed record.
function parse(rec) {
    const p = rec.split('|');
    if (p.length !== 11 || p[1] !== 'v6') {
        throw new Error('Unsupported record (expected 11-field v6, got ' + p.length + ' fields)');
    }
    const o = { _raw: rec };
    FIELD_NAMES.forEach((n, i) => { o[n] = p[i]; });
    return o;
}

// Canonical order = byte-sorted record strings (matches PHP sort()/SORT_STRING
// and the browser's _canonicalRecords(), so the manifest HMAC lines up).
function canonical(records) { return records.slice().sort(); }

function _timestamp() {
    const d = new Date();
    const p2 = n => String(n).padStart(2, '0');
    const micros = String((d.getMilliseconds() * 1000) % 1000000).padStart(6, '0');
    return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}_` +
           `${p2(d.getHours())}.${p2(d.getMinutes())}.${p2(d.getSeconds())}.${micros}`;
}

function _backup() {
    let current;
    try { current = fs.readFileSync(LINES); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
    if (current.length === 0) return;
    if (!fs.existsSync(BAK)) fs.mkdirSync(BAK, { mode: 0o700 });
    const bakfile = path.join(BAK, 'lines.' + _timestamp());
    fs.writeFileSync(bakfile, current, { mode: 0o600 });
    _prune();
}

function _prune() {
    let files;
    try { files = fs.readdirSync(BAK).filter(f => f.startsWith('lines.')); } catch { return; }
    files.sort();                                   // fixed-width timestamp → chronological (oldest first)
    if (BAK_MAX_AGE > 0) {
        const cutoff = Date.now() - BAK_MAX_AGE * 1000;
        files = files.filter(f => {
            const p = path.join(BAK, f);
            let mt;
            try { mt = fs.statSync(p).mtimeMs; } catch { return false; }
            if (mt < cutoff) { try { fs.unlinkSync(p); } catch {} return false; }
            return true;
        });
    }
    if (BAK_KEEP > 0 && files.length > BAK_KEEP) {
        for (const f of files.slice(0, files.length - BAK_KEEP)) {
            try { fs.unlinkSync(path.join(BAK, f)); } catch {}
        }
    }
}

// Atomically replace `lines` with `records` (backs up first, writes sorted).
function writeRecords(records) {
    _backup();
    const sorted = canonical(records);
    const out = sorted.length ? sorted.join('\n') + '\n' : '';
    const tmp = LINES + '.tmp' + process.pid;
    fs.writeFileSync(tmp, out);
    fs.renameSync(tmp, LINES);
    return sorted;
}

function readManifest() {
    try { return fs.readFileSync(MANIFEST, 'utf8').trim() || null; }
    catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
function writeManifest(str) {
    const tmp = MANIFEST + '.tmp' + process.pid;
    fs.writeFileSync(tmp, str + '\n', { mode: 0o600 });
    fs.renameSync(tmp, MANIFEST);
}

// The vault-wide Argon2id cost line (`a2id|memKiB|t|p`), or null when absent
// (⇒ the default cost). Not secret — it sits next to the salts — and read-only
// here; the TUI never writes it (Change KDF Parameters is a browser-only flow).
function readKdf() {
    try { return fs.readFileSync(KDFPARAMS, 'utf8').trim() || null; }
    catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}

// Accepts both manifest versions (mirrors javascript.js's _parseManifest):
//   vm1 | salt1 | salt2 | revision | timestamp | hmac            (legacy, 6 fields)
//   vm2 | salt1 | salt2 | revision | timestamp | kdf | hmac      (kdf is itself
//       "a2id|m|t|p", so a vm2 manifest splits into 10 fields; kdf occupies 5..8)
function parseManifest(str) {
    if (!str) return null;
    const p = str.split('|');
    if (p[0] === 'vm1') {
        if (p.length !== 6) return null;
        return { version: 'vm1', salt1Hex: p[1], salt2Hex: p[2], revision: parseInt(p[3], 10),
                 timestamp: parseInt(p[4], 10), kdfStr: null, hmacHex: p[5] };
    }
    if (p[0] === 'vm2') {
        if (p.length !== 10) return null;
        return { version: 'vm2', salt1Hex: p[1], salt2Hex: p[2], revision: parseInt(p[3], 10),
                 timestamp: parseInt(p[4], 10), kdfStr: p.slice(5, 9).join('|'), hmacHex: p[9] };
    }
    return null;
}

module.exports = {
    ROOT, LINES, MANIFEST, KDFPARAMS,
    readRecords, parse, canonical, writeRecords,
    readManifest, writeManifest, parseManifest, readKdf,
};
