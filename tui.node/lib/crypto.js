'use strict';
// ============================================================
// crypto.js — v6 record crypto for the Node TUI.
//
// Reuses the EXACT cipher implementations the browser app ships so the
// ciphertext is byte-identical: the ChaCha20-Poly1305 / Twofish-256 / Serpent-256
// IIFE bundles are sliced straight out of ../../javascript.js, and the Argon2id
// WASM bundle out of ../../argon2-worker.js. Everything above the bundles (the
// HKDF / cascade / TOTP / manifest helpers) mirrors the browser source 1:1.
//
// No re-implementation of any primitive — the only thing we add is calling them
// from Node instead of the DOM.
// ============================================================

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');

// WebCrypto + a `self` alias (the argon2 worker tail sets `self.onmessage`).
if (!globalThis.crypto) globalThis.crypto = nodeCrypto.webcrypto;
if (!globalThis.self) globalThis.self = globalThis;

// ---- Load the cipher bundles (chacha / twofish / serpent) ------------------
(function loadCascadeBundles() {
    if (globalThis.serpentEncryptBlock && globalThis.twofishEncryptBlock && globalThis.chacha20poly1305) return;
    const js = fs.readFileSync(path.join(ROOT, 'javascript.js'), 'utf8');
    const marker = 'globalThis.serpentEncryptBlock = encryptBlock;';
    const mi = js.indexOf(marker);
    if (mi < 0) throw new Error('cipher bundle marker not found in javascript.js');
    const end = js.indexOf('})();', mi) + '})();'.length;
    vm.runInThisContext(js.slice(0, end), { filename: 'cascade-bundles.js' });
})();

// ---- Load the Argon2id WASM bundle -----------------------------------------
(function loadArgon() {
    if (globalThis.argon2idHash) return;
    const src = fs.readFileSync(path.join(ROOT, 'argon2-worker.js'), 'utf8');
    vm.runInThisContext(src, { filename: 'argon2-worker.js' });
})();

const { chacha20poly1305, twofishMakeSession, twofishEncryptBlock,
        serpentMakeSession, serpentEncryptBlock, argon2idHash } = globalThis;
const subtle = globalThis.crypto.subtle;

// Argon2id worker-thread pool — fans the memory-hard derivations out across all
// CPU cores (the slow part of unlock). Falls back to the in-process argon2idHash
// above when worker_threads is unavailable. See argon-pool.js.
const argonPool = require('./argon-pool');

// ============================================================
// Byte / hex utilities (mirror javascript.js)
// ============================================================
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
}
const te = new TextEncoder();
const td = new TextDecoder();

// ============================================================
// Length-hiding payload padding (mirror javascript.js _padPlaintext)
// ============================================================
// Pad the encoded plaintext up to the next PAYLOAD_PAD_BUCKET multiple (min one
// bucket) with trailing ASCII spaces (0x20 — valid trailing JSON whitespace, so
// JSON.parse ignores it on decrypt; no un-pad step needed), so the stored
// ciphertext length only reveals the 256-byte bucket, not the true length.
const PAYLOAD_PAD_BUCKET = 256;
function _padPlaintext(bytes) {
    const target = Math.max(PAYLOAD_PAD_BUCKET,
        Math.ceil(bytes.length / PAYLOAD_PAD_BUCKET) * PAYLOAD_PAD_BUCKET);
    const out = new Uint8Array(target);
    out.set(bytes);
    out.fill(0x20, bytes.length);
    return out;
}

// ============================================================
// CTR helpers (mirror javascript.js exactly)
// ============================================================
function twofishCTR(key32, nonce16, data) {
    const session = twofishMakeSession(key32);
    const out = new Uint8Array(data.length);
    const counter = new Uint8Array(16); counter.set(nonce16);
    const keystream = new Uint8Array(16);
    for (let i = 0; i < data.length; i += 16) {
        twofishEncryptBlock(counter, 0, keystream, 0, session);
        const blockLen = Math.min(16, data.length - i);
        for (let j = 0; j < blockLen; j++) out[i + j] = data[i + j] ^ keystream[j];
        for (let k = 15; k >= 0; k--) { if (++counter[k] !== 0) break; }
    }
    return out;
}
function serpentCTR(key32, nonce16, data) {
    const session = serpentMakeSession(key32);
    const out = new Uint8Array(data.length);
    const counter = new Uint8Array(16); counter.set(nonce16);
    const keystream = new Uint8Array(16);
    for (let i = 0; i < data.length; i += 16) {
        serpentEncryptBlock(counter, 0, keystream, 0, session);
        const blockLen = Math.min(16, data.length - i);
        for (let j = 0; j < blockLen; j++) out[i + j] = data[i + j] ^ keystream[j];
        for (let k = 15; k >= 0; k--) { if (++counter[k] !== 0) break; }
    }
    return out;
}

// ============================================================
// Key derivation — Argon2id → HKDF-SHA-256 subkeys
// ============================================================
// Vault-wide Argon2id cost. The default mirrors the vault's current default
// (128 MiB / t=3 / p=1 — same as post.php's absent-kdfparams fallback); the
// active cost is set at load from the `kdfparams` file via setKdf(), so the TUI
// derives at whatever cost the vault was last (re-)encrypted with (the browser
// reads the same value from the embedded #vault-kdf span). Bounds mirror
// post.php's is_valid_kdf() / crypto-vault.js.
const ARGON2_HASHLEN = 32;
const DEFAULT_KDF = { iterations: 3, memorySize: 131072, parallelism: 1, hashLength: ARGON2_HASHLEN };
const KDF_MEM_MIN_KIB = 65536, KDF_MEM_MAX_KIB = 1048576, KDF_TIME_MIN = 2, KDF_TIME_MAX = 10;
let _kdf = Object.assign({}, DEFAULT_KDF);

function setKdf(kdf) { _kdf = kdf ? Object.assign({}, DEFAULT_KDF, kdf) : Object.assign({}, DEFAULT_KDF); }

// Parse an `a2id|memKiB|t|p` line (the `kdfparams` file) → a cost object, or null
// if malformed / out of bounds (caller then falls back to DEFAULT_KDF).
function parseKdf(s) {
    if (typeof s !== 'string') return null;
    const p = s.trim().split('|');
    if (p.length !== 4 || p[0] !== 'a2id') return null;
    if (!/^\d{1,10}$/.test(p[1]) || !/^\d{1,10}$/.test(p[2]) || !/^\d{1,10}$/.test(p[3])) return null;
    const m = parseInt(p[1], 10), t = parseInt(p[2], 10), pp = parseInt(p[3], 10);
    if (m < KDF_MEM_MIN_KIB || m > KDF_MEM_MAX_KIB) return null;
    if (t < KDF_TIME_MIN || t > KDF_TIME_MAX) return null;
    if (pp !== 1) return null;
    return { iterations: t, memorySize: m, parallelism: pp, hashLength: ARGON2_HASHLEN };
}

const _HK = {
    nameAes: 'v6|name|aes-gcm', nameChacha: 'v6|name|chacha20',
    payAes: 'v6|pay|aes-gcm', payChacha: 'v6|pay|chacha20',
    payTwofish: 'v6|pay|twofish', paySerpent: 'v6|pay|serpent'
};

const _mkCache = new Map();
function clearKeyCache() { _mkCache.clear(); argonPool.terminate(); }

function _argonInProcess(pwBytes, saltBytes, opts) { return argon2idHash(pwBytes, saltBytes, opts); }

async function deriveMasterKey(password, saltBytes) {
    const opts = {
        iterations: _kdf.iterations, memorySize: _kdf.memorySize,
        parallelism: _kdf.parallelism, hashLength: _kdf.hashLength,
    };
    // Cost is part of the cache key (mirrors the browser _mkCache) so a vault
    // re-encrypted at a new cost never reuses a stale key.
    const cacheKey = password + ':' + bytesToHex(saltBytes) +
        ':' + opts.memorySize + ':' + opts.iterations + ':' + opts.parallelism;
    if (_mkCache.has(cacheKey)) return _mkCache.get(cacheKey);
    // Dispatch to the worker-thread pool (one worker per core); _argonInProcess
    // is the fallback when worker_threads is unavailable or a worker crashes.
    const mk = await argonPool.derive(te.encode(password), saltBytes, opts, _argonInProcess);
    _mkCache.set(cacheKey, mk);
    return mk;
}
async function hkdfBytes(masterKeyBytes, infoLabel) {
    const base = await subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(infoLabel) }, base, 256);
    return new Uint8Array(bits);
}
async function hkdfAesKey(masterKeyBytes, infoLabel) {
    const base = await subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(infoLabel) },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ============================================================
// v6 payload + name encrypt/decrypt (mirror javascript.js)
// ============================================================
async function encryptFields(password, password2, recSalt1, recSalt2, fields) {
    const iv1 = crypto.getRandomValues(new Uint8Array(12));
    const nonce2 = crypto.getRandomValues(new Uint8Array(12));
    const nonce3 = crypto.getRandomValues(new Uint8Array(16));
    const nonce4 = crypto.getRandomValues(new Uint8Array(16));
    const [mk1, mk2] = await Promise.all([deriveMasterKey(password, recSalt1), deriveMasterKey(password2, recSalt2)]);
    const [aesKey, chachaKey, twofishKey, serpentKey] = await Promise.all([
        hkdfAesKey(mk1, _HK.payAes), hkdfBytes(mk1, _HK.payChacha),
        hkdfBytes(mk2, _HK.payTwofish), hkdfBytes(mk2, _HK.paySerpent)]);
    const plain = _padPlaintext(te.encode(JSON.stringify(fields)));
    const mid = chacha20poly1305(chachaKey, nonce2).encrypt(plain);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: iv1 }, aesKey, mid));
    const tf = twofishCTR(twofishKey, nonce3, ct);
    const outer = serpentCTR(serpentKey, nonce4, tf);
    return {
        iv1Hex: bytesToHex(iv1), nonce2Hex: bytesToHex(nonce2),
        nonce3Hex: bytesToHex(nonce3), nonce4Hex: bytesToHex(nonce4), encHex: bytesToHex(outer)
    };
}
async function decryptFields(password, password2, recSalt1Hex, recSalt2Hex, iv1Hex, nonce2Hex, nonce3Hex, nonce4Hex, encHex) {
    const [mk1, mk2] = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex)), deriveMasterKey(password2, hexToBytes(recSalt2Hex))]);
    const [serpentKey, twofishKey, aesKey, chachaKey] = await Promise.all([
        hkdfBytes(mk2, _HK.paySerpent), hkdfBytes(mk2, _HK.payTwofish),
        hkdfAesKey(mk1, _HK.payAes), hkdfBytes(mk1, _HK.payChacha)]);
    const tf = serpentCTR(serpentKey, hexToBytes(nonce4Hex), hexToBytes(encHex));
    const ct = twofishCTR(twofishKey, hexToBytes(nonce3Hex), tf);
    const mid = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(iv1Hex) }, aesKey, ct));
    const plain = chacha20poly1305(chachaKey, hexToBytes(nonce2Hex)).decrypt(mid);
    return JSON.parse(td.decode(plain));
}
async function encryptName(password, password2, recSalt1, recSalt2, name) {
    const nonce1 = crypto.getRandomValues(new Uint8Array(12));
    const nonce2 = crypto.getRandomValues(new Uint8Array(12));
    const [mk1, mk2] = await Promise.all([deriveMasterKey(password, recSalt1), deriveMasterKey(password2, recSalt2)]);
    const [aesKey, chachaKey] = await Promise.all([hkdfAesKey(mk1, _HK.nameAes), hkdfBytes(mk2, _HK.nameChacha)]);
    const mid = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce1 }, aesKey, te.encode(name)));
    const ct = chacha20poly1305(chachaKey, nonce2).encrypt(mid);
    return { nameNonce1Hex: bytesToHex(nonce1), nameNonce2Hex: bytesToHex(nonce2), encNameHex: bytesToHex(ct) };
}
async function decryptName(password, password2, recSalt1Hex, recSalt2Hex, nameNonce1Hex, nameNonce2Hex, encNameHex) {
    const [mk1, mk2] = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex)), deriveMasterKey(password2, hexToBytes(recSalt2Hex))]);
    const [chachaKey, aesKey] = await Promise.all([hkdfBytes(mk2, _HK.nameChacha), hkdfAesKey(mk1, _HK.nameAes)]);
    const mid = chacha20poly1305(chachaKey, hexToBytes(nameNonce2Hex)).decrypt(hexToBytes(encNameHex));
    const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(nameNonce1Hex) }, aesKey, mid));
    return td.decode(plain);
}

// ============================================================
// TOTP (RFC 6238)
// ============================================================
function base32ToBytes(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    const clean = base32.toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
    for (let i = 0; i < clean.length; i++) {
        const val = alphabet.indexOf(clean[i]);
        if (val < 0) throw new Error('Invalid base32 character: ' + clean[i]);
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    return bytes;
}
async function computeTotp(base32Secret, timeOffset) {
    timeOffset = timeOffset || 0;
    const keyBytes = base32ToBytes(base32Secret);
    const ck = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / 30) + timeOffset;
    const timeBytes = new Uint8Array(8);
    timeBytes[4] = (counter >>> 24) & 0xff; timeBytes[5] = (counter >>> 16) & 0xff;
    timeBytes[6] = (counter >>> 8) & 0xff;  timeBytes[7] = counter & 0xff;
    const hmac = new Uint8Array(await subtle.sign('HMAC', ck, timeBytes));
    const offset = hmac[19] & 0x0f;
    const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset + 1] << 16 |
                   hmac[offset + 2] << 8 | hmac[offset + 3]) % 1000000;
    return code.toString().padStart(6, '0');
}

// ============================================================
// Vault integrity manifest (vm1) — mirror javascript.js
// ============================================================
async function sha256Hex(str) {
    const buf = await subtle.digest('SHA-256', te.encode(str));
    return bytesToHex(new Uint8Array(buf));
}
async function manifestHmacHex(pw, pw2, salt1Hex, salt2Hex, revision, timestamp, records) {
    const [mk1, mk2] = await Promise.all([
        deriveMasterKey(pw, hexToBytes(salt1Hex)), deriveMasterKey(pw2, hexToBytes(salt2Hex))]);
    const ikm = new Uint8Array(64); ikm.set(mk1, 0); ikm.set(mk2, 32);
    const keyBytes = await hkdfBytes(ikm, 'v6|manifest|hmac');
    const ck = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const msg = 'vm1|' + salt1Hex + '|' + salt2Hex + '|' + revision + '|' + timestamp + '\n' + records.join('\n');
    const sig = await subtle.sign('HMAC', ck, te.encode(msg));
    return bytesToHex(new Uint8Array(sig));
}

function randomSaltHex(n) { return bytesToHex(crypto.getRandomValues(new Uint8Array(n))); }

module.exports = {
    bytesToHex, hexToBytes,
    encryptFields, decryptFields, encryptName, decryptName,
    computeTotp, base32ToBytes,
    sha256Hex, manifestHmacHex, randomSaltHex,
    deriveMasterKey, clearKeyCache,
    setKdf, parseKdf, DEFAULT_KDF,
};
