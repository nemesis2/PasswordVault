#!/usr/bin/env node
'use strict';

// =============================================================================
// test-client.js — client-side unit tests for the crypto + pure logic in
// javascript.js. Loads the unmodified browser source into a Node VM with a small
// host-global shim (the same pattern as moved/repad-vault.js: stub document /
// window / localStorage, leave `Worker` undefined so deriveMasterKey falls back
// to the in-process argon2idHash), then exercises the functions directly.
//
//   node test-client.js
//
// Covers: v6 name+payload encrypt→decrypt round-trip, _assembleRecord shape vs
// _isValidV6Record, _estimateBits strength estimator, computeTotp against the
// RFC 6238 SHA-1/256/512 vectors, the manifest HMAC (_manifestHmacHex) +
// _constTimeHexEq integrity primitives, and _normalizeTags / _padPlaintext.
//
// Uses a deliberately cheap Argon2id cost (8 MiB / t=2) so the suite runs in a
// few seconds — these tests check the cipher/HKDF/HMAC wiring, not KDF strength.
// =============================================================================

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const SRC = path.join(__dirname, 'javascript.js');
const CHEAP_KDF = { memorySize: 8192, iterations: 2, parallelism: 1, hashLength: 32 };

let passed = 0, failed = 0;
function ok(name)        { passed++; console.log('  ✓ ' + name); }
function bad(name, why)  { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function approx(a, b, eps) { return Math.abs(a - b) <= (eps || 0.01); }

// --- Load javascript.js into a sandboxed VM context (mirrors repad-vault.js) ---
function loadContext() {
    const noop = function () {};
    const elStub = {
        addEventListener: noop, removeEventListener: noop, setAttribute: noop,
        appendChild: noop, focus: noop, value: '', textContent: '', dataset: {},
        style: {}, classList: { add: noop, remove: noop, toggle: noop, contains: () => false }
    };
    const sandbox = {};
    Object.assign(sandbox, {
        globalThis: sandbox, self: sandbox, window: sandbox,
        crypto: webcrypto, TextEncoder, TextDecoder, console,
        setTimeout, clearTimeout, setInterval, clearInterval,
        Buffer, performance: { now: () => Date.now() },
        atob: (b) => Buffer.from(b, 'base64').toString('binary'),
        btoa: (b) => Buffer.from(b, 'binary').toString('base64'),
        localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
        document: {
            addEventListener: noop, removeEventListener: noop,
            getElementById: () => null, querySelector: () => null,
            querySelectorAll: () => [], createElement: () => Object.assign({}, elStub),
            body: elStub
        }
        // navigator + Worker intentionally absent → in-process argon2idHash fallback.
    });
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(SRC, 'utf8'), ctx, { filename: SRC });
    return sandbox;
}

// RFC 4648 base32 (no padding) — to feed the RFC 6238 ASCII secrets to computeTotp.
function base32(bytes) {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, val = 0, out = '';
    for (let i = 0; i < bytes.length; i++) {
        val = (val << 8) | bytes[i]; bits += 8;
        while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += A[(val << (5 - bits)) & 31];
    return out;
}
const asciiBytes = (s) => Uint8Array.from(Buffer.from(s, 'ascii'));

async function main() {
    const C = loadContext();

    // Sanity: the refactored helpers must be present.
    for (const fn of ['encryptName', 'encryptFields', 'decryptName', 'decryptFields',
                      '_assembleRecord', '_isValidV6Record', '_estimateBits', 'computeTotp',
                      '_manifestHmacHex', '_constTimeHexEq', '_normalizeTags', '_padPlaintext',
                      '_fuzzyMatch']) {
        if (typeof C[fn] !== 'function') { bad('load ' + fn, 'missing'); }
    }

    console.log('\nv6 encrypt → decrypt round-trip');
    {
        const pw1 = 'first-pass-é', pw2 = 'second-pass-☃';
        const name = 'Example über Account';
        const fields = {
            url: 'https://example.com', username: 'alice', password: 'p@ss w0rd!',
            token: '', notes: 'multi\nline', tags: 'work, vip', extra: [{ label: 'PIN', value: '1234', secret: true }],
            history: [], pwModified: 1700000000, created: 1690000000
        };
        const s1 = webcrypto.getRandomValues(new Uint8Array(32));
        const s2 = webcrypto.getRandomValues(new Uint8Array(32));
        const ne = await C.encryptName(pw1, pw2, s1, s2, name, CHEAP_KDF);
        const rf = await C.encryptFields(pw1, pw2, s1, s2, fields, CHEAP_KDF);
        const rec = C._assembleRecord(ne, rf, s1, s2);

        check('record passes _isValidV6Record', C._isValidV6Record(rec), 'assembled record rejected');
        check('record has 11 fields, v6 tag', rec.split('|').length === 11 && rec.split('|')[1] === 'v6');

        const p = rec.split('|');
        const dName = await C.decryptName(pw1, pw2, p[2], p[3], p[4], p[5], p[0], CHEAP_KDF);
        const dF = await C.decryptFields(pw1, pw2, p[2], p[3], p[6], p[7], p[8], p[9], p[10], CHEAP_KDF);
        check('name round-trips', dName === name, JSON.stringify(dName));
        check('fields round-trip', JSON.stringify(dF) === JSON.stringify(fields), JSON.stringify(dF));

        // Wrong second password must fail the AEAD auth tag (not silently decrypt).
        let threw = false;
        try { await C.decryptFields(pw1, 'WRONG', p[2], p[3], p[6], p[7], p[8], p[9], p[10], CHEAP_KDF); }
        catch (_) { threw = true; }
        check('wrong password throws', threw, 'decrypt did not throw on wrong key');
    }

    console.log('\n_padPlaintext (length-hiding)');
    {
        const pad = (n) => C._padPlaintext(new Uint8Array(n)).length;
        check('empty pads to one 256 bucket', pad(0) === 256, String(pad(0)));
        check('100 bytes → 256', pad(100) === 256, String(pad(100)));
        check('256 bytes → 256 (exact multiple)', pad(256) === 256, String(pad(256)));
        check('257 bytes → 512', pad(257) === 512, String(pad(257)));
    }

    console.log('\n_normalizeTags');
    {
        check('lowercases, trims, dedupes, sorts-stable',
            C._normalizeTags('Work,  vip , work,VIP,') === 'work, vip',
            JSON.stringify(C._normalizeTags('Work,  vip , work,VIP,')));
        check('empty → empty', C._normalizeTags('') === '');
    }

    console.log('\n_fuzzyMatch (command-palette matcher)');
    {
        const fm = C._fuzzyMatch;
        check('empty query matches anything', fm('', 'anything').hit);
        check('substring hits', fm('git', 'GitHub').hit);
        check('subsequence hits', fm('gh', 'GitHub').hit);
        check('out-of-order misses', fm('hg', 'GitHub').hit === false);
        check('non-subsequence misses', fm('xyz', 'GitHub').hit === false);
        check('substring outscores scattered subsequence',
            fm('git', 'GitHub').score > fm('gh', 'GitHub').score,
            fm('git', 'GitHub').score + ' vs ' + fm('gh', 'GitHub').score);
        check('earlier substring scores higher',
            fm('a', 'apple').score > fm('a', 'banana').score,
            fm('a', 'apple').score + ' vs ' + fm('a', 'banana').score);
    }

    console.log('\n_estimateBits');
    {
        check('empty → 0 bits', C._estimateBits('') === 0);
        check('8 lowercase ≈ 37.6', approx(C._estimateBits('aaaaaaaa'), Math.log2(26) * 8), String(C._estimateBits('aaaaaaaa')));
        check('8 all-classes ≈ 52.4', approx(C._estimateBits('Aa1!Aa1!'), Math.log2(94) * 8), String(C._estimateBits('Aa1!Aa1!')));
        check('"password" is weak (<40)', C._estimateBits('password') < 40);
        check('long mixed is strong (>=80)', C._estimateBits('Tr0ub4dour&3xtra-Long!Pass') >= 80);
    }

    console.log('\ncomputeTotp (RFC 6238 vectors, T=59s → counter 1)');
    {
        // Date is a VM intrinsic (not a sandbox prop), so pin Date.now() inside
        // the context to land on counter 1 (epoch 59s / period 30).
        vm.runInContext('globalThis.__realNow = Date.now; Date.now = function () { return 59000; };', C);
        try {
            const vec = [
                ['SHA-1',   '12345678901234567890',                                             '287082'],
                ['SHA-256', '12345678901234567890123456789012',                                 '119246'],
                ['SHA-512', '1234567890123456789012345678901234567890123456789012345678901234', '693936']
            ];
            for (const [alg, secret, expect] of vec) {
                const cfg = { secret: base32(asciiBytes(secret)), digits: 6, period: 30, algorithm: alg, steam: false };
                const code = await C.computeTotp(cfg, 0);
                check(alg + ' → ' + expect, code === expect, 'got ' + code);
            }
        } finally { vm.runInContext('Date.now = globalThis.__realNow;', C); }
    }

    console.log('\nManifest HMAC (_manifestHmacHex) + _constTimeHexEq');
    {
        C._vaultKdf = CHEAP_KDF;   // _manifestHmacHex derives at _vaultKdf
        const pw1 = 'mp1', pw2 = 'mp2';
        const s1 = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('hex');
        const s2 = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('hex');
        const recs = ['recordAlpha', 'recordBeta', 'recordGamma'];
        const h1 = await C._manifestHmacHex(pw1, pw2, s1, s2, 5, 1700000000, recs);
        const h2 = await C._manifestHmacHex(pw1, pw2, s1, s2, 5, 1700000000, recs);
        check('HMAC is deterministic', h1 === h2);
        check('HMAC is 64 hex chars', /^[0-9a-f]{64}$/.test(h1), h1);

        const tampered = await C._manifestHmacHex(pw1, pw2, s1, s2, 5, 1700000000, ['recordAlpha', 'recordBetaX', 'recordGamma']);
        check('tampered record → different HMAC', tampered !== h1);
        const wrongPw = await C._manifestHmacHex(pw1, 'WRONG', s1, s2, 5, 1700000000, recs);
        check('wrong password → different HMAC', wrongPw !== h1);

        check('_constTimeHexEq matches equal', C._constTimeHexEq(h1, h2) === true);
        check('_constTimeHexEq rejects different', C._constTimeHexEq(h1, tampered) === false);
        check('_constTimeHexEq rejects length mismatch', C._constTimeHexEq(h1, h1.slice(0, -2)) === false);
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('test-client.js crashed:', e && e.stack || e); process.exit(2); });
