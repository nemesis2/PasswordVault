'use strict';

// =============================================================================
// seed-vault.js — build a throwaway vault directory whose records are encrypted
// under KNOWN test passwords, so a browser can actually unlock and decrypt it.
//
// It loads the unmodified ../javascript.js into a Node VM (the same host-shim
// trick as test-client.js) to reuse the real encryptName / encryptFields /
// _assembleRecord, writes `lines` + a matching `kdfparams`, copies the assets
// index.html pulls in (javascript.js, argon2-worker.js, manifest.json, sw.js,
// icon.png) plus the part1/part2 templates, then calls server.js's handleWrite
// in regen mode to splice the real index.html. Returns the dir + the plaintext
// the test should expect to see after decrypt.
//
// A deliberately small Argon2id cost (64 MiB / t=2 — the lowest the validators
// accept) keeps the in-browser reveal-all to a couple of seconds.
// =============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.join(__dirname, '..');
const srv = require(path.join(ROOT, 'server.js'));

// kdfparams string AND the matching KDF object must agree, or the browser (which
// reads the string from #vault-kdf) derives a different key than we encrypted with.
const KDF_STR = 'a2id|65536|2|1';
const KDF_OBJ = { iterations: 2, memorySize: 65536, parallelism: 1, hashLength: 32 };

const PW1 = 'correct-horse';
const PW2 = 'battery-staple';

// The plaintext entries the browser test will unlock and assert against.
const ENTRIES = [
    { name: 'GitHub', url: 'https://github.com',     username: 'octocat',           password: 'gh-Secret-pw!1' },
    { name: 'Email',  url: 'https://mail.example.com', username: 'alice@example.com', password: 'Em@il-pw-123' },
    { name: 'Bank',   url: 'https://bank.example.com', username: 'alice',             password: 'B4nk$tr0ng-xyz' },
];

function loadCryptoContext() {
    const noop = function () {};
    const elStub = {
        addEventListener: noop, removeEventListener: noop, setAttribute: noop,
        appendChild: noop, focus: noop, value: '', textContent: '', dataset: {},
        style: {}, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    };
    // javascript.js schedules background timers at load (auto-lock, OTP ticks).
    // We only need its synchronous crypto, so wrap timers to swallow callback
    // errors (they touch a real DOM we don't have) and unref them so neither this
    // module nor the test process is kept alive by the seed VM.
    const safeTimer = (orig) => (fn, ms, ...a) => {
        const t = orig(() => { try { fn(...a); } catch (_) {} }, ms);
        if (t && typeof t.unref === 'function') t.unref();
        return t;
    };
    // Return a fresh benign stub for any element lookup so those timer callbacks
    // read `.value === ''` instead of throwing on null.
    const elFor = () => Object.assign({}, elStub);
    const sandbox = {};
    Object.assign(sandbox, {
        globalThis: sandbox, self: sandbox, window: sandbox,
        crypto: webcrypto, TextEncoder, TextDecoder, console, URL,
        setTimeout: safeTimer(setTimeout), clearTimeout,
        setInterval: safeTimer(setInterval), clearInterval,
        Buffer, performance: { now: () => Date.now() },
        atob: (b) => Buffer.from(b, 'base64').toString('binary'),
        btoa: (b) => Buffer.from(b, 'binary').toString('base64'),
        location: { pathname: '/' },
        localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
        document: {
            addEventListener: noop, removeEventListener: noop,
            getElementById: elFor, querySelector: elFor,
            querySelectorAll: () => [], createElement: elFor,
            documentElement: elStub, body: elStub,
        },
        // navigator + Worker intentionally absent → in-process argon2idHash fallback.
    });
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'javascript.js'), 'utf8'), ctx, { filename: 'javascript.js' });
    return sandbox;
}

async function buildRecord(C, e) {
    const s1 = webcrypto.getRandomValues(new Uint8Array(32));
    const s2 = webcrypto.getRandomValues(new Uint8Array(32));
    const fields = {
        url: e.url, username: e.username, password: e.password, token: '',
        notes: e.name + ' notes', tags: 'test', extra: [], history: [],
        pwModified: 1700000000, created: 1690000000,
    };
    const ne = await C.encryptName(PW1, PW2, s1, s2, e.name, KDF_OBJ);
    const rf = await C.encryptFields(PW1, PW2, s1, s2, fields, KDF_OBJ);
    return C._assembleRecord(ne, rf, s1, s2);
}

async function seedVault() {
    const C = loadCryptoContext();
    const records = [];
    for (const e of ENTRIES) records.push(await buildRecord(C, e));

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-browsertest-'));
    fs.writeFileSync(path.join(dir, 'lines'), srv.sortRecords(records).join('\n') + '\n');
    fs.writeFileSync(path.join(dir, 'kdfparams'), KDF_STR);
    // Templates buildIndex needs + the assets index.html fetches at runtime.
    for (const f of ['part1', 'part2', 'javascript.js', 'argon2-worker.js', 'manifest.json', 'sw.js', 'icon.png']) {
        try { fs.copyFileSync(path.join(ROOT, f), path.join(dir, f)); } catch (_) { /* optional asset */ }
    }
    const r = srv.handleWrite(dir, {}, true);          // regen → splice index.html
    if (r.code !== 200) throw new Error('regen failed: ' + r.code + ' ' + JSON.stringify(r.json || r.text));

    return { dir, pw1: PW1, pw2: PW2, entries: ENTRIES, kdf: KDF_STR };
}

module.exports = { seedVault, ENTRIES, PW1, PW2, KDF_STR };

if (require.main === module) {
    seedVault().then((v) => { console.log('seeded', v.dir, '(' + v.entries.length + ' entries)'); })
        .catch((e) => { console.error(e); process.exit(1); });
}
