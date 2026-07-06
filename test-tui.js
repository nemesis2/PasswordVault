#!/usr/bin/env node
'use strict';

// =============================================================================
// test-tui.js — tests for tui.node (vault-tui): the storage layer (lib/vault.js),
// the v6 crypto (lib/crypto.js), and the in-memory model (lib/model.js), run
// against seeded temp vault directories — no real terminal, and the repo's own
// `lines`/`bak`/`manifest` are never touched. Also checks wire-format interop
// against the browser's javascript.js (same v6 cascade, byte-identical records
// and manifests) — the central compatibility claim in tui.node/README.md.
//
//   node test-tui.js
//
// Uses a deliberately cheap Argon2id cost (8 MiB / t=2) so the suite runs in a
// few seconds — these tests check protocol/wiring, not KDF strength.
// =============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const { webcrypto } = nodeCrypto;

const ROOT = __dirname;
const TUI = path.join(ROOT, 'tui.node');
// Cap the Argon2id worker pool so repeated unlock() calls across scenarios
// spin up/tear down quickly.
process.env.VAULT_TUI_THREADS = process.env.VAULT_TUI_THREADS || '2';

let passed = 0, failed = 0;
function ok(name)       { passed++; console.log('  ✓ ' + name); }
function bad(name, why) { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function eq(name, a, b) { check(name, a === b, 'got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); }

const CHEAP_KDF = { memorySize: 8192, iterations: 2, parallelism: 1, hashLength: 32 };
const rh = (n) => nodeCrypto.randomBytes(n / 2).toString('hex');
const makeRecord = () => [rh(40), 'v6', rh(64), rh(64), rh(24), rh(24), rh(24), rh(24), rh(32), rh(32), rh(120)].join('|');

// ---- temp-vault helpers -----------------------------------------------------
const tmpVaults = [];
function seedDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-tuitest-'));
    tmpVaults.push(dir);
    return dir;
}
function cleanup() { for (const d of tmpVaults) try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {} }

// lib/vault.js resolves VAULT_DIR once at require time, so point at the target
// dir and reload it (and lib/model.js, which requires it) fresh for each
// scenario. lib/crypto.js / lib/argon-pool.js are vault-dir-independent and are
// left cached — reloading them would re-run the (slow) cipher-bundle parse.
function loadVaultLibs(dir) {
    process.env.VAULT_DIR = dir;
    delete require.cache[require.resolve(path.join(TUI, 'lib/vault.js'))];
    delete require.cache[require.resolve(path.join(TUI, 'lib/model.js'))];
    return {
        V: require(path.join(TUI, 'lib/vault.js')),
        M: require(path.join(TUI, 'lib/model.js')),
    };
}
const C = require(path.join(TUI, 'lib/crypto.js'));

function freshVault(dir) {
    const { V, M } = loadVaultLibs(dir);
    const v = new M.Vault();
    v.load();
    C.setKdf(CHEAP_KDF);   // load() adopts kdfparams (absent here ⇒ DEFAULT_KDF) — override for speed
    return { v, V };
}

// ---- browser (javascript.js) VM context, to check TUI/browser interop ------
// Mirrors test-client.js's loadContext(): stub document/window/localStorage,
// leave Worker undefined so deriveMasterKey falls back to in-process argon2idHash.
function loadBrowserContext() {
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
    });
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'javascript.js'), 'utf8'), ctx, { filename: 'javascript.js' });
    return sandbox;
}

async function main() {
    // -------------------------------------------------------------------------
    console.log('\nlib/vault.js — record parsing + canonical order');
    {
        const rec = makeRecord();
        const { V } = loadVaultLibs(seedDir());
        const p = V.parse(rec);
        eq('parse: encName', p.encName, rec.split('|')[0]);
        eq('parse: version', p.version, 'v6');
        eq('parse: enc (last field)', p.enc, rec.split('|')[10]);
        check('parse throws on wrong field count', (() => { try { V.parse('a|v6|b'); return false; } catch (_) { return true; } })());
        check('parse throws on non-v6 tag', (() => { try { V.parse(rec.replace('|v6|', '|v5|')); return false; } catch (_) { return true; } })());

        const unsorted = ['c', 'a', 'B', 'A'];
        eq('canonical is byte-wise (uppercase before lowercase)', JSON.stringify(V.canonical(unsorted)), JSON.stringify(['A', 'B', 'a', 'c']));
        check('canonical does not mutate its input', unsorted[0] === 'c');
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/vault.js — lines / bak / manifest / kdfparams round-trip');
    {
        const dir = seedDir();
        const { V } = loadVaultLibs(dir);
        eq('readRecords on a missing lines file is []', V.readRecords().length, 0);
        eq('readManifest on a missing file is null', V.readManifest(), null);
        eq('readKdf on a missing file is null', V.readKdf(), null);

        const recs = Array.from({ length: 3 }, makeRecord);
        V.writeRecords(recs);
        eq('readRecords round-trips (sorted)', JSON.stringify(V.readRecords()), JSON.stringify(V.canonical(recs)));
        check('lines file ends with a trailing newline', fs.readFileSync(path.join(dir, 'lines'), 'utf8').endsWith('\n'));
        check('no bak/ yet (first write, nothing to back up)', !fs.existsSync(path.join(dir, 'bak')));

        const recs2 = recs.slice(1);   // a second write must back up the first
        V.writeRecords(recs2);
        check('bak/ now holds a backup of the pre-write content',
            fs.existsSync(path.join(dir, 'bak')) &&
            fs.readdirSync(path.join(dir, 'bak')).some((f) => f.startsWith('lines.') &&
                fs.readFileSync(path.join(dir, 'bak', f), 'utf8').includes(recs[0].split('|')[0])));

        const m = 'vm1|' + rh(64) + '|' + rh(64) + '|7|1750000000|' + rh(64);
        V.writeManifest(m);
        eq('readManifest round-trips', V.readManifest(), m);
        const pm = V.parseManifest(m);
        eq('parseManifest vm1: revision', pm.revision, 7);
        eq('parseManifest vm1: kdfStr is null', pm.kdfStr, null);
        const m2 = 'vm2|' + rh(64) + '|' + rh(64) + '|9|1750000001|a2id|262144|4|1|' + rh(64);
        const pm2 = V.parseManifest(m2);
        eq('parseManifest vm2: revision', pm2.revision, 9);
        eq('parseManifest vm2: kdfStr', pm2.kdfStr, 'a2id|262144|4|1');
        eq('parseManifest rejects unknown tag', V.parseManifest('vm3|a|b|1|2|c'), null);
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/crypto.js — parseKdf / kdfToString bounds (mirror post.php is_valid_kdf)');
    {
        check('accepts default a2id|131072|3|1', C.parseKdf('a2id|131072|3|1') !== null);
        check('accepts min memory 65536', C.parseKdf('a2id|65536|2|1') !== null);
        check('accepts max memory 1048576', C.parseKdf('a2id|1048576|10|1') !== null);
        check('rejects memory below 64MiB', C.parseKdf('a2id|65535|3|1') === null);
        check('rejects memory above 1GiB', C.parseKdf('a2id|1048577|3|1') === null);
        check('rejects iterations < 2', C.parseKdf('a2id|131072|1|1') === null);
        check('rejects iterations > 10', C.parseKdf('a2id|131072|11|1') === null);
        check('rejects parallelism != 1', C.parseKdf('a2id|131072|3|2') === null);
        check('rejects wrong tag', C.parseKdf('a2i|131072|3|1') === null);
        eq('kdfToString ∘ parseKdf round-trips', C.kdfToString(C.parseKdf('a2id|262144|4|1')), 'a2id|262144|4|1');

        C.setKdf(CHEAP_KDF);
        const got = C.getKdf();
        check('setKdf/getKdf round-trips', ['memorySize', 'iterations', 'parallelism', 'hashLength'].every((k) => got[k] === CHEAP_KDF[k]), JSON.stringify(got));
        C.setKdf(null);
        eq('setKdf(null) resets to DEFAULT_KDF', JSON.stringify(C.getKdf()), JSON.stringify(C.DEFAULT_KDF));
        C.setKdf(CHEAP_KDF);   // back to cheap for the rest of the suite
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/crypto.js — v6 name + payload round-trip, TOTP, manifest HMAC');
    {
        const pw1 = 'tui-pass-1é', pw2 = 'tui-pass-2☃';
        const name = 'TUI Example Account';
        const fields = {
            url: 'https://example.com', username: 'alice', password: 'p@ss w0rd!',
            token: '', notes: 'multi\nline', tags: 'work, vip', extra: [{ label: 'PIN', value: '1234', secret: true }],
            history: [], pwModified: 1700000000
        };
        const s1 = webcrypto.getRandomValues(new Uint8Array(32));
        const s2 = webcrypto.getRandomValues(new Uint8Array(32));
        const ne = await C.encryptName(pw1, pw2, s1, s2, name);
        const ef = await C.encryptFields(pw1, pw2, s1, s2, fields);
        const rec = [ne.encNameHex, 'v6', C.bytesToHex(s1), C.bytesToHex(s2), ne.nameNonce1Hex, ne.nameNonce2Hex,
            ef.iv1Hex, ef.nonce2Hex, ef.nonce3Hex, ef.nonce4Hex, ef.encHex].join('|');
        const p = rec.split('|');
        const dName = await C.decryptName(pw1, pw2, p[2], p[3], p[4], p[5], p[0]);
        const dFields = await C.decryptFields(pw1, pw2, p[2], p[3], p[6], p[7], p[8], p[9], p[10]);
        eq('name round-trips', dName, name);
        eq('fields round-trip', JSON.stringify(dFields), JSON.stringify(fields));
        let threw = false;
        try { await C.decryptFields(pw1, 'WRONG', p[2], p[3], p[6], p[7], p[8], p[9], p[10]); } catch (_) { threw = true; }
        check('wrong 2nd password throws (AEAD auth fails)', threw);

        // RFC 6238 SHA-1 vector, T=59s → counter 1 (computeTotp is fixed SHA-1/30s/6-digit).
        const base32 = (bytes) => {
            const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let bits = 0, val = 0, out = '';
            for (let i = 0; i < bytes.length; i++) { val = (val << 8) | bytes[i]; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } }
            if (bits > 0) out += A[(val << (5 - bits)) & 31];
            return out;
        };
        const secret = base32(Uint8Array.from(Buffer.from('12345678901234567890', 'ascii')));
        const realNow = Date.now;
        Date.now = () => 59000;
        try {
            eq('computeTotp matches RFC 6238 SHA-1 vector', await C.computeTotp(secret, 0), '287082');
        } finally { Date.now = realNow; }

        const s1h = C.randomSaltHex(32), s2h = C.randomSaltHex(32);
        const recs = ['recordAlpha', 'recordBeta', 'recordGamma'];
        const h1 = await C.manifestHmacHex(pw1, pw2, s1h, s2h, 5, 1700000000, null, recs);
        const h2 = await C.manifestHmacHex(pw1, pw2, s1h, s2h, 5, 1700000000, null, recs);
        eq('manifest HMAC is deterministic', h1, h2);
        check('manifest HMAC is 64 hex chars', /^[0-9a-f]{64}$/.test(h1));
        const tampered = await C.manifestHmacHex(pw1, pw2, s1h, s2h, 5, 1700000000, null, ['recordAlpha', 'recordBetaX', 'recordGamma']);
        check('tampered record changes the HMAC', tampered !== h1);
        const v2 = await C.manifestHmacHex(pw1, pw2, s1h, s2h, 5, 1700000000, 'a2id|9000|2|1', recs);
        check('vm2 (kdf-bound) HMAC differs from vm1', v2 !== h1);
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/model.js — Vault: unlock / add / edit / delete / lock, against a seeded temp dir');
    {
        const dir = seedDir();
        const { v, V } = freshVault(dir);
        eq('fresh vault has no records', v.records.length, 0);
        eq('fresh vault is locked', v.unlocked, false);

        await v.unlock('primary-pw', 'secondary-pw', () => {});
        check('unlock succeeds on an empty vault', v.unlocked);

        const raw1 = await v.add('Example Site', { url: 'https://a.test', username: 'alice', password: 'pw-A', token: '', notes: 'hello' });
        eq('add grows the list to 1', v.list().length, 1);
        eq('added entry name decrypts', v.list()[0].name, 'Example Site');
        eq('lines file now holds one record on disk', V.readRecords().length, 1);

        const entry1 = await v.decryptEntry(raw1);
        eq('decryptEntry: url', entry1.url, 'https://a.test');
        eq('decryptEntry: username', entry1.username, 'alice');
        eq('decryptEntry: password', entry1.password, 'pw-A');

        // Simulate a browser-set tag/custom-field (fields the TUI's add()/edit()
        // forms never surface) landing on the entry, then verify edit() preserves
        // them rather than dropping them — the invariant model.js's edit() comment
        // calls out explicitly.
        const full1 = await v._decryptFull(raw1);
        full1.tags = 'work, vip';
        full1.extra = [{ label: 'PIN', value: '1234', secret: true }];
        const raw1b = await v._buildRecord('Example Site', full1);
        v.records = V.canonical([...v.records.filter((r) => r !== raw1), raw1b]);
        v.names.delete(raw1); v.names.set(raw1b, 'Example Site');
        await v._commit();

        const raw2 = await v.edit(raw1b, 'Example Site', { url: 'https://b.test', username: 'alice', password: 'pw-B', token: '', notes: 'hello2' });
        const full2 = await v._decryptFull(raw2);
        eq('edit preserves tags not surfaced by the edit form', full2.tags, 'work, vip');
        eq('edit preserves extra custom fields', JSON.stringify(full2.extra), JSON.stringify([{ label: 'PIN', value: '1234', secret: true }]));
        eq('edit changes the password', full2.password, 'pw-B');
        check('edit archives the OLD password into history on a password change', full2.history.length === 1 && full2.history[0].p === 'pw-A');
        check('edit restamps pwModified on a password change', full2.pwModified >= full1.pwModified);

        const manifestBefore = V.parseManifest(V.readManifest());
        await v.remove(raw2);
        eq('remove empties the list', v.list().length, 0);
        eq('lines file now empty on disk', V.readRecords().length, 0);
        const manifestAfter = V.parseManifest(V.readManifest());
        check('every commit (add/rebuild/edit/remove) bumps the manifest revision', manifestAfter.revision > manifestBefore.revision);
        eq('manifest is signed vm2 (binds the active kdf)', manifestAfter.version, 'vm2');

        // The persisted manifest's HMAC must independently re-verify against
        // whatever is currently on disk (what a fresh reader — the web UI or a
        // second TUI process — would recompute).
        const recheck = await C.manifestHmacHex('primary-pw', 'secondary-pw',
            manifestAfter.salt1Hex, manifestAfter.salt2Hex, manifestAfter.revision, manifestAfter.timestamp,
            manifestAfter.kdfStr, V.canonical(V.readRecords()));
        eq('manifest HMAC independently re-verifies from disk', recheck, manifestAfter.hmacHex);

        v.lock();
        eq('lock() clears the unlocked flag', v.unlocked, false);
        eq('lock() clears decrypted names', v.names.size, 0);
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/model.js — wrong password on unlock throws (does not silently succeed)');
    {
        const dir = seedDir();
        const first = freshVault(dir);
        await first.v.unlock('right-pw-1', 'right-pw-2');
        await first.v.add('Some Entry', { url: '', username: 'u', password: 'p', token: '', notes: '' });

        const second = freshVault(dir);
        let threw = false;
        try { await second.v.unlock('right-pw-1', 'WRONG'); } catch (_) { threw = true; }
        check('unlock with a wrong 2nd password throws', threw);
        eq('failed unlock leaves the vault locked', second.v.unlocked, false);
    }

    // -------------------------------------------------------------------------
    console.log('\ncross-compat: TUI-written vault decrypts under the browser javascript.js (and vice versa)');
    {
        const B = loadBrowserContext();
        // The vault-wide kdfStr the TUI signs with (CHEAP_KDF, chosen for test
        // speed) is below both implementations' 64MiB production minimum, so
        // parseKdf()/_parseKdf() reject it and each side falls back to its own
        // "active" cost global. Point the browser's at the same cheap cost so
        // that fallback lands on identical params on both sides.
        B._vaultKdf = CHEAP_KDF;
        const dir = seedDir();
        const { v, V } = freshVault(dir);
        await v.unlock('interop-pw-1', 'interop-pw-2');
        await v.add('Interop Entry', { url: 'https://interop.test', username: 'carol', password: 'interop-pw!', token: '', notes: 'n' });

        // A second, independent reader (the browser) parses what the TUI put on
        // disk and decrypts it with its own implementation, at the same cost.
        const onDisk = V.readRecords();
        eq('one record on disk', onDisk.length, 1);
        const p = onDisk[0].split('|');
        check('record on disk passes the browser _isValidV6Record', B._isValidV6Record(onDisk[0]));
        const browserName = await B.decryptName('interop-pw-1', 'interop-pw-2', p[2], p[3], p[4], p[5], p[0], CHEAP_KDF);
        const browserFields = await B.decryptFields('interop-pw-1', 'interop-pw-2', p[2], p[3], p[6], p[7], p[8], p[9], p[10], CHEAP_KDF);
        eq('browser decrypts the TUI-written name', browserName, 'Interop Entry');
        eq('browser decrypts the TUI-written username', browserFields.username, 'carol');
        eq('browser decrypts the TUI-written password', browserFields.password, 'interop-pw!');

        // The manifest the TUI signed independently re-verifies via the browser's
        // own _manifestHmacHex — the same claim the README makes for the web UI's
        // integrity badge.
        const m = V.parseManifest(V.readManifest());
        const browserHmac = await B._manifestHmacHex('interop-pw-1', 'interop-pw-2', m.salt1Hex, m.salt2Hex, m.revision, m.timestamp, m.kdfStr, V.canonical(onDisk));
        eq('browser _manifestHmacHex agrees with the TUI-signed manifest', browserHmac, m.hmacHex);

        // Round-trip the other direction: browser encrypts, a fresh TUI Vault
        // unlocks and decrypts it after the record is spliced directly into `lines`.
        const s1 = webcrypto.getRandomValues(new Uint8Array(32));
        const s2 = webcrypto.getRandomValues(new Uint8Array(32));
        const ne = await B.encryptName('interop-pw-1', 'interop-pw-2', s1, s2, 'Browser-Made Entry', CHEAP_KDF);
        const rf = await B.encryptFields('interop-pw-1', 'interop-pw-2', s1, s2,
            { url: '', username: 'dave', password: 'browser-set-pw', token: '', notes: '', tags: '', extra: [], history: [], pwModified: 1700000000 }, CHEAP_KDF);
        const browserRec = B._assembleRecord(ne, rf, s1, s2);
        V.writeRecords(V.canonical([...V.readRecords(), browserRec]));

        const { v: v2 } = freshVault(dir);
        await v2.unlock('interop-pw-1', 'interop-pw-2');
        const found = v2.list().find((e) => e.name === 'Browser-Made Entry');
        check('TUI unlock decrypts a browser-encrypted name', !!found);
        if (found) {
            const e = await v2.decryptEntry(found.raw);
            eq('TUI decrypts a browser-encrypted username', e.username, 'dave');
            eq('TUI decrypts a browser-encrypted password', e.password, 'browser-set-pw');
        }
    }

    // -------------------------------------------------------------------------
    console.log('\nlib/ui.js — ANSI-aware string width/layout + raw-key parsing');
    {
        const U = require(path.join(TUI, 'lib/ui.js'));
        const bold = U.style.bold, reset = U.RESET;

        eq('visLen ignores SGR escapes', U.visLen(bold + 'abc' + reset), 3);
        eq('visLen on a plain string', U.visLen('hello'), 5);

        eq('truncate is a no-op when the string already fits', U.truncate('abc', 5), 'abc');
        const t = U.truncate('abcdefgh', 4);
        check('truncate cuts to width - 1 + ellipsis', U.visLen(t) === 4 && t.indexOf('…') !== -1,
            'got ' + JSON.stringify(t));
        const tStyled = U.truncate(bold + 'abcdefgh' + reset, 4);
        check('truncate preserves embedded SGR codes while counting only visible cols',
            tStyled.indexOf(bold) !== -1 && U.visLen(tStyled) === 4);

        eq('padEnd pads short strings to width', U.padEnd('ab', 5), 'ab   ');
        eq('padEnd is a no-op past width', U.padEnd('abcdef', 3), 'abcdef');
        eq('padEnd counts visible width only (ignores SGR)', U.visLen(U.padEnd(bold + 'ab' + reset, 5)), 5);

        eq('center pads evenly (extra space on the right for odd deltas)', U.center('ab', 5), ' ab  ');
        eq('center is a no-op when it does not fit', U.center('abcdef', 3), 'abcdef');

        eq('parseKey: enter', U.parseKey('\r').name, 'enter');
        eq('parseKey: tab', U.parseKey('\t').name, 'tab');
        eq('parseKey: shift-tab (CSI Z)', U.parseKey(U.ESC + '[Z').name, 'tab');
        check('parseKey: shift-tab sets shift', U.parseKey(U.ESC + '[Z').shift === true);
        eq('parseKey: backspace (DEL)', U.parseKey('\x7f').name, 'backspace');
        eq('parseKey: escape', U.parseKey(U.ESC).name, 'escape');
        eq('parseKey: ctrl-c', U.parseKey('\x03').name, 'c');
        check('parseKey: ctrl-c sets ctrl', U.parseKey('\x03').ctrl === true);
        eq('parseKey: arrow up (CSI A)', U.parseKey(U.ESC + '[A').name, 'up');
        eq('parseKey: arrow down (CSI B)', U.parseKey(U.ESC + '[B').name, 'down');
        eq('parseKey: delete (CSI 3~)', U.parseKey(U.ESC + '[3~').name, 'delete');
        eq('parseKey: unrecognized CSI sequence', U.parseKey(U.ESC + '[9~').name, 'unknown');
        eq('parseKey: ctrl-a (0x01)', U.parseKey('\x01').name, 'a');
        eq('parseKey: printable char passes through', U.parseKey('x').name, 'x');
        eq('parseKey: printable char carries ch', U.parseKey('x').ch, 'x');
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
}

main()
    .then(() => { cleanup(); process.exit(failed ? 1 : 0); })
    .catch((e) => { cleanup(); console.error('test-tui.js crashed:', e && e.stack || e); process.exit(2); });
