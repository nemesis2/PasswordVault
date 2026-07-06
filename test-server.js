#!/usr/bin/env node
'use strict';

// =============================================================================
// test-server.js — standalone integration tests for server.js's write protocol
// and validators. Unlike parity-test.js (which diffs server.js against the live
// post.php and therefore needs `php` on PATH), this suite exercises server.js's
// exported handleWrite() / validators directly against seeded temp vaults — so
// it runs anywhere Node does, with no PHP.
//
//   node test-server.js
//
// Covers: isValidRecord / isValidManifest / isValidKdf (accept + reject),
// htmlspecialchars, sortRecords byte-ordering, sha256hex, and the full write
// protocol surface — add / dedup / delete-by-content (+ soft-delete to trash) /
// edit / 409-staleness / bulk (count-locked) / bulk+kdf / restore (count-flex) /
// sign / regen / trash list+untrash+purge — asserting both the JSON response and
// the persisted lines / index.html / manifest / kdfparams / trash.
// =============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const srv = require('./server.js');
const ROOT = __dirname;

let passed = 0, failed = 0;
function ok(name)       { passed++; console.log('  ✓ ' + name); }
function bad(name, why) { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function eq(name, a, b) { check(name, a === b, 'got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); }

const rh = (n) => crypto.randomBytes(n / 2).toString('hex');             // n hex chars
// A shape-valid v6 record (the server only shape-checks; it never decrypts).
function makeRecord() {
    return [rh(40), 'v6', rh(64), rh(64), rh(24), rh(24), rh(24), rh(24), rh(32), rh(32), rh(120)].join('|');
}
const joinHash = (arr) => crypto.createHash('sha256').update(arr.join('\n')).digest('hex');
const curHash  = (records) => joinHash(srv.sortRecords(records));        // expect_hash over current set

// ---- temp-vault helpers -----------------------------------------------------
const tmpVaults = [];
function seed(records) {
    // Production `lines` is always byte-sorted (every write re-sorts), and the
    // server's expect_hash check joins the on-disk order — so seed sorted too.
    records = srv.sortRecords(records);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-srvtest-'));
    fs.writeFileSync(path.join(dir, 'lines'), records.length ? records.join('\n') + '\n' : '');
    fs.copyFileSync(path.join(ROOT, 'part1'), path.join(dir, 'part1'));
    fs.copyFileSync(path.join(ROOT, 'part2'), path.join(dir, 'part2'));
    tmpVaults.push(dir);
    return dir;
}
const readOrNull = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return null; } };
const linesOf    = (dir) => { const s = readOrNull(path.join(dir, 'lines')); return s ? s.split('\n').filter(Boolean) : []; };
const write      = (dir, params, isRegen) => srv.handleWrite(dir, Object.assign({}, params), !!isRegen);
function cleanup() { for (const d of tmpVaults) try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {} }

function main() {
    const REC = Array.from({ length: 5 }, makeRecord);

    // -------------------------------------------------------------------------
    console.log('\nisValidRecord');
    {
        check('accepts a well-formed v6 record', srv.isValidRecord(makeRecord()));
        check('rejects wrong field count', !srv.isValidRecord('a|v6|b'));
        check('rejects non-v6 tag', !srv.isValidRecord(makeRecord().replace('|v6|', '|v5|')));
        const p = makeRecord().split('|'); p[2] = p[2].slice(0, 62);   // salt1 wrong length
        check('rejects wrong hex length', !srv.isValidRecord(p.join('|')));
        const q = makeRecord().split('|'); q[10] = 'zz' + q[10].slice(2);
        check('rejects non-hex payload', !srv.isValidRecord(q.join('|')));
        check('rejects empty string', !srv.isValidRecord(''));
        check('rejects non-string', !srv.isValidRecord(null));
        check('rejects oversize (>64KiB)', !srv.isValidRecord(makeRecord().slice(0, -120) + 'a'.repeat(70000)));
    }

    // -------------------------------------------------------------------------
    console.log('\nisValidManifest');
    {
        const m = `vm1|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`;
        check('accepts a well-formed vm1', srv.isValidManifest(m));
        check('rejects short salt', !srv.isValidManifest(`vm1|${rh(62)}|${rh(64)}|7|1750000000|${rh(64)}`));
        check('rejects non-digit revision', !srv.isValidManifest(`vm1|${rh(64)}|${rh(64)}|x|1750000000|${rh(64)}`));
        check('rejects >512 bytes', !srv.isValidManifest('vm1|' + 'a'.repeat(600)));
        check('rejects unknown tag', !srv.isValidManifest(`vm3|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`));
        // vm2 binds the kdf ("a2id|m|t|p"), which is itself 4 pipe fields → 10 total.
        const m2 = `vm2|${rh(64)}|${rh(64)}|7|1750000000|a2id|262144|4|1|${rh(64)}`;
        check('accepts a well-formed vm2', srv.isValidManifest(m2));
        check('rejects vm2 with out-of-bounds kdf', !srv.isValidManifest(`vm2|${rh(64)}|${rh(64)}|7|1750000000|a2id|99|4|1|${rh(64)}`));
        check('rejects vm2 with wrong field count', !srv.isValidManifest(`vm2|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`));
        check('rejects vm2 with short hmac', !srv.isValidManifest(`vm2|${rh(64)}|${rh(64)}|7|1750000000|a2id|262144|4|1|${rh(62)}`));
    }

    // -------------------------------------------------------------------------
    console.log('\nisValidKdf');
    {
        check('accepts default a2id|131072|3|1', srv.isValidKdf('a2id|131072|3|1'));
        check('accepts min memory 65536', srv.isValidKdf('a2id|65536|2|1'));
        check('accepts max memory 1048576', srv.isValidKdf('a2id|1048576|10|1'));
        check('rejects memory below 64MiB', !srv.isValidKdf('a2id|65535|3|1'));
        check('rejects memory above 1GiB', !srv.isValidKdf('a2id|1048577|3|1'));
        check('rejects iterations < 2', !srv.isValidKdf('a2id|131072|1|1'));
        check('rejects iterations > 10', !srv.isValidKdf('a2id|131072|11|1'));
        check('rejects parallelism != 1', !srv.isValidKdf('a2id|131072|3|2'));
        check('rejects wrong tag', !srv.isValidKdf('a2i|131072|3|1'));
    }

    // -------------------------------------------------------------------------
    console.log('\npure helpers');
    {
        eq('htmlspecialchars escapes the five entities',
            srv.htmlspecialchars(`<a href="x" id='y'>&`), '&lt;a href=&quot;x&quot; id=&apos;y&apos;&gt;&amp;');
        eq('htmlspecialchars is a no-op on a v6 record', srv.htmlspecialchars(REC[0]), REC[0]);
        const unsorted = ['c', 'a', 'B', 'A'];
        check('sortRecords is byte-wise (uppercase before lowercase)',
            JSON.stringify(srv.sortRecords(unsorted)) === JSON.stringify(['A', 'B', 'a', 'c']));
        check('sortRecords does not mutate its input', unsorted[0] === 'c');
        eq('sha256hex matches Node crypto', srv.sha256hex('abc'),
            crypto.createHash('sha256').update('abc').digest('hex'));
    }

    // -------------------------------------------------------------------------
    console.log('\nregen (no record change)');
    {
        const d = seed(REC);
        const before = readOrNull(path.join(d, 'lines'));
        const r = write(d, {}, true);
        eq('returns 200', r.code, 200);
        eq('json.regen is true', r.json.regen, true);
        eq('lines untouched', readOrNull(path.join(d, 'lines')), before);
        check('index.html (re)written', readOrNull(path.join(d, 'index.html')) !== null);
        eq('entries count matches', r.json.entries.length, REC.length);
        check('kdf defaults when kdfparams absent', r.json.kdf === 'a2id|131072|3|1');
    }

    // -------------------------------------------------------------------------
    console.log('\nadd / dedup');
    {
        const d = seed(REC);
        const fresh = makeRecord();
        const r = write(d, { data: fresh });
        eq('add returns 200', r.code, 200);
        eq('lines grew by one', linesOf(d).length, REC.length + 1);
        check('new record present', linesOf(d).indexOf(fresh) !== -1);
        check('index.html embeds the new record', readOrNull(path.join(d, 'index.html')).indexOf(fresh) !== -1);

        const r2 = write(d, { data: fresh });               // adding it again is a no-op
        eq('dedup add returns 200', r2.code, 200);
        eq('dedup did not grow lines', linesOf(d).length, REC.length + 1);
    }

    // -------------------------------------------------------------------------
    console.log('\ndelete-by-content (+ soft-delete to trash)');
    {
        const d = seed(REC);
        const r = write(d, { delete_rec: REC[2] });
        eq('delete returns 200', r.code, 200);
        eq('lines shrank by one', linesOf(d).length, REC.length - 1);
        check('record gone from lines', linesOf(d).indexOf(REC[2]) === -1);
        const trash = readOrNull(path.join(d, 'trash')) || '';
        check('deleted record moved to trash', trash.indexOf(REC[2]) !== -1);
        check('a bak/ backup was written', fs.readdirSync(path.join(d, 'bak')).some((f) => f.startsWith('lines.')));
    }

    // -------------------------------------------------------------------------
    console.log('\ndelete stale (gone) → 409');
    {
        const d = seed(REC);
        const r = write(d, { delete_rec: makeRecord() });   // never present
        eq('returns 409', r.code, 409);
        eq('json.error is "stale"', r.json.error, 'stale');
        eq('lines untouched', linesOf(d).length, REC.length);
    }

    // -------------------------------------------------------------------------
    console.log('\nedit (atomic delete+add)');
    {
        const d = seed(REC);
        const replacement = makeRecord();
        const r = write(d, { delete_rec: REC[1], data: replacement });
        eq('returns 200', r.code, 200);
        eq('count unchanged', linesOf(d).length, REC.length);
        check('old record gone', linesOf(d).indexOf(REC[1]) === -1);
        check('replacement present', linesOf(d).indexOf(replacement) !== -1);
    }
    {
        const d = seed(REC);
        const r = write(d, { delete_rec: makeRecord(), data: makeRecord() });  // stale old → whole op 409s
        eq('stale edit returns 409', r.code, 409);
        eq('nothing inserted', linesOf(d).length, REC.length);
    }

    // -------------------------------------------------------------------------
    console.log('\nbulk replace (count-locked)');
    {
        const d = seed(REC);
        const next = Array.from({ length: REC.length }, makeRecord);
        const r = write(d, { bulk: '1', bulk_data: next.join('\n'), expect_hash: curHash(REC) });
        eq('returns 200', r.code, 200);
        check('lines fully replaced', next.every((x) => linesOf(d).indexOf(x) !== -1));
        check('old records gone', REC.every((x) => linesOf(d).indexOf(x) === -1));
    }
    {
        const d = seed(REC);
        const next = Array.from({ length: REC.length }, makeRecord);
        const r = write(d, { bulk: '1', bulk_data: next.join('\n'), expect_hash: rh(64) });  // stale hash
        eq('stale hash returns 409', r.code, 409);
        check('lines untouched', REC.every((x) => linesOf(d).indexOf(x) !== -1));
    }
    {
        const d = seed(REC);
        const next = Array.from({ length: REC.length + 1 }, makeRecord);   // count differs
        const r = write(d, { bulk: '1', bulk_data: next.join('\n'), expect_hash: curHash(REC) });
        eq('bulk count mismatch returns 409', r.code, 409);
    }
    {
        const d = seed(REC);
        const r = write(d, { bulk: '1', bulk_data: REC.join('\n'), expect_hash: curHash(REC), data: makeRecord() });
        eq('bulk + data is rejected 400', r.code, 400);
    }

    // -------------------------------------------------------------------------
    console.log('\nbulk + kdf change (atomic lines + kdfparams)');
    {
        const d = seed(REC);
        const next = Array.from({ length: REC.length }, makeRecord);
        const r = write(d, { bulk: '1', bulk_data: next.join('\n'), kdf: 'a2id|262144|4|1', expect_hash: curHash(REC) });
        eq('returns 200', r.code, 200);
        eq('kdfparams written', (readOrNull(path.join(d, 'kdfparams')) || '').trim(), 'a2id|262144|4|1');
        eq('json reports new kdf', r.json.kdf, 'a2id|262144|4|1');
        check('index.html embeds the new kdf', readOrNull(path.join(d, 'index.html')).indexOf('a2id|262144|4|1') !== -1);
    }
    {
        const d = seed(REC);
        const r = write(d, { bulk: '1', bulk_data: REC.join('\n'), kdf: 'a2id|99|3|1', expect_hash: curHash(REC) });
        eq('out-of-range kdf rejected 400', r.code, 400);
    }

    // -------------------------------------------------------------------------
    console.log('\nrestore (count-flexible whole-vault replace)');
    {
        const d = seed(REC);
        const next = Array.from({ length: REC.length + 3 }, makeRecord);   // more entries than before
        const r = write(d, { restore: '1', bulk_data: next.join('\n'), expect_hash: curHash(REC) });
        eq('returns 200 despite count change', r.code, 200);
        eq('lines now holds the imported count', linesOf(d).length, REC.length + 3);
    }
    {
        const d = seed(REC);
        const r = write(d, { restore: '1', bulk_data: 'not|a|record', expect_hash: curHash(REC) });
        eq('invalid imported record rejected 400', r.code, 400);
    }

    // -------------------------------------------------------------------------
    console.log('\nsign (manifest store, no lines change)');
    {
        const d = seed(REC);
        const m = `vm1|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`;
        const before = readOrNull(path.join(d, 'lines'));
        const r = write(d, { sign: '1', manifest: m, expect_hash: curHash(REC) });
        eq('returns 200', r.code, 200);
        eq('manifest persisted', (readOrNull(path.join(d, 'manifest')) || '').trim(), m);
        eq('json carries the manifest', r.json.manifest, m);
        eq('lines untouched', readOrNull(path.join(d, 'lines')), before);
        check('index.html embeds the manifest', readOrNull(path.join(d, 'index.html')).indexOf(m) !== -1);
    }
    {
        const d = seed(REC);
        const m = `vm1|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`;
        const r = write(d, { sign: '1', manifest: m, expect_hash: rh(64) });  // stale
        eq('stale sign returns 409', r.code, 409);
        check('manifest not written', readOrNull(path.join(d, 'manifest')) === null);
    }
    {
        const d = seed(REC);
        const r = write(d, { sign: '1', manifest: 'vm1|bad', expect_hash: curHash(REC) });
        eq('malformed manifest rejected 400', r.code, 400);
    }

    // -------------------------------------------------------------------------
    console.log('\ntrash list / untrash / purge');
    {
        const d = seed(REC);
        write(d, { delete_rec: REC[0] });                   // populate trash
        write(d, { delete_rec: REC[1] });

        const list = write(d, { trash: '1' });
        eq('trash list returns 200', list.code, 200);
        eq('trash holds two records', list.json.trash.length, 2);
        check('trash newest-first', list.json.trash[0].ts >= list.json.trash[1].ts);

        const restored = write(d, { untrash_rec: REC[1] });
        eq('untrash returns 200', restored.code, 200);
        check('record back in lines', linesOf(d).indexOf(REC[1]) !== -1);
        eq('trash now holds one', write(d, { trash: '1' }).json.trash.length, 1);

        const purged = write(d, { purge_trash: REC[0] });
        eq('purge returns 200', purged.code, 200);
        eq('trash now empty', write(d, { trash: '1' }).json.trash.length, 0);

        write(d, { delete_rec: REC[2] });                   // add one back, then empty-all
        const all = write(d, { purge_trash: '__all__' });
        eq('purge __all__ returns 200', all.code, 200);
        eq('trash cleared', write(d, { trash: '1' }).json.trash.length, 0);
    }

    // -------------------------------------------------------------------------
    console.log('\nindex.html splice shape');
    {
        const d = seed(REC);
        write(d, {}, true);
        const html = readOrNull(path.join(d, 'index.html'));
        const btns = (html.match(/class="entry-btn v5-locked"/g) || []).length;
        eq('one locked button per record', btns, REC.length);
        check('carries the kdf span', html.indexOf('id="vault-kdf"') !== -1);
        check('carries the manifest span', html.indexOf('id="vault-manifest"') !== -1);
        check('trailing index appended to data-row', html.indexOf(REC[0] + '|') !== -1 || html.indexOf('|0"') !== -1);
    }

    // -------------------------------------------------------------------------
    console.log('\nmissing templates → 500');
    {
        const d = seed(REC);
        fs.rmSync(path.join(d, 'part1'));
        const r = write(d, { data: makeRecord() });
        eq('returns 500', r.code, 500);
        eq('lines untouched', linesOf(d).length, REC.length);
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
}

try { main(); } finally { cleanup(); }
process.exit(failed ? 1 : 0);
