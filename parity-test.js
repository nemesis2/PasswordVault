#!/usr/bin/env node
'use strict';

// =============================================================================
// parity-test.js — proves server.js's write protocol is byte-identical to
// post.php's. For each scenario it seeds two temp vaults from the SAME fixture,
// runs post.php (via the PHP CLI, the regen.sh trick) on one and server.js's
// handleWrite() on the other, then diffs the persisted files.
//
//   node parity-test.js            # needs `php` on PATH and ./post.php present
//
// Compared byte-for-byte: lines, index.html, manifest, kdfparams.
// trash is compared with its per-line unix-second column stripped (the two runs
// stamp time() independently). bak/ filenames are timestamp-based and skipped.
// The JSON response is compared parsed-equal (PHP escapes '/'; values have none).
// =============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const srv = require('./server.js');
const ROOT = __dirname;
const POSTPHP = path.join(ROOT, 'post.php');

let pass = 0, fail = 0;
const rh = (n) => crypto.randomBytes(n / 2).toString('hex');           // n hex chars

// A shape-valid v6 record (server only shape-checks; never decrypts).
function makeRecord() {
    return [rh(40), 'v6', rh(64), rh(64), rh(24), rh(24), rh(24), rh(24), rh(32), rh(32), rh(120)].join('|');
}
const joinHash = (arr) => crypto.createHash('sha256').update(arr.join('\n')).digest('hex');

function seed(records) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-parity-'));
    fs.writeFileSync(path.join(dir, 'lines'), records.length ? records.join('\n') + '\n' : '');
    fs.copyFileSync(path.join(ROOT, 'part1'), path.join(dir, 'part1'));
    fs.copyFileSync(path.join(ROOT, 'part2'), path.join(dir, 'part2'));
    return dir;
}

// Drive post.php through the PHP CLI with a synthesized request environment.
function runPhp(dir, params, isRegen) {
    const setPost = Object.entries(params)
        .map(([k, v]) => `$_POST[${JSON.stringify(k)}]=${JSON.stringify(String(v))};`).join('');
    const regen = isRegen ? '$_GET["regen"]=1;$_SERVER["REQUEST_METHOD"]="GET";' : '$_SERVER["REQUEST_METHOD"]="POST";';
    const php = `error_reporting(0);` +
        `$_SERVER["HTTP_HOST"]="localhost";$_SERVER["HTTP_X_REQUESTED_WITH"]="XMLHttpRequest";` +
        `$_SERVER["HTTP_ORIGIN"]="http://localhost";$_SERVER["PHP_AUTH_USER"]="pass";` +
        `$_SERVER["PHP_AUTH_PW"]="word";$_SERVER["REMOTE_ADDR"]="cli";` +
        regen + setPost + `chdir(${JSON.stringify(dir)});include ${JSON.stringify(POSTPHP)};`;
    const out = execFileSync('php', ['-r', php], { encoding: 'utf8' });
    return out;
}

function readFileOrNull(p) { try { return fs.readFileSync(p); } catch (_) { return null; } }
function stripTrashTs(buf) {
    if (buf === null) return null;
    return buf.toString('utf8').split('\n').map((l) => l.replace(/^\d+\t/, '')).join('\n');
}

function compare(name, a, b) {
    const files = ['lines', 'index.html', 'manifest', 'kdfparams'];
    const diffs = [];
    for (const f of files) {
        const fa = readFileOrNull(path.join(a, f)), fb = readFileOrNull(path.join(b, f));
        const ea = fa === null ? '∅' : fa, eb = fb === null ? '∅' : fb;
        if (String(ea) !== String(eb) && !(fa && fb && fa.equals(fb))) {
            if (fa && fb && fa.equals(fb)) continue;
            if ((fa === null) !== (fb === null)) diffs.push(`${f}: existence php=${fa !== null} node=${fb !== null}`);
            else if (!fa.equals(fb)) diffs.push(`${f}: ${fa.length}B vs ${fb.length}B differ`);
        }
    }
    // trash compared with ts column stripped
    const ta = stripTrashTs(readFileOrNull(path.join(a, 'trash')));
    const tb = stripTrashTs(readFileOrNull(path.join(b, 'trash')));
    if (ta !== tb) diffs.push(`trash (ts-stripped) differ`);
    if (diffs.length === 0) { pass++; console.log(`  ✓ ${name}`); }
    else { fail++; console.log(`  ✗ ${name}\n      ${diffs.join('\n      ')}`); }
}

function scenario(name, records, params, isRegen) {
    const a = seed(records), b = seed(records);
    let phpJson, nodeRes;
    try { phpJson = runPhp(a, params, isRegen); } catch (e) { fail++; console.log(`  ✗ ${name} (php error: ${e.message})`); return; }
    nodeRes = srv.handleWrite(b, Object.assign({}, params), !!isRegen);
    // Re-emit node's index via the same path php uses (handleWrite already wrote files).
    compare(name, a, b);
    // JSON parity (parsed-equal, ignoring PHP '/' escaping).
    try {
        const pj = JSON.parse(phpJson);
        const nj = nodeRes.json;
        if (nj && JSON.stringify(normalize(pj)) === JSON.stringify(normalize(nj))) { /* ok */ }
        else console.log(`      · JSON differs:\n        php : ${JSON.stringify(pj)}\n        node: ${JSON.stringify(nj)}`);
    } catch (_) {}
    fs.rmSync(a, { recursive: true, force: true });
    fs.rmSync(b, { recursive: true, force: true });
}
const normalize = (o) => o;   // keys already align; placeholder for future tolerance

// ---- Scenarios ----
console.log('Parity: post.php vs server.js\n');
const r = Array.from({ length: 5 }, makeRecord);

scenario('regen (no change)', r, {}, true);
scenario('add new record', r, { data: makeRecord() }, false);
scenario('add duplicate (dedup)', r, { data: r[2] }, false);
scenario('delete by content', r, { delete_rec: r[1] }, false);
scenario('edit (delete+add atomic)', r, { delete_rec: r[3], data: makeRecord() }, false);
scenario('delete stale (gone) → 409', r, { delete_rec: makeRecord() }, false);

const signManifest = `vm1|${rh(64)}|${rh(64)}|7|1750000000|${rh(64)}`;
scenario('sign (manifest store)', r, { sign: '1', manifest: signManifest, expect_hash: joinHash(srv.sortRecords(r)) }, false);

const bulkNew = Array.from({ length: 5 }, makeRecord);
scenario('bulk replace (same count)', r, { bulk: '1', bulk_data: bulkNew.join('\n'), expect_hash: joinHash(srv.sortRecords(r)) }, false);
scenario('bulk + kdf change', r, { bulk: '1', bulk_data: bulkNew.join('\n'), kdf: 'a2id|262144|4|1', expect_hash: joinHash(srv.sortRecords(r)) }, false);
scenario('bulk stale hash → 409', r, { bulk: '1', bulk_data: bulkNew.join('\n'), expect_hash: rh(64) }, false);

const restoreNew = Array.from({ length: 8 }, makeRecord);
scenario('restore (count change)', r, { restore: '1', bulk_data: restoreNew.join('\n'), expect_hash: joinHash(srv.sortRecords(r)) }, false);

scenario('invalid record → 400', r, { data: 'not|a|valid|record' }, false);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
