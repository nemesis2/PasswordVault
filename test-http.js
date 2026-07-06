#!/usr/bin/env node
'use strict';

// =============================================================================
// test-http.js — HTTP-layer integration tests for server.js. Where test-server.js
// drives handleWrite()/validators directly, this suite stands up a real server via
// the exported createServer() on an ephemeral port and makes live HTTP requests, so
// it covers the request-routing layer those unit tests never touch:
//
//   node test-http.js
//
// Covers: static serving (index no-store vs cacheable assets, MIME, security
// headers), the traversal / dotfile / deny-list / deny-dir guards, malformed-URL
// → 400, method handling (405), local-mode unauthenticated writes, and the full
// web-mode gate — Basic-Auth (401 + WWW-Authenticate), CSRF/same-origin (403),
// the chrome-/moz-extension origin allowance, rate-limiting (429 + Retry-After),
// and that regen bypasses CSRF but not auth. Pure Node, no PHP.
// =============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const srv = require('./server.js');
const ROOT = __dirname;

let passed = 0, failed = 0;
function ok(name)       { passed++; console.log('  ✓ ' + name); }
function bad(name, why) { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function eq(name, a, b) { check(name, a === b, 'got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); }

const rh = (n) => crypto.randomBytes(n / 2).toString('hex');
const makeRecord = () => [rh(40), 'v6', rh(64), rh(64), rh(24), rh(24), rh(24), rh(24), rh(32), rh(32), rh(120)].join('|');
const BASIC = (u, p) => 'Basic ' + Buffer.from(u + ':' + p).toString('base64');

// ---- temp-vault + server helpers -------------------------------------------
const tmpVaults = [], servers = [];
function seed(records) {
    records = srv.sortRecords(records);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-httptest-'));
    fs.writeFileSync(path.join(dir, 'lines'), records.length ? records.join('\n') + '\n' : '');
    fs.copyFileSync(path.join(ROOT, 'part1'), path.join(dir, 'part1'));
    fs.copyFileSync(path.join(ROOT, 'part2'), path.join(dir, 'part2'));
    fs.writeFileSync(path.join(dir, 'app-asset.js'), '// cacheable static asset\n');
    srv.handleWrite(dir, {}, true);                       // build index.html
    tmpVaults.push(dir);
    return dir;
}
function start(cfg) {
    return new Promise((resolve) => {
        const server = srv.createServer(cfg);
        servers.push(server);
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
}
function req(port, { method = 'GET', path = '/', headers = {} } = {}, body) {
    return new Promise((resolve, reject) => {
        const r = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
        });
        r.on('error', reject);
        if (body !== undefined) r.write(body);
        r.end();
    });
}
function cleanup() {
    for (const s of servers) try { s.close(); } catch (_) {}
    for (const d of tmpVaults) try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

async function main() {
    const REC = Array.from({ length: 4 }, makeRecord);

    // -------------------------------------------------------------------------
    console.log('\nstatic serving (local mode)');
    {
        const { port } = await start({ mode: 'local', dir: seed(REC), user: 'pass', pass: 'word' });

        const root = await req(port, { path: '/' });
        eq('GET / → 200', root.status, 200);
        check('serves index.html (has DOCTYPE)', /<!DOCTYPE/i.test(root.body), root.body.slice(0, 40));
        check('index content-type is html', /text\/html/.test(root.headers['content-type']));
        eq('index is no-store', root.headers['cache-control'], 'no-store');
        check('CSP header present', !!root.headers['content-security-policy']);
        eq('X-Content-Type-Options nosniff', root.headers['x-content-type-options'], 'nosniff');
        eq('Referrer-Policy no-referrer', root.headers['referrer-policy'], 'no-referrer');
        check('no HSTS in local mode', root.headers['strict-transport-security'] === undefined);

        const asset = await req(port, { path: '/app-asset.js' });
        eq('GET /app-asset.js → 200', asset.status, 200);
        check('asset content-type is javascript', /javascript/.test(asset.headers['content-type']));
        check('non-index asset is cacheable (no Cache-Control)', asset.headers['cache-control'] === undefined);

        const missing = await req(port, { path: '/does-not-exist.txt' });
        eq('missing file → 404', missing.status, 404);
    }

    // -------------------------------------------------------------------------
    console.log('\nstatic guards (traversal / dotfile / deny-list)');
    {
        const { port } = await start({ mode: 'local', dir: seed(REC), user: 'pass', pass: 'word' });

        for (const f of ['lines', 'trash', 'manifest', 'kdfparams', 'part1', 'part2']) {
            eq('deny-exact /' + f + ' → 403', (await req(port, { path: '/' + f })).status, 403);
        }
        eq('deny-dir /bak/x → 403', (await req(port, { path: '/bak/lines.123' })).status, 403);
        eq('deny-dir /moved/x → 403', (await req(port, { path: '/moved/repad-vault.js' })).status, 403);
        eq('dotfile /.htaccess → 403', (await req(port, { path: '/.htaccess' })).status, 403);
        eq('traversal /..%2f..%2fetc%2fpasswd → 403', (await req(port, { path: '/..%2f..%2fetc%2fpasswd' })).status, 403);
        eq('traversal /%2e%2e/lines → 403', (await req(port, { path: '/%2e%2e/lines' })).status, 403);
        eq('malformed %-escape → 400', (await req(port, { path: '/%c0' })).status, 400);
    }

    // -------------------------------------------------------------------------
    console.log('\nmethod handling');
    {
        const { port } = await start({ mode: 'local', dir: seed(REC), user: 'pass', pass: 'word' });
        eq('PUT / → 405', (await req(port, { method: 'PUT', path: '/' })).status, 405);
        eq('DELETE / → 405', (await req(port, { method: 'DELETE', path: '/' })).status, 405);
        const head = await req(port, { method: 'HEAD', path: '/' });
        eq('HEAD / → 200', head.status, 200);
        const post404 = await req(port, { method: 'POST', path: '/somewhere', headers: { 'content-type': 'application/x-www-form-urlencoded' } }, 'data=x');
        eq('POST to non-post path → 404', post404.status, 404);
    }

    // -------------------------------------------------------------------------
    console.log('\nlocal mode writes (no auth, but CSRF/same-origin still enforced)');
    {
        const { port } = await start({ mode: 'local', dir: seed(REC), user: 'pass', pass: 'word' });
        const FORM = 'application/x-www-form-urlencoded';
        const fresh = makeRecord();

        // CSRF: a cross-origin page can reach the loopback server, so a simple POST
        // with no same-origin signal must be refused even though local mode has no auth.
        const noCsrf = await req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM } }, 'data=' + encodeURIComponent(fresh));
        eq('POST without X-Requested-With → 403 (local CSRF guard)', noCsrf.status, 403);
        const crossOrigin = await req(port, { method: 'POST', path: '/post.php', headers: {
            'content-type': FORM, 'x-requested-with': 'XMLHttpRequest', origin: 'http://evil.example.com',
        } }, 'data=' + encodeURIComponent(fresh));
        eq('cross-origin POST → 403 (local CSRF guard)', crossOrigin.status, 403);

        // The legit same-origin client (X-Requested-With + matching Origin) still writes.
        const add = await req(port, { method: 'POST', path: '/post.php', headers: {
            'content-type': FORM, 'x-requested-with': 'XMLHttpRequest', origin: 'http://127.0.0.1:' + port,
        } }, 'data=' + encodeURIComponent(fresh));
        eq('same-origin POST add → 200 (no auth needed locally)', add.status, 200);
        check('response is JSON', /application\/json/.test(add.headers['content-type']));
        check('added record reported in entries', add.body.indexOf(fresh) !== -1);

        const regen = await req(port, { method: 'GET', path: '/post.php?regen=1' });
        eq('GET regen → 200', regen.status, 200);
        check('regen json.regen true', JSON.parse(regen.body).regen === true);
    }

    // -------------------------------------------------------------------------
    console.log('\nweb mode: static still served, HSTS present');
    {
        const { port } = await start({ mode: 'web', dir: seed(REC), user: 'pass', pass: 'word' });
        const root = await req(port, { path: '/' });
        eq('GET / → 200 (static is not auth-gated)', root.status, 200);
        eq('HSTS present in web mode', root.headers['strict-transport-security'], 'max-age=63072000');
    }

    // -------------------------------------------------------------------------
    console.log('\nweb mode: Basic-Auth + CSRF gate');
    {
        const { port } = await start({ mode: 'web', dir: seed(REC), user: 'pass', pass: 'word' });
        const body = 'data=' + encodeURIComponent(makeRecord());
        const FORM = 'application/x-www-form-urlencoded';

        const noAuth = await req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM } }, body);
        eq('POST without auth → 401', noAuth.status, 401);
        check('challenges with WWW-Authenticate', /Basic/.test(noAuth.headers['www-authenticate'] || ''));

        const badAuth = await req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM, authorization: BASIC('pass', 'nope') } }, body);
        eq('POST wrong password → 401', badAuth.status, 401);

        // Correct creds but no same-origin signal → CSRF block.
        const noCsrf = await req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM, authorization: BASIC('pass', 'word') } }, body);
        eq('auth ok but no X-Requested-With → 403', noCsrf.status, 403);

        const wrongOrigin = await req(port, { method: 'POST', path: '/post.php', headers: {
            'content-type': FORM, authorization: BASIC('pass', 'word'),
            'x-requested-with': 'XMLHttpRequest', origin: 'http://evil.example.com',
        } }, body);
        eq('cross-origin POST → 403', wrongOrigin.status, 403);

        const good = await req(port, { method: 'POST', path: '/post.php', headers: {
            'content-type': FORM, authorization: BASIC('pass', 'word'),
            'x-requested-with': 'XMLHttpRequest', origin: 'http://127.0.0.1:' + port,
        } }, body);
        eq('auth + same-origin POST → 200', good.status, 200);

        // The passkey companion extension posts from its own unspoofable origin.
        const ext = await req(port, { method: 'POST', path: '/post.php', headers: {
            'content-type': FORM, authorization: BASIC('pass', 'word'),
            'x-requested-with': 'XMLHttpRequest', origin: 'chrome-extension://abcdefghijklmnop',
        } }, 'data=' + encodeURIComponent(makeRecord()));
        eq('chrome-extension origin accepted → 200', ext.status, 200);

        // regen bypasses CSRF but still needs auth.
        const regenNoAuth = await req(port, { method: 'GET', path: '/post.php?regen=1' });
        eq('regen without auth → 401', regenNoAuth.status, 401);
        const regenAuth = await req(port, { method: 'GET', path: '/post.php?regen=1', headers: { authorization: BASIC('pass', 'word') } });
        eq('regen with auth, no same-origin → 200', regenAuth.status, 200);
    }

    // -------------------------------------------------------------------------
    console.log('\nweb mode: rate limiting (per-IP, 5 fails / window)');
    {
        const { port } = await start({ mode: 'web', dir: seed(REC), user: 'pass', pass: 'word' });
        const FORM = 'application/x-www-form-urlencoded';
        const body = 'data=' + encodeURIComponent(makeRecord());
        const fail = () => req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM, authorization: BASIC('pass', 'WRONG') } }, body);

        // A correct-creds request clears any prior rl state for this IP (auth runs
        // before the CSRF check), giving the counter a deterministic starting point.
        await req(port, { method: 'POST', path: '/post.php', headers: { 'content-type': FORM, authorization: BASIC('pass', 'word') } }, body);

        let last;
        for (let i = 1; i <= 5; i++) { last = await fail(); eq('fail #' + i + ' → 401', last.status, 401); }
        const blocked = await fail();
        eq('6th attempt → 429', blocked.status, 429);
        check('429 carries Retry-After', /^\d+$/.test(blocked.headers['retry-after'] || ''), blocked.headers['retry-after']);
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
}

main()
    .catch((e) => { console.error('test-http.js crashed:', e && e.stack || e); failed++; })
    .finally(() => { cleanup(); process.exit(failed ? 1 : 0); });
