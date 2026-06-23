'use strict';
// ============================================================
// argon-thread.js — worker_threads entry for one Argon2id worker.
//
// Each worker thread is its own V8 isolate with its own WASM instance, so N
// workers give real parallelism (hash-wasm otherwise serialises every
// derivation on a single instance behind an internal mutex). This loads the
// SAME argon2-worker.js bundle the browser/main thread use, then bridges its
// argon2idHash to the worker_threads message channel.
//
// Protocol: parent posts { id, password:Uint8Array, salt:Uint8Array, opts }.
// We reply { id, ok:true, hash:Uint8Array } (output buffer transferred back) or
// { id, ok:false, error:string }. Inputs are passed by copy (never transferred),
// so the parent keeps its buffers and can retry on the main thread on failure.
// ============================================================

const { parentPort } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

if (!globalThis.crypto) globalThis.crypto = nodeCrypto.webcrypto;
if (!globalThis.self) globalThis.self = globalThis;

const ROOT = path.resolve(__dirname, '..', '..');
(function loadArgon() {
    const src = fs.readFileSync(path.join(ROOT, 'argon2-worker.js'), 'utf8');
    vm.runInThisContext(src, { filename: 'argon2-worker.js' });
})();

const argon2idHash = globalThis.argon2idHash;

parentPort.on('message', (m) => {
    Promise.resolve()
        .then(() => argon2idHash(m.password, m.salt, m.opts))
        .then((hash) => { parentPort.postMessage({ id: m.id, ok: true, hash }, [hash.buffer]); })
        .catch((err) => { parentPort.postMessage({ id: m.id, ok: false, error: String((err && err.message) || err) }); });
});
