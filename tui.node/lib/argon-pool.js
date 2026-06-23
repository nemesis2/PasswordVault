'use strict';
// ============================================================
// argon-pool.js — Node worker_threads pool for Argon2id (mirrors the browser
// app's "Argon2id Web Worker pool").
//
// hash-wasm runs Argon2id synchronously on a single WASM instance behind an
// internal mutex, so deriving many keys with `await` on the main thread pins
// them to one core. Unlock derives two memory-hard keys per entry name (128 MiB
// each at the vault's default cost), so on a vault of any size that is the
// dominant cost. Here each derivation is dispatched to a
// pool of worker threads — ONE PER CPU CORE — each with its own WASM instance,
// so the work fans out across every core.
//
//   • Pool size  = navigator-equivalent core count: os.cpus().length
//                  (override with the VAULT_TUI_THREADS env var).
//   • Peak memory ≈ poolSize × the vault's Argon2id memory cost (128 MiB by
//     default; up to 1 GiB if raised), only while hashing. On a many-core box
//     this can be large; set VAULT_TUI_THREADS to cap it.
//   • Inputs are passed by structured-clone COPY (never transferred), so a
//     worker crash can retry the derivation on the main thread without losing
//     the password/salt buffers.
//   • Lifecycle is explicit: start() before a batch (unlock's name decryption),
//     terminate() right after — freeing the workers' WASM heaps (which only
//     grow) and dropping residual password bytes. derive() uses the pool only
//     while it is running; outside a batch (e.g. a single entry view) it runs
//     in-process, so we never spin up N workers + ~1 GB just for 2 derivations.
// ============================================================

const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');

const WORKER_FILE = path.join(__dirname, 'argon-thread.js');

// One worker per logical core; VAULT_TUI_THREADS overrides (e.g. to cap memory).
function poolSize() {
    const env = parseInt(process.env.VAULT_TUI_THREADS, 10);
    if (Number.isFinite(env) && env > 0) return env;
    const n = (os.cpus() || []).length || 1;
    return Math.max(1, n);
}

let pool = null;         // [{ worker, busy }] once initialised
let queue = [];          // pending { password, salt, opts, fallback, resolve, reject }
const jobs = new Map();  // id -> { item, slot }
let seq = 0;
let workersOK = true;    // flips false permanently if Workers can't be constructed

// Spin up the worker pool (one per core). Idempotent; safe to call before every
// batch. Returns true if the pool is available, false if worker_threads can't be
// used (caller then just runs in-process).
function start() {
    if (pool) return true;
    if (!workersOK) return false;
    try {
        pool = [];
        for (let i = 0; i < poolSize(); i++) {
            const w = new Worker(WORKER_FILE);
            const slot = { worker: w, busy: false };
            w.on('message', (msg) => onMessage(slot, msg));
            w.on('error', (err) => onError(slot, err));
            pool.push(slot);
        }
        return true;
    } catch (e) {
        workersOK = false;   // worker_threads unavailable / blocked — main-thread fallback
        pool = null;
        return false;
    }
}

function onMessage(slot, msg) {
    slot.busy = false;
    const job = jobs.get(msg.id);
    if (job) {
        jobs.delete(msg.id);
        if (msg.ok) job.item.resolve(new Uint8Array(msg.hash));
        else job.item.reject(new Error(msg.error || 'argon2 worker error'));
    }
    drain();
}

function onError(slot, err) {
    // A worker crashed. Retry whatever it was running on the main thread (inputs
    // were copied, not transferred, so they're intact), drop the dead slot, and
    // keep going on the survivors.
    jobs.forEach((job, id) => {
        if (job.slot !== slot) return;
        jobs.delete(id);
        const it = job.item;
        Promise.resolve().then(() => it.fallback(it.password, it.salt, it.opts)).then(it.resolve, it.reject);
    });
    try { slot.worker.terminate(); } catch (_) {}
    if (pool) {
        pool = pool.filter(s => s !== slot);
        if (pool.length === 0) pool = null;   // all gone → next derive falls back / re-inits
    }
    drain();
}

function drain() {
    if (!pool) return;
    for (const slot of pool) {
        if (slot.busy || queue.length === 0) continue;
        const item = queue.shift();
        const id = ++seq;
        slot.busy = true;
        jobs.set(id, { item, slot });
        slot.worker.postMessage({ id, password: item.password, salt: item.salt, opts: item.opts });
    }
}

// Derive one Argon2id key. Uses the pool when it is running (i.e. inside a
// start()…terminate() batch); otherwise runs the in-process `fallbackFn`, which
// is also the retry path if a worker dies. `fallbackFn(password, salt, opts)`.
function derive(passwordBytes, saltBytes, opts, fallbackFn) {
    if (!pool || pool.length === 0) return fallbackFn(passwordBytes, saltBytes, opts);
    return new Promise((resolve, reject) => {
        queue.push({ password: passwordBytes, salt: saltBytes, opts, fallback: fallbackFn, resolve, reject });
        drain();
    });
}

// Whether the pool is currently running (so callers can choose batch concurrency).
function active() { return !!(pool && pool.length); }

// Tear the pool down (after a batch / on lock): terminate workers and reject
// anything still pending so callers settle.
function terminate() {
    const p = pool; pool = null;
    if (p) p.forEach(s => { try { s.worker.terminate(); } catch (_) {} });
    jobs.forEach(job => job.item.reject(new Error('argon2 pool terminated')));
    jobs.clear();
    const q = queue; queue = [];
    q.forEach(item => item.reject(new Error('argon2 pool terminated')));
}

module.exports = { poolSize, start, active, derive, terminate };
