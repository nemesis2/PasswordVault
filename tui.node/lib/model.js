'use strict';
// ============================================================
// model.js — in-memory vault model: unlock, decrypt, CRUD, re-sign.
// Ties crypto.js (the v6 cascade) to vault.js (the `lines` file).
// ============================================================

const crypto = require('crypto').webcrypto;
const C = require('./crypto');
const V = require('./vault');
const argonPool = require('./argon-pool');

class Vault {
    constructor() {
        this.pw = null;
        this.pw2 = null;
        this.records = [];          // raw record strings, canonical order
        this.names = new Map();     // raw -> decrypted name
        this.manifest = null;
    }

    load() {
        this.records = V.canonical(V.readRecords());
        this.manifest = V.readManifest();
        // Adopt the vault-wide Argon2id cost (kdfparams), else the default — so
        // the TUI derives keys at the same cost the vault was encrypted with.
        C.setKdf(C.parseKdf(V.readKdf()) || C.DEFAULT_KDF);
    }

    get unlocked() { return this.pw != null; }

    // Decrypt every entry name. Throws on the first failure (wrong password /
    // tampered record). onProgress(done, total) is called as it goes.
    //
    // Names are decrypted with bounded concurrency so the Argon2id worker-thread
    // pool (one worker per core) stays saturated: each name issues two
    // memory-hard derivations (128 MiB each at the default cost), so running
    // ~poolSize names at once keeps ~2×poolSize jobs
    // queued — every core busy without the main thread blocking. (A plain
    // sequential await would leave all but one core idle.)
    async unlock(pw, pw2, onProgress) {
        this.names.clear();
        const records = this.records;
        const total = records.length;
        let done = 0, next = 0, firstErr = null;

        // Spin up the worker pool for the batch, then size concurrency to it so
        // every core stays busy (~2×poolSize derivations queued). The pool is
        // torn down in finally so its ~poolSize×(vault memory cost) is freed once names are
        // decrypted; single-entry views afterwards derive in-process.
        argonPool.start();
        const concurrency = Math.max(1, Math.min(argonPool.poolSize(), total || 1));

        const runner = async () => {
            while (firstErr === null) {
                const i = next++;
                if (i >= total) return;
                const raw = records[i];
                const p = V.parse(raw);
                let name;
                try {
                    name = await C.decryptName(pw, pw2, p.recSalt1, p.recSalt2,
                        p.nameNonce1, p.nameNonce2, p.encName);
                } catch (e) {
                    if (firstErr === null) firstErr = e;
                    return;
                }
                this.names.set(raw, name);
                if (onProgress) onProgress(++done, total);
            }
        };

        try {
            const runners = [];
            for (let i = 0; i < concurrency; i++) runners.push(runner());
            await Promise.all(runners);
        } finally {
            argonPool.terminate();
        }
        if (firstErr) throw firstErr;
        this.pw = pw; this.pw2 = pw2;
    }

    lock() {
        this.pw = this.pw2 = null;
        this.names.clear();
        C.clearKeyCache();
    }

    nameOf(raw) { return this.names.get(raw) || '(locked)'; }

    // Entries sorted by decrypted name (case-insensitive), with their raw record.
    list() {
        return this.records
            .map(raw => ({ raw, name: this.nameOf(raw) }))
            .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    }

    // Full decrypted payload object (all keys, untrimmed) — used to carry forward
    // fields the TUI doesn't surface (tags, custom fields, history, age) on edit.
    async _decryptFull(raw) {
        const p = V.parse(raw);
        return C.decryptFields(this.pw, this.pw2, p.recSalt1, p.recSalt2,
            p.iv1, p.nonce2, p.nonce3, p.nonce4, p.enc);
    }

    async decryptEntry(raw) {
        const fields = await this._decryptFull(raw);
        return {
            name: this.nameOf(raw),
            url: (fields.url || '').trim(),
            username: (fields.username || '').trim(),
            password: (fields.password || '').trim(),
            token: (fields.token || '').trim(),
            notes: (fields.notes || '').trim(),
        };
    }

    // Encrypt `payload` (the exact object stored in the v6 record — no `name`
    // key; the name is encrypted separately) into a fresh record string.
    async _buildRecord(name, payload) {
        const s1 = crypto.getRandomValues(new Uint8Array(32));
        const s2 = crypto.getRandomValues(new Uint8Array(32));
        const en = await C.encryptName(this.pw, this.pw2, s1, s2, name);
        const ef = await C.encryptFields(this.pw, this.pw2, s1, s2, payload);
        return [en.encNameHex, 'v6', C.bytesToHex(s1), C.bytesToHex(s2),
            en.nameNonce1Hex, en.nameNonce2Hex,
            ef.iv1Hex, ef.nonce2Hex, ef.nonce3Hex, ef.nonce4Hex, ef.encHex].join('|');
    }

    async add(name, fields) {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            url: fields.url || '', username: fields.username || '', password: fields.password || '',
            token: fields.token || '', notes: fields.notes || '',
            // Match the browser's payload shape so a TUI-created entry is identical.
            tags: '', extra: [], history: [], pwModified: now,
        };
        const rec = await this._buildRecord(name, payload);
        this.records = V.canonical([...this.records, rec]);
        this.names.set(rec, name);
        await this._commit();
        return rec;
    }

    async edit(oldRaw, name, fields) {
        // Start from the FULL original payload so fields the TUI doesn't surface
        // (tags, custom fields, password history, age) are preserved, not dropped.
        let prev = {};
        try { prev = await this._decryptFull(oldRaw); } catch (_) { prev = {}; }
        const payload = Object.assign({}, prev, {
            url: fields.url || '', username: fields.username || '', password: fields.password || '',
            token: fields.token || '', notes: fields.notes || '',
        });
        // Mirror the browser: when the password changes, archive the old one
        // (newest-first, capped at 20) and restamp the age.
        if (prev.password != null && payload.password !== prev.password) {
            const now = Math.floor(Date.now() / 1000);
            const hist = Array.isArray(prev.history) ? prev.history.slice() : [];
            hist.unshift({ p: prev.password, t: now });
            payload.history = hist.slice(0, 20);
            payload.pwModified = now;
        }
        const rec = await this._buildRecord(name, payload);
        this.records = V.canonical([...this.records.filter(r => r !== oldRaw), rec]);
        this.names.delete(oldRaw);
        this.names.set(rec, name);
        await this._commit();
        return rec;
    }

    async remove(raw) {
        this.records = this.records.filter(r => r !== raw);
        this.names.delete(raw);
        await this._commit();
    }

    // Persist `lines` + re-sign the integrity manifest (so the web UI stays green).
    async _commit() {
        this.records = V.writeRecords(this.records);
        await this._sign();
    }

    async _sign() {
        const recs = V.canonical(this.records);
        const old = V.parseManifest(this.manifest);
        const salt1Hex = old ? old.salt1Hex : C.randomSaltHex(32);
        const salt2Hex = old ? old.salt2Hex : C.randomSaltHex(32);
        const revision = (old ? old.revision : 0) + 1;
        const ts = Math.floor(Date.now() / 1000);
        // Always (re-)sign as vm2, binding the active vault-wide Argon2id cost —
        // matches javascript.js's _signVault(), so a TUI write never downgrades an
        // existing vm2 manifest back to the un-kdf-bound vm1 shape.
        const kdfStr = C.kdfToString(C.getKdf());
        const hmac = await C.manifestHmacHex(this.pw, this.pw2, salt1Hex, salt2Hex, revision, ts, kdfStr, recs);
        const manifest = ['vm2', salt1Hex, salt2Hex, String(revision), String(ts), kdfStr, hmac].join('|');
        V.writeManifest(manifest);
        this.manifest = manifest;
        return { revision, ts };
    }
}

module.exports = { Vault };
