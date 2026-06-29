#!/usr/bin/env node
'use strict';

// ============================================================
// repad-vault.js  —  offline vault re-encryption to apply the length-hiding
// payload padding (PAYLOAD_PAD_BUCKET, added to encryptFields).
//
// Unlike the Argon2id param change (see upgrade-params.js), this changes neither
// the record format (still v6, 11 fields) NOR the KDF params — only the payload
// PLAINTEXT is now padded up to a 256-byte bucket before encryption, so stored
// ciphertext lengths stop leaking how long a password/note is. Existing unpadded
// records still decrypt with the current code (the pad is trailing JSON
// whitespace that JSON.parse ignores), so a SINGLE javascript.js context handles
// both sides: decrypt each record, then re-encrypt under the SAME passwords with
// fresh salts/nonces — encryptFields now pads automatically.
//
// It uses the exact browser code path (no re-implementation that could drift):
// it `vm`-loads javascript.js and calls its real decryptFields/encryptFields.
// Only strings cross the realm boundary.
//
// All-or-nothing / always-readable: every record is decrypted, re-encrypted, AND
// re-decrypted from its new form and compared back to the original before
// ANYTHING is written. Any failure aborts with no output. The live `lines` is
// never touched — output goes to moved/lines.padded for the operator to review
// and swap in. Re-running it is harmless (idempotent: re-padding an already
// padded record yields the same bucketed length).
//
// Usage (run in a real terminal — it prompts for both passwords with echo off,
// so nothing lands in shell history or the process list):
//   node moved/repad-vault.js
//
// After it succeeds:
//   cp moved/lines.padded lines && chown www-data:www-data lines
//   curl -u USER:PASS 'https://host/pass/master/post?regen=1'
//   then unlock in the browser and click Sign (Vault Tools) to re-baseline the manifest.
// ============================================================

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');
const { webcrypto } = require('crypto');

const ROOT  = path.resolve(__dirname, '..');
const SRC   = path.join(ROOT, 'javascript.js');   // current source (padded encryptFields)
const LINES = path.join(ROOT, 'lines');
const OUT   = path.join(__dirname, 'lines.padded');

function die(msg) { console.error('ABORT: ' + msg); process.exit(1); }

// Read one line from the terminal without echoing it (no asterisks either — the
// length is not revealed). Handles paste (a chunk of chars), Backspace, Enter,
// Ctrl-C and Ctrl-D. Rejects if stdin is not a TTY so a typo can't silently come
// from a pipe. Keeping the secret off argv/env keeps it out of shell history.
function readSecret(promptText) {
  return new Promise((resolve, reject) => {
    const { stdin, stdout } = process;
    if (!stdin.isTTY) {
      reject(new Error('stdin is not a TTY — run this in an interactive terminal.'));
      return;
    }
    stdout.write(promptText);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const finish = (val) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write('\n');
      resolve(val);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') { finish(buf); return; }
        if (ch === '\u0003') {                       // Ctrl-C
          stdin.setRawMode(false); stdout.write('\n'); process.exit(130);
        }
        if (ch === '\u007f' || ch === '\b') { buf = buf.slice(0, -1); continue; } // Backspace
        if (ch < ' ') continue;                      // ignore other control chars
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

// Build a VM context that can run the browser javascript.js unchanged: shim the
// handful of host globals its top level touches (the cipher-bundle IIFEs use
// globalThis; the file tail calls document.addEventListener) and deliberately
// leave `Worker` undefined so _argonDerive falls back to the in-process,
// mutex-serialized argon2idHash (one heap at a time — safe and simple).
function loadContext(srcPath) {
  if (!fs.existsSync(srcPath)) die('source not found: ' + srcPath);
  const noop  = function () {};
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
    // navigator + Worker intentionally absent.
  });
  const ctx = vm.createContext(sandbox);
  try {
    vm.runInContext(fs.readFileSync(srcPath, 'utf8'), ctx, { filename: srcPath });
  } catch (e) {
    die('failed to load ' + srcPath + ': ' + (e && e.stack || e));
  }
  return sandbox;
}

async function main() {
  if (!fs.existsSync(LINES)) die('lines not found at ' + LINES);

  const ctx = loadContext(SRC);   // decrypt + re-encrypt + verify (current source)

  // Sanity: confirm this source actually carries the padding code, else running
  // it would be a pointless no-op that still re-rolls every salt.
  if (typeof ctx._padPlaintext !== 'function' || ctx.PAYLOAD_PAD_BUCKET !== 256) {
    die('javascript.js does not have the padding scheme (PAYLOAD_PAD_BUCKET/_padPlaintext) — apply the padding edit first.');
  }
  if (typeof ctx.decryptFields !== 'function' || typeof ctx.encryptFields !== 'function') {
    die('expected crypto functions missing — is javascript.js intact?');
  }

  // v6 record: encName|v6|recSalt1|recSalt2|nameNonce1|nameNonce2|iv1|nonce2|nonce3|nonce4|enc
  // Decode → re-encode with fresh salts/nonces (encryptFields pads) → re-decode
  // and compare. Only JSON strings cross the realm boundary.
  vm.runInContext(`
  globalThis.__decode = async function (rec, p1, p2) {
    var p = rec.split('|');
    var name   = await decryptName(p1, p2, p[2], p[3], p[4], p[5], p[0]);
    var fields = await decryptFields(p1, p2, p[2], p[3], p[6], p[7], p[8], p[9], p[10]);
    return JSON.stringify({ name: name, fields: fields });
  };
  globalThis.__rnd = function () { return crypto.getRandomValues(new Uint8Array(32)); };
  globalThis.__encode = async function (payload, p1, p2) {
    var o = JSON.parse(payload);
    var recSalt1 = __rnd(), recSalt2 = __rnd();
    var nameEnc = await encryptName(p1, p2, recSalt1, recSalt2, o.name);
    var result  = await encryptFields(p1, p2, recSalt1, recSalt2, o.fields);
    return [nameEnc.encNameHex, 'v6',
      bytesToHex(recSalt1), bytesToHex(recSalt2),
      nameEnc.nameNonce1Hex, nameEnc.nameNonce2Hex,
      result.iv1Hex, result.nonce2Hex, result.nonce3Hex, result.nonce4Hex,
      result.encHex].join('|');
  };`, ctx);

  const pw1 = await readSecret('Primary password:   ');
  const pw2 = await readSecret('Secondary password: ');
  if (!pw1 || !pw2) die('both passwords are required.');

  const records = fs.readFileSync(LINES, 'utf8').split('\n').map(s => s.trim()).filter(s => s !== '');
  if (!records.length) die('lines is empty — nothing to re-encrypt.');
  console.log('Re-encrypting ' + records.length + ' record(s) with length-hiding padding (m=128 MiB, t=4 — slow, 8 derivations/record)…');

  const out = [];
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    const ver = rec.split('|')[1];
    if (ver !== 'v6') die('record ' + (i + 1) + ' is not v6 (found "' + ver + '") — refusing.');

    let decoded, newRec, roundtrip;
    try { decoded = await ctx.__decode(rec, pw1, pw2); }
    catch (e) { die('record ' + (i + 1) + ' failed to DECRYPT (wrong passwords or corrupt): ' + (e && e.message || e)); }

    try { newRec = await ctx.__encode(decoded, pw1, pw2); }
    catch (e) { die('record ' + (i + 1) + ' failed to RE-ENCRYPT: ' + (e && e.message || e)); }

    try { roundtrip = await ctx.__decode(newRec, pw1, pw2); }
    catch (e) { die('record ' + (i + 1) + ' new output failed to RE-DECRYPT: ' + (e && e.message || e)); }

    if (roundtrip !== decoded) die('record ' + (i + 1) + ' round-trip mismatch.');
    out.push(newRec);
    process.stdout.write('  ' + (i + 1) + '/' + records.length + '\r');
  }
  console.log('\nAll ' + records.length + ' record(s) re-encrypted, padded, and verified readable.');

  out.sort();   // canonical (ASCII) order, matching the server's SORT_STRING
  fs.writeFileSync(OUT, out.join('\n') + '\n', { mode: 0o644 });
  console.log('Wrote ' + OUT + ' (' + out.length + ' records).');
  console.log('\nNext (operator):');
  console.log('  cp ' + OUT + ' ' + LINES + ' && chown www-data:www-data ' + LINES);
  console.log('  curl -u USER:PASS "https://host/pass/master/post?regen=1"');
  console.log('  Unlock in the browser, then click Sign (Vault Tools) to re-baseline the manifest.');
}

// WASM/WebCrypto can leave handles that keep the loop alive — exit explicitly.
main().then(() => process.exit(0)).catch(e => die((e && e.stack) || String(e)));
