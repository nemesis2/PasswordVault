#!/usr/bin/env node
'use strict';

// =============================================================================
// test-client-extras.js — additional pure-logic unit tests for javascript.js,
// complementing test-client.js (which covers the crypto round-trip, padding,
// tags, strength, TOTP vectors, and the manifest HMAC). This file targets the
// non-crypto helpers that have no KDF cost, so it runs near-instantly:
//
//   node test-client-extras.js
//
// Covers: _parseOtp (bare secret / otpauth URI params / Steam detection),
// _csvParse + _csvField (RFC-4180 round-trip, quotes, embedded commas/newlines),
// _avatarColor + _avatarLetter + _favHash (stable, deterministic hashing),
// _entryGroupKey (A–Z / '#' bucketing), _searchIndex (secret-field exclusion),
// and _isValidV6Record reject cases (the client mirror of post.php's validator).
//
// Loads the unmodified browser source into a Node VM with the same host-global
// shim as test-client.js (no Worker → in-process Argon2id fallback, though none
// of these tests touch the KDF).
// =============================================================================

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const SRC = path.join(__dirname, 'javascript.js');

let passed = 0, failed = 0;
function ok(name)       { passed++; console.log('  ✓ ' + name); }
function bad(name, why) { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function eq(name, a, b) { check(name, a === b, 'got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); }

// --- Load javascript.js into a sandboxed VM context (mirrors test-client.js) ---
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
        crypto: webcrypto, TextEncoder, TextDecoder, console, URL,
        setTimeout, clearTimeout, setInterval, clearInterval,
        Buffer, performance: { now: () => Date.now() },
        atob: (b) => Buffer.from(b, 'base64').toString('binary'),
        btoa: (b) => Buffer.from(b, 'binary').toString('base64'),
        location: { pathname: '/pass/test/' },
        localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
        document: {
            addEventListener: noop, removeEventListener: noop,
            getElementById: () => null, querySelector: () => null,
            querySelectorAll: () => [], createElement: () => Object.assign({}, elStub),
            documentElement: elStub, body: elStub
        }
    });
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(SRC, 'utf8'), ctx, { filename: SRC });
    return sandbox;
}

function main() {
    const C = loadContext();

    for (const fn of ['_parseOtp', '_csvParse', '_csvField', '_avatarColor', '_avatarLetter',
                      '_favHash', '_entryGroupKey', '_searchIndex', '_isValidV6Record', '_normalizeTags']) {
        if (typeof C[fn] !== 'function') bad('load ' + fn, 'missing');
    }

    console.log('\n_parseOtp');
    {
        const bare = C._parseOtp('  jbsw y3dp ehpk3pxp ');
        eq('bare secret uppercased + despaced', bare.secret, 'JBSWY3DPEHPK3PXP');
        eq('bare defaults to 6 digits', bare.digits, 6);
        eq('bare defaults to 30s period', bare.period, 30);
        eq('bare defaults to SHA-1', bare.algorithm, 'SHA-1');
        check('bare is not steam', bare.steam === false);

        const uri = C._parseOtp('otpauth://totp/ACME:alice?secret=GEZDGNBV&digits=8&period=60&algorithm=SHA256&issuer=ACME');
        eq('uri secret parsed', uri.secret, 'GEZDGNBV');
        eq('uri digits parsed', uri.digits, 8);
        eq('uri period parsed', uri.period, 60);
        eq('uri algorithm normalized', uri.algorithm, 'SHA-256');

        const steam = C._parseOtp('otpauth://totp/Steam:bob?secret=GEZDGNBV&issuer=Steam');
        check('steam detected from issuer', steam.steam === true);
        eq('steam forces 5 digits', steam.digits, 5);

        const bad = C._parseOtp('otpauth://totp/x?nosecret=1');
        eq('malformed uri → empty secret', bad.secret, '');
    }

    console.log('\n_csvParse / _csvField');
    {
        const rows = C._csvParse('a,b,c\r\n1,2,3\n');
        check('parses two rows', rows.length === 2);
        check('first row split on commas', JSON.stringify(rows[0]) === JSON.stringify(['a', 'b', 'c']));

        const quoted = C._csvParse('"has, comma","line\nbreak","quote""inside"');
        eq('embedded comma kept inside quotes', quoted[0][0], 'has, comma');
        eq('embedded newline kept inside quotes', quoted[0][1], 'line\nbreak');
        eq('doubled quote unescaped', quoted[0][2], 'quote"inside');

        const bom = C._csvParse('﻿name,url\nx,y');
        eq('BOM stripped from first field', bom[0][0], 'name');

        eq('_csvField always-quotes', C._csvField('plain'), '"plain"');
        eq('_csvField doubles quotes', C._csvField('a"b'), '"a""b"');
        eq('_csvField null → empty quoted', C._csvField(null), '""');

        // Round-trip: field → csv → parse must recover the original value.
        const vals = ['simple', 'with, comma', 'with "quote"', 'multi\nline', ''];
        const line = vals.map(C._csvField).join(',');
        const back = C._csvParse(line)[0];
        check('field/parse round-trip', JSON.stringify(back) === JSON.stringify(vals),
            JSON.stringify(back));
    }

    console.log('\n_avatarColor / _avatarLetter / _favHash');
    {
        eq('avatar letter is uppercased first char', C._avatarLetter('gmail'), 'G');
        eq('avatar letter falls back to #', C._avatarLetter('  '), '#');
        eq('avatar color is deterministic', C._avatarColor('GitHub'), C._avatarColor('GitHub'));
        check('avatar color is an hsl() string', /^hsl\(\d{1,3},42%,45%\)$/.test(C._avatarColor('GitHub')));
        check('different names usually differ in color', C._avatarColor('GitHub') !== C._avatarColor('GitLab'));

        eq('favHash is 8 hex chars', C._favHash('Example').length, 8);
        check('favHash is hex', /^[0-9a-f]{8}$/.test(C._favHash('Example')));
        eq('favHash is deterministic', C._favHash('Example'), C._favHash('Example'));
        check('favHash differs by name', C._favHash('Example') !== C._favHash('Example2'));
    }

    console.log('\n_entryGroupKey');
    {
        eq('lowercase first letter → uppercase bucket', C._entryGroupKey('amazon'), 'A');
        eq('uppercase stays', C._entryGroupKey('Zoom'), 'Z');
        eq('digit → #', C._entryGroupKey('1Password'), '#');
        eq('symbol → #', C._entryGroupKey('@home'), '#');
        eq('non-Latin → #', C._entryGroupKey('über'), '#');
        eq('empty → #', C._entryGroupKey(''), '#');
    }

    console.log('\n_searchIndex (secret-field exclusion)');
    {
        const idx = C._searchIndex({
            tags: 'Work, VIP', notes: 'Some NOTE',
            extra: [{ label: 'Recovery', value: 'plaincode', secret: false },
                    { label: 'PIN', value: 'topsecret', secret: true }]
        });
        eq('tags lowercased', idx.tags, 'work, vip');
        eq('notes lowercased', idx.notes, 'some note');
        check('non-secret custom field indexed', idx.extra.indexOf('plaincode') !== -1);
        check('secret custom field excluded', idx.extra.indexOf('topsecret') === -1);
    }

    console.log('\n_isValidV6Record (client mirror of is_valid_record)');
    {
        const rh = (n) => Buffer.from(webcrypto.getRandomValues(new Uint8Array(n / 2))).toString('hex');
        const good = [rh(40), 'v6', rh(64), rh(64), rh(24), rh(24), rh(24), rh(24), rh(32), rh(32), rh(120)].join('|');
        check('accepts a well-formed v6 record', C._isValidV6Record(good));
        check('rejects too-few fields', !C._isValidV6Record('a|v6|b'));
        check('rejects non-v6 tag', !C._isValidV6Record(good.replace('|v6|', '|v5|')));
        const p = good.split('|'); p[4] = p[4].slice(0, 22);
        check('rejects wrong nonce length', !C._isValidV6Record(p.join('|')));
        check('rejects empty string', !C._isValidV6Record(''));
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    process.exit(failed ? 1 : 0);
}

main();
