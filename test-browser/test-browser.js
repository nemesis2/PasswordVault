#!/usr/bin/env node
'use strict';

// =============================================================================
// test-browser.js — end-to-end browser/DOM tests for the vault PWA, driven with
// Playwright (Chromium, headless). Where the Node suites test crypto and the
// server in isolation, this one proves the whole thing works in a real browser:
//
//   node test-browser.js
//
// It seeds a throwaway vault encrypted under known passwords (seed-vault.js),
// serves it with the real server.js (createServer, local mode) on an ephemeral
// port, then drives a headless Chromium through the actual user flow:
//   • page loads, title + assets resolve, no uncaught exceptions / CSP violations
//   • the no-inline-handler (CSP) event-binding model works — data-action buttons
//     (theme toggle, About modal) respond
//   • entries render locked (🔒) before any key is entered
//   • entering both passwords reveals every entry name (real in-browser Argon2id
//     via the worker pool), and clicking one decrypts its fields
//   • a wrong secondary password reveals nothing (AEAD auth-tag failure)
//
// Requires the Playwright Chromium browser (`npx playwright install chromium`).
// run-tests.sh skips this suite gracefully when Playwright isn't installed.
// =============================================================================

const path = require('path');
const fs = require('fs');
const srv = require(path.join(__dirname, '..', 'server.js'));
const { seedVault } = require('./seed-vault.js');

let chromium;
try { ({ chromium } = require('playwright')); }
catch (_) { console.log('playwright not installed — run `npm install` in test-browser/ first.'); process.exit(3); }

let passed = 0, failed = 0;
function ok(name)       { passed++; console.log('  ✓ ' + name); }
function bad(name, why) { failed++; console.log('  ✗ ' + name + (why ? ' — ' + why : '')); }
function check(name, cond, why) { cond ? ok(name) : bad(name, why); }
function eq(name, a, b) { check(name, a === b, 'got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); }

// Set a masked key field through its own (overridden) value setter, then fire the
// events the app binds — `input` (relock) and, on the 2nd field, `blur` (reveal-all).
async function setKey(page, id, value, fireBlur) {
    await page.evaluate(([i, v, blur]) => {
        const el = document.getElementById(i);
        el.value = v;                                   // invokes the masked-input setter → _real
        el.dispatchEvent(new Event('input', { bubbles: true }));
        if (blur) el.dispatchEvent(new Event('blur', { bubbles: true }));
    }, [id, value, !!fireBlur]);
}
// _setEntryName stores the plaintext name in dataset.name (the visible button
// text is an avatar monogram span + a label span, so read the dataset instead).
const revealedNames = (page) => page.$$eval('.entry-grid .entry-btn:not(.v5-locked)',
    (btns) => btns.map((b) => b.dataset.name || '').filter(Boolean));

async function main() {
    const vault = await seedVault();
    const server = srv.createServer({ mode: 'local', dir: vault.dir, user: 'pass', pass: 'word' });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port + '/';

    const browser = await chromium.launch();
    const page = await browser.newPage();
    const pageErrors = [], cspErrors = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    page.on('console', (m) => {
        if (m.type() === 'error' && /content security policy|refused to (load|execute|connect)/i.test(m.text())) {
            cspErrors.push(m.text());
        }
    });

    try {
        console.log('\npage load');
        {
            const resp = await page.goto(base, { waitUntil: 'load' });
            eq('GET / → 200', resp.status(), 200);
            eq('document title', await page.title(), 'Password Vault');
            check('javascript.js evaluated (control form present)', await page.$('#aeskey') !== null);
        }

        console.log('\ninitial locked state');
        {
            const total = await page.$$eval('.entry-grid .entry-btn', (b) => b.length);
            eq('all seeded entries rendered', total, vault.entries.length);
            const visible = (await revealedNames(page)).length;
            eq('none revealed before unlock', visible, 0);
            const locked = await page.$$eval('.entry-grid .entry-btn.v5-locked', (b) => b.length);
            eq('every entry is v5-locked', locked, vault.entries.length);
        }

        console.log('\nCSP / event-binding (no inline handlers)');
        {
            // data-action delegation must work despite a strict CSP (no unsafe-inline).
            const before = await page.evaluate(() => document.documentElement.classList.contains('theme-light'));
            await page.click('[data-action="toggle-theme"]');
            const after = await page.evaluate(() => document.documentElement.classList.contains('theme-light'));
            check('theme toggle flips theme-light class', before !== after, before + '→' + after);
            await page.click('[data-action="toggle-theme"]');   // restore

            await page.click('[data-action="open-about"]');
            const aboutVisible = await page.evaluate(() => {
                const o = document.getElementById('about-overlay');
                return !!o && getComputedStyle(o).display !== 'none';
            });
            check('About modal opens via data-action', aboutVisible);
            const closeOk = await page.$('#about-close') !== null;
            if (closeOk) await page.click('#about-close');
        }

        console.log('\nwrong secondary password reveals nothing');
        {
            await setKey(page, 'aeskey', vault.pw1, false);
            await setKey(page, 'aeskey2', 'totally-wrong', true);
            // reveal-all runs Argon2id then fails every AEAD tag → nothing unhides.
            await page.waitForTimeout(6000);
            const names = await revealedNames(page);
            eq('no entries revealed with wrong key', names.length, 0);
        }

        console.log('\nunlock + reveal all names');
        {
            // Clear the bad key first (input → _relockV5Entries), then the right pair.
            await setKey(page, 'aeskey2', '', false);
            await setKey(page, 'aeskey', vault.pw1, false);
            await setKey(page, 'aeskey2', vault.pw2, true);
            await page.waitForFunction(
                (n) => document.querySelectorAll('.entry-grid .entry-btn:not(.v5-locked)').length === n,
                vault.entries.length, { timeout: 30000 });
            const names = (await revealedNames(page)).sort();
            const want = vault.entries.map((e) => e.name).sort();
            eq('all names revealed', JSON.stringify(names), JSON.stringify(want));
        }

        console.log('\ndecrypt a clicked entry');
        {
            const target = vault.entries.find((e) => e.name === 'GitHub');
            await page.click(`.entry-grid .entry-btn:has-text("${target.name}")`);
            await page.waitForFunction(
                (u) => (document.getElementById('decusername').textContent || '').trim() === u,
                target.username, { timeout: 30000 });
            eq('decrypted username', (await page.textContent('#decusername')).trim(), target.username);
            eq('decrypted password', (await page.textContent('#decpassword')).trim(), target.password);
            const decName = (await page.textContent('#decname')).trim();
            check('decrypted name shown', decName.indexOf(target.name) !== -1, decName);
        }

        console.log('\nno uncaught exceptions / CSP violations');
        {
            eq('zero uncaught page errors', pageErrors.length, 0, pageErrors.join(' | '));
            eq('zero CSP violations', cspErrors.length, 0, cspErrors.join(' | '));
        }
    } finally {
        await browser.close();
        server.close();
        try { fs.rmSync(vault.dir, { recursive: true, force: true }); } catch (_) {}
    }

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
}

main()
    .catch((e) => { console.error('test-browser.js crashed:', e && e.stack || e); failed++; })
    .finally(() => process.exit(failed ? 1 : 0));
