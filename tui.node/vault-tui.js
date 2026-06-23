#!/usr/bin/env node
'use strict';
// ============================================================
// vault-tui.js — terminal client for the client-side-encrypted password vault.
//
// Same crypto, same `lines`/`manifest` files as the web app — just an ANSI TUI
// that dynamically fits and fills the terminal. Run from anywhere:
//     node vault-tui.js
// ============================================================

const { spawnSync } = require('child_process');
const UI = require('./lib/ui');
const { C, style, RESET } = UI;
const { Vault } = require('./lib/model');
const Cr = require('./lib/crypto');

const _INACTIVITY_MS = 5 * 60 * 1000;   // auto-lock after 5 min idle (matches web app)

class App {
    constructor() {
        this.screen = new UI.Screen();
        this.vault = new Vault();
        this.mode = 'login';
        this.status = '';
        this.statusKind = 'info';        // info | ok | warn | err
        this.lastActivity = Date.now();

        // login
        this.login = { pw: '', pw2: '', focus: 0, reveal: false, busy: false, progress: null };
        // list
        this.list = { filter: '', searching: false, items: [], sel: 0, scrollRow: 0, cols: 1 };
        // detail
        this.detail = { raw: null, entry: null, otp: null, otpRemain: 0, busy: false };
        // form
        this.form = null;
        // confirm
        this.confirm = null;
    }

    // ---------- lifecycle ----------
    start() {
        UI.enter();
        this.vault.load();
        this.unsub = UI.onKeys(k => this.onKey(k));
        this.onResize = () => { this.screen.resize(); this.render(); };
        process.stdout.on('resize', this.onResize);
        this.tick = setInterval(() => this.onTick(), 1000);
        process.on('exit', () => this.cleanup());
        this.render();
    }
    cleanup() {
        if (this._cleaned) return; this._cleaned = true;
        clearInterval(this.tick);
        if (this.unsub) this.unsub();
        process.stdout.off('resize', this.onResize);
        UI.leave();
    }
    quit() { this.cleanup(); process.exit(0); }

    setStatus(msg, kind) { this.status = msg; this.statusKind = kind || 'info'; }

    onTick() {
        // auto-lock
        if (this.vault.unlocked && Date.now() - this.lastActivity > _INACTIVITY_MS) {
            this.vault.lock();
            this.mode = 'login';
            this.login = { pw: '', pw2: '', focus: 0, reveal: false, busy: false, progress: null };
            this.setStatus('Vault auto-locked after inactivity', 'warn');
            this.render();
            return;
        }
        // live TOTP refresh in detail view
        if (this.mode === 'detail' && this.detail.entry && this.detail.entry.token) {
            this.refreshOtp().then(() => { if (this.mode === 'detail') this.render(); });
        }
    }

    // ---------- key dispatch ----------
    async onKey(k) {
        this.lastActivity = Date.now();
        if (k.ctrl && k.name === 'c') { this.quit(); return; }
        try {
            if (this.mode === 'login') return await this.keyLogin(k);
            if (this.mode === 'list') return await this.keyList(k);
            if (this.mode === 'detail') return await this.keyDetail(k);
            if (this.mode === 'form') return await this.keyForm(k);
            if (this.mode === 'confirm') return await this.keyConfirm(k);
        } catch (e) {
            this.setStatus('Error: ' + (e && e.message || e), 'err');
            this.render();
        }
    }

    // ---------- LOGIN ----------
    async keyLogin(k) {
        const L = this.login;
        if (L.busy) return;
        if (k.name === 'escape') { this.quit(); return; }
        if (k.name === 'tab' || k.name === 'down') { L.focus = (L.focus + 1) % 2; return this.render(); }
        if (k.name === 'up' || (k.name === 'tab' && k.shift)) { L.focus = (L.focus + 1) % 2; return this.render(); }
        if (k.ctrl && k.name === 'r') { L.reveal = !L.reveal; return this.render(); }
        if (k.name === 'backspace') { const f = L.focus === 0 ? 'pw' : 'pw2'; L[f] = L[f].slice(0, -1); return this.render(); }
        if (k.name === 'enter') {
            if (L.focus === 0) { L.focus = 1; return this.render(); }
            return this.doUnlock();
        }
        if (k.ch && k.ch >= ' ') { const f = L.focus === 0 ? 'pw' : 'pw2'; L[f] += k.ch; return this.render(); }
    }

    async doUnlock() {
        const L = this.login;
        if (!L.pw || !L.pw2) { this.setStatus('Both passwords are required for v6 entries', 'warn'); return this.render(); }
        L.busy = true; L.progress = { done: 0, total: this.vault.records.length };
        this.setStatus('Deriving keys & decrypting entry names…', 'info'); this.render();
        try {
            await this.vault.unlock(L.pw, L.pw2, (done, total) => {
                L.progress = { done, total };
                if (done % 3 === 0 || done === total) this.render();
            });
        } catch (e) {
            this.vault.lock();
            L.busy = false; L.progress = null;
            this.setStatus('Unlock failed — wrong password or tampered record', 'err');
            return this.render();
        }
        L.busy = false; L.progress = null;
        this.enterList();
        const n = this.vault.records.length;
        this.setStatus(`Unlocked · ${n} entr${n === 1 ? 'y' : 'ies'} · manifest ${this.manifestBadge()}`, 'ok');
        this.render();
    }

    manifestBadge() {
        const m = require('./lib/vault').parseManifest(this.vault.manifest);
        return m ? `rev ${m.revision}` : 'unsigned';
    }

    // ---------- LIST ----------
    enterList() {
        this.mode = 'list';
        this.refreshItems();
        this.list.sel = Math.min(this.list.sel, Math.max(0, this.list.items.length - 1));
    }
    refreshItems() {
        const all = this.vault.list();
        const q = this.list.filter.trim().toLowerCase();
        this.list.items = q ? all.filter(e => e.name.toLowerCase().includes(q)) : all;
        if (this.list.sel >= this.list.items.length) this.list.sel = Math.max(0, this.list.items.length - 1);
    }

    async keyList(k) {
        const Ls = this.list;
        if (Ls.searching) {
            if (k.name === 'escape') { Ls.searching = false; Ls.filter = ''; this.refreshItems(); return this.render(); }
            if (k.name === 'enter') { Ls.searching = false; return this.render(); }
            if (k.name === 'backspace') { Ls.filter = Ls.filter.slice(0, -1); this.refreshItems(); return this.render(); }
            if (k.ch && k.ch >= ' ') { Ls.filter += k.ch; Ls.sel = 0; this.refreshItems(); return this.render(); }
            return;
        }
        const cols = Ls.cols || 1;
        const n = Ls.items.length;
        switch (k.name) {
            case 'q': case 'escape': this.quit(); return;
            case 'l': if (!k.ctrl) { this.vault.lock(); this.mode = 'login'; this.login = { pw: '', pw2: '', focus: 0, reveal: false, busy: false, progress: null }; this.setStatus('Locked', 'warn'); return this.render(); } break;
            case 'left': case 'h': if (Ls.sel > 0) Ls.sel--; return this.render();
            case 'right': if (Ls.sel < n - 1) Ls.sel++; return this.render();
            case 'up': case 'k': if (Ls.sel - cols >= 0) Ls.sel -= cols; return this.render();
            case 'down': case 'j': if (Ls.sel + cols < n) Ls.sel += cols; else if (Ls.sel < n - 1) Ls.sel = n - 1; return this.render();
            case 'home': Ls.sel = 0; return this.render();
            case 'end': Ls.sel = Math.max(0, n - 1); return this.render();
            case 'pageup': Ls.sel = Math.max(0, Ls.sel - cols * this._visGridRows()); return this.render();
            case 'pagedown': Ls.sel = Math.min(n - 1, Ls.sel + cols * this._visGridRows()); return this.render();
            case '/': Ls.searching = true; Ls.filter = ''; return this.render();
            case 'a': return this.openForm(null);
            case 'enter': if (n) return this.openDetail(Ls.items[Ls.sel].raw); return;
            case 'e': if (n) return this.openForm(Ls.items[Ls.sel].raw); return;
            case 'd': if (n) { this.confirm = { raw: Ls.items[Ls.sel].raw, name: Ls.items[Ls.sel].name }; this.mode = 'confirm'; return this.render(); } return;
        }
    }

    // ---------- DETAIL ----------
    async openDetail(raw) {
        this.detail = { raw, entry: null, otp: null, otpRemain: 0, busy: true };
        this.mode = 'detail';
        this.setStatus('Decrypting…', 'info'); this.render();
        try {
            this.detail.entry = await this.vault.decryptEntry(raw);
        } catch (e) {
            this.setStatus('Decrypt failed: ' + (e.message || e), 'err'); this.mode = 'list'; return this.render();
        }
        this.detail.busy = false;
        if (this.detail.entry.token) await this.refreshOtp();
        this.setStatus('', 'info'); this.render();
    }
    async refreshOtp() {
        const e = this.detail.entry; if (!e || !e.token) return;
        try {
            this.detail.otp = await Cr.computeTotp(e.token, 0);
            this.detail.otpRemain = 30 - (Math.floor(Date.now() / 1000) % 30);
        } catch { this.detail.otp = '------'; }
    }
    async keyDetail(k) {
        const e = this.detail.entry;
        switch (k.name) {
            case 'escape': case 'q': case 'backspace': this.enterList(); return this.render();
            case 'e': if (e) return this.openForm(this.detail.raw); return;
            case 'd': if (e) { this.confirm = { raw: this.detail.raw, name: e.name }; this.mode = 'confirm'; return this.render(); } return;
            case 'c': if (e) return this.copy(e.password, 'Password');
            case 'u': if (e) return this.copy(e.username, 'Username');
            case 'p': if (e) return this.copy(e.password, 'Password');
            case 't': if (e && this.detail.otp) return this.copy(this.detail.otp, 'TOTP code');
            case 'o': if (e && e.url) return this.openUrl(e.url);
        }
    }

    // ---------- FORM (add / edit) ----------
    async openForm(raw) {
        const blank = { name: '', url: '', username: '', password: '', token: '', notes: '' };
        if (raw) {
            this.setStatus('Loading entry…', 'info'); this.mode = 'form';
            this.form = { editingRaw: raw, fields: blank, focus: 0, reveal: false, busy: true, keys: ['name', 'url', 'username', 'password', 'token', 'notes'] };
            this.render();
            try {
                const e = await this.vault.decryptEntry(raw);
                this.form.fields = { name: e.name, url: e.url, username: e.username, password: e.password, token: e.token, notes: e.notes };
            } catch (err) { this.setStatus('Decrypt failed: ' + (err.message || err), 'err'); this.mode = 'list'; return this.render(); }
            this.form.busy = false;
        } else {
            this.form = { editingRaw: null, fields: blank, focus: 0, reveal: false, busy: false, keys: ['name', 'url', 'username', 'password', 'token', 'notes'] };
            this.mode = 'form';
        }
        this.setStatus('Ctrl-S save · Esc cancel · Ctrl-R reveal · Ctrl-G generate pw', 'info');
        this.render();
    }
    async keyForm(k) {
        const F = this.form; if (F.busy) return;
        const key = F.keys[F.focus];
        if (k.name === 'escape') { this.afterMutateReturn(); return; }
        if (k.ctrl && k.name === 's') return this.saveForm();
        if (k.ctrl && k.name === 'r') { F.reveal = !F.reveal; return this.render(); }
        if (k.ctrl && k.name === 'g') { F.fields.password = this.genPassword(20); return this.render(); }
        if (k.name === 'tab') { F.focus = (F.focus + (k.shift ? F.keys.length - 1 : 1)) % F.keys.length; return this.render(); }
        if (k.name === 'down') { F.focus = (F.focus + 1) % F.keys.length; return this.render(); }
        if (k.name === 'up') { F.focus = (F.focus + F.keys.length - 1) % F.keys.length; return this.render(); }
        if (k.name === 'enter') { F.focus = (F.focus + 1) % F.keys.length; return this.render(); }
        if (k.name === 'backspace') { F.fields[key] = F.fields[key].slice(0, -1); return this.render(); }
        if (k.ch && k.ch >= ' ') { F.fields[key] += k.ch; return this.render(); }
    }
    async saveForm() {
        const F = this.form;
        const name = (F.fields.name || '').trim();
        if (!name) { this.setStatus('Name is required', 'warn'); return this.render(); }
        F.busy = true; this.setStatus('Encrypting & signing…', 'info'); this.render();
        try {
            if (F.editingRaw) await this.vault.edit(F.editingRaw, name, F.fields);
            else await this.vault.add(name, F.fields);
        } catch (e) { F.busy = false; this.setStatus('Save failed: ' + (e.message || e), 'err'); return this.render(); }
        this.setStatus(`Saved “${name}” · ${this.manifestBadge()}`, 'ok');
        this.enterList();
        // select the saved entry
        const idx = this.list.items.findIndex(it => it.name === name);
        if (idx >= 0) this.list.sel = idx;
        this.render();
    }
    afterMutateReturn() { this.enterList(); this.render(); }

    // ---------- CONFIRM DELETE ----------
    async keyConfirm(k) {
        if (k.name === 'y' || (k.ch && k.ch.toLowerCase() === 'y')) {
            const raw = this.confirm.raw, name = this.confirm.name;
            this.confirm = null;
            this.setStatus('Deleting & signing…', 'info'); this.render();
            try { await this.vault.remove(raw); } catch (e) { this.setStatus('Delete failed: ' + (e.message || e), 'err'); this.enterList(); return this.render(); }
            this.setStatus(`Deleted “${name}” · ${this.manifestBadge()}`, 'ok');
            this.enterList(); return this.render();
        }
        this.confirm = null; this.enterList(); return this.render();
    }

    // ---------- helpers ----------
    genPassword(len) {
        const sets = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+';
        const rnd = require('crypto').randomBytes(len);
        let out = ''; for (let i = 0; i < len; i++) out += sets[rnd[i] % sets.length];
        return out;
    }
    copy(text, label) {
        if (!text) { this.setStatus(`${label} is empty`, 'warn'); return this.render(); }
        const ok = clipboardCopy(text);
        this.setStatus(ok ? `${label} copied to clipboard` : `No clipboard tool found (install xclip/xsel/wl-clipboard)`, ok ? 'ok' : 'warn');
        this.render();
    }
    openUrl(url) {
        const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
        try { spawnSync(cmd, [url], { stdio: 'ignore' }); this.setStatus('Opened URL', 'ok'); }
        catch { this.setStatus('Could not open URL', 'warn'); }
        this.render();
    }
    _visGridRows() { return Math.max(1, this.screen.rows - 4 /*header*/ - 1 /*footer*/); }

    // ============================================================
    // RENDER
    // ============================================================
    render() {
        const s = this.screen; s.clear();
        if (this.mode === 'login') this.renderLogin();
        else if (this.mode === 'list') this.renderList();
        else if (this.mode === 'detail') this.renderDetail();
        else if (this.mode === 'form') this.renderForm();
        else if (this.mode === 'confirm') this.renderConfirm();
        s.render();
    }

    statusColor() {
        return this.statusKind === 'ok' ? C.green : this.statusKind === 'warn' ? C.amber
            : this.statusKind === 'err' ? C.red : C.dim;
    }
    titleBar(title, right) {
        const w = this.screen.cols;
        const left = ` ${style.bold}${C.green}🔐 ${title}${RESET}`;
        const r = right ? `${C.dim}${right} ${RESET}` : '';
        const pad = Math.max(0, w - UI.visLen(left) - UI.visLen(r));
        return C.barBg + UI.padEnd(left + ' '.repeat(pad) + r, w) + RESET;
    }
    footer(hints) {
        const w = this.screen.cols;
        const txt = ' ' + hints.map(([k, d]) => `${C.accent}${k}${RESET}${C.dim} ${d}${RESET}`).join(`${C.dim}  ·  ${RESET}`);
        return C.barBg + UI.padEnd(txt, w) + RESET;
    }
    statusLine() {
        const w = this.screen.cols;
        if (!this.status) return '';
        return UI.padEnd(' ' + this.statusColor() + this.status + RESET, w);
    }

    renderLogin() {
        const s = this.screen, w = s.cols, h = s.rows;
        s.line(0, this.titleBar('Password Vault', 'v6 · client-side encrypted'));
        const L = this.login;
        const box = [];
        box.push('');
        box.push(`${C.dim}Enter both master passwords to unlock the vault.${RESET}`);
        box.push('');
        const field = (label, val, focused, masked) => {
            const shown = masked && !L.reveal ? '•'.repeat(val.length) : val;
            const cursor = focused ? style.inverse + ' ' + RESET : '';
            const bar = focused ? C.accent : C.dim;
            return `${bar}${focused ? '▶ ' : '  '}${UI.padEnd(label, 20)}${RESET}${C.text}${shown}${cursor}${RESET}`;
        };
        box.push(field('Primary password', L.pw, L.focus === 0, true));
        box.push(field('Secondary password', L.pw2, L.focus === 1, true));
        box.push('');
        if (L.busy && L.progress) {
            const { done, total } = L.progress;
            box.push(`${C.amber}Decrypting names ${done}/${total}…${RESET}  ${this.bar(done, total, Math.min(40, w - 30))}`);
        } else {
            box.push(`${C.dim}Tab/↑↓ switch · Ctrl-R reveal · Enter unlock · Esc quit${RESET}`);
        }
        const top = Math.max(2, (h >> 1) - (box.length >> 1));
        const indent = Math.max(2, (w - 56) >> 1);
        box.forEach((ln, i) => s.line(top + i, ' '.repeat(indent) + ln));
        if (this.status) s.line(h - 1, this.statusLine());
    }
    bar(done, total, width) {
        const filled = total ? Math.round(width * done / total) : 0;
        return C.green + '█'.repeat(filled) + C.dim + '░'.repeat(Math.max(0, width - filled)) + RESET;
    }

    renderList() {
        const s = this.screen, w = s.cols, h = s.rows;
        const Ls = this.list;
        const total = this.vault.records.length;
        s.line(0, this.titleBar(`Vault · ${Ls.items.length}/${total}`, this.manifestBadge()));
        // search line
        if (Ls.searching || Ls.filter) {
            s.line(1, ` ${C.accent}/${RESET} ${C.text}${Ls.filter}${Ls.searching ? style.inverse + ' ' + RESET : ''}${RESET}${C.dim}  ${Ls.searching ? '(Enter to keep, Esc to clear)' : ''}${RESET}`);
        } else {
            s.line(1, `${C.dim}  ${total === 0 ? 'Vault is empty — press a to add an entry' : 'Type / to search'}${RESET}`);
        }
        s.line(2, C.dim + ' ' + '─'.repeat(Math.max(0, w - 2)) + RESET);

        // responsive grid
        const items = Ls.items;
        const gridTop = 3, gridBottom = h - 2;            // rows [gridTop, gridBottom)
        const gridH = Math.max(1, gridBottom - gridTop);
        const maxName = items.reduce((m, e) => Math.max(m, e.name.length), 8);
        const cellW = Math.min(Math.max(maxName + 3, 14), Math.max(14, w - 2));
        const cols = Math.max(1, Math.floor((w - 1) / cellW));
        Ls.cols = cols;
        const rowsNeeded = Math.ceil(items.length / cols);
        const selRow = Math.floor(Ls.sel / cols);
        // scroll window
        if (selRow < Ls.scrollRow) Ls.scrollRow = selRow;
        if (selRow >= Ls.scrollRow + gridH) Ls.scrollRow = selRow - gridH + 1;
        if (Ls.scrollRow > Math.max(0, rowsNeeded - gridH)) Ls.scrollRow = Math.max(0, rowsNeeded - gridH);
        if (Ls.scrollRow < 0) Ls.scrollRow = 0;

        for (let r = 0; r < gridH; r++) {
            const gridRow = Ls.scrollRow + r;
            let line = ' ';
            for (let c = 0; c < cols; c++) {
                const idx = gridRow * cols + c;
                if (idx >= items.length) break;
                const sel = idx === Ls.sel;
                let label = items[idx].name || '(unnamed)';
                label = ' ' + label + ' ';
                let cell = UI.truncate(label, cellW - 1);
                cell = UI.padEnd(cell, cellW - 1);
                line += sel ? (C.selBg + style.bold + C.text + cell + RESET) : (C.text + cell + RESET);
            }
            s.line(gridTop + r, line);
        }
        // scroll indicator
        if (rowsNeeded > gridH) {
            const pct = Math.round(100 * (Ls.scrollRow) / Math.max(1, rowsNeeded - gridH));
            s.line(gridBottom - 1, '');
        }
        s.line(h - 2, this.statusLine());
        s.line(h - 1, this.footer([
            ['↵', 'view'], ['a', 'add'], ['e', 'edit'], ['d', 'delete'], ['/', 'search'], ['l', 'lock'], ['q', 'quit'],
        ]));
    }

    renderDetail() {
        const s = this.screen, w = s.cols, h = s.rows;
        const e = this.detail.entry;
        s.line(0, this.titleBar('Entry', this.manifestBadge()));
        if (this.detail.busy || !e) { s.line(2, `  ${C.dim}Decrypting…${RESET}`); s.line(h - 1, this.footer([['Esc', 'back']])); return; }
        let r = 2;
        const indent = '  ';
        const row = (label, value, color) => {
            const lbl = `${C.dim}${UI.padEnd(label, 12)}${RESET}`;
            s.line(r++, indent + lbl + (color || C.text) + value + RESET);
        };
        s.line(r++, indent + style.bold + C.green + (e.name || '(unnamed)') + RESET);
        r++;
        if (e.url) row('URL', e.url, C.accent);
        if (e.username) row('Username', e.username);
        row('Password', e.password ? e.password : `${C.dim}(none)${RESET}`);
        if (e.token) {
            const otp = this.detail.otp || '------';
            const rem = this.detail.otpRemain;
            const barW = 20;
            const filled = Math.round(barW * rem / 30);
            const tbar = C.green + '█'.repeat(filled) + C.dim + '░'.repeat(barW - filled) + RESET;
            s.line(r++, indent + `${C.dim}${UI.padEnd('TOTP', 12)}${RESET}${style.bold}${C.green}${otp}${RESET}  ${tbar} ${C.dim}${rem}s${RESET}`);
        }
        if (e.notes) {
            r++;
            s.line(r++, indent + `${C.dim}Notes${RESET}`);
            const wrapW = w - 4;
            for (const ln of wrap(e.notes, wrapW)) { if (r >= h - 2) break; s.line(r++, indent + C.text + ln + RESET); }
        }
        s.line(h - 2, this.statusLine());
        s.line(h - 1, this.footer([
            ['c', 'copy pw'], ['u', 'copy user'], ...(e.token ? [['t', 'copy otp']] : []), ...(e.url ? [['o', 'open url']] : []),
            ['e', 'edit'], ['d', 'delete'], ['Esc', 'back'],
        ]));
    }

    renderForm() {
        const s = this.screen, w = s.cols, h = s.rows;
        const F = this.form;
        s.line(0, this.titleBar(F.editingRaw ? 'Edit Entry' : 'New Entry'));
        if (F.busy) { s.line(2, `  ${C.dim}Working…${RESET}`); }
        const labels = { name: 'Name *', url: 'URL', username: 'Username', password: 'Password', token: 'TOTP secret', notes: 'Notes' };
        let r = 2;
        const indent = '  ';
        F.keys.forEach((key, i) => {
            const focused = i === F.focus && !F.busy;
            const masked = (key === 'password' || key === 'token') && !F.reveal;
            let val = F.fields[key] || '';
            if (masked && val) val = '•'.repeat(val.length);
            const bar = focused ? C.accent + '▶ ' : '  ';
            const lbl = (focused ? C.accent : C.dim) + UI.padEnd(labels[key], 14) + RESET;
            const cursor = focused ? style.inverse + ' ' + RESET : '';
            const valShown = UI.truncate(C.text + val + RESET, w - 22);
            s.line(r++, indent + bar + lbl + valShown + cursor);
            r++; // spacer
        });
        s.line(h - 2, this.statusLine());
        s.line(h - 1, this.footer([
            ['Ctrl-S', 'save'], ['Tab/↑↓', 'fields'], ['Ctrl-R', 'reveal'], ['Ctrl-G', 'gen pw'], ['Esc', 'cancel'],
        ]));
    }

    renderConfirm() {
        // render the list underneath, then a centered prompt
        this.renderList();
        const s = this.screen, w = s.cols, h = s.rows;
        const msg = `Delete “${this.confirm.name}”?`;
        const sub = `${C.amber}y${RESET}${C.dim} confirm · any other key cancel${RESET}`;
        const boxW = Math.min(w - 4, Math.max(UI.visLen(msg), UI.visLen(sub)) + 6);
        const top = (h >> 1) - 2;
        const left = (w - boxW) >> 1;
        const border = C.red + '─'.repeat(boxW) + RESET;
        s.line(top, ' '.repeat(left) + C.red + '┌' + '─'.repeat(boxW - 2) + '┐' + RESET);
        s.line(top + 1, ' '.repeat(left) + C.red + '│' + RESET + UI.center(C.text + msg + RESET, boxW - 2) + C.red + '│' + RESET);
        s.line(top + 2, ' '.repeat(left) + C.red + '│' + RESET + UI.center(sub, boxW - 2) + C.red + '│' + RESET);
        s.line(top + 3, ' '.repeat(left) + C.red + '└' + '─'.repeat(boxW - 2) + '┘' + RESET);
    }
}

function wrap(text, width) {
    const out = [];
    for (const para of String(text).split('\n')) {
        if (para === '') { out.push(''); continue; }
        let line = '';
        for (const word of para.split(/\s+/)) {
            if ((line + (line ? ' ' : '') + word).length > width) {
                if (line) out.push(line);
                if (word.length > width) { for (let i = 0; i < word.length; i += width) out.push(word.slice(i, i + width)); line = ''; }
                else line = word;
            } else line += (line ? ' ' : '') + word;
        }
        if (line) out.push(line);
    }
    return out;
}

function clipboardCopy(text) {
    const tries = process.platform === 'darwin'
        ? [['pbcopy', []]]
        : [['wl-copy', []], ['xclip', ['-selection', 'clipboard']], ['xsel', ['-b', '-i']]];
    for (const [cmd, args] of tries) {
        try {
            const r = spawnSync(cmd, args, { input: text });
            if (r.status === 0 || (r.status == null && !r.error)) return true;
        } catch {}
    }
    return false;
}

module.exports = { App, wrap, clipboardCopy };

// ---- bootstrap (only when run directly) ----
if (require.main === module) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
        console.error('vault-tui must run in an interactive terminal (TTY).');
        process.exit(1);
    }
    const app = new App();
    process.on('uncaughtException', e => { app.cleanup(); console.error(e); process.exit(1); });
    app.start();
}
