'use strict';
// ============================================================
// ui.js — dependency-free ANSI terminal primitives:
//   - alt-screen / cursor control, SGR colour helpers
//   - a double-buffered screen that diffs lines (flicker-free, fits any size)
//   - raw-mode key parser (arrows, tab, enter, ctrl-keys, printable)
//   - resize handling
// ============================================================

const ESC = '\x1b';
const CSI = ESC + '[';

// ---- Raw control sequences ----
const ALT_ON = CSI + '?1049h';
const ALT_OFF = CSI + '?1049l';
const CURSOR_HIDE = CSI + '?25l';
const CURSOR_SHOW = CSI + '?25h';
const CLEAR = CSI + '2J' + CSI + 'H';
const at = (row, col) => CSI + (row + 1) + ';' + (col + 1) + 'H';   // 0-based in, 1-based out

// ---- SGR colours ----
const SGR = c => CSI + c + 'm';
const RESET = SGR(0);
const style = {
    reset: RESET, bold: SGR(1), dim: SGR(2), italic: SGR(3), underline: SGR(4),
    inverse: SGR(7),
    fg: (r, g, b) => CSI + '38;2;' + r + ';' + g + ';' + b + 'm',
    bg: (r, g, b) => CSI + '48;2;' + r + ';' + g + ';' + b + 'm',
};
// Palette tuned to the web app (teal accents, blue links, amber warn).
const C = {
    green: style.fg(63, 207, 142),
    accent: style.fg(77, 142, 255),
    amber: style.fg(240, 180, 70),
    red: style.fg(235, 90, 90),
    dim: style.fg(130, 140, 150),
    text: style.fg(220, 225, 230),
    selBg: style.bg(40, 70, 120),
    barBg: style.bg(28, 34, 44),
};

// Strip ANSI for width math.
const reAnsi = /\x1b\[[0-9;]*m/g;
function visLen(s) { return s.replace(reAnsi, '').length; }

// Truncate a (possibly styled) string to `w` visible columns, ellipsis-aware.
function truncate(s, w) {
    if (visLen(s) <= w) return s;
    let out = '', vis = 0;
    const max = Math.max(0, w - 1);
    for (let i = 0; i < s.length;) {
        if (s[i] === '\x1b') { const m = s.slice(i).match(/^\x1b\[[0-9;]*m/); if (m) { out += m[0]; i += m[0].length; continue; } }
        if (vis >= max) break;
        out += s[i]; vis++; i++;
    }
    return out + '…' + RESET;
}
function padEnd(s, w) { const d = w - visLen(s); return d > 0 ? s + ' '.repeat(d) : s; }
function center(s, w) { const d = w - visLen(s); if (d <= 0) return s; const l = d >> 1; return ' '.repeat(l) + s + ' '.repeat(d - l); }

// ============================================================
// Screen — a line buffer the size of the terminal; render() diffs vs the last
// frame and only repaints changed rows. Resizes with the terminal.
// ============================================================
class Screen {
    constructor() {
        this.out = process.stdout;
        this.prev = [];
        this.resize();
    }
    resize() {
        this.cols = this.out.columns || 80;
        this.rows = this.out.rows || 24;
        this.prev = [];                       // force full repaint after a resize
        this.buf = new Array(this.rows).fill('');
    }
    clear() { this.buf = new Array(this.rows).fill(''); }
    // Set the full styled content of a row (callers compose whole lines).
    line(row, text) { if (row >= 0 && row < this.rows) this.buf[row] = text; }
    render() {
        let frame = '';
        for (let r = 0; r < this.rows; r++) {
            const cur = this.buf[r] || '';
            if (this.prev[r] !== cur) {
                frame += at(r, 0) + CSI + '2K' + cur + RESET;
                this.prev[r] = cur;
            }
        }
        if (frame) this.out.write(frame);
    }
    full() { this.prev = []; }
}

// ============================================================
// Lifecycle
// ============================================================
function enter() {
    process.stdout.write(ALT_ON + CURSOR_HIDE + CLEAR);
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
}
function leave() {
    if (process.stdin.isTTY) { try { process.stdin.setRawMode(false); } catch {} }
    process.stdout.write(CURSOR_SHOW + ALT_OFF);
    process.stdin.pause();
}

// ============================================================
// Key parser — turns a raw stdin chunk into one key event.
// Returns { name, ctrl, shift, ch }.
// ============================================================
function parseKey(s) {
    if (s === '\r' || s === '\n') return { name: 'enter' };
    if (s === '\t') return { name: 'tab' };
    if (s === ESC + '[Z') return { name: 'tab', shift: true };
    if (s === '\x7f' || s === '\b') return { name: 'backspace' };
    if (s === ESC) return { name: 'escape' };
    if (s === '\x03') return { name: 'c', ctrl: true };
    // CSI sequences
    if (s.startsWith(ESC + '[') || s.startsWith(ESC + 'O')) {
        const code = s.slice(2);
        const map = { A: 'up', B: 'down', C: 'right', D: 'left', H: 'home', F: 'end',
            '5~': 'pageup', '6~': 'pagedown', '3~': 'delete', '1~': 'home', '4~': 'end' };
        if (map[code]) return { name: map[code] };
        return { name: 'unknown' };
    }
    // Ctrl-letter (1..26), excluding the ones handled above
    if (s.length === 1) {
        const code = s.charCodeAt(0);
        if (code >= 1 && code <= 26) return { name: String.fromCharCode(96 + code), ctrl: true };
        return { name: s, ch: s };
    }
    return { name: 'unknown', ch: s };
}

// Subscribe to keys. Returns an unsubscribe fn. Calls onKey(key) per event.
function onKeys(onKey) {
    const handler = chunk => {
        const s = chunk.toString('utf8');
        // A pasted/multi-byte chunk may carry several events; split on ESC boundaries.
        if (s.length > 1 && !s.startsWith(ESC)) {
            // Treat as a run of printable chars (e.g. fast typing / paste).
            for (const ch of s) onKey(parseKey(ch));
            return;
        }
        onKey(parseKey(s));
    };
    process.stdin.on('data', handler);
    return () => process.stdin.off('data', handler);
}

module.exports = {
    ESC, CSI, CLEAR, at, style, C, RESET,
    visLen, truncate, padEnd, center,
    Screen, enter, leave, parseKey, onKeys,
};
