// background.js — MV3 service worker: the UI / chrome.* half of the extension.
//
// In Firefox the whole extension lives in one persistent background page. Chrome
// MV3 forbids that: the background is an ephemeral service worker with no DOM and
// no Web Workers. So the work is split — the decrypted session, the Argon2id
// worker pool, DOMParser, and clipboard wiping live in the persistent OFFSCREEN
// document (offscreen.js); this service worker owns the chrome.* APIs the
// offscreen page can't touch: the toolbar action icon/badge, idle detection,
// tabs + scripting (autofill), and message routing between the popup and the
// offscreen document.
//
// Crypto/session commands from the popup are relayed to the offscreen document
// tagged { target: "offscreen" }; the offscreen page streams unlock progress
// back, which this worker turns into the animated toolbar icon.

"use strict";

var LOCK_IDLE_SECS = 5 * 60; // lock after 5 minutes of true system idle

// The service worker can be killed and respawned at any time, losing its locals.
// chrome.storage.session is in-memory only (never written to disk, cleared when
// the browser closes), so it is the right place to mirror the lock state + match
// hosts so the icon/badges are correct after a respawn WITHOUT forcing the
// offscreen document open. The offscreen document remains the authority and is
// queried for the real state on every popup open ("status").
var _unlocked = false;
var _matchHosts = []; // entry URLs, for the per-tab ✓ match badge
var _autoLock = true;

// ============================================================
// Offscreen document lifecycle
// ============================================================
var OFFSCREEN_URL = "offscreen.html";
var _creatingOffscreen = null;

async function _hasOffscreen() {
  try {
    if (chrome.offscreen && chrome.offscreen.hasDocument) return await chrome.offscreen.hasDocument();
  } catch (e) {}
  // Fallback for older builds: look for the offscreen client among extension contexts.
  try {
    var ctxs = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    return ctxs && ctxs.length > 0;
  } catch (e) {}
  return false;
}

async function ensureOffscreen() {
  if (await _hasOffscreen()) return;
  if (_creatingOffscreen) { await _creatingOffscreen; return; }
  _creatingOffscreen = chrome.offscreen.createDocument({
    url: OFFSCREEN_URL,
    reasons: ["WORKERS", "DOM_PARSER", "CLIPBOARD"],
    justification:
      "Hold the unlocked vault session in memory, run the Argon2id worker pool, parse the vault index, and clear copied secrets from the clipboard.",
  });
  try {
    await _creatingOffscreen;
  } catch (e) {
    // A racing createDocument may report "already exists" — treat as success.
    if (!/exist/i.test(String((e && e.message) || e))) throw e;
  } finally {
    _creatingOffscreen = null;
  }
}

// Relay a command to the offscreen document and return its response.
async function toOffscreen(msg) {
  await ensureOffscreen();
  return chrome.runtime.sendMessage(Object.assign({ target: "offscreen" }, msg));
}

// ============================================================
// Toolbar icon (OffscreenCanvas — no DOM in a service worker)
// ============================================================
var BADGE_GREEN = "#3fcf8e";
var BADGE_RED = "#c0392b"; // muted brick red (icon glyph — less bright than the popup's)
// Chrome ignores a fully-transparent badge background (it falls back to its
// default red), so use an explicit dark chip behind the green ✓ instead.
var BADGE_BG = "#1a1d24";

var _bmpColor = null;   // color (unlocked)
var _bmpMono = null;    // grayscale (locked)
var _bmpReady = false;

async function _loadBitmaps() {
  if (_bmpReady) return;
  try {
    var res = await Promise.all([
      fetch(chrome.runtime.getURL("icons/icon-96.png")).then(function (r) { return r.blob(); }),
      fetch(chrome.runtime.getURL("icons/icon-96-mono.png")).then(function (r) { return r.blob(); }),
    ]);
    var bmps = await Promise.all([createImageBitmap(res[0]), createImageBitmap(res[1])]);
    _bmpColor = bmps[0];
    _bmpMono = bmps[1];
    _bmpReady = true;
    _refreshIcons(); // re-apply now that compositing is possible
  } catch (e) {}
}

// One-time badge defaults: a dark chip behind the green ✓.
try { chrome.action.setBadgeBackgroundColor({ color: BADGE_BG }); } catch (e) {}
try { chrome.action.setBadgeTextColor({ color: BADGE_GREEN }); } catch (e) {}

// Toolbar icon: monochrome while locked, full-color once unlocked. When auto-lock
// is disabled, a red stopwatch glyph is composited on top to warn that the vault
// won't time out (needs the base bitmap), falling back to the plain path icons
// until the bitmaps have loaded.
function _setIcon(unlocked) {
  try {
    if (!_autoLock && _bmpReady) {
      chrome.action.setIcon({
        imageData: { 16: _iconImageData(16, unlocked, true), 32: _iconImageData(32, unlocked, true) },
      });
    } else {
      chrome.action.setIcon({
        path: unlocked
          ? { 48: "icons/icon-48.png", 96: "icons/icon-96.png" }
          : { 48: "icons/icon-48-mono.png", 96: "icons/icon-96-mono.png" },
      });
    }
  } catch (e) {}
}

// Re-apply the global icon + every per-tab badge (after a lock-state or
// auto-lock-setting change, or once the base bitmaps load).
function _refreshIcons() {
  _setIcon(_unlocked);
  _refreshAllBadges();
}

// Small red stopwatch tucked into the upper-LEFT corner — warns that auto-lock is
// disabled. Kept small and off-center so it never covers the central key (the ✓
// match indicator is a native badge in the opposite, lower-right corner).
function _drawTimerGlyph(x, size) {
  var r = size * 0.17;
  var gx = r + size * 0.05; // inset from the left edge
  var gy = r + size * 0.06; // inset from the top edge
  x.save();
  x.shadowColor = "rgba(0,0,0,0.55)";
  x.shadowBlur = Math.max(1, size * 0.06);
  x.fillStyle = BADGE_RED;
  // top button/stem
  x.fillRect(gx - size * 0.028, gy - r - size * 0.06, size * 0.056, size * 0.06);
  // filled red clock face
  x.beginPath();
  x.arc(gx, gy, r, 0, Math.PI * 2);
  x.fill();
  // white hands (no shadow so they stay crisp)
  x.shadowBlur = 0;
  x.strokeStyle = "#fff";
  x.lineWidth = Math.max(1, size * 0.045);
  x.lineCap = "round";
  x.beginPath();
  x.moveTo(gx, gy);
  x.lineTo(gx, gy - r * 0.55); // minute hand (up)
  x.moveTo(gx, gy);
  x.lineTo(gx + r * 0.45, gy); // hour hand (right)
  x.stroke();
  x.restore();
}

// Composite the base bitmap (color/mono) with the optional red-timer glyph into
// ImageData for chrome.action.setIcon. (The green ✓ is a native badge.)
function _iconImageData(size, unlocked, withTimer) {
  var c = new OffscreenCanvas(size, size);
  var x = c.getContext("2d");
  var base = unlocked ? _bmpColor : _bmpMono;
  if (base) x.drawImage(base, 0, 0, size, size);
  if (withTimer) _drawTimerGlyph(x, size);
  return x.getImageData(0, 0, size, size);
}

function _anyMatch(host) {
  if (!_unlocked || !host) return false;
  return _matchHosts.some(function (u) { return _hostMatch(u, host); });
}

// Per-tab site-match indicator: a green ✓ native badge when the tab's site
// matches a stored entry, cleared otherwise.
function _updateBadge(tabId, url) {
  try {
    var matched = _anyMatch(_hostOf(url || ""));
    chrome.action.setBadgeText({ tabId: tabId, text: matched ? "✓" : "" });
  } catch (e) {}
}

function _refreshAllBadges() {
  try {
    chrome.tabs.query({}, function (tabs) {
      if (!tabs) return;
      tabs.forEach(function (t) { _updateBadge(t.id, t.url); });
    });
  } catch (e) {}
}

chrome.tabs.onActivated.addListener(function (info) {
  chrome.tabs.get(info.tabId, function (t) {
    if (chrome.runtime.lastError || !t) return;
    _updateBadge(t.id, t.url);
  });
});
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" || changeInfo.url) _updateBadge(tabId, tab.url);
});

// ---- Animated toolbar icon while decrypting ----
// The toolbar icon is redrawn every ~120ms: a rotating green arc (a progress ring
// once we know the record count) around a wiggling 🔑, so the icon itself visibly
// works during the decrypt. The active unlock keeps the service worker alive.
var _animTimer = null;
var _animFrame = 0;
var _unlockProgress = { done: 0, total: 0 };

function _drawIcon(size, frame, prog) {
  var c = new OffscreenCanvas(size, size);
  var x = c.getContext("2d");
  var cx = size / 2,
    cy = size / 2,
    r = size * 0.4;
  x.clearRect(0, 0, size, size);
  // track ring
  x.lineWidth = Math.max(2, size * 0.09);
  x.lineCap = "round";
  x.strokeStyle = "rgba(255,255,255,0.18)";
  x.beginPath();
  x.arc(cx, cy, r, 0, Math.PI * 2);
  x.stroke();
  // progress / spinner arc
  x.strokeStyle = "#3fcf8e";
  var start = -Math.PI / 2;
  if (prog.total > 0) {
    var frac = prog.done / prog.total;
    var spin = frame * 0.25; // keep moving between discrete record steps
    x.beginPath();
    x.arc(cx, cy, r, start + spin, start + spin + Math.max(0.2, frac * Math.PI * 2));
    x.stroke();
  } else {
    var a = frame * 0.5;
    x.beginPath();
    x.arc(cx, cy, r, a, a + Math.PI * 0.6);
    x.stroke();
  }
  // key glyph, gentle wiggle
  x.save();
  x.translate(cx, cy);
  x.rotate(Math.sin(frame * 0.6) * 0.35);
  x.font = size * 0.5 + "px serif";
  x.textAlign = "center";
  x.textBaseline = "middle";
  x.fillText("🔑", 0, 0);
  x.restore();
  return x.getImageData(0, 0, size, size);
}

function _animTick() {
  _animFrame++;
  try {
    chrome.action.setIcon({
      imageData: { 16: _drawIcon(16, _animFrame, _unlockProgress), 32: _drawIcon(32, _animFrame, _unlockProgress) },
    });
  } catch (e) {}
}

function _startIconAnim() {
  _unlockProgress = { done: 0, total: 0 };
  _animFrame = 0;
  if (_animTimer) clearInterval(_animTimer);
  _animTick();
  _animTimer = setInterval(_animTick, 120);
}

function _stopIconAnim() {
  if (_animTimer) {
    clearInterval(_animTimer);
    _animTimer = null;
  }
  _setIcon(_unlocked); // restore static color (unlocked) / mono (locked)
}

// ============================================================
// hostname matcher (mirrors offscreen.js / content.js)
// ============================================================
function _hostOf(u) {
  try {
    return new URL(/^[a-z]+:\/\//i.test(u) ? u : "https://" + u)
      .hostname.toLowerCase().replace(/^www\./, "");
  } catch (e) {
    return "";
  }
}
// Public-suffix / multi-tenant-host guard (mirrors offscreen.js / content.js) so
// the ✓ match badge never lights up across unrelated sites that merely share a
// public suffix or hosting domain.
var _PUBLIC_SUFFIXES = {
  "co.uk": 1, "org.uk": 1, "gov.uk": 1, "ac.uk": 1, "com.au": 1, "net.au": 1,
  "org.au": 1, "co.nz": 1, "co.jp": 1, "co.kr": 1, "com.br": 1, "com.cn": 1,
  "co.in": 1, "co.za": 1,
  "github.io": 1, "gitlab.io": 1, "web.app": 1, "firebaseapp.com": 1,
  "glitch.me": 1, "herokuapp.com": 1, "vercel.app": 1, "netlify.app": 1,
  "pages.dev": 1, "workers.dev": 1, "azurewebsites.net": 1, "cloudfront.net": 1,
  "appspot.com": 1, "repl.co": 1, "surge.sh": 1, "now.sh": 1,
};
function _isPubSuffix(h) {
  return !h || h.indexOf(".") < 0 || !!_PUBLIC_SUFFIXES[h];
}
function _hostMatch(entryUrl, tabHost) {
  var eh = _hostOf(entryUrl);
  if (!eh || !tabHost) return false;
  if (eh === tabHost) return true;
  if (tabHost.endsWith("." + eh) && !_isPubSuffix(eh)) return true;
  if (eh.endsWith("." + tabHost) && !_isPubSuffix(tabHost)) return true;
  return false;
}

// ============================================================
// Lock-state persistence across service-worker restarts
// ============================================================
function _persistState() {
  try {
    chrome.storage.session.set({ unlocked: _unlocked, matchHosts: _matchHosts });
  } catch (e) {}
}

async function _restoreState() {
  try {
    var s = await chrome.storage.session.get(["unlocked", "matchHosts"]);
    _unlocked = !!(s && s.unlocked);
    _matchHosts = (s && s.matchHosts) || [];
  } catch (e) {}
  try {
    var l = await chrome.storage.local.get("autoLock");
    if (l && typeof l.autoLock === "boolean") _autoLock = l.autoLock;
  } catch (e) {}
  await _loadBitmaps();
  _refreshIcons();
}

// ============================================================
// idle / auto-lock
// ============================================================
try { chrome.idle.setDetectionInterval(LOCK_IDLE_SECS); } catch (e) {}
try {
  chrome.idle.onStateChanged.addListener(function (state) {
    if ((state === "idle" || state === "locked") && _autoLock) lock();
  });
} catch (e) {}

// Auto-lock preference (checkbox in the About modal = "disabled"), kept in sync
// so the idle handler + icon read it synchronously.
try {
  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area === "local" && changes.autoLock) {
      _autoLock = changes.autoLock.newValue !== false;
      _refreshIcons(); // add/remove the red timer glyph on every tab
    }
  });
} catch (e) {}

// ============================================================
// lock / fill
// ============================================================
async function lock() {
  await toOffscreen({ cmd: "lock" });
  _unlocked = false;
  _matchHosts = [];
  _persistState();
  _setIcon(false);
  _refreshAllBadges(); // clears ✓ everywhere (no matches while locked)
}

// Inject the fill into the active tab. The content script is programmatically
// executed so no broad content_scripts registration is needed. Wait until the
// tab reports "complete" (a just-opened/navigating tab isn't injectable yet),
// bounded by a timeout so we never hang.
async function _waitForTabComplete(tabId, timeoutMs) {
  var deadline = Date.now() + (timeoutMs || 5000);
  while (Date.now() < deadline) {
    try {
      var t = await chrome.tabs.get(tabId);
      if (!t) return;
      if (t.status === "complete") return;
    } catch (e) {
      return; // tab gone — let the inject attempt surface the real error
    }
    await new Promise(function (r) { setTimeout(r, 150); });
  }
}

async function fillTab(tabId, username, password, entryUrl) {
  // The target tab (e.g. one just opened via the entry's URL link) may still be
  // loading. Wait for it to finish, then inject + message with a few retries to
  // ride out transient injection failures during navigation. `entryUrl` rides
  // along so each injected frame can gate filling on its own origin matching the
  // entry (see content.js _fillAllowed).
  await _waitForTabComplete(tabId, 5000);
  var lastErr;
  for (var i = 0; i < 4; i++) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId, allFrames: true },
        files: ["content.js"],
      });
      return await chrome.tabs.sendMessage(tabId, {
        cmd: "doFill",
        username: username,
        password: password,
        entryUrl: entryUrl,
      });
    } catch (e) {
      lastErr = e;
      await new Promise(function (r) { setTimeout(r, 250); });
    }
  }
  throw lastErr;
}

// ============================================================
// Passkey ceremonies (content script port → service worker → offscreen)
// ============================================================
// The MAIN-world interceptor relays navigator.credentials.create/get through the
// ISOLATED bridge, which opens a "passkey" Port to here (an open port keeps this
// worker alive across the approval window). Create always prompts (master + write
// passwords) in an approval window; get signs silently when unlocked, or prompts
// an unlock when locked. The offscreen document holds the session + does crypto.

var _pendingApprovals = {}; // id -> { mode, origin, options, rpId, rpName, vaultUrl, port, windowId, handled }

async function _getVaultUrl() {
  try { var s = await chrome.storage.local.get("vaultUrl"); return (s && s.vaultUrl) || ""; }
  catch (e) { return ""; }
}

async function _openApproval(info) {
  var id = "ap" + Date.now() + "-" + Math.random().toString(36).slice(2);
  info.id = id;
  info.handled = false;
  _pendingApprovals[id] = info;
  try {
    var w = await chrome.windows.create({
      url: chrome.runtime.getURL("approve.html?id=" + id),
      type: "popup",
      width: 400,
      // Approximate per-mode content height; approve.js shrinks the window to an
      // exact fit once the visible fields render, so these only minimize flash.
      height: info.mode === "create" ? 470 : info.mode === "confirm" ? 210 : 300,
      focused: true,
    });
    info.windowId = w && w.id;
  } catch (e) {
    _finishApproval(id, { error: "Could not open the approval window" });
  }
}

// Deliver a result to the waiting content-script port and tear down the window.
// Idempotent per id.
function _finishApproval(id, result) {
  var info = _pendingApprovals[id];
  if (!info || info.handled) return;
  info.handled = true;
  delete _pendingApprovals[id];
  try { if (info.port) info.port.postMessage(result); } catch (e) {}
  if (info.windowId != null) { try { chrome.windows.remove(info.windowId); } catch (e) {} }
}

async function handlePasskeyPort(port, msg) {
  try {
    var vaultUrl = await _getVaultUrl();
    if (!vaultUrl) { port.postMessage({ error: "Set the vault URL in the extension first" }); return; }

    if (msg.cmd === "passkey-get") {
      var pre = await toOffscreen({ cmd: "passkey-precheck", options: msg.options, origin: msg.origin });
      if (pre && pre.unlocked) {
        if (!pre.match) { port.postMessage({ passthrough: true }); return; }
        // Require a per-assertion user gesture (WebAuthn user presence) even when
        // unlocked — open a lightweight confirm window instead of signing silently
        // so on-origin scripts can't authenticate as the user without consent.
        _openApproval({
          mode: "confirm", origin: msg.origin, options: msg.options,
          rpId: (msg.options && msg.options.rpId) || "", rpName: "", vaultUrl: vaultUrl, port: port,
        });
        return;
      }
      // Locked: prompt an unlock, then sign (handled in approval-submit).
      _openApproval({
        mode: "unlock", origin: msg.origin, options: msg.options,
        rpId: (msg.options && msg.options.rpId) || "", rpName: "", vaultUrl: vaultUrl, port: port,
      });
      return;
    }

    if (msg.cmd === "passkey-create") {
      var rp = (msg.options && msg.options.rp) || {};
      _openApproval({
        mode: "create", origin: msg.origin, options: msg.options,
        rpId: rp.id || "", rpName: rp.name || rp.id || "", vaultUrl: vaultUrl, port: port,
      });
      return;
    }

    port.postMessage({ error: "unknown passkey command" });
  } catch (e) {
    try { port.postMessage({ error: String((e && e.message) || e) }); } catch (_) {}
  }
}

chrome.runtime.onConnect.addListener(function (port) {
  if (!port || port.name !== "passkey") return;
  port.onMessage.addListener(function (msg) { if (msg && msg.cmd) handlePasskeyPort(port, msg); });
});

// A user who closes the approval window without deciding cancels the ceremony.
chrome.windows.onRemoved.addListener(function (winId) {
  Object.keys(_pendingApprovals).forEach(function (id) {
    var info = _pendingApprovals[id];
    if (info && info.windowId === winId && !info.handled) _finishApproval(id, { error: "User cancelled" });
  });
});

// ============================================================
// message routing (popup → service worker → offscreen)
// ============================================================
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg) return;
  if (msg.target === "offscreen") return; // handled by the offscreen document
  if (msg.cmd === "unlockProgress") {
    // Streamed from the offscreen page during decrypt — feeds the icon animation.
    _unlockProgress = { done: msg.done, total: msg.total };
    return; // (the popup also listens; nothing to respond)
  }

  (async function () {
    try {
      if (msg.cmd === "status") {
        var r = await toOffscreen({ cmd: "status" });
        _unlocked = !!(r && r.unlocked);
        _matchHosts = (r && r.hosts) || [];
        _persistState();
        _setIcon(_unlocked);
        _refreshAllBadges();
        return {
          unlocked: _unlocked,
          count: (r && r.count) || 0,
          vaultUrl: (r && r.vaultUrl) || "",
        };
      }
      if (msg.cmd === "unlock") {
        _startIconAnim();
        try {
          var u = await toOffscreen({ cmd: "unlock", vaultUrl: msg.vaultUrl, pw: msg.pw, pw2: msg.pw2 });
          if (u && u.ok) {
            _unlocked = true;
            _matchHosts = u.hosts || [];
            _persistState();
            _setIcon(true);
            _refreshAllBadges(); // mark tabs whose site now matches a stored entry
          }
          return u;
        } finally {
          _stopIconAnim();
        }
      }
      if (msg.cmd === "lock") {
        await lock();
        return { ok: true };
      }
      if (msg.cmd === "abort") {
        _stopIconAnim();
        _unlockProgress = { done: 0, total: 0 };
        await toOffscreen({ cmd: "abort" });
        return { ok: true };
      }
      if (msg.cmd === "clipDirty") {
        return await toOffscreen({ cmd: "clipDirty" });
      }
      if (msg.cmd === "fill") {
        var d = await toOffscreen({ cmd: "fillData", id: msg.id });
        if (!d || d.error) return d || { error: "locked" };
        var fr = await fillTab(msg.tabId, d.username, d.password, d.url);
        return { ok: !!(fr && fr.ok), filled: fr && fr.filled };
      }
      // match / reveal / details / totp — pure session reads, answered by the
      // offscreen document (which holds the decrypted entries).
      if (msg.cmd === "match" || msg.cmd === "reveal" || msg.cmd === "details" || msg.cmd === "totp") {
        return await toOffscreen(msg);
      }
      // ---- passkey approval window <-> background ----
      if (msg.cmd === "approval-info") {
        var info = _pendingApprovals[msg.id];
        if (!info) return { ok: false };
        return {
          ok: true, mode: info.mode, rpId: info.rpId, rpName: info.rpName,
          origin: info.origin, vaultUrl: info.vaultUrl, writeUser: "pass",
        };
      }
      if (msg.cmd === "approval-candidates") {
        // Existing-entry list for the create approval window's attach picker.
        // Requires an unlocked session (the window unlocks first). Entries whose
        // url matches the rpId host are flagged so the window can surface them.
        var apc = _pendingApprovals[msg.id];
        if (!apc) return { ok: false, entries: [] };
        var rpHost = (apc.rpId || "").toLowerCase();
        if (!rpHost) { try { rpHost = new URL(apc.origin).hostname.toLowerCase().replace(/^www\./, ""); } catch (e) { rpHost = ""; } }
        var mc = await toOffscreen({ cmd: "match", host: rpHost });
        return { ok: true, entries: (mc && mc.entries) || [] };
      }
      if (msg.cmd === "approval-submit") {
        var ap = _pendingApprovals[msg.id];
        if (!ap) return { ok: false, error: "This request expired" };
        var r = msg.result || {};
        if (!r.ok) {
          // "Use this device instead" → let the page fall back to the native
          // authenticator; a plain Deny cancels the ceremony.
          _finishApproval(msg.id, r.native ? { passthrough: true } : { error: "User denied" });
          return { ok: true };
        }

        if (ap.mode === "confirm") {
          // Session already unlocked; Allow is the user-presence gesture → sign.
          var gotc = await toOffscreen({ cmd: "passkey-get", options: ap.options, origin: ap.origin });
          _finishApproval(msg.id, gotc);
          return { ok: true };
        }

        if (ap.mode === "unlock") {
          // approve.js already unlocked the session; precheck + sign now.
          var pre = await toOffscreen({ cmd: "passkey-precheck", options: ap.options, origin: ap.origin });
          if (!pre || !pre.unlocked) return { ok: false, error: "Unlock failed" };
          // Mirror the unlock into the worker's lock-state/icon.
          var st = await toOffscreen({ cmd: "status" });
          if (st && st.unlocked) { _unlocked = true; _matchHosts = st.hosts || []; _persistState(); _setIcon(true); _refreshAllBadges(); }
          var got = pre.match
            ? await toOffscreen({ cmd: "passkey-get", options: ap.options, origin: ap.origin })
            : { passthrough: true };
          _finishApproval(msg.id, got);
          return { ok: true };
        }

        // create: do the offscreen create + vault write now so we can report
        // success/failure back to the window (and keep it open to retry on error).
        var res = await toOffscreen({
          cmd: "passkey-create", options: ap.options, origin: ap.origin,
          pw: r.pw, pw2: r.pw2, writeUser: r.writeUser, writePass: r.writePass, vaultUrl: ap.vaultUrl,
          targetId: (r.targetId == null ? null : r.targetId),
        });
        if (res && res.ok) {
          // The new entry may now be in the session — refresh match hosts/icon.
          try {
            var s2 = await toOffscreen({ cmd: "status" });
            if (s2 && s2.unlocked) { _matchHosts = s2.hosts || []; _persistState(); _refreshAllBadges(); }
          } catch (e) {}
          _finishApproval(msg.id, res);
          return { ok: true };
        }
        return { ok: false, error: (res && res.error) || "Passkey creation failed" };
      }
      return { error: "unknown cmd" };
    } catch (e) {
      return { error: String((e && e.message) || e) };
    }
  })().then(sendResponse);
  return true; // async response
});

// Restore the mirrored state + icon whenever the service worker (re)starts.
_restoreState();
chrome.runtime.onStartup.addListener(_restoreState);
chrome.runtime.onInstalled.addListener(_restoreState);
