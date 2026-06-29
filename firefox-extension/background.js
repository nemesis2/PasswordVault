// background.js — Firefox MV2 persistent background page: the UI half + session host.
//
// The decrypted SESSION, the v6 unlock/decrypt loop, the clipboard auto-clear, the
// hostname matcher, the WebAuthn passkey ceremonies, and the crypto self-test all
// live in vault-session.js, loaded before this file and shared verbatim with the
// Chrome offscreen document. This page owns the Firefox-specific pieces that have
// no Chrome counterpart in the same context: the toolbar action icon/badge, idle
// auto-lock, tab autofill, the passkey approval-window plumbing, and the popup
// message handler. It supplies the few host hooks vault-session.js calls
// (_progress, the unlock/abortUnlock/lock wrappers, _onSelftestFail).

"use strict";

var api = typeof browser !== "undefined" ? browser : chrome;

var LOCK_IDLE_SECS = 5 * 60; // lock after 5 minutes of true system idle

// Auto-lock on idle is on by default; the About modal can disable it (persisted
// in storage.local under "autoLock"). Cached here and kept in sync via
// storage.onChanged so the idle handler reads it synchronously.
var _autoLock = true;
try {
  api.storage.local.get("autoLock").then(function (s) {
    if (s && typeof s.autoLock === "boolean") _autoLock = s.autoLock;
    _refreshIcons(); // reflect a stored "disabled" on startup (red timer glyph)
  });
} catch (e) {}
try {
  api.storage.onChanged.addListener(function (changes, area) {
    if (area === "local" && changes.autoLock) {
      _autoLock = changes.autoLock.newValue !== false;
      _refreshIcons(); // add/remove the red timer glyph on every tab
    }
  });
} catch (e) {}

// True system-idle detection: lock when the OS reports no input for the interval
// (or the screen is locked) — independent of popup activity.
try {
  api.idle.setDetectionInterval(LOCK_IDLE_SECS);
  api.idle.onStateChanged.addListener(function (state) {
    if ((state === "idle" || state === "locked") && SESSION.unlocked && _autoLock) lock();
  });
} catch (e) {}

// Toolbar icon: monochrome (grayscale) while locked, full-color once unlocked.
// When auto-lock is disabled, a red stopwatch glyph is composited on top to warn
// that the vault won't time out — this needs the base image (canvas), so it
// falls back to the plain path until the image has loaded.
function _setIcon(unlocked) {
  try {
    var base = unlocked ? _baseImg : _baseImgMono;
    if (!_autoLock && base && base.complete && base.naturalWidth) {
      api.browserAction.setIcon({
        imageData: { 16: _iconImageData(16, unlocked, true), 32: _iconImageData(32, unlocked, true) },
      });
    } else {
      api.browserAction.setIcon({
        path: unlocked
          ? { 48: "icons/icon-48.png", 96: "icons/icon-96.png" }
          : { 48: "icons/icon-48-mono.png", 96: "icons/icon-96-mono.png" },
      });
    }
  } catch (e) {}
}
_setIcon(false);

// Per-tab badge: a green ✓ over the toolbar icon when the tab's site matches a
// stored entry. Only meaningful while unlocked.
// Match indicator: a plain green check-mark drawn *onto* the toolbar icon for
// tabs whose site matches a stored entry (per-tab icon override) — no badge box
// or border, just the check composited over the icon.
var BADGE_GREEN = "#3fcf8e";
var BADGE_RED = "#c0392b"; // muted brick red (icon glyph — less bright than the popup's)

// The site-match indicator is a native browser badge (a green ✓ the browser
// draws in the icon corner) rather than painting onto the icon — so it never
// collides with the timer glyph and needs no per-tab icon override. The badge
// background is transparent (RGBA alpha 0) so just the green ✓ shows over the
// icon. Colors are a one-time global default.
try { api.browserAction.setBadgeBackgroundColor({ color: [0, 0, 0, 0] }); } catch (e) {}
try { api.browserAction.setBadgeTextColor({ color: BADGE_GREEN }); } catch (e) {}

// Preload both base icons (color + grayscale) so glyphs can be composited over
// whichever matches the lock state. Re-apply the icon once they finish loading
// (the first _setIcon runs before the images are ready).
var _baseImg = new Image();      // color (unlocked)
var _baseImgMono = new Image();  // grayscale (locked)
try { _baseImg.src = api.runtime.getURL("icons/icon-96.png"); } catch (e) {}
try { _baseImgMono.src = api.runtime.getURL("icons/icon-96-mono.png"); } catch (e) {}
_baseImg.onload = _baseImgMono.onload = function () { _refreshIcons(); };

// Re-apply the global icon + every per-tab badge (after a lock-state or
// auto-lock-setting change, or once the base images load).
function _refreshIcons() {
  _setIcon(SESSION.unlocked);
  _refreshAllBadges();
}

function _anyMatch(host) {
  if (!SESSION.unlocked || !host) return false;
  return SESSION.entries.some(function (e) {
    return _hostMatch(e.url, host);
  });
}

// Small red stopwatch tucked into the upper-LEFT corner — warns that auto-lock
// is disabled. Kept small and off-center so it never covers the central key
// (the ✓ match indicator is a native badge in the opposite, lower-right corner).
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

// Composite the base icon (color/mono) with the optional red-timer glyph into
// ImageData for browserAction.setIcon. (The green ✓ is a native badge, not drawn
// here.)
function _iconImageData(size, unlocked, withTimer) {
  var c = document.createElement("canvas");
  c.width = size;
  c.height = size;
  var x = c.getContext("2d");
  var base = unlocked ? _baseImg : _baseImgMono;
  if (base && base.complete && base.naturalWidth) x.drawImage(base, 0, 0, size, size);
  if (withTimer) _drawTimerGlyph(x, size);
  return x.getImageData(0, 0, size, size);
}

// Per-tab site-match indicator: a green ✓ native badge when the tab's site
// matches a stored entry, cleared otherwise. Independent of the icon, so it
// never fights the global icon / decode animation.
function _updateBadge(tabId, url) {
  try {
    if (SESSION.integrityFailed) {
      api.browserAction.setBadgeText({ tabId: tabId, text: "✗" });
    } else {
      var matched = _anyMatch(_hostOf(url || ""));
      api.browserAction.setBadgeText({ tabId: tabId, text: matched ? "✓" : "" });
    }
  } catch (e) {}
}

// Re-evaluate every open tab (after unlock) or clear them all (on lock).
function _refreshAllBadges() {
  try {
    api.tabs.query({}).then(function (tabs) {
      tabs.forEach(function (t) {
        _updateBadge(t.id, t.url);
      });
    });
  } catch (e) {}
}

api.tabs.onActivated.addListener(function (info) {
  api.tabs.get(info.tabId).then(function (t) {
    _updateBadge(t.id, t.url);
  }).catch(function () {});
});
api.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" || changeInfo.url) _updateBadge(tabId, tab.url);
});

// ---- Animated toolbar icon while decrypting ----
// The toolbar icon is redrawn on a canvas every ~120ms: a rotating green arc
// (a progress ring once we know the record count) around a wiggling 🔑, so the
// icon itself visibly works during the (slow, single-threaded) decrypt.
var _animTimer = null;
var _animFrame = 0;
var _unlockProgress = { done: 0, total: 0 };

function _drawIcon(size, frame, prog) {
  var c = document.createElement("canvas");
  c.width = size;
  c.height = size;
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
  // Global icon only — the ✓ match indicator is now a native badge, so nothing
  // sets a per-tab icon override that could hide this animation.
  try {
    api.browserAction.setIcon({
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
  _setIcon(SESSION.unlocked); // restore static color (unlocked) / mono (locked)
}

// Best-effort progress ping to the popup during the (slow) decrypt loop. Fails
// silently if the popup is closed. Also feeds the toolbar icon animation — the
// shared _unlockInner calls this host hook for every record. (Firefox's icon
// animation reads _unlockProgress; Chrome's lives in the service worker, so its
// _progress only messages.)
function _progress(done, total, workers) {
  _unlockProgress = { done: done, total: total };
  try {
    api.runtime
      .sendMessage({ cmd: "unlockProgress", done: done, total: total, workers: workers })
      .catch(function () {});
  } catch (e) {}
}

// Host lock(): wipe the shared SESSION + caches, then restore this page's icon /
// badges. The shared session core has no lock() — each platform paints its own UI.
function lock() {
  SESSION.unlocked = false;
  SESSION.entries = [];
  SESSION.vaultUrl = "";
  SESSION.integrity = null;
  VaultCrypto.clearCache();
  VaultCrypto.terminatePool(); // free worker WASM heaps + drop residual key bytes
  _wipeClipboardIfDirty();     // cancel the auto-clear timer + wipe any copied secret now
  _clearIntegrityBadge();      // restore badge colors before _refreshAllBadges
  _setIcon(false);
  _refreshAllBadges(); // clears ✗/✓ everywhere (no matches while locked)
}

// Stop an in-flight unlock and tear down the worker pool. Called when the user
// clicks back into a password field to fix a mistyped password — the workers
// stop immediately and any partial decode is discarded. (_unlockGen lives in the
// shared session core; _unlockInner watches it.)
function abortUnlock() {
  _unlockGen++;                 // stale-out any running _unlockInner
  VaultCrypto.terminatePool();  // stop all workers (rejects in-flight derivations)
  _progress(0, 0);              // clear the popup progress bar
  _stopIconAnim();
}

// Animate the toolbar icon for the whole unlock (fetch + decrypt), restoring the
// static icon when done (success or failure). The shared _unlockInner is UI-free
// and returns the result; this wrapper paints this page's icon + badges from it.
async function unlock(vaultUrl, pw, pw2) {
  var gen = ++_unlockGen; // supersede any prior in-flight unlock
  _startIconAnim();
  try {
    var r = await _unlockInner(vaultUrl, pw, pw2, gen);
    if (r && r.ok) {
      if (r.integrityFailed) _setIntegrityBadge();
      else _clearIntegrityBadge();
      _setIcon(true);
      _refreshAllBadges(); // mark tabs with ✗ (integrity fail) or ✓/"" (match indicator)
    }
    return r;
  } catch (e) {
    // If this unlock was aborted (gen bumped), terminate again now that the
    // in-flight derivations have settled — the worker fallback can transiently
    // re-spawn the pool while draining, so this mop-up guarantees no workers
    // are left alive after the user re-enters a password.
    if (gen !== _unlockGen) VaultCrypto.terminatePool();
    throw e;
  } finally {
    _stopIconAnim();
  }
}

// Inject the fill into the active tab. The content script is programmatically
// executed so no broad content_scripts registration is needed.
// Wait until the tab reports "complete" (a just-opened/navigating tab isn't
// injectable yet), bounded by a timeout so we never hang.
async function _waitForTabComplete(tabId, timeoutMs) {
  var deadline = Date.now() + (timeoutMs || 5000);
  while (Date.now() < deadline) {
    try {
      var t = await api.tabs.get(tabId);
      if (!t) return;
      if (t.status === "complete") return;
    } catch (e) {
      return; // tab gone — let the inject attempt surface the real error
    }
    await new Promise(function (r) { setTimeout(r, 150); });
  }
}

async function fillTab(tabId, username, password, entryUrl) {
  // Readiness guard: the target tab (e.g. one just opened via the entry's URL
  // link) may still be loading. Wait for it to finish, then inject + message
  // with a few retries to ride out transient injection failures during
  // navigation. The content script itself polls for the form to render.
  // `entryUrl` rides along so each injected frame can gate filling on its own
  // origin matching the entry (see content.js _fillAllowed).
  await _waitForTabComplete(tabId, 5000);
  var lastErr;
  for (var i = 0; i < 4; i++) {
    try {
      await api.tabs.executeScript(tabId, { file: "content.js", allFrames: true });
      return await api.tabs.sendMessage(tabId, { cmd: "doFill", username: username, password: password, entryUrl: entryUrl });
    } catch (e) {
      lastErr = e;
      await new Promise(function (r) { setTimeout(r, 250); });
    }
  }
  throw lastErr;
}

// Set a persistent red ✗ badge on every tab (global, no tabId) to signal that
// the self-test failed and the extension is not safe to use.
function _setSelftestBadge() {
  try { api.browserAction.setBadgeBackgroundColor({ color: "#c0392b" }); } catch (e) {}
  try { api.browserAction.setBadgeTextColor({ color: "#ffffff" }); } catch (e) {}
  try { api.browserAction.setBadgeText({ text: "✗" }); } catch (e) {}
}

// Host hook for vault-session.js's self-test runner — paint the red ✗ badge.
function _onSelftestFail() { _setSelftestBadge(); }

// Mark the vault as integrity-failed: flip badge colors to red so _refreshAllBadges
// paints ✗ on every tab instead of the normal ✓ / "" match indicator.
function _setIntegrityBadge() {
  SESSION.integrityFailed = true;
  try { api.browserAction.setBadgeBackgroundColor({ color: "#c0392b" }); } catch (e) {}
  try { api.browserAction.setBadgeTextColor({ color: "#ffffff" }); } catch (e) {}
}
// Restore default badge colors when integrity recovers (clean re-unlock or lock).
function _clearIntegrityBadge() {
  SESSION.integrityFailed = false;
  try { api.browserAction.setBadgeBackgroundColor({ color: [0, 0, 0, 0] }); } catch (e) {}
  try { api.browserAction.setBadgeTextColor({ color: BADGE_GREEN }); } catch (e) {}
}

api.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  (async function () {
    try {
      if (msg.cmd === "selftest") {
        await _selftestPromise;
        return _selftestResult || { ok: true, failures: [] };
      }
      if (msg.cmd === "status") {
        return {
          unlocked: SESSION.unlocked,
          count: SESSION.entries.length,
          vaultUrl: SESSION.vaultUrl,
        };
      }
      if (msg.cmd === "unlock") {
        var r = await unlock(msg.vaultUrl, msg.pw, msg.pw2);
        return r;
      }
      if (msg.cmd === "lock") {
        lock();
        return { ok: true };
      }
      if (msg.cmd === "abort") {
        abortUnlock();
        return { ok: true };
      }
      if (msg.cmd === "clipDirty") {
        // Popup copied a secret to the clipboard — arm the auto-clear timer.
        _armClipClear();
        return { ok: true };
      }

      // ---- passkey (WebAuthn) — work above the unlock gate ----
      if (msg.cmd === "passkey-create") return await passkeyCreate(msg);
      if (msg.cmd === "passkey-precheck") return passkeyPrecheck(msg);
      if (msg.cmd === "passkey-get") return await passkeyGet(msg);
      if (msg.cmd === "approval-info") {
        var ai = _pendingApprovals[msg.id];
        if (!ai) return { ok: false };
        return {
          ok: true, mode: ai.mode, rpId: ai.rpId, rpName: ai.rpName,
          origin: ai.origin, vaultUrl: ai.vaultUrl, writeUser: "pass",
        };
      }
      if (msg.cmd === "approval-candidates") {
        // Existing-entry list for the create approval window's attach picker.
        // Requires an unlocked session (the window unlocks first). Entries whose
        // url matches the rpId host are flagged so the window can surface them.
        var apc = _pendingApprovals[msg.id];
        if (!apc || !SESSION.unlocked) return { ok: false, entries: [] };
        var rpHost = (apc.rpId || "").toLowerCase();
        if (!rpHost) { try { rpHost = new URL(apc.origin).hostname.toLowerCase().replace(/^www\./, ""); } catch (e) { rpHost = ""; } }
        var clist = SESSION.entries.map(function (e) {
          return {
            id: e.id, name: e.name, username: e.username, url: e.url,
            hasTotp: !!e.token, hasPasskey: !!e.passkey, match: _hostMatch(e.url, rpHost),
          };
        });
        clist.sort(function (a, b) {
          if (a.match !== b.match) return a.match ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        return { ok: true, entries: clist };
      }
      if (msg.cmd === "approval-submit") {
        var ap = _pendingApprovals[msg.id];
        if (!ap) return { ok: false, error: "This request expired" };
        var rr = msg.result || {};
        if (!rr.ok) {
          // "Use this device instead" → fall back to the native authenticator; a
          // plain Deny cancels the ceremony.
          _finishApproval(msg.id, rr.native ? { passthrough: true } : { error: "User denied" });
          return { ok: true };
        }
        if (ap.mode === "confirm") {
          // Session already unlocked; Allow is the user-presence gesture → sign.
          var gotc = await passkeyGet({ options: ap.options, origin: ap.origin });
          _finishApproval(msg.id, gotc);
          return { ok: true };
        }
        if (ap.mode === "unlock") {
          var pre = passkeyPrecheck({ options: ap.options, origin: ap.origin });
          if (!pre.unlocked) return { ok: false, error: "Unlock failed" };
          var got = pre.match
            ? await passkeyGet({ options: ap.options, origin: ap.origin })
            : { passthrough: true };
          _finishApproval(msg.id, got);
          return { ok: true };
        }
        // create — passkeyCreate throws on failure → outer catch returns {error},
        // leaving the approval window open to retry.
        var res = await passkeyCreate({
          options: ap.options, origin: ap.origin,
          pw: rr.pw, pw2: rr.pw2, writeUser: rr.writeUser, writePass: rr.writePass, vaultUrl: ap.vaultUrl,
          targetId: (rr.targetId == null ? null : rr.targetId),
        });
        _finishApproval(msg.id, res);
        return { ok: true };
      }

      if (!SESSION.unlocked) return { error: "locked" };

      if (msg.cmd === "match") {
        var host = (msg.host || "").toLowerCase().replace(/^www\./, "");
        var list = SESSION.entries.map(function (e) {
          return {
            id: e.id,
            name: e.name,
            username: e.username,
            url: e.url,
            hasTotp: !!e.token,
            hasPasskey: !!e.passkey,
            match: _hostMatch(e.url, host),
          };
        });
        // Matches first, then the rest alphabetically.
        list.sort(function (a, b) {
          if (a.match !== b.match) return a.match ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        return { entries: list, integrity: SESSION.integrity };
      }

      var entry = SESSION.entries.find(function (e) {
        return e.id === msg.id;
      });
      if (!entry) return { error: "not found" };

      if (msg.cmd === "fill") {
        var fr = await fillTab(msg.tabId, entry.username, entry.password, entry.url);
        return { ok: !!(fr && fr.ok), filled: fr && fr.filled };
      }
      if (msg.cmd === "reveal") {
        return { username: entry.username, password: entry.password };
      }
      if (msg.cmd === "details") {
        // Full field set for the inline expand panel — fetched on demand so
        // secrets aren't shipped to the popup until an entry is opened.
        return {
          name: entry.name,
          url: entry.url,
          username: entry.username,
          password: entry.password,
          token: entry.token,
          hasTotp: !!entry.token,
          notes: entry.notes,
        };
      }
      if (msg.cmd === "totp") {
        if (!entry.token) return { error: "no totp" };
        var cfg = VaultCrypto.parseOtp(entry.token);
        var code = await VaultCrypto.computeTotp(cfg, 0);
        var period = cfg.period || 30;
        var remaining = period - (Math.floor(Date.now() / 1000) % period);
        return { code: code, remaining: remaining };
      }
      return { error: "unknown cmd" };
    } catch (e) {
      return { error: String((e && e.message) || e) };
    }
  })().then(sendResponse);
  return true; // async response
});

// ============================================================
// Passkey approval window + content-script port plumbing
// ============================================================
// The passkey crypto/session functions (passkeyCreate / passkeyGet /
// passkeyPrecheck) live in vault-session.js. This page drives the per-ceremony
// approval window and relays the MAIN-world interceptor's requests to them. In
// Firefox the persistent background page holds the session directly, so it calls
// those functions inline (Chrome relays them to its offscreen document instead).

var _pendingApprovals = {};

async function _getVaultUrl() {
  try { var s = await api.storage.local.get("vaultUrl"); return (s && s.vaultUrl) || ""; }
  catch (e) { return ""; }
}

async function _openApproval(info) {
  var id = "ap" + Date.now() + "-" + Math.random().toString(36).slice(2);
  info.id = id;
  info.handled = false;
  _pendingApprovals[id] = info;
  try {
    var w = await api.windows.create({
      url: api.runtime.getURL("approve.html?id=" + id),
      // Approximate per-mode content height; approve.js shrinks the window to an
      // exact fit once the visible fields render, so these only minimize flash.
      type: "popup", width: 400,
      height: info.mode === "create" ? 470 : info.mode === "confirm" ? 210 : 300,
    });
    info.windowId = w && w.id;
  } catch (e) {
    _finishApproval(id, { error: "Could not open the approval window" });
  }
}

function _finishApproval(id, result) {
  var info = _pendingApprovals[id];
  if (!info || info.handled) return;
  info.handled = true;
  delete _pendingApprovals[id];
  try { if (info.port) info.port.postMessage(result); } catch (e) {}
  if (info.windowId != null) { try { api.windows.remove(info.windowId); } catch (e) {} }
}

async function handlePasskeyPort(port, msg) {
  try {
    var vaultUrl = await _getVaultUrl();
    if (!vaultUrl) { port.postMessage({ error: "Set the vault URL in the extension first" }); return; }

    if (msg.cmd === "passkey-get") {
      var pre = passkeyPrecheck({ options: msg.options, origin: msg.origin });
      if (pre.unlocked) {
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

api.runtime.onConnect.addListener(function (port) {
  if (!port || port.name !== "passkey") return;
  port.onMessage.addListener(function (msg) { if (msg && msg.cmd) handlePasskeyPort(port, msg); });
});

api.windows.onRemoved.addListener(function (winId) {
  Object.keys(_pendingApprovals).forEach(function (id) {
    var info = _pendingApprovals[id];
    if (info && info.windowId === winId && !info.handled) _finishApproval(id, { error: "User cancelled" });
  });
});
