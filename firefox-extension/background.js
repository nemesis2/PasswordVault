// background.js — holds the unlocked vault session in memory.
//
// Loaded (with crypto-ciphers.js + crypto-vault.js) as a persistent background
// page so the decrypted entries survive the popup closing. On unlock it fetches
// the vault's index.html (an unauthenticated read — only post.php *writes* need
// Basic Auth), parses every record out of the data-row attributes, decrypts them
// all with both passwords, and keeps the plaintext (name/url/username/password/
// token) in RAM until lock or the idle timeout. Passwords are never persisted.

"use strict";

var api = typeof browser !== "undefined" ? browser : chrome;

var SESSION = {
  unlocked: false,
  vaultUrl: "",
  entries: [], // [{ id, name, url, username, password, token }]
};

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
    var matched = _anyMatch(_hostOf(url || ""));
    api.browserAction.setBadgeText({ tabId: tabId, text: matched ? "✓" : "" });
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
// silently if the popup is closed. Also feeds the toolbar icon animation.
function _progress(done, total, workers) {
  _unlockProgress = { done: done, total: total };
  try {
    api.runtime
      .sendMessage({ cmd: "unlockProgress", done: done, total: total, workers: workers })
      .catch(function () {});
  } catch (e) {}
}

// ---- Clipboard auto-clear ----
// A copied secret (password / TOTP) must not sit on the clipboard indefinitely.
// The popup does the user-gesture write, then pings us ("clipDirty"); we arm a
// timer here on the *persistent* background page (the popup usually closes
// within a second, so its own setTimeout would never fire). The clear is
// best-effort: an empty textarea + execCommand('copy') (works headless under the
// clipboardWrite permission), falling back to navigator.clipboard. We don't read
// the clipboard (no clipboardRead permission), so the dirty flag just tracks
// that we put a secret there and haven't cleared it yet.
var _CLIP_CLEAR_MS = 45 * 1000;
var _clipTimer = null;
var _clipDirty = false;

function _clearClipboardNow() {
  try {
    var ta = document.createElement("textarea");
    ta.value = "";
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(ta);
    if (!ok && navigator.clipboard) navigator.clipboard.writeText("").catch(function () {});
  } catch (e) {
    try { navigator.clipboard.writeText("").catch(function () {}); } catch (_) {}
  }
}

function _armClipClear() {
  _clipDirty = true;
  if (_clipTimer) clearTimeout(_clipTimer);
  _clipTimer = setTimeout(function () {
    _clipTimer = null;
    _clipDirty = false;
    _clearClipboardNow();
  }, _CLIP_CLEAR_MS);
}

// Cancel the pending timer and wipe immediately if we still own a secret on the
// clipboard. Called on lock so a locked vault never leaves a secret behind.
function _wipeClipboardIfDirty() {
  if (_clipTimer) { clearTimeout(_clipTimer); _clipTimer = null; }
  if (_clipDirty) { _clipDirty = false; _clearClipboardNow(); }
}

function lock() {
  SESSION.unlocked = false;
  SESSION.entries = [];
  VaultCrypto.clearCache();
  VaultCrypto.terminatePool(); // free worker WASM heaps + drop residual key bytes
  _wipeClipboardIfDirty();     // cancel the auto-clear timer + wipe any copied secret now
  _setIcon(false);
  _refreshAllBadges(); // clears ✓ everywhere (no matches while locked)
}

// hostname matcher: exact, or registrable-suffix on either side
// (login.example.com matches example.com and vice-versa).
function _hostOf(u) {
  try {
    return new URL(/^[a-z]+:\/\//i.test(u) ? u : "https://" + u).hostname.toLowerCase().replace(/^www\./, "");
  } catch (e) {
    return "";
  }
}
// Public-suffix / multi-tenant-host guard (mirrors content.js) so suffix
// matching never treats a bare TLD or shared hosting domain as the registrable
// domain, which would cross-match unrelated sites.
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

// Monotonic unlock generation. Each unlock captures the current value; an abort
// (the user re-entering a password field) or a fresh unlock bumps it, so any
// older in-flight decode sees its generation go stale and bails out.
var _unlockGen = 0;

// Stop an in-flight unlock and tear down the worker pool. Called when the user
// clicks back into a password field to fix a mistyped password — the workers
// stop immediately and any partial decode is discarded.
function abortUnlock() {
  _unlockGen++;                 // stale-out any running _unlockInner
  VaultCrypto.terminatePool();  // stop all workers (rejects in-flight derivations)
  _progress(0, 0);              // clear the popup progress bar
  _stopIconAnim();
}

// Animate the toolbar icon for the whole unlock (fetch + decrypt), restoring the
// static icon when done (success or failure).
async function unlock(vaultUrl, pw, pw2) {
  var gen = ++_unlockGen; // supersede any prior in-flight unlock
  _startIconAnim();
  try {
    return await _unlockInner(vaultUrl, pw, pw2, gen);
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

async function _unlockInner(vaultUrl, pw, pw2, gen) {
  function _aborted() { return gen !== _unlockGen; }
  // Normalise to the directory index.
  vaultUrl = vaultUrl.trim();
  if (!/^https?:\/\//i.test(vaultUrl)) vaultUrl = "https://" + vaultUrl;
  var indexUrl = vaultUrl.replace(/\/+$/, "") + "/index.html";

  var resp;
  try {
    resp = await fetch(indexUrl, { credentials: "include", cache: "no-store" });
  } catch (e) {
    // Retry without the /index.html suffix (server may serve the dir directly).
    resp = await fetch(vaultUrl, { credentials: "include", cache: "no-store" });
  }
  if (!resp.ok) throw new Error("Fetch failed (" + resp.status + ")");
  var html = await resp.text();

  var doc = new DOMParser().parseFromString(html, "text/html");
  var kdfEl = doc.getElementById("vault-kdf");
  var kdf = (kdfEl && VaultCrypto.parseKdf(kdfEl.getAttribute("data-kdf") || "")) || VaultCrypto.DEFAULT_KDF;

  var btns = doc.querySelectorAll("[data-row]");
  var records = [];
  btns.forEach(function (b) {
    var r = b.getAttribute("data-row");
    if (r && r.split("|")[1] === "v6") records.push(VaultCrypto.canonicalRecord(r));
  });
  if (!records.length) throw new Error("No v6 records found at that URL");

  // Size the worker pool to this vault's KDF cost (so the RAM budget tracks the
  // actual per-worker heap), then decrypt with the workers running in parallel.
  VaultCrypto.setActiveKdf(kdf);
  var workers = VaultCrypto.poolSize();

  function _toEntry(idx, dec, record) {
    var f = dec.fields || {};
    return {
      id: idx,
      name: dec.name || "(unnamed)",
      url: (f.url || "").trim(),
      username: f.username || "",
      password: f.password || "",
      token: (f.token || "").trim(),
      notes: f.notes || "",
      // The canonical record string, retained so an attach-to-existing passkey
      // create can re-decrypt the FULL record (the lossy entry below drops
      // tags/extra/history) and atomically replace it.
      record: record ? VaultCrypto.canonicalRecord(record) : "",
      // A stored passkey is retained (its private key signs assertions during
      // navigator.credentials.get); tags and custom (extra) fields are dropped —
      // the extension never surfaces them.
      passkey: (f.passkey && typeof f.passkey === "object") ? f.passkey : null,
      // Secure notes (type:"note") have no fillable credentials — flagged so
      // _keepEntry() can hide them from the autofill list.
      isNote: f.type === "note",
    };
  }

  // Hide secure notes from the extension entirely (no username/password/TOTP to
  // fill), but keep one if it carries a passkey — its private key is still
  // needed to sign navigator.credentials.get assertions.
  function _keepEntry(e) {
    return !e.isNote || !!e.passkey;
  }

  var entries = [];
  _progress(0, records.length, workers);

  // Validate the password on the first record so wrong passwords fail fast
  // (instead of grinding through the whole vault before reporting failure).
  var passwordOk = false;
  try {
    var first = _toEntry(0, await VaultCrypto.decodeRecord(records[0], pw, pw2, kdf), records[0]);
    passwordOk = true; // decode succeeded → both passwords are correct
    if (_keepEntry(first)) entries.push(first);
  } catch (e) {
    if (_aborted()) throw new Error("aborted");
    throw new Error("Wrong password(s)");
  }
  if (_aborted()) throw new Error("aborted");
  var done = 1;
  _progress(done, records.length, workers);

  // Remaining records, decoded with bounded concurrency = pool size. Each record
  // needs two Argon2id derivations, so this keeps ~2×pool jobs in flight and all
  // workers busy. A single bad record is skipped (resilient to a partially
  // corrupt vault) rather than aborting the unlock.
  var concurrency = Math.max(2, workers);
  var nextIdx = 1;
  await new Promise(function (resolve) {
    var active = 0;
    function launch() {
      // User re-entered a password (abort) — stop launching new work and
      // resolve once the in-flight derivations drain.
      if (_aborted()) { if (active === 0) resolve(); return; }
      if (nextIdx >= records.length && active === 0) return resolve();
      while (active < concurrency && nextIdx < records.length) {
        var idx = nextIdx++;
        active++;
        VaultCrypto.decodeRecord(records[idx], pw, pw2, kdf)
          .then(function (dec) {
            var e = _toEntry(this.idx, dec, this.rec);
            if (_keepEntry(e)) entries.push(e);
          }.bind({ idx: idx, rec: records[idx] }))
          .catch(function () {
            /* skip this record */
          })
          .then(function () {
            active--;
            done++;
            _progress(done, records.length, workers);
            launch();
          });
      }
    }
    launch();
  });
  if (_aborted()) throw new Error("aborted");
  // Gate on the record-0 decode, not entries.length — a vault containing only
  // secure notes unlocks correctly even though it yields zero fillable entries.
  if (!passwordOk) throw new Error("Wrong password(s)");

  SESSION.unlocked = true;
  SESSION.vaultUrl = vaultUrl;
  SESSION.entries = entries;
  _setIcon(true);
  _refreshAllBadges(); // mark tabs whose site now matches a stored entry
  return { ok: true, count: entries.length };
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

api.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  (async function () {
    try {
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
        return { entries: list };
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
// Passkey (WebAuthn) support
// ============================================================
// In Firefox the persistent background page is the authenticator: it generates/
// stores ECDSA P-256 key pairs (inside encrypted vault records) and signs
// assertions. Creating a passkey is a write and prompts (in the approval window)
// for the two master passwords (to encrypt) and the Basic-Auth write password (to
// POST) — nothing persisted. Using a passkey (get) is read-only; signCount stays
// 0 (no write-back). Mirrors chrome-extension/offscreen.js + background.js, but
// without the offscreen relay (this page holds the session directly).

function _rpIdAllowed(rpId, origin) {
  var host;
  try { host = new URL(origin).hostname.toLowerCase(); } catch (e) { return false; }
  rpId = (rpId || "").toLowerCase();
  if (!host || !rpId) return false;
  // rpId must equal the origin host or be a registrable parent of it — never a
  // public suffix (e.g. "co.uk", "github.io") which would span unrelated sites.
  return host === rpId || (host.endsWith("." + rpId) && !_isPubSuffix(rpId));
}

function _normVaultUrl(u) {
  u = (u || "").trim();
  if (!u) return "";
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u.replace(/\/+$/, "");
}

async function _fetchVaultIndex(vaultUrl) {
  vaultUrl = _normVaultUrl(vaultUrl);
  if (!vaultUrl) throw new Error("No vault URL configured");
  var resp;
  try {
    resp = await fetch(vaultUrl + "/index.html", { credentials: "include", cache: "no-store" });
  } catch (e) {
    resp = await fetch(vaultUrl, { credentials: "include", cache: "no-store" });
  }
  if (!resp.ok) throw new Error("Vault fetch failed (" + resp.status + ")");
  var html = await resp.text();
  var doc = new DOMParser().parseFromString(html, "text/html");
  var kdfEl = doc.getElementById("vault-kdf");
  var kdf = (kdfEl && VaultCrypto.parseKdf(kdfEl.getAttribute("data-kdf") || "")) || VaultCrypto.DEFAULT_KDF;
  var manEl = doc.getElementById("vault-manifest");
  var manifest = (manEl && manEl.getAttribute("data-manifest")) || null;
  var records = [];
  doc.querySelectorAll("[data-row]").forEach(function (b) {
    var r = b.getAttribute("data-row");
    if (r && r.split("|")[1] === "v6") records.push(VaultCrypto.canonicalRecord(r));
  });
  return { vaultUrl: vaultUrl, kdf: kdf, records: records, manifest: manifest };
}

// Canonical, sorted record set from a post.php write response's `entries`
// (each "<record>|<index>"). Matches javascript.js _canonicalRecords() and the
// server's SHA-256(implode("\n", sorted lines)) that backs expect_hash.
function _canonicalRecordsFrom(entries) {
  return (entries || []).map(function (e) { return VaultCrypto.canonicalRecord(e); }).sort();
}

// Re-sign the vault integrity manifest after the passkey record was committed.
// The PWA auto-re-signs after its own writes (_signAfterWrite); the extension is
// the one other writer, so it must do the same or the new record trips the PWA's
// tamper check. writeResp is the post.php JSON ({ entries, manifest, kdf }).
// Best-effort: a sign failure leaves the manifest stale (the record is already
// stored; the PWA's Sign button can re-baseline) rather than failing the whole
// passkey ceremony. One resync-retry on a 409 mirrors _signAfterWrite.
async function _resignVault(vaultUrl, writeResp, pw, pw2, kdf, writeUser, writePass) {
  try {
    var records = _canonicalRecordsFrom(writeResp.entries);
    var prev = writeResp.manifest || null;
    for (var attempt = 0; attempt < 2; attempt++) {
      var m = await VaultCrypto.buildManifest(pw, pw2, records, prev, kdf);
      try {
        await _vaultWrite(vaultUrl,
          "sign=1&expect_hash=" + m.expectHash + "&manifest=" + encodeURIComponent(m.manifest),
          writeUser, writePass);
        return;
      } catch (e) {
        // 409 ("Vault changed") — another client wrote between our add and our
        // sign. Re-fetch the merged set + latest manifest and sign that.
        if (attempt === 1 || !/changed/i.test(e && e.message || "")) throw e;
        var fresh = await _fetchVaultIndex(vaultUrl);
        records = fresh.records.slice().sort();
        prev = fresh.manifest;
      }
    }
  } catch (e) {
    console.warn("Passkey stored but vault re-sign failed:", (e && e.message) || e);
  }
}

async function _vaultWrite(vaultUrl, body, user, pass) {
  var resp = await fetch(_normVaultUrl(vaultUrl) + "/post", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Requested-With": "XMLHttpRequest",
      "Authorization": "Basic " + btoa(user + ":" + pass),
    },
    body: body,
  });
  if (resp.status === 401) throw new Error("Wrong write password");
  if (resp.status === 403) throw new Error("Write refused (CSRF/origin)");
  if (resp.status === 409) throw new Error("Vault changed — try again");
  if (!resp.ok) throw new Error("Write failed (" + resp.status + ")");
  var json = null;
  try { json = JSON.parse(await resp.text()); } catch (e) {}
  if (!json || !json.ok) throw new Error("Write rejected by server");
  return json;
}

async function passkeyCreate(req) {
  var opts = req.options || {};
  var rp = opts.rp || {};
  var user = opts.user || {};
  var rpId = (rp.id || _hostOf(req.origin) || "").toLowerCase();
  if (!rpId) throw new Error("Cannot determine relying party id");
  if (!_rpIdAllowed(rpId, req.origin)) throw new Error("rpId not permitted for this origin");
  var rpName = rp.name || rpId;

  // Honor excludeCredentials: if this authenticator already holds one of the
  // listed credentials for this rpId (only checkable while unlocked), refuse.
  var exclude = Array.isArray(opts.excludeCredentials) ? opts.excludeCredentials : [];
  if (exclude.length && SESSION.unlocked) {
    var excludeIds = exclude.map(function (c) { return c.id; });
    var clash = SESSION.entries.some(function (e) {
      return e.passkey && (e.passkey.rpId || "").toLowerCase() === rpId &&
        excludeIds.indexOf(e.passkey.credentialId) !== -1;
    });
    if (clash) throw new Error("A passkey for this account already exists in the vault");
  }

  var meta = await _fetchVaultIndex(req.vaultUrl);
  if (meta.records.length) {
    try {
      await VaultCrypto.decodeRecord(meta.records[0], req.pw, req.pw2, meta.kdf);
    } catch (e) {
      throw new Error("Wrong master password(s) for this vault");
    }
  }

  // Attach-to-existing: the user picked an existing entry in the approval window
  // (req.targetId). Locate it now so we fail before generating a keypair if it's
  // gone or ineligible. The target comes from the unlocked session, so this path
  // requires the vault to have been unlocked (which the approval window does).
  var target = null;
  if (req.targetId != null) {
    target = SESSION.entries.find(function (e) { return e.id === req.targetId; });
    if (!target || !target.record) throw new Error("Selected entry unavailable — unlock the vault and try again");
    if (target.passkey) throw new Error("That entry already has a passkey");
  }

  var kp = await VaultCrypto.generatePasskeyPair();
  var credIdB64 = WebAuthnKit.bytesToB64url(kp.credentialId);

  var clientData = WebAuthnKit.clientDataJSON("webauthn.create", opts.challenge, req.origin);
  var cose = WebAuthnKit.cosePublicKey(kp.publicKeyJwk);
  var attCred = WebAuthnKit.attestedCredentialData(kp.credentialId, cose);
  var authData = await WebAuthnKit.authenticatorData(rpId, 0x45, 0, attCred);
  var attObj = WebAuthnKit.attestationObject(authData);

  var passkey = {
    credentialId: credIdB64, rpId: rpId, rpName: rpName,
    userHandle: user.id || "",
    privateKeyJwk: kp.privateKeyJwk, publicKeyJwk: kp.publicKeyJwk,
    signCount: 0, createdAt: new Date().toISOString(),
  };

  var writeResp;
  if (target) {
    // Decrypt the FULL existing record (preserving tags / custom fields /
    // history / url that the lossy session entry drops), inject the passkey, and
    // atomically replace the record (delete old + add new in one write).
    var dec = await VaultCrypto.decodeRecord(target.record, req.pw, req.pw2, meta.kdf);
    var mergedFields = dec.fields || {};
    mergedFields.passkey = passkey;
    var newRecord = await VaultCrypto.buildRecord(req.pw, req.pw2, dec.name, mergedFields, meta.kdf);
    writeResp = await _vaultWrite(meta.vaultUrl,
      "delete_rec=" + encodeURIComponent(target.record) + "&data=" + encodeURIComponent(newRecord),
      req.writeUser, req.writePass);
    target.record = VaultCrypto.canonicalRecord(newRecord);
    target.passkey = passkey;
  } else {
    var entryName = rpName + (user.name ? " (" + user.name + ")" : "");
    var fields = {
      url: "passkey://" + rpId,
      username: user.name || user.displayName || "",
      password: "", token: "", notes: "",
      passkey: passkey,
    };
    var record = await VaultCrypto.buildRecord(req.pw, req.pw2, entryName, fields, meta.kdf);
    writeResp = await _vaultWrite(meta.vaultUrl, "data=" + encodeURIComponent(record), req.writeUser, req.writePass);
    if (SESSION.unlocked) {
      // Fresh id beyond every existing one — entries.length can collide with a
      // kept id when some records were skipped during unlock.
      SESSION.entries.push({
        id: _nextEntryId(), name: entryName, url: fields.url,
        username: fields.username, password: "", token: "", notes: "",
        record: VaultCrypto.canonicalRecord(record), passkey: passkey,
      });
    }
  }

  // Re-sign the vault so the new/updated passkey record doesn't trip the PWA's
  // tamper check (the PWA auto-re-signs after its own writes; we're the one other
  // writer). Best-effort — never undoes the already-committed record.
  await _resignVault(meta.vaultUrl, writeResp, req.pw, req.pw2, meta.kdf, req.writeUser, req.writePass);

  return {
    ok: true,
    credential: {
      id: credIdB64, rawId: credIdB64, type: "public-key", authenticatorAttachment: "platform",
      response: {
        clientDataJSON: WebAuthnKit.bytesToB64url(clientData),
        attestationObject: WebAuthnKit.bytesToB64url(attObj),
        authenticatorData: WebAuthnKit.bytesToB64url(authData),
        publicKeyDer: WebAuthnKit.bytesToB64url(kp.publicKeySpki),
        transports: ["internal", "hybrid"],
      },
    },
  };
}

// Next entry id strictly greater than every id currently in the session, so a
// post-unlock insert (passkey create) never reuses a kept record's id even when
// some records were skipped during decrypt.
function _nextEntryId() {
  var max = -1;
  for (var i = 0; i < SESSION.entries.length; i++) {
    if (SESSION.entries[i].id > max) max = SESSION.entries[i].id;
  }
  return max + 1;
}

function _findPasskey(opts, origin) {
  var rpId = (opts.rpId || _hostOf(origin) || "").toLowerCase();
  var allow = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];
  var allowIds = allow.map(function (c) { return c.id; });
  return SESSION.entries.find(function (e) {
    if (!e.passkey || (e.passkey.rpId || "").toLowerCase() !== rpId) return false;
    return allowIds.length === 0 || allowIds.indexOf(e.passkey.credentialId) !== -1;
  });
}

function passkeyPrecheck(req) {
  if (!SESSION.unlocked) return { unlocked: false, match: false };
  return { unlocked: true, match: !!_findPasskey(req.options || {}, req.origin) };
}

async function passkeyGet(req) {
  if (!SESSION.unlocked) return { error: "locked" };
  var opts = req.options || {};
  var rpId = (opts.rpId || _hostOf(req.origin) || "").toLowerCase();
  if (!_rpIdAllowed(rpId, req.origin)) return { error: "rpId not permitted for this origin" };
  var entry = _findPasskey(opts, req.origin);
  if (!entry) return { passthrough: true };
  var pk = entry.passkey;

  var clientData = WebAuthnKit.clientDataJSON("webauthn.get", opts.challenge, req.origin);
  var clientDataHash = await WebAuthnKit.sha256(clientData);
  var authData = await WebAuthnKit.authenticatorData(rpId, 0x05, 0);
  var sig = await VaultCrypto.signPasskeyChallenge(pk.privateKeyJwk, authData, clientDataHash);
  var der = WebAuthnKit.p1363ToDer(sig);

  return {
    ok: true,
    credential: {
      id: pk.credentialId, rawId: pk.credentialId, type: "public-key", authenticatorAttachment: "platform",
      response: {
        clientDataJSON: WebAuthnKit.bytesToB64url(clientData),
        authenticatorData: WebAuthnKit.bytesToB64url(authData),
        signature: WebAuthnKit.bytesToB64url(der),
        userHandle: pk.userHandle || null,
      },
    },
  };
}

// ---- approval window + content-script port plumbing ----
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
