// offscreen.js — the MV3 session host (Chrome/Edge).
//
// A Chrome MV3 service worker has no DOM, cannot spawn Web Workers, and is torn
// down when idle, so it cannot hold a decrypted session the way Firefox's
// persistent background page does. The offscreen document can — it is an ordinary
// extension page that background.js creates once and keeps alive. The decrypted
// SESSION, the v6 unlock/decrypt loop, the Argon2id worker pool, DOMParser, the
// clipboard auto-clear, the WebAuthn passkey ceremonies, and the crypto self-test
// all live in vault-session.js, loaded before this file and shared verbatim with
// the Firefox background page. This file is the thin host: it supplies the few
// platform hooks (_progress, the unlock/abortUnlock/lock wrappers, _onSelftestFail)
// and the message handler that the service worker relays popup commands through.
//
// It owns NO chrome.* UI APIs (action / idle / tabs / scripting live in the
// service worker). The two halves talk over runtime messaging: the service worker
// relays commands here tagged { target: "offscreen" }, and this page broadcasts
// unlock progress back. Passwords are never persisted.

"use strict";

// Best-effort progress ping to the popup + service worker during the (slow)
// decrypt loop — the shared _unlockInner calls this host hook for every record.
// The service worker uses it to animate the toolbar icon; the popup uses it for
// the progress bar. Fails silently if no one is listening. (Firefox's _progress
// also drives its in-page icon; here the icon lives in the service worker, so
// this only messages.)
function _progress(done, total, workers) {
  try {
    chrome.runtime
      .sendMessage({ cmd: "unlockProgress", done: done, total: total, workers: workers })
      .catch(function () {});
  } catch (e) {}
}

// Host unlock(): supersede any prior in-flight unlock by bumping the shared
// _unlockGen, then run the shared UI-free _unlockInner. Its result
// ({ ok, count, vaultUrl, hosts, integrityFailed }) is returned straight to the
// service worker, which paints the toolbar icon/badges from it.
async function unlock(vaultUrl, pw, pw2) {
  var gen = ++_unlockGen; // supersede any prior in-flight unlock
  try {
    return await _unlockInner(vaultUrl, pw, pw2, gen);
  } catch (e) {
    // If this unlock was aborted (gen bumped), terminate again now that the
    // in-flight derivations have settled — the worker fallback can transiently
    // re-spawn the pool while draining, so this mop-up guarantees no workers are
    // left alive after the user re-enters a password.
    if (gen !== _unlockGen) VaultCrypto.terminatePool();
    throw e;
  }
}

// Stop an in-flight unlock and tear down the worker pool. Called when the user
// clicks back into a password field to fix a mistyped password. (The service
// worker stops its own icon animation; this just halts the decode.)
function abortUnlock() {
  _unlockGen++;                 // stale-out any running _unlockInner
  VaultCrypto.terminatePool();  // stop all workers (rejects in-flight derivations)
  _progress(0, 0);              // clear the popup progress bar
}

// Host lock(): wipe the shared SESSION + caches + clipboard. No UI here — the
// service worker repaints the toolbar icon/badges after relaying this.
function lock() {
  SESSION.unlocked = false;
  SESSION.entries = [];
  SESSION.vaultUrl = "";
  SESSION.integrity = null;
  VaultCrypto.clearCache();
  VaultCrypto.terminatePool(); // free worker WASM heaps + drop residual key bytes
  _wipeClipboardIfDirty();     // cancel the auto-clear timer + wipe any copied secret now
}

// Host hook for vault-session.js's self-test runner — tell the service worker to
// set a red badge on the toolbar icon (this page owns no chrome.action API).
function _onSelftestFail() {
  try { chrome.runtime.sendMessage({ cmd: "selftest-badge" }); } catch (e) {}
}

// ---- message handler ----
// Only messages tagged { target: "offscreen" } (relayed by the service worker)
// are ours; everything else is for the service worker, so we ignore it (return
// undefined → don't hold the response channel).
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || msg.target !== "offscreen") return; // not for us

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
          hosts: SESSION.entries.map(function (e) { return e.url; }),
        };
      }
      if (msg.cmd === "unlock") {
        return await unlock(msg.vaultUrl, msg.pw, msg.pw2);
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
        _armClipClear();
        return { ok: true };
      }
      // Passkey create rides its own auth (prompted master + write passwords) and
      // must work even when the session is locked, so it sits above the gate.
      if (msg.cmd === "passkey-create") {
        return await passkeyCreate(msg);
      }
      if (msg.cmd === "passkey-precheck") {
        return passkeyPrecheck(msg);
      }
      if (msg.cmd === "passkey-get") {
        return await passkeyGet(msg);
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

      var entry = SESSION.entries.find(function (e) { return e.id === msg.id; });
      if (!entry) return { error: "not found" };

      if (msg.cmd === "fillData") {
        // Credentials for an autofill — the service worker injects them into the
        // page (it owns chrome.scripting; this page does not).
        return { username: entry.username, password: entry.password, url: entry.url };
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
