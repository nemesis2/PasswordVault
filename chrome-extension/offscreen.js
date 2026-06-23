// offscreen.js — holds the unlocked vault session in memory (MV3 port).
//
// This is the persistent half of the Chrome extension: a Chrome MV3 service
// worker has no DOM, cannot spawn Web Workers, and is torn down when idle, so it
// cannot hold a decrypted session the way Firefox's persistent background page
// does. The offscreen document can — it is an ordinary extension page that
// background.js creates once and keeps alive, so it owns everything the service
// worker can't:
//   • the SESSION (decrypted entries) — survives the popup / service worker
//     closing, just like the Firefox background page;
//   • the Argon2id Web Worker pool (via crypto-vault.js) — real multi-core
//     parallelism during unlock;
//   • DOMParser — to parse the vault's index.html;
//   • the clipboard auto-clear (textarea + execCommand / navigator.clipboard).
//
// It owns NO chrome.* UI APIs (action / idle / tabs / scripting live in the
// service worker). The two halves talk over runtime messaging: the service
// worker relays popup commands here tagged { target: "offscreen" }, and this
// page broadcasts unlock progress back. Passwords are never persisted.

"use strict";

var SESSION = {
  unlocked: false,
  vaultUrl: "",
  entries: [], // [{ id, name, url, username, password, token, notes }]
};

// ---- hostname matcher (mirrors background.js / content.js) ----
function _hostOf(u) {
  try {
    return new URL(/^[a-z]+:\/\//i.test(u) ? u : "https://" + u)
      .hostname.toLowerCase().replace(/^www\./, "");
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

// ---- Clipboard auto-clear ----
// A copied secret (password / TOTP) must not sit on the clipboard indefinitely.
// The popup does the user-gesture write, then the service worker relays a
// "clipDirty" here; we arm a timer on this persistent page (the popup usually
// closes within a second, so its own setTimeout would never fire). The clear is
// best-effort: an empty textarea + execCommand('copy') (works headless under the
// clipboardWrite permission), falling back to navigator.clipboard. We don't read
// the clipboard, so the dirty flag just tracks that we put a secret there and
// haven't cleared it yet.
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
  SESSION.vaultUrl = "";
  VaultCrypto.clearCache();
  VaultCrypto.terminatePool(); // free worker WASM heaps + drop residual key bytes
  _wipeClipboardIfDirty();     // cancel the auto-clear timer + wipe any copied secret now
}

// Best-effort progress ping to the popup + service worker during the (slow)
// decrypt loop. The service worker uses it to animate the toolbar icon; the
// popup uses it for the progress bar. Fails silently if no one is listening.
function _progress(done, total, workers) {
  try {
    chrome.runtime
      .sendMessage({ cmd: "unlockProgress", done: done, total: total, workers: workers })
      .catch(function () {});
  } catch (e) {}
}

// Monotonic unlock generation. Each unlock captures the current value; an abort
// (the user re-entering a password field) or a fresh unlock bumps it, so any
// older in-flight decode sees its generation go stale and bails out.
var _unlockGen = 0;

// Stop an in-flight unlock and tear down the worker pool. Called when the user
// clicks back into a password field to fix a mistyped password.
function abortUnlock() {
  _unlockGen++;                 // stale-out any running _unlockInner
  VaultCrypto.terminatePool();  // stop all workers (rejects in-flight derivations)
  _progress(0, 0);              // clear the popup progress bar
}

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
      // A stored passkey is retained (it holds the private key needed to sign
      // assertions during navigator.credentials.get); tags and custom (extra)
      // fields are dropped — the extension never surfaces them.
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
      // User re-entered a password (abort) — stop launching new work and resolve
      // once the in-flight derivations drain.
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
  return { ok: true, count: entries.length, vaultUrl: vaultUrl, hosts: entries.map(function (e) { return e.url; }) };
}

// ============================================================
// Passkey (WebAuthn) support
// ============================================================
// The extension is the authenticator: it generates/stores ECDSA P-256 key pairs
// (inside encrypted vault records) and signs assertions. Creating a passkey is a
// write, so it prompts (in the approval window) for the two master passwords (to
// encrypt) and the Basic-Auth write password (to POST) — nothing is persisted.
// Using a passkey (get) is read-only: it signs with the in-session private key,
// signCount fixed at 0 (no write-back). All crypto lives here in the offscreen
// document alongside the session + cipher bundles.

// A relying-party id is only valid if it equals the page origin's host or is a
// registrable parent of it (WebAuthn's rpId rule). This stops a page from
// requesting a credential/assertion scoped to a different site.
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

// Fetch + parse the vault index (records + KDF). Used by passkey create so a new
// record is encrypted at the vault's active Argon2id cost even when the vault is
// otherwise locked. Mirrors the fetch/parse in _unlockInner.
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

// Authenticated write to post.php. Basic-Auth + the X-Requested-With CSRF
// sentinel; post.php accepts our extension origin (see is_same_origin).
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

// Create + store a passkey. req: { options (serialized publicKey), origin, pw,
// pw2, writeUser, writePass, vaultUrl }. The vault record is written FIRST, so a
// failed write rejects the ceremony rather than handing the RP a credential that
// was never stored. Returns a serialized credential for the content script.
async function passkeyCreate(req) {
  var opts = req.options || {};
  var rp = opts.rp || {};
  var user = opts.user || {};
  var rpId = (rp.id || _hostOf(req.origin) || "").toLowerCase();
  if (!rpId) throw new Error("Cannot determine relying party id");
  if (!_rpIdAllowed(rpId, req.origin)) throw new Error("rpId not permitted for this origin");
  var rpName = rp.name || rpId;

  // Honor excludeCredentials: if this authenticator already holds one of the
  // listed credentials for this rpId (only checkable while unlocked), refuse —
  // matches a real authenticator's InvalidStateError behavior.
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

  // Verify the prompted master passwords actually decrypt this vault, so the new
  // passkey is encrypted under the same keys the user unlocks with (the
  // always-readable invariant). Skipped only for an empty vault.
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

  // Synthetic attestation (fmt "none").
  var clientData = WebAuthnKit.clientDataJSON("webauthn.create", opts.challenge, req.origin);
  var cose = WebAuthnKit.cosePublicKey(kp.publicKeyJwk);
  var attCred = WebAuthnKit.attestedCredentialData(kp.credentialId, cose);
  var authData = await WebAuthnKit.authenticatorData(rpId, 0x45, 0, attCred);
  var attObj = WebAuthnKit.attestationObject(authData);

  var passkey = {
    credentialId: credIdB64,
    rpId: rpId,
    rpName: rpName,
    userHandle: user.id || "",
    privateKeyJwk: kp.privateKeyJwk,
    publicKeyJwk: kp.publicKeyJwk,
    signCount: 0,
    createdAt: new Date().toISOString(),
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
    // Reflect into the live session: the record string changed and it now holds
    // a passkey.
    target.record = VaultCrypto.canonicalRecord(newRecord);
    target.passkey = passkey;
  } else {
    // Build + commit a brand-new vault record (encrypted under the prompted pws).
    var entryName = rpName + (user.name ? " (" + user.name + ")" : "");
    var fields = {
      url: "passkey://" + rpId,
      username: user.name || user.displayName || "",
      password: "", token: "", notes: "",
      passkey: passkey,
    };
    var record = await VaultCrypto.buildRecord(req.pw, req.pw2, entryName, fields, meta.kdf);
    writeResp = await _vaultWrite(meta.vaultUrl, "data=" + encodeURIComponent(record), req.writeUser, req.writePass);
    // Reflect into the live session if it's unlocked. Use a fresh id beyond every
    // existing one — entries.length can collide with a kept id when some records
    // were skipped during unlock. Built inline (the _toEntry helper is scoped to
    // _unlockInner), and carries the record string so it can be an attach target.
    if (SESSION.unlocked) {
      SESSION.entries.push({
        id: _nextEntryId(), name: entryName, url: fields.url,
        username: fields.username, password: "", token: "", notes: "",
        record: VaultCrypto.canonicalRecord(record), passkey: passkey, isNote: false,
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
      id: credIdB64,
      rawId: credIdB64,
      type: "public-key",
      authenticatorAttachment: "platform",
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

// Find a stored passkey matching a get() request among the unlocked session.
function _findPasskey(opts, origin) {
  var rpId = (opts.rpId || _hostOf(origin) || "").toLowerCase();
  var allow = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];
  var allowIds = allow.map(function (c) { return c.id; });
  return SESSION.entries.find(function (e) {
    if (!e.passkey || (e.passkey.rpId || "").toLowerCase() !== rpId) return false;
    return allowIds.length === 0 || allowIds.indexOf(e.passkey.credentialId) !== -1;
  });
}

// Report whether the session is unlocked and whether a passkey matches — lets the
// service worker decide between signing now, prompting an unlock, or passthrough.
function passkeyPrecheck(req) {
  if (!SESSION.unlocked) return { unlocked: false, match: false };
  return { unlocked: true, match: !!_findPasskey(req.options || {}, req.origin) };
}

// Sign a get() assertion with a stored passkey. Requires an unlocked session.
// Returns { passthrough: true } when no passkey matches (RP falls back to the
// native authenticator). signCount stays 0 → no write-back.
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
      id: pk.credentialId,
      rawId: pk.credentialId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: WebAuthnKit.bytesToB64url(clientData),
        authenticatorData: WebAuthnKit.bytesToB64url(authData),
        signature: WebAuthnKit.bytesToB64url(der),
        userHandle: pk.userHandle || null,
      },
    },
  };
}

// ---- message handler ----
// Only messages tagged { target: "offscreen" } (relayed by the service worker)
// are ours; everything else is for the service worker, so we ignore it (return
// undefined → don't hold the response channel).
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || msg.target !== "offscreen") return; // not for us

  (async function () {
    try {
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
        return { entries: list };
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
