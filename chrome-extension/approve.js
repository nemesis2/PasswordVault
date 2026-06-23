// approve.js — the per-ceremony passkey approval window.
//
// Two modes (set by background via approval-info):
//   create — registering a new passkey: prompts both master passwords (to
//            encrypt the new record) and the vault write credentials (to POST
//            it). Nothing is persisted — "prompt per-write".
//   unlock — signing an assertion while the vault session is locked: prompts the
//            two master passwords to unlock, then background signs.
//
// On Allow it returns the inputs to background (create) or performs the unlock
// (unlock); on Deny / window-close background resolves the ceremony as cancelled.

"use strict";
var api = typeof browser !== "undefined" ? browser : chrome;
var $ = function (id) { return document.getElementById(id); };
function send(msg) { return api.runtime.sendMessage(msg); }

var ID = new URLSearchParams(location.search).get("id") || "";
var MODE = "create";
var VAULT_URL = "";

// Attach-picker state (create mode): the id of the existing entry to attach the
// new passkey to, or null = "Create new entry". _loadedFor guards against
// re-decrypting the vault on every blur for an unchanged password pair.
var _attachTarget = null;
var _candidates = null;
var _loadedFor = "";

(async function init() {
  var info = await send({ cmd: "approval-info", id: ID });
  if (!info || !info.ok) { window.close(); return; }
  MODE = info.mode;
  VAULT_URL = info.vaultUrl || "";
  // The RP-supplied name is attacker-controllable, so always show the validated
  // requesting origin too — a site can't spoof its own origin here.
  $("rp").textContent = info.rpName || info.rpId || info.origin || "this site";
  $("origin").textContent = info.origin || info.rpId || "unknown";

  if (MODE === "unlock") {
    $("title").textContent = "Unlock to use passkey";
    $("write-block").style.display = "none";
  } else if (MODE === "confirm") {
    // Vault already unlocked — just a per-assertion user-presence confirmation,
    // no passwords needed.
    $("title").textContent = "Use passkey to sign in?";
    $("write-block").style.display = "none";
  } else {
    $("title").textContent = "Create a passkey?";
    $("wuser").value = info.writeUser || "pass";
    // Offer a clear path to the browser's own authenticator so create() never
    // hard-fails just because the user doesn't want a vault passkey.
    $("use-native").style.display = "block";
  }

  if (MODE === "confirm") {
    // Hide the password labels + inputs that aren't needed for a confirm.
    ["pw1", "pw2"].forEach(function (id) {
      var inp = $(id);
      if (inp) inp.style.display = "none";
      var lab = document.querySelector('label[for="' + id + '"]');
      if (lab) lab.style.display = "none";
    });
    $("allow").focus();
  } else {
    $("pw1").focus();
  }

  // The window is opened at a fixed height that overshoots the actual content
  // (especially in confirm/unlock mode, where most fields are hidden), leaving
  // blank space at the bottom. Now that the visible fields are settled, shrink
  // the window to fit its content so every mode renders uniformly.
  requestAnimationFrame(fitWindowHeight);
})();

// Resize the popup window so its height matches the rendered content. In create
// mode the entry list can make the content taller than the screen; requesting a
// window taller than the work area lets the OS clip the bottom (the Allow/Deny
// buttons) off-screen with no way to reach them. So cap the height to the screen
// work area and let the document scroll for any overflow — when we clamp, also
// pin the window to the top of the work area so the whole (now scrollable)
// window stays on-screen instead of being centred and overflowing.
async function fitWindowHeight() {
  try {
    var frame = window.outerHeight - window.innerHeight; // titlebar / window chrome
    var content = Math.ceil(document.body.getBoundingClientRect().height) + frame;
    var scr = window.screen || {};
    var maxH = scr.availHeight || content;
    var clamped = content > maxH;
    var target = clamped ? maxH : content;
    var w = await api.windows.getCurrent();
    if (w && w.id != null) {
      var upd = { height: target };
      if (clamped) upd.top = scr.availTop || 0;
      await api.windows.update(w.id, upd);
    }
  } catch (e) { /* best-effort cosmetic fit */ }
}

function setStatus(t) { $("status").textContent = t || ""; }
function setAttachStatus(t) { $("attach-status").textContent = t || ""; }

// Create mode: once both master passwords are entered, unlock the vault (reusing
// the normal unlock path — this leaves the session unlocked) and load the list
// of existing entries so the user can attach the new passkey to one instead of
// always creating a fresh entry. Re-runs only when the password pair changes.
async function loadCandidates() {
  if (MODE !== "create") return;
  var pw = $("pw1").value, pw2 = $("pw2").value;
  if (!pw || !pw2) return;
  var key = pw + "\n" + pw2;
  if (_loadedFor === key) return;
  _loadedFor = key;

  $("attach-block").style.display = "block";
  setAttachStatus("Unlocking vault to list entries…");
  $("attach-list").innerHTML = "";
  $("attach-search").style.display = "none";
  try {
    var u = await send({ cmd: "unlock", vaultUrl: VAULT_URL, pw: pw, pw2: pw2 });
    if (!u || !u.ok) {
      _loadedFor = ""; // let a corrected password retry
      setAttachStatus((u && u.error) || "Could not read existing entries");
      _candidates = null;
      requestAnimationFrame(fitWindowHeight);
      return;
    }
    var c = await send({ cmd: "approval-candidates", id: ID });
    _candidates = (c && c.entries) || [];
    renderAttach(_candidates);
  } catch (e) {
    _loadedFor = "";
    setAttachStatus(String((e && e.message) || e));
  }
  requestAnimationFrame(fitWindowHeight);
}

function renderAttach(list) {
  var box = $("attach-list");
  box.innerHTML = "";
  setAttachStatus(list.length
    ? "Attach to an existing entry, or create a new one:"
    : "No existing entries — a new one will be created.");
  // "Create new entry" is always first and selected by default.
  box.appendChild(_attachRow("", "＋ Create new entry", "", false, false, true));
  list.forEach(function (e) {
    box.appendChild(_attachRow(String(e.id), e.name, e.url || "", !!e.match, !!e.hasPasskey, false));
  });
  $("attach-search").style.display = list.length ? "block" : "none";
  $("attach-search").value = "";
  _attachTarget = null;
}

// Build one selectable radio row. value "" = create-new. Rows for entries that
// already hold a passkey are disabled (we won't clobber an existing credential).
function _attachRow(value, name, url, isMatch, hasPasskey, checked) {
  var row = document.createElement("label");
  row.className = "ar" + (hasPasskey ? " disabled" : "");
  row.dataset.search = (name + " " + url).toLowerCase();

  var radio = document.createElement("input");
  radio.type = "radio";
  radio.name = "attach";
  radio.value = value;
  radio.checked = checked;
  radio.disabled = hasPasskey;
  radio.addEventListener("change", function () {
    if (radio.checked) _attachTarget = value === "" ? null : Number(value);
  });

  var col = document.createElement("div");
  var n = document.createElement("div");
  n.className = "an";
  n.textContent = name;
  if (isMatch) {
    var m = document.createElement("span");
    m.className = "amatch";
    m.textContent = "  ·  matches this site";
    n.appendChild(m);
  }
  if (hasPasskey) {
    var pk = document.createElement("span");
    pk.className = "apk";
    pk.textContent = "  ·  already has a passkey";
    n.appendChild(pk);
  }
  col.appendChild(n);
  if (url) {
    var u = document.createElement("div");
    u.className = "au";
    u.textContent = url;
    col.appendChild(u);
  }

  row.appendChild(radio);
  row.appendChild(col);
  return row;
}

function filterAttach() {
  var q = $("attach-search").value.toLowerCase().trim();
  var rows = $("attach-list").querySelectorAll(".ar");
  rows.forEach(function (r, i) {
    if (i === 0) return; // always keep "Create new entry"
    r.style.display = (!q || (r.dataset.search || "").indexOf(q) !== -1) ? "" : "none";
  });
}

async function allow() {
  // Confirm mode: the session is already unlocked, so no passwords — Allow is the
  // per-assertion user-presence gesture WebAuthn expects.
  if (MODE === "confirm") {
    $("allow").disabled = true;
    setStatus("Signing in…");
    try {
      var c = await send({ cmd: "approval-submit", id: ID, result: { ok: true } });
      if (c && c.ok) { window.close(); return; }
      setStatus((c && c.error) || "Could not sign in");
      $("allow").disabled = false;
    } catch (e) {
      setStatus(String((e && e.message) || e));
      $("allow").disabled = false;
    }
    return;
  }

  var pw = $("pw1").value, pw2 = $("pw2").value;
  if (!pw || !pw2) { setStatus("Enter both master passwords."); return; }
  $("allow").disabled = true;

  try {
    if (MODE === "unlock") {
      setStatus("Unlocking…");
      var u = await send({ cmd: "unlock", vaultUrl: VAULT_URL, pw: pw, pw2: pw2 });
      if (!u || !u.ok) { setStatus((u && u.error) || "Unlock failed"); $("allow").disabled = false; return; }
      await send({ cmd: "approval-submit", id: ID, result: { ok: true } });
      window.close();
      return;
    }
    // create
    var wuser = $("wuser").value.trim(), wpass = $("wpass").value;
    if (!wpass) { setStatus("Enter the vault write password."); $("allow").disabled = false; return; }
    setStatus("Creating passkey…");
    var r = await send({
      cmd: "approval-submit", id: ID,
      result: { ok: true, pw: pw, pw2: pw2, writeUser: wuser, writePass: wpass, targetId: _attachTarget },
    });
    // Background performs the offscreen create + write, then reports back here.
    if (r && r.ok) { window.close(); return; }
    setStatus((r && r.error) || "Passkey creation failed");
    $("allow").disabled = false;
  } catch (e) {
    setStatus(String((e && e.message) || e));
    $("allow").disabled = false;
  }
}

function deny() {
  send({ cmd: "approval-submit", id: ID, result: { ok: false } }).finally(function () { window.close(); });
}

// Create mode only: decline the vault and let the page fall through to the
// browser's native authenticator instead of failing the ceremony.
function useNative() {
  send({ cmd: "approval-submit", id: ID, result: { ok: false, native: true } })
    .finally(function () { window.close(); });
}

$("allow").addEventListener("click", allow);
$("deny").addEventListener("click", deny);
$("use-native").addEventListener("click", useNative);
// Create mode: load the existing-entry picker once both master passwords are in.
$("pw2").addEventListener("blur", function () { loadCandidates(); });
$("attach-search").addEventListener("input", filterAttach);
document.addEventListener("keydown", function (e) {
  if (e.key === "Enter") allow();
  if (e.key === "Escape") deny();
});
