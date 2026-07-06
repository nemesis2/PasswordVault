// popup.js — UI for the autofill companion. All crypto/state lives in the
// background page; the popup only sends messages and renders results.
"use strict";

var api = typeof browser !== "undefined" ? browser : chrome;

// Firefox renders an inner overflow:auto scroll region inside a popup with
// un-painted (blank) areas; only the popup's own document-level scroll paints
// reliably. Tag the root so the stylesheet can drop the entry list's internal
// scroll on Firefox and let the whole popup scroll natively. Inert on Chrome
// (where `browser` is undefined and the inner-scroll list works correctly), so
// this file stays byte-identical across both extensions.
if (typeof browser !== "undefined") {
  try { document.documentElement.classList.add("is-firefox"); } catch (e) {}
}

var $ = function (id) { return document.getElementById(id); };
function send(msg) {
  return api.runtime.sendMessage(msg);
}

var _entries = [];
var _tabId = null;
var _tabHost = "";
var _autoLockDisabled = false; // mirrors the stored autoLock setting

// Mirrors the PWA's confirmation when auto-lock is turned off: it leaves the
// vault unlocked indefinitely, so we make the user re-acknowledge that risk —
// both when the checkbox is toggled on and (see init) when a session starts
// with it already disabled and the vault unlocked.
var _autolockConfirmMsg =
  "Disabling auto-lock means this vault will stay unlocked indefinitely, " +
  "even if you walk away from your device.\n\n" +
  "Are you sure you want to turn off auto-lock?";

// Persist the auto-lock preference and refresh the dependent UI. `disabled` is
// the checkbox state (checked = auto-lock disabled). Background reads the stored
// `autoLock` flag via storage.onChanged.
function _setAutoLockDisabled(disabled) {
  api.storage.local.set({ autoLock: !disabled });
  _autoLockDisabled = disabled;
  var cb = $("disable-autolock");
  if (cb) cb.checked = disabled;
  _reflectAutoLockGlyph();
}

// Show the red stopwatch glyph (next to the Lock link) only while the vault is
// unlocked AND auto-lock is disabled.
function _reflectAutoLockGlyph() {
  var g = $("autolock-off");
  if (g) g.hidden = !(_autoLockDisabled && !$("entries-view").hidden);
}

// Re-acknowledge a sticky "auto-lock disabled" choice. Called only at the points
// where the user is actively (re)establishing a session — the initial unlock and
// the About checkbox toggle — never on a plain popup reopen. Cancelling re-enables
// auto-lock.
function _maybeConfirmAutoLockDisabled() {
  if (_autoLockDisabled && !window.confirm(_autolockConfirmMsg)) {
    _setAutoLockDisabled(false);
  }
}

async function currentTab() {
  var tabs = await api.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function setStatus(el, text, cls) {
  el.textContent = text || "";
  el.className = "status" + (cls ? " " + cls : "");
}

function setProgress(done, total) {
  var box = $("unlock-progress");
  if (total <= 0) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  var pct = Math.round((done / total) * 100);
  $("progress-fill").style.width = pct + "%";
  $("progress-key").style.left = pct + "%";
  $("progress-pct").textContent = done + " / " + total + " (" + pct + "%)";
}

// Live decrypt progress streamed from the background page during unlock/refresh.
api.runtime.onMessage.addListener(function (msg) {
  if (msg && msg.cmd === "unlockProgress") {
    setProgress(msg.done, msg.total);
    if (msg.workers) {
      var lbl = "Decrypting with " + msg.workers + " worker" + (msg.workers === 1 ? "" : "s") + "…";
      setStatus($("unlock-status"), lbl);
    }
  }
});

function toggleEye(btn) {
  var inp = $(btn.dataset.target);
  if (!inp) return;
  var show = inp.type === "password";
  inp.type = show ? "text" : "password";
  btn.classList.toggle("on", show);
  btn.textContent = show ? "🙈" : "👁";
}

// ---- Unlock flow ----
var _unlocking = false;

// Force both password fields back to masked + reset the eye toggles. Called as
// decoding begins so a revealed password is never left on screen while the
// (slow) key derivation runs.
function _hidePasswords() {
  ["pw1", "pw2"].forEach(function (id) {
    var inp = $(id);
    if (inp) inp.type = "password";
  });
  Array.prototype.forEach.call(document.querySelectorAll(".eye"), function (btn) {
    btn.classList.remove("on");
    btn.textContent = "👁";
  });
}

async function doUnlock() {
  if (_unlocking) return; // already decoding (Enter + Tab, double click, …)
  var url = $("vault-url").value;
  var pw = $("pw1").value;
  var pw2 = $("pw2").value;
  if (!url || !pw || !pw2) {
    setStatus($("unlock-status"), "All fields are required.", "err");
    return;
  }
  _unlocking = true;
  _hidePasswords(); // hide before the keys are derived
  $("unlock-btn").disabled = true;
  setStatus($("unlock-status"), "Unlocking… (deriving keys, may take a moment)");
  setProgress(0, 1);
  // Remember the URL for next time (not the passwords).
  try { await api.storage.local.set({ vaultUrl: url }); } catch (e) {}

  var r = await send({ cmd: "unlock", vaultUrl: url, pw: pw, pw2: pw2 });
  _unlocking = false;
  $("unlock-btn").disabled = false;
  if (r && r.ok) {
    $("pw1").value = "";
    $("pw2").value = "";
    setProgress(0, 0); // hide
    await showEntries();
    // Initial unlock only: if auto-lock was already disabled from a previous
    // session, re-acknowledge the indefinitely-unlocked risk once here. We do
    // NOT re-ask on a plain popup reopen of an already-unlocked session (init).
    _maybeConfirmAutoLockDisabled();
  } else if (r && r.error === "aborted") {
    // User clicked back into a password field to fix a typo — keep what they
    // typed and let them re-edit; the workers were already stopped.
    setProgress(0, 0); // hide
    setStatus($("unlock-status"), "");
  } else {
    $("pw1").value = "";
    $("pw2").value = "";
    setProgress(0, 0); // hide
    setStatus($("unlock-status"), (r && r.error) || "Unlock failed.", "err");
  }
}

// ---- Entries flow ----
// Refresh re-reads the vault, but we deliberately do NOT keep the passwords in
// memory — so it re-prompts. Unlock always re-fetches index.html, so re-entering
// the passwords here picks up any changes made in the Edit tab. The background's
// master-key cache stays warm, so unchanged records re-decrypt instantly.
function doRefresh() {
  showUnlock();
  setStatus($("unlock-status"), "Re-enter passwords to re-read the vault.");
  $("pw1").focus();
}

async function showEntries() {
  $("unlock-view").hidden = true;
  $("entries-view").hidden = false;
  $("lock-btn").hidden = false;
  $("refresh-btn").hidden = false;
  _reflectAutoLockGlyph();
  var r = await send({ cmd: "match", host: _tabHost });
  if (r && r.error) {
    // session lost mid-flight
    return showUnlock();
  }
  _entries = (r && r.entries) || [];
  var matches = _entries.filter(function (e) { return e.match; }).length;
  var metaEl = $("meta");
  metaEl.textContent = "";
  var metaL = document.createElement("span");
  metaL.textContent = _entries.length + " entries · " + (matches ? matches + " for " + _tabHost : "none match " + _tabHost);
  metaEl.appendChild(metaL);
  var intg = r && r.integrity;
  if (intg && intg.status === "ok") {
    var metaR = document.createElement("span");
    metaR.className = "meta-r";
    metaR.textContent = "rev " + intg.revision + " · " + new Date(intg.timestamp * 1000).toLocaleDateString();
    metaEl.appendChild(metaR);
  }
  var integrityFailed = intg && intg.status === "fail";
  // Code-integrity pinning: a mismatch means the served app bundle doesn't match
  // the hash this extension pinned — the served javascript.js may have been
  // tampered. Warn prominently and disable autofill (warn-not-block).
  var code = r && r.code;
  var codeMismatch = code && code.status === "mismatch";
  var intNotice = $("integrity-notice");
  if (intNotice) {
    if (integrityFailed) {
      $("integrity-reason").textContent = intg.reason || "HMAC mismatch";
      intNotice.hidden = false;
    } else {
      intNotice.hidden = true;
    }
  }
  var codeNotice = $("code-notice");
  if (codeNotice) {
    if (codeMismatch) {
      $("code-reason").textContent = "Altered: " + (code.reason || "app bundle");
      codeNotice.hidden = false;
    } else {
      codeNotice.hidden = true;
    }
  }
  if (integrityFailed || codeMismatch) {
    $("filter").disabled = true;
    $("filter").value = "";
    render([]);
  } else {
    $("filter").disabled = false;
    render(_entries);
  }
}

function render(list) {
  var ul = $("entries");
  ul.textContent = "";
  if (!list.length) {
    var li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No entries.";
    ul.appendChild(li);
    return;
  }
  _collapse();
  list.forEach(function (e) {
    var li = document.createElement("li");
    if (e.match) li.className = "match";

    var row = document.createElement("div");
    row.className = "entry-row";

    var main = document.createElement("div");
    main.className = "entry-main";
    main.title = "Show details";
    var nm = document.createElement("div");
    nm.className = "entry-name";
    nm.textContent = e.name;
    var sub = document.createElement("div");
    sub.className = "entry-sub";
    sub.textContent = e.username || e.url || "";
    main.appendChild(nm);
    main.appendChild(sub);
    main.addEventListener("click", function () { toggleDetails(li, e.id); });

    var actions = document.createElement("div");
    actions.className = "entry-actions";

    var fillBtn = document.createElement("button");
    fillBtn.textContent = "Fill";
    fillBtn.title = "Fill username + password into this page";
    fillBtn.addEventListener("click", function () { doFill(e.id, fillBtn); });
    actions.appendChild(fillBtn);

    var copyBtn = document.createElement("button");
    copyBtn.textContent = "📋";
    copyBtn.title = "Copy password";
    copyBtn.addEventListener("click", function () { copyPw(e.id, copyBtn); });
    actions.appendChild(copyBtn);

    if (e.hasTotp) {
      var otpBtn = document.createElement("button");
      otpBtn.textContent = "OTP";
      otpBtn.title = "Copy current TOTP code";
      otpBtn.addEventListener("click", function () { copyOtp(e.id, otpBtn); });
      actions.appendChild(otpBtn);
    }

    row.appendChild(main);
    row.appendChild(actions);
    li.appendChild(row);
    ul.appendChild(li);
  });
}

// ---- Inline details panel (one open at a time) ----
var _expandedId = null;
var _otpTimer = null;

function _collapse() {
  if (_otpTimer) { clearInterval(_otpTimer); _otpTimer = null; }
  var open = document.querySelector(".entry-details");
  if (open) open.remove();
  var li = document.querySelector("li.expanded");
  if (li) li.classList.remove("expanded");
  _expandedId = null;
}

async function toggleDetails(li, id) {
  if (_expandedId === id) { _collapse(); return; }
  _collapse();
  _expandedId = id;
  li.classList.add("expanded");
  var panel = document.createElement("div");
  panel.className = "entry-details";
  panel.textContent = "Loading…";
  li.appendChild(panel);
  var d = await send({ cmd: "details", id: id });
  if (_expandedId !== id) return; // collapsed or switched while loading
  if (!d || d.error) { panel.textContent = (d && d.error) || "Failed to load."; return; }
  buildDetails(panel, d, id);
}

// One field row: a dim label + a click-to-copy value. `opts.mask` renders the
// value masked with a 👁 reveal toggle; `opts.link` renders an <a>; `opts.multi`
// keeps newlines (notes).
function fieldRow(label, text, opts) {
  opts = opts || {};
  var row = document.createElement("div");
  row.className = "df-row";
  var lab = document.createElement("div");
  lab.className = "df-label";
  lab.textContent = label;
  row.appendChild(lab);

  var val = document.createElement("div");
  val.className = "df-val" + (opts.multi ? " multi" : "");

  if (opts.link && /^https?:\/\//i.test(text)) {
    var a = document.createElement("a");
    a.href = text;
    a.textContent = text;
    a.target = "_blank";
    a.rel = "noopener";
    val.appendChild(a);
  } else {
    var span = document.createElement("span");
    span.className = "df-text";
    var revealed = !opts.mask;
    function paint() { span.textContent = revealed ? text : "•".repeat(Math.min(12, Math.max(6, text.length))); }
    paint();
    if (!opts.mask) {
      span.title = "Click to copy";
      span.style.cursor = "pointer";
      span.addEventListener("click", function () { copyText(text, span, paint); });
    }
    val.appendChild(span);
    if (opts.mask) {
      var eye = document.createElement("button");
      eye.className = "df-eye";
      eye.textContent = "👁";
      eye.title = "Show/hide";
      eye.addEventListener("click", function () {
        revealed = !revealed;
        eye.textContent = revealed ? "🙈" : "👁";
        paint();
      });
      val.appendChild(eye);
      var cp = document.createElement("button");
      cp.className = "df-eye";
      cp.textContent = "📋";
      cp.title = "Copy";
      cp.addEventListener("click", function () { copyText(text, cp, function () { cp.textContent = "📋"; }, true); });
      val.appendChild(cp);
    }
  }
  row.appendChild(val);
  return row;
}

function buildDetails(panel, d, id) {
  panel.textContent = "";
  if (d.url) panel.appendChild(fieldRow("URL", d.url, { link: true }));
  if (d.username) panel.appendChild(fieldRow("Username", d.username));
  if (d.password) panel.appendChild(fieldRow("Password", d.password, { mask: true }));

  if (d.hasTotp) {
    var row = document.createElement("div");
    row.className = "df-row";
    var lab = document.createElement("div");
    lab.className = "df-label";
    lab.textContent = "TOTP";
    var val = document.createElement("div");
    val.className = "df-val";
    var code = document.createElement("span");
    code.className = "df-text totp";
    code.textContent = "……";
    code.title = "Click to copy";
    code.style.cursor = "pointer";
    val.appendChild(code);
    row.appendChild(lab);
    row.appendChild(val);
    panel.appendChild(row);
    startOtp(code, id);
  }

  if (d.notes) panel.appendChild(fieldRow("Notes", d.notes, { multi: true }));
  // Tags and custom (extra) fields are intentionally not shown in the extension —
  // the expanded entry surfaces only URL / Username / Password / TOTP / Notes.
}

async function startOtp(codeEl, id) {
  async function upd() {
    var r = await send({ cmd: "totp", id: id });
    if (!r || !r.code) { codeEl.textContent = "—"; return; }
    codeEl.textContent = r.code + "  " + r.remaining + "s";
    codeEl.onclick = function () { copyText(r.code, codeEl, function () { codeEl.textContent = r.code + "  " + r.remaining + "s"; }, true); };
  }
  await upd();
  _otpTimer = setInterval(upd, 1000);
}

// Tell the background page a secret is now on the clipboard so it can arm the
// 45s auto-clear. The popup can't run that timer itself — it usually closes
// within a second of the copy.
function armClipClear() {
  try { send({ cmd: "clipDirty" }); } catch (e) {}
}

async function copyText(text, el, restore, secret) {
  try {
    await navigator.clipboard.writeText(text);
    if (secret) armClipClear();
    var prev = el.textContent;
    el.textContent = "Copied ✓";
    setTimeout(function () { restore ? restore() : (el.textContent = prev); }, 900);
  } catch (e) {}
}

async function doFill(id, btn) {
  btn.disabled = true;
  // Re-query the active tab now rather than trusting the one captured at popup
  // open: clicking an entry's URL link opens (and activates) a new tab while the
  // popup stays up, so the captured _tabId would be stale and fill the wrong tab.
  var tab = await currentTab();
  var tabId = (tab && tab.id) || _tabId;
  var r = await send({ cmd: "fill", id: id, tabId: tabId });
  btn.disabled = false;
  flash(btn, r && r.ok ? "✓" : "✗", "Fill");
}

async function copyPw(id, btn) {
  var r = await send({ cmd: "reveal", id: id });
  if (r && r.password != null) {
    await navigator.clipboard.writeText(r.password);
    armClipClear();
    flash(btn, "✓", "📋");
  }
}

async function copyOtp(id, btn) {
  var r = await send({ cmd: "totp", id: id });
  if (r && r.code) {
    await navigator.clipboard.writeText(r.code);
    armClipClear();
    flash(btn, r.code, "OTP");
  } else {
    flash(btn, "✗", "OTP");
  }
}

function flash(btn, text, restore) {
  var old = btn.textContent;
  btn.textContent = text;
  setTimeout(function () { btn.textContent = restore || old; }, 1100);
}

function showUnlock() {
  $("entries-view").hidden = true;
  $("unlock-view").hidden = false;
  $("lock-btn").hidden = true;
  $("refresh-btn").hidden = true;
  _reflectAutoLockGlyph();
  setStatus($("unlock-status"), "");
}

// ---- About modal ----
async function openAbout() {
  // Reflect the current auto-lock preference (checkbox = "disabled").
  try {
    var s = await api.storage.local.get("autoLock");
    $("disable-autolock").checked = s && s.autoLock === false;
  } catch (e) {}
  try {
    $("about-version").textContent = api.runtime.getManifest().version;
  } catch (e) {}
  $("about-overlay").hidden = false;
}
function closeAbout() {
  $("about-overlay").hidden = true;
}

// Open the vault web app in a new tab so the user can add/edit entries.
async function openVault() {
  var url = ($("vault-url").value || "").trim();
  if (!url) {
    try {
      var s = await api.storage.local.get("vaultUrl");
      url = (s && s.vaultUrl) || "";
    } catch (e) {}
  }
  if (!url) {
    setStatus($("unlock-status"), "Set a vault URL first.", "err");
    $("vault-url").focus();
    return;
  }
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  api.tabs.create({ url: url });
  window.close();
}

async function init() {
  var tab = await currentTab();
  _tabId = tab && tab.id;
  try { _tabHost = new URL(tab.url).hostname.toLowerCase().replace(/^www\./, ""); } catch (e) { _tabHost = ""; }

  try {
    var s = await api.storage.local.get(["vaultUrl", "autoLock"]);
    if (s && s.vaultUrl) $("vault-url").value = s.vaultUrl;
    _autoLockDisabled = s && s.autoLock === false;
  } catch (e) {}

  $("unlock-btn").addEventListener("click", doUnlock);
  // Match the PWA key-field tab order: Tab from the primary password clears +
  // jumps straight to the secondary (and Shift+Tab back), skipping the eye
  // show/hide buttons that sit between them in DOM order.
  $("pw1").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { doUnlock(); return; }
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      var p2 = $("pw2");
      p2.value = "";
      p2.focus();
    }
  });
  $("pw2").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { doUnlock(); return; }
    if (e.key === "Tab" && e.shiftKey) {
      e.preventDefault();
      var p1 = $("pw1");
      p1.value = "";
      p1.focus();
      return;
    }
    // Tabbing off the secondary password starts decoding when both fields are
    // filled (mirrors the PWA, which reveals on blur of the 2nd key field).
    if (e.key === "Tab" && !e.shiftKey && $("pw1").value && $("pw2").value) {
      e.preventDefault();
      doUnlock();
    }
  });

  // Editing either password field while a decode is running aborts it — stops
  // all workers — so the user can fix a mistyped password. We listen on `input`
  // (an actual edit) rather than `focus`: the Tab-to-unlock path leaves pw2
  // focused, and _hidePasswords() flips the field's `type`, which can emit a
  // spurious focus event that would otherwise self-abort the decode instantly.
  ["pw1", "pw2"].forEach(function (id) {
    $(id).addEventListener("input", function () {
      if (_unlocking) send({ cmd: "abort" });
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll(".eye"), function (btn) {
    btn.addEventListener("click", function () { toggleEye(btn); });
  });
  $("about-btn").addEventListener("click", openAbout);
  $("about-close").addEventListener("click", closeAbout);
  $("disable-autolock").addEventListener("change", function () {
    // Turning it ON (disabling auto-lock) requires explicit confirmation, like
    // the PWA; cancelling reverts the checkbox without changing anything.
    if (this.checked && !window.confirm(_autolockConfirmMsg)) {
      this.checked = false;
      return;
    }
    _setAutoLockDisabled(this.checked);
  });
  $("about-overlay").addEventListener("click", function (e) {
    if (e.target === this) closeAbout();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !$("about-overlay").hidden) closeAbout();
  });
  $("edit-btn").addEventListener("click", openVault);
  $("refresh-btn").addEventListener("click", doRefresh);
  $("lock-btn").addEventListener("click", async function () {
    await send({ cmd: "lock" });
    showUnlock();
  });
  $("filter").addEventListener("input", function () {
    var q = this.value.toLowerCase();
    render(
      _entries.filter(function (e) {
        return (
          e.name.toLowerCase().includes(q) ||
          (e.username || "").toLowerCase().includes(q) ||
          (e.url || "").toLowerCase().includes(q)
        );
      })
    );
  });

  // Await the crypto self-test before showing the unlock form.
  // On failure: disable inputs and show a notice; on pass: proceed normally.
  var stResult = await send({ cmd: "selftest" });
  if (stResult && !stResult.ok) {
    var notice = $("selftest-notice");
    if (notice) notice.hidden = false;
    var failList = $("selftest-failures");
    if (failList) {
      failList.textContent = "";
      (stResult.failures || []).forEach(function (f) {
        var li = document.createElement("li");
        li.textContent = f;
        failList.appendChild(li);
      });
    }
    [$("pw1"), $("pw2"), $("unlock-btn")].forEach(function (el) { if (el) el.disabled = true; });
  }

  var st = await send({ cmd: "status" });
  if (st && st.unlocked) {
    if (st.vaultUrl) $("vault-url").value = st.vaultUrl;
    await showEntries();
    // Reopening the popup on an already-unlocked session must NOT re-prompt the
    // auto-lock confirmation — that only happens at the About toggle and at the
    // initial unlock (see doUnlock / _maybeConfirmAutoLockDisabled).
  } else {
    showUnlock();
    if (!stResult || stResult.ok) $("pw1").focus();
  }
}

init();
