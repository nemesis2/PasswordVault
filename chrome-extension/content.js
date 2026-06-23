// content.js — injected on demand to fill credentials into the page.
//
// Programmatically executed by the background script (one-shot) when the user
// clicks "Fill", then receives a doFill message with the username/password.

(function () {
  "use strict";
  var api = typeof browser !== "undefined" ? browser : chrome;

  if (window.__vaultFillBound) return;
  window.__vaultFillBound = true;

  // ---- Origin gate ----
  // Only fill a frame whose host matches the entry's stored URL. This stops a
  // third-party iframe embedded on the target page from capturing an autofilled
  // credential (the script is injected into all frames, but each frame decides
  // for itself whether it's allowed to fill). Mirrors background.js's host match.
  function _hostOf(u) {
    try {
      return new URL(/^[a-z]+:\/\//i.test(u) ? u : "https://" + u)
        .hostname.toLowerCase().replace(/^www\./, "");
    } catch (e) {
      return "";
    }
  }
  // A small public-suffix / multi-tenant-host guard so suffix matching never
  // treats a shared parent (a bare TLD, co.uk, or a hosting domain like
  // github.io / web.app) as the registrable domain — which would cross-match
  // unrelated sites. Not a full PSL, but covers the common shared hosts.
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
  function _hostMatch(entryHost, frameHost) {
    if (!entryHost || !frameHost) return false;
    if (entryHost === frameHost) return true;
    // Only allow a subdomain<->parent match when the shared parent is a real
    // registrable domain, never a public suffix / multi-tenant host.
    if (frameHost.endsWith("." + entryHost) && !_isPubSuffix(entryHost)) return true;
    if (entryHost.endsWith("." + frameHost) && !_isPubSuffix(frameHost)) return true;
    return false;
  }
  function _fillAllowed(entryUrl) {
    var entryHost = _hostOf(entryUrl || "");
    var frameHost = (location.hostname || "").toLowerCase().replace(/^www\./, "");
    // No URL on the entry → nothing to match against, so restrict to the top
    // frame; a cross-origin sub-frame can never be autofilled in that case.
    if (!entryHost) return window.top === window.self;
    return _hostMatch(entryHost, frameHost);
  }

  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    var r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    var st = getComputedStyle(el);
    return st.visibility !== "hidden" && st.display !== "none";
  }

  function setValue(el, value) {
    // React/Vue controlled inputs ignore plain .value writes; go through the
    // native setter then dispatch input+change so frameworks notice.
    var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function findFields() {
    var pwFields = Array.prototype.filter.call(
      document.querySelectorAll('input[type="password"]'),
      visible
    );
    var pw = pwFields[0] || null;

    var user = null;
    // Prefer an explicit username/email field near the password. When the
    // password is inside a <form>, restrict candidates to that same form first
    // so a second login/search form elsewhere on the page can't be targeted.
    var SEL =
      'input[type="text"], input[type="email"], input[type="tel"], input[autocomplete="username"], input:not([type])';
    var scope = (pw && pw.form) || document;
    var candidates = Array.prototype.filter.call(scope.querySelectorAll(SEL), visible);
    if (pw && pw.form && !candidates.length) {
      // Form had no usable text field — widen to the whole document.
      candidates = Array.prototype.filter.call(document.querySelectorAll(SEL), visible);
    }
    if (pw) {
      // Closest preceding text/email input in document order.
      var before = candidates.filter(function (c) {
        return pw.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_PRECEDING;
      });
      user = before[before.length - 1] || candidates[0] || null;
    } else {
      user = candidates[0] || null;
    }
    return { user: user, pw: pw };
  }

  function doFillNow(f, msg) {
    var filled = [];
    if (f.user && msg.username) {
      setValue(f.user, msg.username);
      filled.push("username");
    }
    if (f.pw && msg.password) {
      setValue(f.pw, msg.password);
      filled.push("password");
    }
    if (f.pw) f.pw.focus();
    return filled;
  }

  api.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.cmd !== "doFill") return;
    // A frame that isn't allowed stays silent (no sendResponse, channel not kept
    // open) so it can't shadow a matching frame's reply — only allowed frames
    // fill and respond.
    if (!_fillAllowed(msg.entryUrl)) return;
    // Readiness guard: the page (often just opened via the entry's URL link) may
    // still be rendering its login form when Fill is clicked. Poll briefly for
    // the fields to appear before giving up, so an early click still lands.
    var start = Date.now();
    var MAX_WAIT = 4000; // overall budget
    var USER_GRACE = 800; // if only a username field is up, wait a bit for a pw
    var POLL = 150;

    function attempt() {
      var f = findFields();
      var elapsed = Date.now() - start;
      // Fill once the password field is present; for staged (username-first)
      // logins, fall back to filling just the username after a short grace.
      if (f.pw || (f.user && elapsed >= USER_GRACE)) {
        var filled = doFillNow(f, msg);
        sendResponse({ ok: filled.length > 0, filled: filled });
      } else if (elapsed < MAX_WAIT) {
        setTimeout(attempt, POLL);
      } else {
        sendResponse({ ok: false, filled: [] });
      }
    }
    attempt();
    return true; // keep the message channel open for the async sendResponse
  });
})();
