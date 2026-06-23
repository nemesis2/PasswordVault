// content_passkey_bridge.js — runs in the ISOLATED world at document_start.
//
// The MAIN-world interceptor (content_passkey_main.js) has no chrome.* access, so
// this bridge relays its window.postMessage requests to the extension and posts
// the reply back into the page. It adds the trusted page origin (location.origin
// here is authoritative — the MAIN script shares the page's context and could be
// tampered with) so the offscreen document scopes the credential correctly.
//
// A passkey ceremony can outlive a one-shot message (the user types passwords in
// an approval window), so each request opens a long-lived Port: an open port
// keeps the MV3 service worker from being torn down mid-ceremony, and the result
// arrives as a port message.

(function () {
  "use strict";
  var api = typeof browser !== "undefined" ? browser : chrome;

  window.addEventListener("message", function (ev) {
    if (ev.source !== window) return;
    var d = ev.data;
    if (!d || d.__vaultPasskey !== "req") return;
    var cmd = d.kind === "create" ? "passkey-create" : d.kind === "get" ? "passkey-get" : null;
    if (!cmd) return;

    var replied = false;
    function reply(result) {
      if (replied) return;
      replied = true;
      window.postMessage({ __vaultPasskey: "res", id: d.id, result: result }, ev.origin || "*");
    }

    var port;
    try {
      port = api.runtime.connect({ name: "passkey" });
    } catch (e) {
      return reply({ passthrough: true });
    }
    port.onMessage.addListener(function (result) {
      reply(result || { error: "no response" });
      try { port.disconnect(); } catch (e) {}
    });
    port.onDisconnect.addListener(function () {
      // Service worker died or extension reloaded before answering → fall back to
      // the native authenticator rather than hanging the page.
      reply({ passthrough: true });
    });
    try {
      port.postMessage({ cmd: cmd, options: d.options, origin: window.location.origin });
    } catch (e) {
      reply({ passthrough: true });
    }
  });
})();
