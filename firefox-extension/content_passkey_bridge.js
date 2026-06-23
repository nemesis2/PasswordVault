// content_passkey_bridge.js — Firefox MV2 content script (ISOLATED world).
//
// Firefox MV2 has no `world:"MAIN"` content scripts, so this bridge does two
// things at document_start:
//   1. Injects passkey-inpage.js into the PAGE (MAIN world) by appending a
//      <script> — that is the navigator.credentials interceptor (it needs the
//      page's JS context). passkey-inpage.js is a web_accessible_resource.
//   2. Relays the interceptor's window.postMessage requests to the background
//      page over a long-lived Port and posts the reply back into the page. The
//      trusted page origin is taken from location.origin here, not from the
//      (page-tamperable) MAIN script.

(function () {
  "use strict";
  var api = typeof browser !== "undefined" ? browser : chrome;

  // 1. Inject the MAIN-world interceptor before page scripts run.
  try {
    var s = document.createElement("script");
    s.src = api.runtime.getURL("passkey-inpage.js");
    s.async = false;
    s.onload = function () { s.remove(); };
    (document.head || document.documentElement).appendChild(s);
  } catch (e) {}

  // 2. Relay window <-> background port.
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
    try { port = api.runtime.connect({ name: "passkey" }); }
    catch (e) { return reply({ passthrough: true }); }

    port.onMessage.addListener(function (result) {
      reply(result || { error: "no response" });
      try { port.disconnect(); } catch (e) {}
    });
    port.onDisconnect.addListener(function () { reply({ passthrough: true }); });
    try { port.postMessage({ cmd: cmd, options: d.options, origin: window.location.origin }); }
    catch (e) { reply({ passthrough: true }); }
  });
})();
