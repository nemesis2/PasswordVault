// content_passkey_main.js — runs in the page's MAIN world at document_start.
//
// Overrides navigator.credentials.create/get so the vault can act as a WebAuthn
// authenticator. The MAIN world shares the page's JS context (required to replace
// navigator.credentials) but has NO chrome.* APIs, so it relays requests to the
// ISOLATED-world bridge (content_passkey_bridge.js) via window.postMessage; the
// bridge talks to the extension and posts the reply back here.
//
// Sensitive crypto never happens here — this only serializes the request, awaits
// a synthetic credential built in the offscreen document, and rebuilds a
// PublicKeyCredential-shaped object the relying party can consume.

(function () {
  "use strict";
  if (!navigator.credentials || !window.PublicKeyCredential) return;

  var _nativeCreate = navigator.credentials.create.bind(navigator.credentials);
  var _nativeGet = navigator.credentials.get.bind(navigator.credentials);

  // ---- base64url <-> ArrayBuffer ----
  function abToB64url(buf) {
    var b = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlToAb(str) {
    str = String(str).replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    var bin = atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  // ---- request/response bridge over window.postMessage ----
  var _seq = 0;
  var _pending = {};
  // NOTE: this runs in the page's MAIN world, so page script shares this context
  // and could post a forged {__vaultPasskey:"res"} reply. That is not a privilege
  // escalation: the page can already call the native API itself, and it can never
  // forge a *vault-signed* assertion (the private key lives in the extension) — a
  // forged reply can at most make this call fall back to native or hand the page a
  // credential it fabricated for itself. We still gate on a pending id so unrelated
  // page messages can't resolve a request.
  window.addEventListener("message", function (ev) {
    if (ev.source !== window) return;
    var d = ev.data;
    if (!d || d.__vaultPasskey !== "res") return;
    var p = _pending[d.id];
    if (!p) return;
    delete _pending[d.id];
    p(d.result);
  });
  function ask(kind, options) {
    return new Promise(function (resolve) {
      var id = "pk" + (++_seq) + "-" + Date.now();
      _pending[id] = resolve;
      window.postMessage({ __vaultPasskey: "req", id: id, kind: kind, options: options }, window.origin || "*");
      // Safety timeout: if the bridge never answers, fall through to native.
      setTimeout(function () {
        if (_pending[id]) { delete _pending[id]; resolve({ timeout: true }); }
      }, 120000);
    });
  }

  function _serMappedCred(c) {
    return { type: c.type, id: abToB64url(c.id), transports: c.transports || undefined };
  }
  function _serCreate(publicKey) {
    return {
      challenge: abToB64url(publicKey.challenge),
      rp: publicKey.rp ? { id: publicKey.rp.id, name: publicKey.rp.name } : {},
      user: publicKey.user
        ? { id: abToB64url(publicKey.user.id), name: publicKey.user.name, displayName: publicKey.user.displayName }
        : {},
      pubKeyCredParams: publicKey.pubKeyCredParams || [],
      timeout: publicKey.timeout,
      attestation: publicKey.attestation,
      authenticatorSelection: publicKey.authenticatorSelection,
      excludeCredentials: (publicKey.excludeCredentials || []).map(_serMappedCred),
    };
  }
  function _serGet(publicKey) {
    return {
      challenge: abToB64url(publicKey.challenge),
      rpId: publicKey.rpId,
      timeout: publicKey.timeout,
      userVerification: publicKey.userVerification,
      allowCredentials: (publicKey.allowCredentials || []).map(_serMappedCred),
    };
  }

  // Rebuild a PublicKeyCredential-shaped object from the serialized response.
  function _buildCredential(cred, isCreate) {
    var resp;
    if (isCreate) {
      resp = {
        clientDataJSON: b64urlToAb(cred.response.clientDataJSON),
        attestationObject: b64urlToAb(cred.response.attestationObject),
        getTransports: function () { return cred.response.transports || []; },
        getAuthenticatorData: function () {
          return cred.response.authenticatorData ? b64urlToAb(cred.response.authenticatorData) : null;
        },
        getPublicKey: function () {
          return cred.response.publicKeyDer ? b64urlToAb(cred.response.publicKeyDer) : null;
        },
        getPublicKeyAlgorithm: function () { return -7; },
      };
    } else {
      resp = {
        clientDataJSON: b64urlToAb(cred.response.clientDataJSON),
        authenticatorData: b64urlToAb(cred.response.authenticatorData),
        signature: b64urlToAb(cred.response.signature),
        userHandle: cred.response.userHandle ? b64urlToAb(cred.response.userHandle) : null,
      };
    }
    var obj = {
      id: cred.id,
      rawId: b64urlToAb(cred.rawId),
      type: "public-key",
      authenticatorAttachment: cred.authenticatorAttachment || "platform",
      response: resp,
      getClientExtensionResults: function () { return {}; },
    };
    // Help libraries that check `instanceof PublicKeyCredential`.
    try { Object.setPrototypeOf(obj, window.PublicKeyCredential.prototype); } catch (e) {}
    return obj;
  }

  async function interceptCreate(options) {
    if (!options || !options.publicKey) return _nativeCreate(options);
    var pk = options.publicKey;
    // Only ES256 (alg -7) is supported; if the RP doesn't allow it, defer to the
    // browser's own authenticators.
    var params = pk.pubKeyCredParams || [];
    if (params.length && !params.some(function (p) { return p.alg === -7; })) {
      return _nativeCreate(options);
    }
    // If the RP explicitly wants a roaming/security-key authenticator, don't
    // hijack it with a platform-style vault passkey.
    var sel = pk.authenticatorSelection || {};
    if (sel.authenticatorAttachment === "cross-platform") {
      return _nativeCreate(options);
    }
    var res = await ask("create", _serCreate(pk));
    if (res && res.ok && res.credential) return _buildCredential(res.credential, true);
    // passthrough ("Use this device instead"), timeout, or the user declining the
    // vault → fall back to the browser's native authenticator rather than failing
    // the whole ceremony, so native passkey enrollment still works everywhere.
    // Re-focus the page first: the approval window stole focus, and the browser
    // refuses a native WebAuthn call from an unfocused document
    // ("CredentialsContainer request is not allowed.").
    if (res && (res.passthrough || res.timeout || res.native)) {
      try { window.focus(); } catch (e) {}
      return _nativeCreate(options);
    }
    throw new DOMException((res && res.error) || "Passkey creation failed", "NotAllowedError");
  }

  async function interceptGet(options) {
    if (!options || !options.publicKey) return _nativeGet(options);
    // Conditional / silent mediation (passkey autofill, page-load discovery) must
    // never raise modal UI — defer straight to the browser's native handling so
    // we don't pop an unsolicited unlock/approval window while browsing.
    if (options.mediation === "conditional" || options.mediation === "silent") {
      return _nativeGet(options);
    }
    var res = await ask("get", _serGet(options.publicKey));
    if (res && res.ok && res.credential) return _buildCredential(res.credential, false);
    // Re-focus before deferring to native — see interceptCreate above.
    if (res && (res.passthrough || res.timeout || res.native)) {
      try { window.focus(); } catch (e) {}
      return _nativeGet(options);
    }
    throw new DOMException((res && res.error) || "Passkey assertion failed", "NotAllowedError");
  }

  // Replace the methods. Non-configurable so page scripts can't clobber them.
  try {
    Object.defineProperty(navigator.credentials, "create", {
      configurable: false, enumerable: true,
      value: function (options) { return interceptCreate(options); },
    });
    Object.defineProperty(navigator.credentials, "get", {
      configurable: false, enumerable: true,
      value: function (options) { return interceptGet(options); },
    });
  } catch (e) {
    // If the property is already locked down, leave the native impl in place.
  }
})();
