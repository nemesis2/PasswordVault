// webauthn.js — WebAuthn byte-structure builders for the passkey flows.
//
// The vault acts as a software authenticator: the relying party validates these
// structures cryptographically, so they must be byte-perfect. We only ever
// *encode* CBOR (the COSE public key and the registration attestationObject), so
// this ships a ~40-line CBOR encoder rather than bundling a full CBOR library —
// keeping the extension small and CSP-clean. No CBOR decoder is needed.
//
// Exposes globalThis.WebAuthnKit. Runs in the offscreen document (Chrome) and the
// background page (Firefox); both have crypto.subtle / TextEncoder / btoa/atob.

(function () {
  "use strict";

  var _TE = new TextEncoder();

  // ---- base64url <-> bytes ----
  function bytesToB64url(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function _concat(arrays) {
    var len = 0, i;
    for (i = 0; i < arrays.length; i++) len += arrays[i].length;
    var out = new Uint8Array(len);
    var o = 0;
    for (i = 0; i < arrays.length; i++) { out.set(arrays[i], o); o += arrays[i].length; }
    return out;
  }

  // ---- minimal CBOR encoder (encode only) ----
  // Supports: unsigned/negative ints, byte strings (Uint8Array), text strings,
  // and ordered maps. Maps are passed as [[k,v],...] wrapped via cborMap() so key
  // order is preserved.
  function _cborHead(major, len) {
    var mt = major << 5;
    if (len < 24) return Uint8Array.of(mt | len);
    if (len < 0x100) return Uint8Array.of(mt | 24, len & 0xff);
    if (len < 0x10000) return Uint8Array.of(mt | 25, (len >> 8) & 0xff, len & 0xff);
    return Uint8Array.of(mt | 26, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
  }
  function cborMap(entries) { return { __cborMap: true, entries: entries }; }
  function _cbor(value) {
    if (typeof value === "number") {
      if (!Number.isInteger(value)) throw new Error("CBOR: non-integer number");
      if (value >= 0) return _cborHead(0, value);
      return _cborHead(1, -1 - value);
    }
    if (value instanceof Uint8Array) {
      return _concat([_cborHead(2, value.length), value]);
    }
    if (typeof value === "string") {
      var b = _TE.encode(value);
      return _concat([_cborHead(3, b.length), b]);
    }
    if (value && value.__cborMap) {
      var parts = [_cborHead(5, value.entries.length)];
      value.entries.forEach(function (e) { parts.push(_cbor(e[0])); parts.push(_cbor(e[1])); });
      return _concat(parts);
    }
    throw new Error("CBOR: unsupported value");
  }
  function cborEncode(value) { return _cbor(value); }

  // ---- COSE public key (EC2 / ES256 / P-256) from a JWK ----
  // {1:2 (kty EC2), 3:-7 (alg ES256), -1:1 (crv P-256), -2:x, -3:y}
  function cosePublicKey(publicKeyJwk) {
    var x = b64urlToBytes(publicKeyJwk.x);
    var y = b64urlToBytes(publicKeyJwk.y);
    return _cbor(cborMap([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
  }

  // ---- attestedCredentialData: aaguid(16,0) | credIdLen(2) | credId | cosePub ----
  function attestedCredentialData(credentialId, cosePub) {
    var out = new Uint8Array(16 + 2 + credentialId.length + cosePub.length);
    out[16] = (credentialId.length >> 8) & 0xff;
    out[17] = credentialId.length & 0xff;
    out.set(credentialId, 18);
    out.set(cosePub, 18 + credentialId.length);
    return out;
  }

  // ---- authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | [attested] ----
  // flags: 0x45 (UP|UV|AT) for create, 0x05 (UP|UV) for get.
  async function authenticatorData(rpId, flags, signCount, attested) {
    var rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", _TE.encode(rpId)));
    var out = new Uint8Array(37 + (attested ? attested.length : 0));
    out.set(rpIdHash, 0);
    out[32] = flags & 0xff;
    out[33] = (signCount >>> 24) & 0xff;
    out[34] = (signCount >>> 16) & 0xff;
    out[35] = (signCount >>> 8) & 0xff;
    out[36] = signCount & 0xff;
    if (attested) out.set(attested, 37);
    return out;
  }

  // ---- attestationObject (fmt "none"): {fmt, attStmt:{}, authData} ----
  function attestationObject(authData) {
    return _cbor(cborMap([["fmt", "none"], ["attStmt", cborMap([])], ["authData", authData]]));
  }

  // ---- clientDataJSON bytes ----
  // challengeB64url must be the base64url of the RP's original challenge bytes.
  function clientDataJSON(type, challengeB64url, origin) {
    return _TE.encode(JSON.stringify({
      type: type, challenge: challengeB64url, origin: origin, crossOrigin: false,
    }));
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  // ---- IEEE P1363 (r||s, 64B) -> DER ECDSA signature ----
  // P-256 DER bodies stay < 128 bytes, so single-byte DER lengths suffice.
  function p1363ToDer(sig) {
    function trim(b) {
      var i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      b = b.slice(i);
      if (b[0] & 0x80) { var t = new Uint8Array(b.length + 1); t.set(b, 1); b = t; }
      return b;
    }
    var r = trim(sig.slice(0, 32));
    var s = trim(sig.slice(32, 64));
    var body = new Uint8Array(2 + r.length + 2 + s.length);
    var o = 0;
    body[o++] = 0x02; body[o++] = r.length; body.set(r, o); o += r.length;
    body[o++] = 0x02; body[o++] = s.length; body.set(s, o); o += s.length;
    var out = new Uint8Array(2 + body.length);
    out[0] = 0x30; out[1] = body.length; out.set(body, 2);
    return out;
  }

  globalThis.WebAuthnKit = {
    bytesToB64url: bytesToB64url,
    b64urlToBytes: b64urlToBytes,
    cborEncode: cborEncode,
    cborMap: cborMap,
    cosePublicKey: cosePublicKey,
    attestedCredentialData: attestedCredentialData,
    authenticatorData: authenticatorData,
    attestationObject: attestationObject,
    clientDataJSON: clientDataJSON,
    sha256: sha256,
    p1363ToDer: p1363ToDer,
  };
})();
