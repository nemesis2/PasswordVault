// crypto-vault.js — standalone orchestration layer for the Firefox companion.
//
// The four cipher bundles (ChaCha20-Poly1305, Twofish, Serpent, Argon2id) and
// the twofishCTR/serpentCTR helpers are loaded verbatim from crypto-ciphers.js
// (a byte-for-byte slice of the vault's javascript.js, lines 1-1641), so the
// extension decrypts with the *exact* code path the web app uses — no
// reimplementation to drift. This file reimplements only the thin, DOM-free
// orchestration: key derivation, HKDF, the v6 decrypt flows, TOTP, and record
// parsing. It mirrors the same-named functions in javascript.js.
//
// Exposes globalThis.VaultCrypto.

(function () {
  "use strict";

  var _TE = new TextEncoder();
  var _TD = new TextDecoder();

  var _HEX = [];
  for (var _h = 0; _h < 256; _h++) _HEX[_h] = (_h + 256).toString(16).slice(1);

  function bytesToHex(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++) out += _HEX[bytes[i]];
    return out;
  }

  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("Odd-length hex string");
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // HKDF info labels — must match javascript.js exactly.
  var _HK = {
    nameAes: "v6|name|aes-gcm",
    nameChacha: "v6|name|chacha20",
    payAes: "v6|pay|aes-gcm",
    payChacha: "v6|pay|chacha20",
    payTwofish: "v6|pay|twofish",
    paySerpent: "v6|pay|serpent",
  };

  // KDF defaults / bounds — mirror javascript.js + post.php is_valid_kdf().
  var DEFAULT_KDF = { iterations: 3, memorySize: 131072, parallelism: 1, hashLength: 32 };
  var KDF_MEM_MIN_KIB = 65536,
    KDF_MEM_MAX_KIB = 1048576,
    KDF_TIME_MIN = 2,
    KDF_TIME_MAX = 10;

  function parseKdf(s) {
    if (typeof s !== "string") return null;
    var p = s.split("|");
    if (p.length !== 4 || p[0] !== "a2id") return null;
    if (!/^\d{1,10}$/.test(p[1]) || !/^\d{1,10}$/.test(p[2]) || !/^\d{1,10}$/.test(p[3])) return null;
    var m = parseInt(p[1], 10),
      t = parseInt(p[2], 10),
      pp = parseInt(p[3], 10);
    if (m < KDF_MEM_MIN_KIB || m > KDF_MEM_MAX_KIB) return null;
    if (t < KDF_TIME_MIN || t > KDF_TIME_MAX) return null;
    if (pp !== 1) return null;
    return { iterations: t, memorySize: m, parallelism: pp, hashLength: 32 };
  }

  // ============================================================
  // Argon2id Web Worker pool — mirrors javascript.js so the extension gets the
  // same real parallelism instead of running every memory-hard derivation
  // serially on the background page's single thread. Each worker (the served
  // argon2-worker.js) owns its own WASM instance. deriveMasterKey dispatches
  // through _argonDerive, which prefers the pool and falls back to the in-process
  // argon2idHash if Workers are unavailable or error out.
  // ============================================================
  var _ARGON_POOL_MAX = 24;
  var _ARGON_POOL_MAX_MOBILE = 2;
  var _ARGON_RETRIES = 2;
  var WORKER_URL = "argon2-worker.js"; // resolved relative to the background page

  var _pool = null; // [{ worker, busy }]
  var _workersOK = true;
  var _jobs = new Map(); // id -> { resolve, reject, slot }
  var _queue = [];
  var _jobSeq = 0;
  // Per-worker heap size (the active vault memory cost, KiB) used to bound the
  // pool by a RAM budget. Set by setActiveKdf() at unlock; defaults to 128 MiB.
  var _activeMemKiB = DEFAULT_KDF.memorySize;

  function setActiveKdf(kdf) {
    _activeMemKiB = (kdf && kdf.memorySize) || DEFAULT_KDF.memorySize;
  }

  function _isMobile() {
    if (typeof navigator === "undefined") return false;
    if (navigator.userAgentData && typeof navigator.userAgentData.mobile === "boolean") {
      return navigator.userAgentData.mobile;
    }
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet/i.test(
      navigator.userAgent || ""
    );
  }

  function poolSize() {
    var hc = (typeof navigator !== "undefined" && navigator.hardwareConcurrency) || 2;
    var cap = _isMobile() ? _ARGON_POOL_MAX_MOBILE : _ARGON_POOL_MAX;
    var byCores = Math.max(1, Math.min(hc, cap));
    var devGiB = (typeof navigator !== "undefined" && navigator.deviceMemory) || 0;
    if (!devGiB) return byCores;
    var budgetMiB = devGiB * 1024 * 0.5; // at most ~half of RAM
    var byMem = Math.max(1, Math.floor(budgetMiB / (_activeMemKiB / 1024)));
    return Math.min(byCores, byMem);
  }

  function _initPool() {
    if (_pool || !_workersOK) return;
    if (typeof Worker === "undefined") {
      _workersOK = false;
      return;
    }
    try {
      _pool = [];
      var n = poolSize();
      for (var i = 0; i < n; i++) {
        var w = new Worker(WORKER_URL);
        w.onmessage = _onMsg;
        w.onerror = _onErr;
        _pool.push({ worker: w, busy: false });
      }
    } catch (e) {
      _workersOK = false;
      _pool = null;
    }
  }

  function terminatePool() {
    var pool = _pool;
    _pool = null;
    if (pool) pool.forEach(function (s) { try { s.worker.terminate(); } catch (_) {} });
    _jobs.forEach(function (j) { j.reject(new Error("argon2 pool terminated")); });
    _jobs.clear();
    var q = _queue;
    _queue = [];
    q.forEach(function (j) { j.reject(new Error("argon2 pool terminated")); });
  }

  function _onMsg(e) {
    var d = e.data;
    var job = _jobs.get(d.id);
    if (!job) return;
    _jobs.delete(d.id);
    job.slot.busy = false;
    if (d.error) job.reject(new Error(d.error));
    else job.resolve(d.hash);
    _drain();
  }

  function _onErr(e) {
    try { e.preventDefault && e.preventDefault(); } catch (_) {}
    _workersOK = false;
    terminatePool();
  }

  function _drain() {
    if (!_pool) return;
    for (var i = 0; i < _pool.length && _queue.length; i++) {
      var slot = _pool[i];
      if (slot.busy) continue;
      var job = _queue.shift();
      var id = ++_jobSeq;
      slot.busy = true;
      _jobs.set(id, { resolve: job.resolve, reject: job.reject, slot: slot });
      slot.worker.postMessage({ id: id, password: job.password, salt: job.salt, opts: job.opts });
    }
  }

  function _dispatch(passwordBytes, saltBytes, opts) {
    return new Promise(function (resolve, reject) {
      _queue.push({ password: passwordBytes, salt: saltBytes, opts: opts, resolve: resolve, reject: reject });
      _drain();
    });
  }

  async function _argonDerive(passwordBytes, saltBytes, opts) {
    var lastErr;
    for (var attempt = 0; attempt <= _ARGON_RETRIES; attempt++) {
      _initPool();
      if (_workersOK && _pool) {
        try {
          return await _dispatch(passwordBytes, saltBytes, opts);
        } catch (e) {
          lastErr = e; // worker path failed — degrade to main thread
        }
      }
      try {
        return await globalThis.argon2idHash(passwordBytes, saltBytes, opts);
      } catch (e) {
        lastErr = e;
        if (attempt < _ARGON_RETRIES) {
          var backoff = 50 * (attempt + 1);
          await new Promise(function (r) { setTimeout(r, backoff); });
        }
      }
    }
    throw lastErr;
  }

  // Master-key cache, keyed like javascript.js's _mkCache. Cleared by clearCache().
  var _mkCache = new Map();
  function clearCache() {
    _mkCache.clear();
  }

  async function deriveMasterKey(password, saltBytes, kdf) {
    if (!kdf) kdf = DEFAULT_KDF;
    var cacheKey =
      password + ":" + bytesToHex(saltBytes) + ":" + kdf.memorySize + ":" + kdf.iterations + ":" + kdf.parallelism;
    if (_mkCache.has(cacheKey)) return _mkCache.get(cacheKey);
    var mk = await _argonDerive(_TE.encode(password), saltBytes, {
      iterations: kdf.iterations,
      memorySize: kdf.memorySize,
      parallelism: kdf.parallelism,
      hashLength: kdf.hashLength,
    });
    _mkCache.set(cacheKey, mk);
    return mk;
  }

  async function hkdfBytes(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey("raw", masterKeyBytes, "HKDF", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: _TE.encode(infoLabel) },
      base,
      256
    );
    return new Uint8Array(bits);
  }

  async function hkdfAesKey(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey("raw", masterKeyBytes, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: _TE.encode(infoLabel) },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // v6 name decryption: ChaCha20-Poly1305(MK2) then AES-256-GCM(MK1). Throws on
  // wrong key / tamper.
  async function decryptName(password, password2, recSalt1Hex, recSalt2Hex, nameNonce1Hex, nameNonce2Hex, encNameHex, kdf) {
    var mks = await Promise.all([
      deriveMasterKey(password, hexToBytes(recSalt1Hex), kdf),
      deriveMasterKey(password2, hexToBytes(recSalt2Hex), kdf),
    ]);
    var subs = await Promise.all([hkdfBytes(mks[1], _HK.nameChacha), hkdfAesKey(mks[0], _HK.nameAes)]);
    var chachaKey = subs[0],
      aesKey = subs[1];
    var mid = globalThis.chacha20poly1305(chachaKey, hexToBytes(nameNonce2Hex)).decrypt(hexToBytes(encNameHex));
    var plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(nameNonce1Hex) }, aesKey, mid)
    );
    return _TD.decode(plain);
  }

  // v6 payload decryption: Serpent → Twofish → AES-GCM → ChaCha20. Throws on
  // wrong key / tamper.
  async function decryptFields(password, password2, recSalt1Hex, recSalt2Hex, iv1Hex, nonce2Hex, nonce3Hex, nonce4Hex, encHex, kdf) {
    var mks = await Promise.all([
      deriveMasterKey(password, hexToBytes(recSalt1Hex), kdf),
      deriveMasterKey(password2, hexToBytes(recSalt2Hex), kdf),
    ]);
    var mk1 = mks[0],
      mk2 = mks[1];
    var subs = await Promise.all([
      hkdfBytes(mk2, _HK.paySerpent),
      hkdfBytes(mk2, _HK.payTwofish),
      hkdfAesKey(mk1, _HK.payAes),
      hkdfBytes(mk1, _HK.payChacha),
    ]);
    var serpentKey = subs[0],
      twofishKey = subs[1],
      aesKey = subs[2],
      chachaKey = subs[3];
    var tf = globalThis.serpentCTR(serpentKey, hexToBytes(nonce4Hex), hexToBytes(encHex));
    var ct = globalThis.twofishCTR(twofishKey, hexToBytes(nonce3Hex), tf);
    var mid = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(iv1Hex) }, aesKey, ct));
    var plain = globalThis.chacha20poly1305(chachaKey, hexToBytes(nonce2Hex)).decrypt(mid);
    return JSON.parse(_TD.decode(plain));
  }

  // ---- TOTP (RFC 6238) ----
  function base32ToBytes(base32) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var bits = "";
    var clean = base32.toUpperCase().replace(/\s/g, "").replace(/=+$/, "");
    for (var i = 0; i < clean.length; i++) {
      var val = alphabet.indexOf(clean[i]);
      if (val < 0) throw new Error("Invalid base32 character: " + clean[i]);
      bits += val.toString(2).padStart(5, "0");
    }
    var bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    return bytes;
  }

  function normOtpAlg(a) {
    a = (a || "").toUpperCase().replace(/^SHA([0-9])/, "SHA-$1");
    return (a === "SHA-256" || a === "SHA-512") ? a : "SHA-1";
  }

  var STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

  // Parse a TOTP token: a bare Base32 secret (defaults 6/30/SHA-1) or a full
  // otpauth:// URI carrying digits/period/algorithm. Steam Guard is detected from
  // the URI host/issuer/label or encoder=steam. Mirrors _parseOtp in the web app.
  function parseOtp(token) {
    var cfg = { secret: "", digits: 6, period: 30, algorithm: "SHA-1", steam: false };
    var raw = (token || "").trim();
    if (/^otpauth:\/\//i.test(raw)) {
      try {
        var u = new URL(raw);
        var p = u.searchParams;
        cfg.secret = (p.get("secret") || "").toUpperCase().replace(/\s+/g, "");
        if (p.get("digits")) cfg.digits = parseInt(p.get("digits"), 10) || cfg.digits;
        if (p.get("period")) cfg.period = parseInt(p.get("period"), 10) || cfg.period;
        if (p.get("algorithm")) cfg.algorithm = normOtpAlg(p.get("algorithm"));
        var label = decodeURIComponent(u.pathname.slice(1)).toLowerCase();
        var issuer = (p.get("issuer") || "").toLowerCase();
        var host = (u.host || "").toLowerCase();
        if ((p.get("encoder") || "").toLowerCase() === "steam" ||
            issuer === "steam" || host === "steam" || label.indexOf("steam") === 0) {
          cfg.steam = true; cfg.digits = 5; cfg.algorithm = "SHA-1";
        }
      } catch (e) { /* malformed otpauth URI — leave secret empty */ }
    } else {
      cfg.secret = raw.toUpperCase().replace(/\s+/g, "");
    }
    return cfg;
  }

  // Accepts a raw token string or a parsed parseOtp() config. Honors
  // digits/period/algorithm and Steam Guard.
  async function computeTotp(token, timeOffset) {
    timeOffset = timeOffset || 0;
    var cfg = (token && token.secret !== undefined) ? token : parseOtp(token);
    var keyBytes = base32ToBytes(cfg.secret);
    var ck = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: cfg.algorithm }, false, ["sign"]);
    var epoch = Math.floor(Date.now() / 1000);
    var counter = Math.floor(epoch / cfg.period) + timeOffset;
    var timeBytes = new Uint8Array(8);
    var hi = Math.floor(counter / 0x100000000), lo = counter >>> 0;
    timeBytes[0] = (hi >>> 24) & 0xff; timeBytes[1] = (hi >>> 16) & 0xff;
    timeBytes[2] = (hi >>> 8) & 0xff;  timeBytes[3] = hi & 0xff;
    timeBytes[4] = (lo >>> 24) & 0xff; timeBytes[5] = (lo >>> 16) & 0xff;
    timeBytes[6] = (lo >>> 8) & 0xff;  timeBytes[7] = lo & 0xff;
    var hmac = new Uint8Array(await crypto.subtle.sign("HMAC", ck, timeBytes));
    var offset = hmac[hmac.length - 1] & 0x0f;
    var bin =
      (((hmac[offset] & 0x7f) << 24) |
        (hmac[offset + 1] << 16) |
        (hmac[offset + 2] << 8) |
        hmac[offset + 3]) >>> 0;
    if (cfg.steam) {
      var out = "";
      for (var i = 0; i < 5; i++) { out += STEAM_ALPHABET[bin % 26]; bin = Math.floor(bin / 26); }
      return out;
    }
    var code = bin % Math.pow(10, cfg.digits);
    return code.toString().padStart(cfg.digits, "0");
  }

  // ============================================================
  // Encryption (write path) — mirrors javascript.js exactly so records the
  // extension writes are byte-compatible with the web app's decrypt path. Used
  // only by the passkey-store flow; the autofill path stays read-only.
  // ============================================================

  var PAYLOAD_PAD_BUCKET = 256; // bytes — must match javascript.js

  // Pad encoded plaintext up to the next PAYLOAD_PAD_BUCKET multiple with trailing
  // ASCII spaces (one-bucket floor). Spaces are valid trailing JSON whitespace, so
  // decryptFields' JSON.parse needs no un-pad step.
  function _padPlaintext(bytes) {
    var target = Math.max(
      PAYLOAD_PAD_BUCKET,
      Math.ceil(bytes.length / PAYLOAD_PAD_BUCKET) * PAYLOAD_PAD_BUCKET
    );
    var out = new Uint8Array(target);
    out.set(bytes);
    out.fill(0x20, bytes.length);
    return out;
  }

  // v6 payload encryption: ChaCha20 → AES-GCM → Twofish-CTR → Serpent-CTR.
  async function encryptFields(password, password2, recSalt1, recSalt2, fields, kdf) {
    var iv1 = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12)); // ChaCha20
    var nonce3 = crypto.getRandomValues(new Uint8Array(16)); // Twofish-CTR
    var nonce4 = crypto.getRandomValues(new Uint8Array(16)); // Serpent-CTR
    var mks = await Promise.all([deriveMasterKey(password, recSalt1, kdf), deriveMasterKey(password2, recSalt2, kdf)]);
    var mk1 = mks[0], mk2 = mks[1];
    var subs = await Promise.all([
      hkdfAesKey(mk1, _HK.payAes),
      hkdfBytes(mk1, _HK.payChacha),
      hkdfBytes(mk2, _HK.payTwofish),
      hkdfBytes(mk2, _HK.paySerpent),
    ]);
    var aesKey = subs[0], chachaKey = subs[1], twofishKey = subs[2], serpentKey = subs[3];
    var plain = _padPlaintext(_TE.encode(JSON.stringify(fields)));
    var mid = globalThis.chacha20poly1305(chachaKey, nonce2).encrypt(plain);
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, aesKey, mid));
    var tf = globalThis.twofishCTR(twofishKey, nonce3, ct);
    var outer = globalThis.serpentCTR(serpentKey, nonce4, tf);
    return {
      iv1Hex: bytesToHex(iv1), nonce2Hex: bytesToHex(nonce2),
      nonce3Hex: bytesToHex(nonce3), nonce4Hex: bytesToHex(nonce4),
      encHex: bytesToHex(outer),
    };
  }

  // v6 name encryption: AES-256-GCM (MK1) then ChaCha20-Poly1305 (MK2).
  async function encryptName(password, password2, recSalt1, recSalt2, name, kdf) {
    var nonce1 = crypto.getRandomValues(new Uint8Array(12)); // name AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12)); // name ChaCha20
    var mks = await Promise.all([deriveMasterKey(password, recSalt1, kdf), deriveMasterKey(password2, recSalt2, kdf)]);
    var subs = await Promise.all([hkdfAesKey(mks[0], _HK.nameAes), hkdfBytes(mks[1], _HK.nameChacha)]);
    var aesKey = subs[0], chachaKey = subs[1];
    var mid = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce1 }, aesKey, _TE.encode(name)));
    var ct = globalThis.chacha20poly1305(chachaKey, nonce2).encrypt(mid);
    return { nameNonce1Hex: bytesToHex(nonce1), nameNonce2Hex: bytesToHex(nonce2), encNameHex: bytesToHex(ct) };
  }

  // Build a full 11-field v6 record string from a name + payload object. Fresh
  // random salts/nonces per record. Mirrors saveEntry()'s assembly.
  async function buildRecord(password, password2, name, fields, kdf) {
    var recSalt1 = crypto.getRandomValues(new Uint8Array(32));
    var recSalt2 = crypto.getRandomValues(new Uint8Array(32));
    var nameEnc = await encryptName(password, password2, recSalt1, recSalt2, name, kdf);
    var result = await encryptFields(password, password2, recSalt1, recSalt2, fields, kdf);
    return [
      nameEnc.encNameHex, "v6",
      bytesToHex(recSalt1), bytesToHex(recSalt2),
      nameEnc.nameNonce1Hex, nameEnc.nameNonce2Hex,
      result.iv1Hex, result.nonce2Hex, result.nonce3Hex, result.nonce4Hex,
      result.encHex,
    ].join("|");
  }

  // ============================================================
  // Passkey (WebAuthn) ECDSA P-256 helpers. The key pair is generated here,
  // stored (as JWK) inside the encrypted payload, and used to sign assertions.
  // ============================================================

  // Generate an ECDSA P-256 key pair + a random 32-byte credential id. Also
  // exports the public key as SPKI so the create response can satisfy WebAuthn
  // libraries that call PublicKeyCredential.response.getPublicKey().
  async function generatePasskeyPair() {
    var kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    var privateKeyJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    var publicKeyJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    var publicKeySpki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
    var credentialId = crypto.getRandomValues(new Uint8Array(32));
    return {
      privateKeyJwk: privateKeyJwk,
      publicKeyJwk: publicKeyJwk,
      publicKeySpki: publicKeySpki,
      credentialId: credentialId,
    };
  }

  // Export a stored public-key JWK as SPKI (DER) bytes — used to back
  // getPublicKey() on assertions/registrations recovered from the vault.
  async function publicKeyJwkToSpki(publicKeyJwk) {
    var key = await crypto.subtle.importKey(
      "jwk", publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]
    );
    return new Uint8Array(await crypto.subtle.exportKey("spki", key));
  }

  // Sign authenticatorData || SHA-256(clientDataJSON) with a stored private key.
  // Returns the raw IEEE-P1363 signature (64 bytes); callers DER-encode for
  // WebAuthn assertions (see webauthn.js p1363ToDer).
  async function signPasskeyChallenge(privateKeyJwk, authenticatorData, clientDataHash) {
    var key = await crypto.subtle.importKey(
      "jwk", privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
    var payload = new Uint8Array(authenticatorData.length + clientDataHash.length);
    payload.set(authenticatorData, 0);
    payload.set(clientDataHash, authenticatorData.length);
    var sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, payload);
    return new Uint8Array(sig);
  }

  // Decode one v6 record string into { name, fields }. The record is the
  // 11-field pipe-joined form (with or without a trailing line index — both are
  // handled). Throws on a wrong password (AEAD failure) or malformed record.
  async function decodeRecord(record, password, password2, kdf) {
    var parts = record.split("|");
    if (parts.length < 11 || parts[1] !== "v6") throw new Error("Unsupported record");
    var name = await decryptName(password, password2, parts[2], parts[3], parts[4], parts[5], parts[0], kdf);
    var fields = await decryptFields(
      password,
      password2,
      parts[2],
      parts[3],
      parts[6],
      parts[7],
      parts[8],
      parts[9],
      parts[10],
      kdf
    );
    return { name: name, fields: fields };
  }

  // Strip a trailing numeric line-index field if present, returning the 11-field
  // canonical record string.
  function canonicalRecord(record) {
    var p = record.split("|");
    if (p.length === 12 && /^\d+$/.test(p[11])) p = p.slice(0, 11);
    return p.join("|");
  }

  // ---- Vault integrity manifest (vm1) ---------------------------------------
  // Mirrors javascript.js's _parseManifest / _manifestHmacHex / _signVault so a
  // record written by the extension (the passkey-create path) can re-sign the
  // vault, exactly as the PWA auto-re-signs after its own writes. Without this
  // the new record would leave the served manifest signing the OLD set → the
  // PWA's reveal-all verify flips the integrity badge red ("HMAC mismatch").

  function parseManifest(s) {
    if (typeof s !== "string" || s === "") return null;
    var p = s.split("|");
    if (p.length !== 6 || p[0] !== "vm1") return null;
    if (!/^[0-9a-f]{64}$/.test(p[1]) || !/^[0-9a-f]{64}$/.test(p[2])) return null;
    if (!/^\d{1,15}$/.test(p[3]) || !/^\d{1,15}$/.test(p[4])) return null;
    if (!/^[0-9a-f]{64}$/.test(p[5])) return null;
    return {
      salt1Hex: p[1], salt2Hex: p[2], revision: parseInt(p[3], 10),
      timestamp: parseInt(p[4], 10), hmacHex: p[5],
    };
  }

  // HMAC-SHA-256(vaultKey, "vm1|s1|s2|rev|ts" + "\n" + records.join("\n")),
  // vaultKey = HKDF(Argon2id(pw1,s1) ‖ Argon2id(pw2,s2), "v6|manifest|hmac").
  // The two manifest salts are independent of any record's salts (kdf is the
  // vault-wide Argon2id cost, so the keys derive at the same price the PWA pays).
  async function manifestHmacHex(pw, pw2, salt1Hex, salt2Hex, revision, timestamp, records, kdf) {
    var mks = await Promise.all([
      deriveMasterKey(pw, hexToBytes(salt1Hex), kdf),
      deriveMasterKey(pw2, hexToBytes(salt2Hex), kdf),
    ]);
    var ikm = new Uint8Array(64);
    ikm.set(mks[0], 0);
    ikm.set(mks[1], 32);
    var keyBytes = await hkdfBytes(ikm, "v6|manifest|hmac");
    var ck = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    var msg = "vm1|" + salt1Hex + "|" + salt2Hex + "|" + revision + "|" + timestamp + "\n" + records.join("\n");
    var sig = await crypto.subtle.sign("HMAC", ck, _TE.encode(msg));
    return bytesToHex(new Uint8Array(sig));
  }

  async function verifyManifest(manifestStr, pw, pw2, records, kdf) {
    if (!manifestStr) return { status: "unsigned" };
    var m = parseManifest(manifestStr);
    if (!m) return { status: "fail", reason: "Malformed manifest" };
    var sortedRecords = records.slice().sort();
    var computed = await manifestHmacHex(pw, pw2, m.salt1Hex, m.salt2Hex, m.revision, m.timestamp, sortedRecords, kdf);
    if (computed !== m.hmacHex) return { status: "fail", reason: "HMAC mismatch", revision: m.revision, timestamp: m.timestamp };
    return { status: "ok", revision: m.revision, timestamp: m.timestamp };
  }

  async function sha256Hex(str) {
    var buf = await crypto.subtle.digest("SHA-256", _TE.encode(str));
    return bytesToHex(new Uint8Array(buf));
  }

  // Build a fresh vm1 manifest + the matching expect_hash for the `sign=1`
  // write. records must be the canonical, sorted (SORT_STRING) record set.
  // Reuses the previous manifest's salts (so signing hits _mkCache) and bumps
  // its revision by one; fresh salts only on a first-ever sign.
  async function buildManifest(pw, pw2, records, prevManifest, kdf) {
    var old = parseManifest(prevManifest);
    var salt1Hex = old ? old.salt1Hex : bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    var salt2Hex = old ? old.salt2Hex : bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    var revision = (old ? old.revision : 0) + 1;
    var ts = Math.floor(Date.now() / 1000);
    var hmac = await manifestHmacHex(pw, pw2, salt1Hex, salt2Hex, revision, ts, records, kdf);
    var manifest = ["vm1", salt1Hex, salt2Hex, String(revision), String(ts), hmac].join("|");
    var expectHash = await sha256Hex(records.join("\n"));
    return { manifest: manifest, expectHash: expectHash, revision: revision };
  }

  globalThis.VaultCrypto = {
    parseKdf: parseKdf,
    DEFAULT_KDF: DEFAULT_KDF,
    deriveMasterKey: deriveMasterKey,
    decryptName: decryptName,
    decryptFields: decryptFields,
    encryptName: encryptName,
    encryptFields: encryptFields,
    buildRecord: buildRecord,
    generatePasskeyPair: generatePasskeyPair,
    publicKeyJwkToSpki: publicKeyJwkToSpki,
    signPasskeyChallenge: signPasskeyChallenge,
    decodeRecord: decodeRecord,
    canonicalRecord: canonicalRecord,
    parseManifest: parseManifest,
    verifyManifest: verifyManifest,
    buildManifest: buildManifest,
    computeTotp: computeTotp,
    parseOtp: parseOtp,
    clearCache: clearCache,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    setActiveKdf: setActiveKdf,
    poolSize: poolSize,
    terminatePool: terminatePool,
  };
})();
