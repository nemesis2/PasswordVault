// selftest.js — validates the extension's decrypt path by building a v6 record
// with the same cipher bundles (the encrypt side, mirroring javascript.js) and
// decrypting it back through VaultCrypto. Run: node selftest.js
"use strict";
const fs = require("fs");
const vm = require("vm");

// Minimal browser-ish globals for the bundles + crypto-vault.
const { webcrypto } = require("crypto");
const sandbox = {
  crypto: webcrypto,
  TextEncoder,
  TextDecoder,
  console,
  btoa: (s) => Buffer.from(s, "binary").toString("base64"),
  atob: (s) => Buffer.from(s, "base64").toString("binary"),
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
vm.createContext(sandbox);

vm.runInContext(fs.readFileSync(__dirname + "/crypto-ciphers.js", "utf8"), sandbox, { filename: "crypto-ciphers.js" });
vm.runInContext(fs.readFileSync(__dirname + "/crypto-vault.js", "utf8"), sandbox, { filename: "crypto-vault.js" });
vm.runInContext(fs.readFileSync(__dirname + "/webauthn.js", "utf8"), sandbox, { filename: "webauthn.js" });

const TE = new TextEncoder();
const hex = sandbox.VaultCrypto.bytesToHex;
const VC = sandbox.VaultCrypto;

// Use a cheap KDF so the test is fast (still exercises the full pipeline).
const KDF = { iterations: 2, memorySize: 65536, parallelism: 1, hashLength: 32 };

const _HK = {
  nameAes: "v6|name|aes-gcm",
  nameChacha: "v6|name|chacha20",
  payAes: "v6|pay|aes-gcm",
  payChacha: "v6|pay|chacha20",
  payTwofish: "v6|pay|twofish",
  paySerpent: "v6|pay|serpent",
};

async function hkdfBytes(mk, info) {
  const base = await sandbox.crypto.subtle.importKey("raw", mk, "HKDF", false, ["deriveBits"]);
  const bits = await sandbox.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: TE.encode(info) },
    base,
    256
  );
  return new Uint8Array(bits);
}
async function hkdfAesKey(mk, info) {
  const base = await sandbox.crypto.subtle.importKey("raw", mk, "HKDF", false, ["deriveKey"]);
  return sandbox.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: TE.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function buildRecord(pw, pw2, name, fields) {
  const recSalt1 = sandbox.crypto.getRandomValues(new Uint8Array(32));
  const recSalt2 = sandbox.crypto.getRandomValues(new Uint8Array(32));
  const mk1 = await VC.deriveMasterKey(pw, recSalt1, KDF);
  const mk2 = await VC.deriveMasterKey(pw2, recSalt2, KDF);

  // ---- name: AES-GCM(MK1) then ChaCha20(MK2) ----
  const nN1 = sandbox.crypto.getRandomValues(new Uint8Array(12));
  const nN2 = sandbox.crypto.getRandomValues(new Uint8Array(12));
  const nameAes = await hkdfAesKey(mk1, _HK.nameAes);
  const nameCha = await hkdfBytes(mk2, _HK.nameChacha);
  const nMid = new Uint8Array(await sandbox.crypto.subtle.encrypt({ name: "AES-GCM", iv: nN1 }, nameAes, TE.encode(name)));
  const encName = sandbox.chacha20poly1305(nameCha, nN2).encrypt(nMid);

  // ---- payload: ChaCha20(MK1) -> AES-GCM(MK1) -> Twofish(MK2) -> Serpent(MK2) ----
  const iv1 = sandbox.crypto.getRandomValues(new Uint8Array(12));
  const n2 = sandbox.crypto.getRandomValues(new Uint8Array(12));
  const n3 = sandbox.crypto.getRandomValues(new Uint8Array(16));
  const n4 = sandbox.crypto.getRandomValues(new Uint8Array(16));
  const payAes = await hkdfAesKey(mk1, _HK.payAes);
  const payCha = await hkdfBytes(mk1, _HK.payChacha);
  const payTf = await hkdfBytes(mk2, _HK.payTwofish);
  const paySp = await hkdfBytes(mk2, _HK.paySerpent);
  // pad to 256
  const raw = TE.encode(JSON.stringify(fields));
  const target = Math.max(256, Math.ceil(raw.length / 256) * 256);
  const plain = new Uint8Array(target);
  plain.set(raw);
  plain.fill(0x20, raw.length);
  const mid = sandbox.chacha20poly1305(payCha, n2).encrypt(plain);
  const ct = new Uint8Array(await sandbox.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, payAes, mid));
  const tf = sandbox.twofishCTR(payTf, n3, ct);
  const outer = sandbox.serpentCTR(paySp, n4, tf);

  return [
    hex(encName), "v6", hex(recSalt1), hex(recSalt2), hex(nN1), hex(nN2),
    hex(iv1), hex(n2), hex(n3), hex(n4), hex(outer), "0",
  ].join("|");
}

(async function () {
  const pw = "correct horse";
  const pw2 = "battery staple";
  const fields = { url: "https://example.com/login", username: "alice@example.com", password: "s3cr3t!", token: "JBSWY3DPEHPK3PXP", notes: "hi", tags: "" };

  VC.clearCache();
  // Cross-check: the local reference encoder AND VaultCrypto's own encrypt path
  // must both decode. The latter is the code the passkey-store flow actually uses.
  const recRef = await buildRecord(pw, pw2, "Example Account", fields);
  const rec = await VC.buildRecord(pw, pw2, "Example Account", fields, KDF);

  // 1. correct passwords decode (both encoders)
  VC.clearCache();
  const decRef = await VC.decodeRecord(recRef, pw, pw2, KDF);
  const dec = await VC.decodeRecord(rec, pw, pw2, KDF);
  let pass = true;
  function check(cond, label) { console.log((cond ? "  ok  " : " FAIL ") + label); if (!cond) pass = false; }
  check(decRef.name === "Example Account", "reference encoder round-trip");
  check(dec.name === "Example Account", "VaultCrypto.buildRecord name round-trip");
  check(dec.fields.username === fields.username, "username round-trip");
  check(dec.fields.password === fields.password, "password round-trip");
  check(dec.fields.url === fields.url, "url round-trip");

  // 2. TOTP for the known secret matches RFC test expectation shape (6 digits)
  const code = await VC.computeTotp(fields.token, 0);
  check(/^\d{6}$/.test(code), "totp produces 6-digit code (" + code + ")");

  // 3. wrong password throws
  VC.clearCache();
  let threw = false;
  try { await VC.decodeRecord(rec, "wrong", pw2, KDF); } catch (e) { threw = true; }
  check(threw, "wrong primary password rejected");

  VC.clearCache();
  threw = false;
  try { await VC.decodeRecord(rec, pw, "wrong", KDF); } catch (e) { threw = true; }
  check(threw, "wrong secondary password rejected");

  // 4. passkey sub-object survives the encrypt/decrypt round-trip
  VC.clearCache();
  const kp = await VC.generatePasskeyPair();
  const WA = sandbox.WebAuthnKit;
  const pkFields = Object.assign({}, fields, {
    url: "passkey://example.com",
    passkey: {
      credentialId: WA.bytesToB64url(kp.credentialId),
      rpId: "example.com",
      rpName: "Example",
      userHandle: WA.bytesToB64url(new Uint8Array([1, 2, 3, 4])),
      privateKeyJwk: kp.privateKeyJwk,
      publicKeyJwk: kp.publicKeyJwk,
      signCount: 0,
      createdAt: "2026-06-21T00:00:00Z",
    },
  });
  const pkRec = await VC.buildRecord(pw, pw2, "Example Passkey", pkFields, KDF);
  VC.clearCache();
  const pkDec = await VC.decodeRecord(pkRec, pw, pw2, KDF);
  check(!!pkDec.fields.passkey, "passkey sub-object present after round-trip");
  check(pkDec.fields.passkey.rpId === "example.com", "passkey.rpId round-trip");
  check(pkDec.fields.passkey.privateKeyJwk.d === kp.privateKeyJwk.d, "private key JWK round-trip");

  // 5. ECDSA sign -> verify with the public key (the assertion crypto)
  const authData = await WA.authenticatorData("example.com", 0x05, 0);
  const clientDataHash = await WA.sha256(WA.clientDataJSON("webauthn.get", "Y2hhbGxlbmdl", "https://example.com"));
  const sig = await VC.signPasskeyChallenge(kp.privateKeyJwk, authData, clientDataHash);
  check(sig.length === 64, "P1363 signature is 64 bytes");
  const pubKey = await sandbox.crypto.subtle.importKey("jwk", kp.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const signed = new Uint8Array(authData.length + clientDataHash.length);
  signed.set(authData, 0); signed.set(clientDataHash, authData.length);
  const verified = await sandbox.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, sig, signed);
  check(verified, "ECDSA assertion signature verifies");

  // 6. DER conversion yields a well-formed SEQUENCE of two INTEGERs
  const der = WA.p1363ToDer(sig);
  check(der[0] === 0x30 && der[1] === der.length - 2 && der[2] === 0x02, "p1363ToDer shape (SEQ of INTs)");

  // 7. CBOR encoders produce non-empty bytes (attestationObject + COSE key)
  const cose = WA.cosePublicKey(kp.publicKeyJwk);
  const attData = await WA.authenticatorData("example.com", 0x45, 0, WA.attestedCredentialData(kp.credentialId, cose));
  const attObj = WA.attestationObject(attData);
  check(cose.length > 0 && attObj.length > attData.length, "CBOR COSE key + attestationObject built");

  console.log(pass ? "\nALL PASS" : "\nFAILED");
  process.exit(pass ? 0 : 1);
})();
