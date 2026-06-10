"use strict";

// ============================================================
// ChaCha20-Poly1305  —  @noble/ciphers (MIT, paulmillr.com)
// Bundled inline; provides globalThis.chacha20poly1305
// ============================================================
(() => {
  // node_modules/@noble/ciphers/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  function abool(b) {
    if (typeof b !== "boolean")
      throw new TypeError(`boolean expected, not ${b}`);
  }
  function anumber(n) {
    if (typeof n !== "number")
      throw new TypeError("number expected, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError("positive integer expected, got " + n);
  }
  function abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || needsLen && len !== length) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : "";
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
      if (!bytes)
        throw new TypeError(message);
      throw new RangeError(message);
    }
    return value;
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance, onlyAligned = false) {
    abytes(out, void 0, "output");
    const min = instance.outputLen;
    if (out.length < min) {
      throw new RangeError("digestInto() expects output buffer of length at least " + min);
    }
    if (onlyAligned && !isAligned32(out))
      throw new Error("invalid output, must be aligned");
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  var byteSwap = (word) => word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  var byteSwap32 = (arr) => {
    for (let i = 0; i < arr.length; i++)
      arr[i] = byteSwap(arr[i]);
    return arr;
  };
  var swap32IfBE = isLE ? (u) => u : byteSwap32;
  function checkOpts(defaults, opts) {
    if (opts == null || typeof opts !== "object")
      throw new Error("options must be defined");
    const merged = Object.assign(defaults, opts);
    return merged;
  }
  function equalBytes(a, b) {
    if (a.length !== b.length)
      return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
      diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function wrapMacConstructor(keyLen, macCons, fromMsg) {
    const mac = macCons;
    const getArgs = fromMsg || (() => []);
    const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
    const tmp = mac(new Uint8Array(keyLen), ...getArgs(new Uint8Array(0)));
    macC.outputLen = tmp.outputLen;
    macC.blockLen = tmp.blockLen;
    macC.create = (key, ...args) => mac(key, ...args);
    return macC;
  }
  var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
    function wrappedCipher(key, ...args) {
      abytes(key, void 0, "key");
      if (params.nonceLength !== void 0) {
        const nonce = args[0];
        abytes(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
      }
      const tagl = params.tagLength;
      if (tagl && args[1] !== void 0)
        abytes(args[1], void 0, "AAD");
      const cipher = constructor(key, ...args);
      const checkOutput = (fnLength, output) => {
        if (output !== void 0) {
          if (fnLength !== 2)
            throw new Error("cipher output not supported");
          abytes(output, void 0, "output");
        }
      };
      let called = false;
      const wrCipher = {
        encrypt(data, output) {
          if (called)
            throw new Error("cannot encrypt() twice with same key + nonce");
          called = true;
          abytes(data);
          checkOutput(cipher.encrypt.length, output);
          return cipher.encrypt(data, output);
        },
        decrypt(data, output) {
          abytes(data);
          if (tagl && data.length < tagl)
            throw new Error('"ciphertext" expected length bigger than tagLength=' + tagl);
          checkOutput(cipher.decrypt.length, output);
          return cipher.decrypt(data, output);
        }
      };
      return wrCipher;
    }
    Object.assign(wrappedCipher, params);
    return wrappedCipher;
  };
  function getOutput(expectedLength, out, onlyAligned = true) {
    if (out === void 0)
      return new Uint8Array(expectedLength);
    abytes(out, void 0, "output");
    if (out.length !== expectedLength)
      throw new Error('"output" expected Uint8Array of length ' + expectedLength + ", got: " + out.length);
    if (onlyAligned && !isAligned32(out))
      throw new Error("invalid output, must be aligned");
    return out;
  }
  function u64Lengths(dataLength, aadLength, isLE2) {
    anumber(dataLength);
    anumber(aadLength);
    abool(isLE2);
    const num = new Uint8Array(16);
    const view = createView(num);
    view.setBigUint64(0, BigInt(aadLength), isLE2);
    view.setBigUint64(8, BigInt(dataLength), isLE2);
    return num;
  }
  function isAligned32(bytes) {
    return bytes.byteOffset % 4 === 0;
  }
  function copyBytes(bytes) {
    return Uint8Array.from(abytes(bytes));
  }

  // node_modules/@noble/ciphers/_arx.js
  var encodeStr = (str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0));
  var sigma16_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 16-byte k"))))();
  var sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 32-byte k"))))();
  function rotl(a, b) {
    return a << b | a >>> 32 - b;
  }
  var BLOCK_LEN = 64;
  var BLOCK_LEN32 = 16;
  var MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
  var U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
  function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
    const len = data.length;
    const block = new Uint8Array(BLOCK_LEN);
    const b32 = u32(block);
    const isAligned = isLE && isAligned32(data) && isAligned32(output);
    const d32 = isAligned ? u32(data) : U32_EMPTY;
    const o32 = isAligned ? u32(output) : U32_EMPTY;
    if (!isLE) {
      for (let pos = 0; pos < len; counter++) {
        core(sigma, key, nonce, b32, counter, rounds);
        swap32IfBE(b32);
        if (counter >= MAX_COUNTER)
          throw new Error("arx: counter overflow");
        const take = Math.min(BLOCK_LEN, len - pos);
        for (let j = 0, posj; j < take; j++) {
          posj = pos + j;
          output[posj] = data[posj] ^ block[j];
        }
        pos += take;
      }
      return;
    }
    for (let pos = 0; pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      if (isAligned && take === BLOCK_LEN) {
        const pos32 = pos / 4;
        if (pos % 4 !== 0)
          throw new Error("arx: invalid block position");
        for (let j = 0, posj; j < BLOCK_LEN32; j++) {
          posj = pos32 + j;
          o32[posj] = d32[posj] ^ b32[j];
        }
        pos += BLOCK_LEN;
        continue;
      }
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
  }
  function createCipher(core, opts) {
    const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
    if (typeof core !== "function")
      throw new Error("core must be a function");
    anumber(counterLength);
    anumber(rounds);
    abool(counterRight);
    abool(allowShortKeys);
    return (key, nonce, data, output, counter = 0) => {
      abytes(key, void 0, "key");
      abytes(nonce, void 0, "nonce");
      abytes(data, void 0, "data");
      const len = data.length;
      output = getOutput(len, output, false);
      anumber(counter);
      if (counter < 0 || counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const toClean = [];
      let l = key.length;
      let k;
      let sigma;
      if (l === 32) {
        toClean.push(k = copyBytes(key));
        sigma = sigma32_32;
      } else if (l === 16 && allowShortKeys) {
        k = new Uint8Array(32);
        k.set(key);
        k.set(key, 16);
        sigma = sigma16_32;
        toClean.push(k);
      } else {
        abytes(key, 32, "arx key");
        throw new Error("invalid key size");
      }
      if (!isLE || !isAligned32(nonce))
        toClean.push(nonce = copyBytes(nonce));
      let k32 = u32(k);
      if (extendNonceFn) {
        if (nonce.length !== 24)
          throw new Error(`arx: extended nonce must be 24 bytes`);
        const n16 = nonce.subarray(0, 16);
        if (isLE)
          extendNonceFn(sigma, k32, u32(n16), k32);
        else {
          const sigmaRaw = swap32IfBE(Uint32Array.from(sigma));
          extendNonceFn(sigmaRaw, k32, u32(n16), k32);
          clean(sigmaRaw);
          swap32IfBE(k32);
        }
        nonce = nonce.subarray(16);
      } else if (!isLE)
        swap32IfBE(k32);
      const nonceNcLen = 16 - counterLength;
      if (nonceNcLen !== nonce.length)
        throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
      if (nonceNcLen !== 12) {
        const nc = new Uint8Array(12);
        nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
        nonce = nc;
        toClean.push(nonce);
      }
      const n32 = swap32IfBE(u32(nonce));
      try {
        runCipher(core, sigma, k32, n32, data, output, counter, rounds);
        return output;
      } finally {
        clean(...toClean);
      }
    };
  }

  // node_modules/@noble/ciphers/_poly1305.js
  function u8to16(a, i) {
    return a[i++] & 255 | (a[i++] & 255) << 8;
  }
  var Poly1305 = class {
    blockLen = 16;
    outputLen = 16;
    buffer = new Uint8Array(16);
    r = new Uint16Array(10);
    h = new Uint16Array(10);
    pad = new Uint16Array(8);
    pos = 0;
    finished = false;
    destroyed = false;
    constructor(key) {
      key = copyBytes(abytes(key, 32, "key"));
      const t0 = u8to16(key, 0);
      const t1 = u8to16(key, 2);
      const t2 = u8to16(key, 4);
      const t3 = u8to16(key, 6);
      const t4 = u8to16(key, 8);
      const t5 = u8to16(key, 10);
      const t6 = u8to16(key, 12);
      const t7 = u8to16(key, 14);
      this.r[0] = t0 & 8191;
      this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
      this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
      this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
      this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
      this.r[5] = t4 >>> 1 & 8190;
      this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
      this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
      this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
      this.r[9] = t7 >>> 5 & 127;
      for (let i = 0; i < 8; i++)
        this.pad[i] = u8to16(key, 16 + 2 * i);
    }
    process(data, offset, isLast = false) {
      const hibit = isLast ? 0 : 1 << 11;
      const { h, r } = this;
      const r0 = r[0]; const r1 = r[1]; const r2 = r[2]; const r3 = r[3]; const r4 = r[4];
      const r5 = r[5]; const r6 = r[6]; const r7 = r[7]; const r8 = r[8]; const r9 = r[9];
      const t0 = u8to16(data, offset + 0);
      const t1 = u8to16(data, offset + 2);
      const t2 = u8to16(data, offset + 4);
      const t3 = u8to16(data, offset + 6);
      const t4 = u8to16(data, offset + 8);
      const t5 = u8to16(data, offset + 10);
      const t6 = u8to16(data, offset + 12);
      const t7 = u8to16(data, offset + 14);
      let h0 = h[0] + (t0 & 8191);
      let h1 = h[1] + ((t0 >>> 13 | t1 << 3) & 8191);
      let h2 = h[2] + ((t1 >>> 10 | t2 << 6) & 8191);
      let h3 = h[3] + ((t2 >>> 7 | t3 << 9) & 8191);
      let h4 = h[4] + ((t3 >>> 4 | t4 << 12) & 8191);
      let h5 = h[5] + (t4 >>> 1 & 8191);
      let h6 = h[6] + ((t4 >>> 14 | t5 << 2) & 8191);
      let h7 = h[7] + ((t5 >>> 11 | t6 << 5) & 8191);
      let h8 = h[8] + ((t6 >>> 8 | t7 << 8) & 8191);
      let h9 = h[9] + (t7 >>> 5 | hibit);
      let c = 0;
      let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
      c = d0 >>> 13; d0 &= 8191;
      d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
      c += d0 >>> 13; d0 &= 8191;
      let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
      c = d1 >>> 13; d1 &= 8191;
      d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
      c += d1 >>> 13; d1 &= 8191;
      let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
      c = d2 >>> 13; d2 &= 8191;
      d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
      c += d2 >>> 13; d2 &= 8191;
      let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
      c = d3 >>> 13; d3 &= 8191;
      d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
      c += d3 >>> 13; d3 &= 8191;
      let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
      c = d4 >>> 13; d4 &= 8191;
      d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
      c += d4 >>> 13; d4 &= 8191;
      let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
      c = d5 >>> 13; d5 &= 8191;
      d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
      c += d5 >>> 13; d5 &= 8191;
      let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
      c = d6 >>> 13; d6 &= 8191;
      d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
      c += d6 >>> 13; d6 &= 8191;
      let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
      c = d7 >>> 13; d7 &= 8191;
      d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
      c += d7 >>> 13; d7 &= 8191;
      let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
      c = d8 >>> 13; d8 &= 8191;
      d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
      c += d8 >>> 13; d8 &= 8191;
      let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
      c = d9 >>> 13; d9 &= 8191;
      d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
      c += d9 >>> 13; d9 &= 8191;
      c = (c << 2) + c | 0;
      c = c + d0 | 0;
      d0 = c & 8191;
      c = c >>> 13;
      d1 += c;
      h[0] = d0; h[1] = d1; h[2] = d2; h[3] = d3; h[4] = d4;
      h[5] = d5; h[6] = d6; h[7] = d7; h[8] = d8; h[9] = d9;
    }
    finalize() {
      const { h, pad } = this;
      const g = new Uint16Array(10);
      let c = h[1] >>> 13;
      h[1] &= 8191;
      for (let i = 2; i < 10; i++) {
        h[i] += c;
        c = h[i] >>> 13;
        h[i] &= 8191;
      }
      h[0] += c * 5;
      c = h[0] >>> 13;
      h[0] &= 8191;
      h[1] += c;
      c = h[1] >>> 13;
      h[1] &= 8191;
      h[2] += c;
      g[0] = h[0] + 5;
      c = g[0] >>> 13;
      g[0] &= 8191;
      for (let i = 1; i < 10; i++) {
        g[i] = h[i] + c;
        c = g[i] >>> 13;
        g[i] &= 8191;
      }
      g[9] -= 1 << 13;
      let mask = (c ^ 1) - 1;
      for (let i = 0; i < 10; i++)
        g[i] &= mask;
      mask = ~mask;
      for (let i = 0; i < 10; i++)
        h[i] = h[i] & mask | g[i];
      h[0] = (h[0] | h[1] << 13) & 65535;
      h[1] = (h[1] >>> 3 | h[2] << 10) & 65535;
      h[2] = (h[2] >>> 6 | h[3] << 7) & 65535;
      h[3] = (h[3] >>> 9 | h[4] << 4) & 65535;
      h[4] = (h[4] >>> 12 | h[5] << 1 | h[6] << 14) & 65535;
      h[5] = (h[6] >>> 2 | h[7] << 11) & 65535;
      h[6] = (h[7] >>> 5 | h[8] << 8) & 65535;
      h[7] = (h[8] >>> 8 | h[9] << 5) & 65535;
      let f = h[0] + pad[0];
      h[0] = f & 65535;
      for (let i = 1; i < 8; i++) {
        f = (h[i] + pad[i] | 0) + (f >>> 16) | 0;
        h[i] = f & 65535;
      }
      clean(g);
    }
    update(data) {
      aexists(this);
      abytes(data);
      data = copyBytes(data);
      const { buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(data, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(buffer, 0, false);
          this.pos = 0;
        }
      }
      return this;
    }
    destroy() {
      this.destroyed = true;
      clean(this.h, this.r, this.buffer, this.pad);
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, h } = this;
      let { pos } = this;
      if (pos) {
        buffer[pos++] = 1;
        for (; pos < 16; pos++)
          buffer[pos] = 0;
        this.process(buffer, 0, true);
      }
      this.finalize();
      let opos = 0;
      for (let i = 0; i < 8; i++) {
        out[opos++] = h[i] >>> 0;
        out[opos++] = h[i] >>> 8;
      }
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
  };
  var poly1305 = /* @__PURE__ */ wrapMacConstructor(32, (key) => new Poly1305(key));

  // node_modules/@noble/ciphers/chacha.js
  function chachaCore(s, k, n, out, cnt, rounds = 20) {
    let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let r = 0; r < rounds; r += 2) {
      x00 = x00 + x04 | 0; x12 = rotl(x12 ^ x00, 16); x08 = x08 + x12 | 0; x04 = rotl(x04 ^ x08, 12);
      x00 = x00 + x04 | 0; x12 = rotl(x12 ^ x00,  8); x08 = x08 + x12 | 0; x04 = rotl(x04 ^ x08,  7);
      x01 = x01 + x05 | 0; x13 = rotl(x13 ^ x01, 16); x09 = x09 + x13 | 0; x05 = rotl(x05 ^ x09, 12);
      x01 = x01 + x05 | 0; x13 = rotl(x13 ^ x01,  8); x09 = x09 + x13 | 0; x05 = rotl(x05 ^ x09,  7);
      x02 = x02 + x06 | 0; x14 = rotl(x14 ^ x02, 16); x10 = x10 + x14 | 0; x06 = rotl(x06 ^ x10, 12);
      x02 = x02 + x06 | 0; x14 = rotl(x14 ^ x02,  8); x10 = x10 + x14 | 0; x06 = rotl(x06 ^ x10,  7);
      x03 = x03 + x07 | 0; x15 = rotl(x15 ^ x03, 16); x11 = x11 + x15 | 0; x07 = rotl(x07 ^ x11, 12);
      x03 = x03 + x07 | 0; x15 = rotl(x15 ^ x03,  8); x11 = x11 + x15 | 0; x07 = rotl(x07 ^ x11,  7);
      x00 = x00 + x05 | 0; x15 = rotl(x15 ^ x00, 16); x10 = x10 + x15 | 0; x05 = rotl(x05 ^ x10, 12);
      x00 = x00 + x05 | 0; x15 = rotl(x15 ^ x00,  8); x10 = x10 + x15 | 0; x05 = rotl(x05 ^ x10,  7);
      x01 = x01 + x06 | 0; x12 = rotl(x12 ^ x01, 16); x11 = x11 + x12 | 0; x06 = rotl(x06 ^ x11, 12);
      x01 = x01 + x06 | 0; x12 = rotl(x12 ^ x01,  8); x11 = x11 + x12 | 0; x06 = rotl(x06 ^ x11,  7);
      x02 = x02 + x07 | 0; x13 = rotl(x13 ^ x02, 16); x08 = x08 + x13 | 0; x07 = rotl(x07 ^ x08, 12);
      x02 = x02 + x07 | 0; x13 = rotl(x13 ^ x02,  8); x08 = x08 + x13 | 0; x07 = rotl(x07 ^ x08,  7);
      x03 = x03 + x04 | 0; x14 = rotl(x14 ^ x03, 16); x09 = x09 + x14 | 0; x04 = rotl(x04 ^ x09, 12);
      x03 = x03 + x04 | 0; x14 = rotl(x14 ^ x03,  8); x09 = x09 + x14 | 0; x04 = rotl(x04 ^ x09,  7);
    }
    let oi = 0;
    out[oi++] = y00 + x00 | 0; out[oi++] = y01 + x01 | 0; out[oi++] = y02 + x02 | 0; out[oi++] = y03 + x03 | 0;
    out[oi++] = y04 + x04 | 0; out[oi++] = y05 + x05 | 0; out[oi++] = y06 + x06 | 0; out[oi++] = y07 + x07 | 0;
    out[oi++] = y08 + x08 | 0; out[oi++] = y09 + x09 | 0; out[oi++] = y10 + x10 | 0; out[oi++] = y11 + x11 | 0;
    out[oi++] = y12 + x12 | 0; out[oi++] = y13 + x13 | 0; out[oi++] = y14 + x14 | 0; out[oi++] = y15 + x15 | 0;
  }
  var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 4,
    allowShortKeys: false
  });
  var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
  var updatePadded = (h, msg) => {
    h.update(msg);
    const leftover = msg.length % 16;
    if (leftover)
      h.update(ZEROS16.subarray(leftover));
  };
  var ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
  function computeTag(fn, key, nonce, ciphertext, AAD) {
    if (AAD !== void 0)
      abytes(AAD, void 0, "AAD");
    const authKey = fn(key, nonce, ZEROS32);
    const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);
    const h = poly1305.create(authKey);
    if (AAD)
      updatePadded(h, AAD);
    updatePadded(h, ciphertext);
    h.update(lengths);
    const res = h.digest();
    clean(authKey, lengths);
    return res;
  }
  var _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
    const tagLength = 16;
    return {
      encrypt(plaintext, output) {
        const plength = plaintext.length;
        output = getOutput(plength + tagLength, output, false);
        output.set(plaintext);
        const oPlain = output.subarray(0, -tagLength);
        xorStream(key, nonce, oPlain, oPlain, 1);
        const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
        output.set(tag, plength);
        clean(tag);
        return output;
      },
      decrypt(ciphertext, output) {
        output = getOutput(ciphertext.length - tagLength, output, false);
        const data = ciphertext.subarray(0, -tagLength);
        const passedTag = ciphertext.subarray(-tagLength);
        const tag = computeTag(xorStream, key, nonce, data, AAD);
        if (!equalBytes(passedTag, tag)) {
          clean(tag);
          throw new Error("invalid tag");
        }
        output.set(ciphertext.subarray(0, -tagLength));
        xorStream(key, nonce, output, output, 1);
        clean(tag);
        return output;
      }
    };
  };
  var chacha20poly1305 = /* @__PURE__ */ wrapCipher(
    { blockSize: 64, nonceLength: 12, tagLength: 16 },
    /* @__PURE__ */ _poly1305_aead(chacha20)
  );
  globalThis.chacha20poly1305 = chacha20poly1305;
})();

// ============================================================
// Twofish-256  —  twofish-ts (MIT, Logan R. Kearsley)
// Bundled inline; provides twofishMakeSession / twofishEncryptBlock
// ============================================================
(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/twofish-ts/bin/index.js
  var require_bin = __commonJS({
    "node_modules/twofish-ts/bin/index.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.decrypt = exports.encrypt = exports.makeSession = void 0;
      var P0 = new Uint8Array([169, 103, 179, 232, 4, 253, 163, 118, 154, 146, 128, 120, 228, 221, 209, 56, 13, 198, 53, 152, 24, 247, 236, 108, 67, 117, 55, 38, 250, 19, 148, 72, 242, 208, 139, 48, 132, 84, 223, 35, 25, 91, 61, 89, 243, 174, 162, 130, 99, 1, 131, 46, 217, 81, 155, 124, 166, 235, 165, 190, 22, 12, 227, 97, 192, 140, 58, 245, 115, 44, 37, 11, 187, 78, 137, 107, 83, 106, 180, 241, 225, 230, 189, 69, 226, 244, 182, 102, 204, 149, 3, 86, 212, 28, 30, 215, 251, 195, 142, 181, 233, 207, 191, 186, 234, 119, 57, 175, 51, 201, 98, 113, 129, 121, 9, 173, 36, 205, 249, 216, 229, 197, 185, 77, 68, 8, 134, 231, 161, 29, 170, 237, 6, 112, 178, 210, 65, 123, 160, 17, 49, 194, 39, 144, 32, 246, 96, 255, 150, 92, 177, 171, 158, 156, 82, 27, 95, 147, 10, 239, 145, 133, 73, 238, 45, 79, 143, 59, 71, 135, 109, 70, 214, 62, 105, 100, 42, 206, 203, 47, 252, 151, 5, 122, 172, 127, 213, 26, 75, 14, 167, 90, 40, 20, 63, 41, 136, 60, 76, 2, 184, 218, 176, 23, 85, 31, 138, 125, 87, 199, 141, 116, 183, 196, 159, 114, 126, 21, 34, 18, 88, 7, 153, 52, 110, 80, 222, 104, 101, 188, 219, 248, 200, 168, 43, 64, 220, 254, 50, 164, 202, 16, 33, 240, 211, 93, 15, 0, 111, 157, 54, 66, 74, 94, 193, 224]);
      var P1 = new Uint8Array([117, 243, 198, 244, 219, 123, 251, 200, 74, 211, 230, 107, 69, 125, 232, 75, 214, 50, 216, 253, 55, 113, 241, 225, 48, 15, 248, 27, 135, 250, 6, 63, 94, 186, 174, 91, 138, 0, 188, 157, 109, 193, 177, 14, 128, 93, 210, 213, 160, 132, 7, 20, 181, 144, 44, 163, 178, 115, 76, 84, 146, 116, 54, 81, 56, 176, 189, 90, 252, 96, 98, 150, 108, 66, 247, 16, 124, 40, 39, 140, 19, 149, 156, 199, 36, 70, 59, 112, 202, 227, 133, 203, 17, 208, 147, 184, 166, 131, 32, 255, 159, 119, 195, 204, 3, 111, 8, 191, 64, 231, 43, 226, 121, 12, 170, 130, 65, 58, 234, 185, 228, 154, 164, 151, 126, 218, 122, 23, 102, 148, 161, 29, 61, 240, 222, 179, 11, 114, 167, 28, 239, 209, 83, 62, 143, 51, 38, 95, 236, 118, 42, 73, 129, 136, 238, 33, 196, 26, 235, 217, 197, 57, 153, 205, 173, 49, 139, 1, 24, 35, 221, 31, 78, 45, 249, 72, 79, 242, 101, 142, 120, 92, 88, 25, 141, 229, 152, 87, 103, 127, 5, 100, 175, 99, 182, 254, 245, 183, 60, 165, 206, 233, 104, 68, 224, 77, 67, 105, 41, 46, 172, 21, 89, 168, 10, 158, 110, 71, 223, 52, 53, 106, 207, 220, 34, 201, 192, 155, 137, 212, 237, 171, 18, 162, 13, 82, 187, 2, 47, 169, 215, 97, 30, 180, 80, 4, 246, 194, 22, 37, 134, 86, 85, 9, 190, 145]);
      var MDS0 = new Uint32Array([3166450293, 3974898163, 538985414, 3014904308, 3671720923, 33721211, 3806473211, 2661219016, 3385453642, 3570665939, 404253670, 505323371, 2560101957, 2998024317, 2795950824, 640071499, 1010587606, 2475919922, 2189618904, 1381144829, 2071712823, 3149608817, 1532729329, 1195869153, 606354480, 1364320783, 3132802808, 1246425883, 3216984199, 218984698, 2964370182, 1970658879, 3537042782, 2105352378, 1717973422, 976921435, 1499012234, 0, 3452801980, 437969053, 2930650221, 2139073473, 724289457, 3200170254, 3772817536, 2324303965, 993743570, 1684323029, 3638069408, 3890718084, 1600120839, 454758676, 741130933, 4244419728, 825304876, 2155898275, 1936927410, 202146163, 2037997388, 1802191188, 1263207058, 1397975412, 2492763958, 2206408529, 707409464, 3301219504, 572704957, 3587569754, 3183330300, 1212708960, 4294954594, 1280051094, 1094809452, 3351766594, 3958056183, 471602192, 1566401404, 909517352, 1734852647, 3924406156, 1145370899, 336915093, 4126522268, 3486456007, 1061104932, 3233866566, 1920129851, 1414818928, 690572490, 4042274275, 134807173, 3334870987, 4092808977, 2358043856, 2762234259, 3402274488, 1751661478, 3099086211, 943204384, 3857002239, 2913818271, 185304183, 3368558019, 2577006540, 1482222851, 421108335, 235801096, 2509602495, 1886408768, 4160172263, 1852755755, 522153698, 3048553849, 151588620, 1633760426, 1465325186, 2678000449, 2644344890, 286352618, 623234489, 2947538404, 1162152090, 3755969956, 2745392279, 3941258622, 892688602, 3991785594, 1128528919, 4177054566, 4227576212, 926405537, 4210704413, 3267520573, 3031747824, 842161630, 2627498419, 1448535819, 3823360626, 2273796263, 353704732, 4193860335, 1667481553, 875866451, 2593817918, 2981184143, 2088554803, 2290653990, 1027450463, 2711738348, 3840204662, 2172752938, 2442199369, 252705665, 4008618632, 370565614, 3621221153, 2543318468, 2779097114, 4278075371, 1835906521, 2021174981, 3318050105, 488498585, 1987486925, 1044307117, 3419105073, 3065399179, 4025441025, 303177240, 1616954659, 1785376989, 1296954911, 3469666638, 3739122733, 1431674361, 2122209864, 555856463, 50559730, 2694850149, 1583225230, 1515873912, 1701137244, 1650609752, 4261233945, 101119117, 1077970661, 4075994776, 859024471, 387420263, 84250239, 3907542533, 1330609508, 2307484335, 269522275, 1953771446, 168457726, 1549570805, 2610656439, 757936956, 808507045, 774785486, 1229556201, 1179021928, 2004309316, 2829637856, 2526413901, 673758531, 2846435689, 3654908201, 2256965934, 3520169900, 4109650453, 2374833497, 3604382376, 3115957258, 1111625118, 4143366510, 791656519, 3722249951, 589510964, 3435946549, 4059153514, 3250655951, 2240146396, 2408554018, 1903272393, 2425417920, 2863289243, 16904585, 2341200340, 1313770733, 2391699371, 2880152082, 1869561506, 3873854477, 3688624722, 2459073467, 3082270210, 1768540719, 960092585, 3553823959, 2812748641, 2728570142, 3284375988, 1819034704, 117900548, 67403766, 656885442, 2896996118, 3503322661, 1347425158, 3705468758, 2223250005, 3789639945, 2054825406, 320073617]);
      var MDS1 = new Uint32Array([2849585465, 1737496343, 3010567324, 3906119334, 67438343, 4254618194, 2741338240, 1994384612, 2584233285, 2449623883, 2158026976, 2019973722, 3839733679, 3719326314, 3518980963, 943073834, 223667942, 3326287904, 895667404, 2562650866, 404623890, 4146392043, 3973554593, 1819754817, 1136470056, 1966259388, 936672123, 647727240, 4201647373, 335103044, 2494692347, 1213890174, 4068082435, 3504639116, 2336732854, 809247780, 2225465319, 1413573483, 3741769181, 600137824, 424017405, 1537423930, 1030275778, 1494584717, 4079086828, 2922473062, 2722000751, 2182502231, 1670713360, 22802415, 2202908856, 781289094, 3652545901, 1361019779, 2605951658, 2086886749, 2788911208, 3946839806, 2782277680, 3190127226, 380087468, 202311945, 3811963120, 1629726631, 3236991120, 2360338921, 981507485, 4120009820, 1937837068, 740766001, 628543696, 199710294, 3145437842, 1323945678, 2314273025, 1805590046, 1403597876, 1791291889, 3029976003, 4053228379, 3783477063, 3865778200, 3184009762, 1158584472, 3798867743, 4106859443, 3056563316, 1724643576, 3439303065, 2515145748, 65886296, 1459084508, 3571551115, 471536917, 514695842, 3607942099, 4213957346, 3273509064, 2384027230, 3049401388, 3918088521, 3474112961, 3212744085, 3122691453, 3932426513, 2005142283, 963495365, 2942994825, 869366908, 3382800753, 1657733119, 1899477947, 2180714255, 2034087349, 156361185, 2916892222, 606945087, 3450107510, 4187837781, 3639509634, 3850780736, 3316545656, 3117229349, 1292146326, 1146451831, 134876686, 2249412688, 3878746103, 2714974007, 490797818, 2855559521, 3985395278, 112439472, 1886147668, 2989126515, 3528604475, 1091280799, 2072707586, 2693322968, 290452467, 828885963, 3259377447, 666920807, 2427780348, 539506744, 4135519236, 1618495560, 4281263589, 2517060684, 1548445029, 2982619947, 2876214926, 2651669058, 2629563893, 1391647707, 468929098, 1604730173, 2472125604, 180140473, 4013619705, 2448364307, 2248017928, 1224839569, 3999340054, 763158238, 1337073953, 2403512753, 1004237426, 1203253039, 2269691839, 1831644846, 1189331136, 3596041276, 1048943258, 1764338089, 1685933903, 714375553, 3460902446, 3407333062, 801794409, 4240686525, 2539430819, 90106088, 2060512749, 2894582225, 2140013829, 3585762404, 447260069, 1270294054, 247054014, 2808121223, 1526257109, 673330742, 336665371, 1071543669, 695851481, 2292903662, 1009986861, 1281325433, 45529015, 3096890058, 3663213877, 2963064004, 402408259, 1427801220, 536235341, 2317113689, 2100867762, 1470903091, 3340292047, 2381579782, 1953059667, 3077872539, 3304429463, 2673257901, 1926947811, 2127948522, 357233908, 580816783, 312650667, 1481532002, 132669279, 2581929245, 876159779, 1858205430, 1346661484, 3730649650, 1752319558, 1697030304, 3163803085, 3674462938, 4173773498, 3371867806, 2827146966, 735014510, 1079013488, 3706422661, 4269083146, 847942547, 2760761311, 3393988905, 269753372, 561240023, 4039947444, 3540636884, 1561365130, 266490193, 0, 1872369945, 2648709658, 915379348, 1122420679, 1257032137, 1593692882, 3249241983, 3772295336]);
      var MDS2 = new Uint32Array([3161832498, 3975408673, 549855299, 3019158473, 3671841283, 41616011, 3808158251, 2663948026, 3377121772, 3570652169, 417732715, 510336671, 2554697742, 2994582072, 2800264914, 642459319, 1020673111, 2469565322, 2195227374, 1392333464, 2067233748, 3144792887, 1542544279, 1205946243, 607134780, 1359958498, 3136862918, 1243302643, 3213344584, 234491248, 2953228467, 1967093214, 3529429757, 2109373728, 1722705457, 979057315, 1502239004, 0, 3451702675, 446503648, 2926423596, 2143387563, 733031367, 3188637369, 3766542496, 2321386e3, 1003633490, 1691706554, 3634419848, 3884246949, 1594318824, 454302481, 750070978, 4237360308, 824979751, 2158198885, 1941074730, 208866433, 2035054943, 1800694593, 1267878658, 1400132457, 2486604943, 2203157279, 708323894, 3299919004, 582820552, 3579500024, 3187457475, 1214269560, 4284678094, 1284918279, 1097613687, 3343042534, 3958893348, 470817812, 1568431459, 908604962, 1730635712, 3918326191, 1142113529, 345314538, 4120704443, 3485978392, 1059340077, 3225862371, 1916498651, 1416647788, 701114700, 4041470005, 142936318, 3335243287, 4078039887, 2362477796, 2761139289, 3401108118, 1755736123, 3095640141, 941635624, 3858752814, 2912922966, 192351108, 3368273949, 2580322815, 1476614381, 426711450, 235408906, 2512360830, 1883271248, 4159174448, 1848340175, 534912878, 3044652349, 151783695, 1638555956, 1468159766, 2671877899, 2637864320, 300552548, 632890829, 2951000029, 1167738120, 3752124301, 2744623964, 3934186197, 903492952, 3984256464, 1125598204, 4167497931, 4220844977, 933312467, 4196268608, 3258827368, 3035673804, 853422685, 2629016689, 1443583719, 3815957466, 2275903328, 354161947, 4193253690, 1674666943, 877868201, 2587794053, 2978984258, 2083749073, 2284226715, 1029651878, 2716639703, 3832997087, 2167046548, 2437517569, 260116475, 4001951402, 384702049, 3609319283, 2546243573, 2769986984, 4276878911, 1842965941, 2026207406, 3308897645, 496573925, 1993176740, 1051541212, 3409038183, 3062609479, 4009881435, 303567390, 1612931269, 1792895664, 1293897206, 3461271273, 3727548028, 1442403741, 2118680154, 558834098, 66192250, 2691014694, 1586388505, 1517836902, 1700554059, 1649959502, 4246338885, 109905652, 1088766086, 4070109886, 861352876, 392632208, 92210574, 3892701278, 1331974013, 2309982570, 274927765, 1958114351, 184420981, 1559583890, 2612501364, 758918451, 816132310, 785264201, 1240025481, 1181238898, 2000975701, 2833295576, 2521667076, 675489981, 2842274089, 3643398521, 2251196049, 3517763975, 4095079498, 2371456277, 3601389186, 3104487868, 1117667853, 4134467265, 793194424, 3722435846, 590619449, 3426077794, 4050317764, 3251618066, 2245821931, 2401406878, 1909027233, 2428539120, 2862328403, 25756145, 2345962465, 1324174988, 2393607791, 2870127522, 1872916286, 3859670612, 3679640562, 2461766267, 3070408630, 1764714954, 967391705, 3554136844, 2808194851, 2719916717, 3283403673, 1817209924, 117704453, 83231871, 667035462, 2887167143, 3492139126, 1350979603, 3696680183, 2220196890, 3775521105, 2059303461, 328274927]);
      var MDS3 = new Uint32Array([3644434905, 2417452944, 1906094961, 3534153938, 84345861, 2555575704, 1702929253, 3756291807, 138779144, 38507010, 2699067552, 1717205094, 3719292125, 2959793584, 3210990015, 908736566, 1424362836, 1126221379, 1657550178, 3203569854, 504502302, 619444004, 3617713367, 2000776311, 3173532605, 851211570, 3564845012, 2609391259, 1879964272, 4181988345, 2986054833, 1518225498, 2047079034, 3834433764, 1203145543, 1009004604, 2783413413, 1097552961, 115203846, 3311412165, 1174214981, 2738510755, 1757560168, 361584917, 569176865, 828812849, 1047503422, 374833686, 2500879253, 1542390107, 1303937869, 2441490065, 3043875253, 528699679, 1403689811, 1667071075, 996714043, 1073670975, 3593512406, 628801061, 2813073063, 252251151, 904979253, 598171939, 4036018416, 2951318703, 2157787776, 2455565714, 2165076865, 657533991, 1993352566, 3881176039, 2073213819, 3922611945, 4043409905, 2669570975, 2838778793, 3304155844, 2579739801, 2539385239, 2202526083, 1796793963, 3357720008, 244860174, 1847583342, 3384014025, 796177967, 3422054091, 4288269567, 3927217642, 3981968365, 4158412535, 3784037601, 454368283, 2913083053, 215209740, 736295723, 499696413, 425627161, 3257710018, 2303322505, 314691346, 2123743102, 545110560, 1678895716, 2215344004, 1841641837, 1787408234, 3514577873, 2708588961, 3472843470, 935031095, 4212097531, 1035303229, 1373702481, 3695095260, 759112749, 2759249316, 2639657373, 4001552622, 2252400006, 2927150510, 3441801677, 76958980, 1433879637, 168691722, 324044307, 821552944, 3543638483, 1090133312, 878815796, 2353982860, 3014657715, 1817473132, 712225322, 1379652178, 194986251, 2332195723, 2295898248, 1341329743, 1741369703, 1177010758, 3227985856, 3036450996, 674766888, 2131031679, 2018009208, 786825006, 122459655, 1264933963, 3341529543, 1871620975, 222469645, 3153435835, 4074459890, 4081720307, 2789040038, 1503957849, 3166243516, 989458234, 4011037167, 4261971454, 26298625, 1628892769, 2094935420, 2988527538, 1118932802, 3681696731, 3090106296, 1220511560, 749628716, 3821029091, 1463604823, 2241478277, 698968361, 2102355069, 2491493012, 1227804233, 398904087, 3395891146, 3284008131, 1554224988, 1592264030, 3505224400, 2278665351, 2382725006, 3127170490, 2829392552, 3072740279, 3116240569, 1619502944, 4174732024, 573974562, 286987281, 3732226014, 2044275065, 2867759274, 858602547, 1601784927, 3065447094, 2529867926, 1479924312, 2630135964, 4232255484, 444880154, 4132249590, 475630108, 951221560, 2889045932, 416270104, 4094070260, 1767076969, 1956362100, 4120364277, 1454219094, 3672339162, 3588914901, 1257510218, 2660180638, 2729120418, 1315067982, 3898542056, 3843922405, 958608441, 3254152897, 1147949124, 1563614813, 1917216882, 648045862, 2479733907, 64674563, 3334142150, 4204710138, 2195105922, 3480103887, 1349533776, 3951418603, 1963654773, 2324902538, 2380244109, 1277807180, 337383444, 1943478643, 3434410188, 164942601, 277503248, 3796963298, 0, 2585358234, 3759840736, 2408855183, 3871818470, 3972614892, 4258422525, 2877276587, 3634946264]);
      var ROUNDS = 16;
      var SK_STEP = 16843009;
      var SK_ROTL = 9;
      var ROUND_SUBKEYS = 8;
      var SUBKEY_CNT = 40;
      var RS_GF_FDBK = 333;
      function b0(x) {
        return x & 255;
      }
      function b1(x) {
        return x >>> 8 & 255;
      }
      function b2(x) {
        return x >>> 16 & 255;
      }
      function b3(x) {
        return x >>> 24 & 255;
      }
      function rsMDSEncode(k0, k1) {
        let b = k1 >>> 24 & 255;
        let g2 = (b << 1 ^ ((b & 128) !== 0 ? RS_GF_FDBK : 0)) & 255;
        let g3 = b >>> 1 ^ ((b & 1) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
        k1 = k1 << 8 ^ g3 << 24 ^ g2 << 16 ^ g3 << 8 ^ b;
        for (let i = 0; i < 3; i++) {
          b = k1 >>> 24 & 255;
          g2 = (b << 1 ^ ((b & 128) !== 0 ? RS_GF_FDBK : 0)) & 255;
          g3 = b >>> 1 ^ ((b & 1) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
          k1 = k1 << 8 ^ g3 << 24 ^ g2 << 16 ^ g3 << 8 ^ b;
        }
        k1 ^= k0;
        for (let i = 0; i < 4; i++) {
          b = k1 >>> 24 & 255;
          g2 = (b << 1 ^ ((b & 128) !== 0 ? RS_GF_FDBK : 0)) & 255;
          g3 = b >>> 1 ^ ((b & 1) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
          k1 = k1 << 8 ^ g3 << 24 ^ g2 << 16 ^ g3 << 8 ^ b;
        }
        return k1;
      }
      var subKeyWord = new Uint32Array(4);
      function getSubKeyWord(k64Cnt, k0, k1, k2, k3, B0, B1, B2, B3) {
        switch (k64Cnt & 3) {
          case 0:
            B0 = P1[B0] ^ b0(k3);
            B1 = P0[B1] ^ b1(k3);
            B2 = P0[B2] ^ b2(k3);
            B3 = P1[B3] ^ b3(k3);
          case 3:
            B0 = P1[B0] ^ b0(k2);
            B1 = P1[B1] ^ b1(k2);
            B2 = P0[B2] ^ b2(k2);
            B3 = P0[B3] ^ b3(k2);
          case 2:
            B0 = P0[B0] ^ b0(k1);
            B1 = P1[B1] ^ b1(k1);
            B2 = P0[B2] ^ b2(k1);
            B3 = P1[B3] ^ b3(k1);
          default:
          case 1:
            subKeyWord[0] = MDS0[P0[B0] ^ b0(k0)];
            subKeyWord[1] = MDS1[P0[B1] ^ b1(k0)];
            subKeyWord[2] = MDS2[P1[B2] ^ b2(k0)];
            subKeyWord[3] = MDS3[P1[B3] ^ b3(k0)];
            return;
        }
      }
      function makeSession2(key) {
        let keyLength = key.length;
        if (keyLength > 32) {
          key = key.subarray(0, 32);
        } else {
          const mod = keyLength & 7;
          if (keyLength === 0 || mod !== 0) {
            keyLength += 8 - mod;
            const nkey = new Uint8Array(keyLength);
            nkey.set(key);
            key = nkey;
          }
        }
        const k64Cnt = keyLength / 8;
        const sessionMemory = new ArrayBuffer(4256);
        const sBox = new Uint32Array(sessionMemory, 0, 1024);
        let offset = 0;
        let k0 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        let k1 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        sBox[k64Cnt - 1] = rsMDSEncode(k0, k1);
        let k2 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        let k3 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        sBox[k64Cnt - 2] = rsMDSEncode(k2, k3);
        const k4 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        const k5 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        sBox[k64Cnt - 3] = rsMDSEncode(k4, k5);
        const k6 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        const k7 = key[offset++] | key[offset++] << 8 | key[offset++] << 16 | key[offset++] << 24;
        sBox[k64Cnt - 4] = rsMDSEncode(k6, k7);
        let A;
        let B;
        const subKeys = new Uint32Array(sessionMemory, 4096, 40);
        for (let i = 0, q = 0, j = 0; i < SUBKEY_CNT / 2; i++, j += 2) {
          getSubKeyWord(k64Cnt, k0, k2, k4, k6, b0(q), b1(q), b2(q), b3(q));
          A = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
          q += SK_STEP;
          getSubKeyWord(k64Cnt, k1, k3, k5, k7, b0(q), b1(q), b2(q), b3(q));
          B = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
          q += SK_STEP;
          B = B << 8 | B >>> 24;
          A += B;
          subKeys[j] = A;
          A += B;
          subKeys[j + 1] = A << SK_ROTL | A >>> 32 - SK_ROTL;
        }
        k0 = sBox[0];
        k1 = sBox[1];
        k2 = sBox[2];
        k3 = sBox[3];
        for (let i = 0, j = 0; i < 256; i++, j += 2) {
          getSubKeyWord(k64Cnt, k0, k1, k2, k3, i, i, i, i);
          sBox[j] = subKeyWord[0];
          sBox[j + 1] = subKeyWord[1];
          sBox[512 + j] = subKeyWord[2];
          sBox[513 + j] = subKeyWord[3];
        }
        return [sBox, subKeys];
      }
      exports.makeSession = makeSession2;
      function outputBlock(out, oo, x0, x1, x2, x3) {
        out[oo++] = x0;
        out[oo++] = x0 >>> 8;
        out[oo++] = x0 >>> 16;
        out[oo++] = x0 >>> 24;
        out[oo++] = x1;
        out[oo++] = x1 >>> 8;
        out[oo++] = x1 >>> 16;
        out[oo++] = x1 >>> 24;
        out[oo++] = x2;
        out[oo++] = x2 >>> 8;
        out[oo++] = x2 >>> 16;
        out[oo++] = x2 >>> 24;
        out[oo++] = x3;
        out[oo++] = x3 >>> 8;
        out[oo++] = x3 >>> 16;
        out[oo++] = x3 >>> 24;
      }
      function encrypt2(plain, io, cipher, oo, [sBox, sKey]) {
        if (cipher.length < oo + 16) {
          throw new Error("Insufficient space to write ciphertext block.");
        }
        let x0 = (plain[io++] | plain[io++] << 8 | plain[io++] << 16 | plain[io++] << 24) ^ sKey[0];
        let x1 = (plain[io++] | plain[io++] << 8 | plain[io++] << 16 | plain[io++] << 24) ^ sKey[1];
        let x2 = (plain[io++] | plain[io++] << 8 | plain[io++] << 16 | plain[io++] << 24) ^ sKey[2];
        let x3 = (plain[io++] | plain[io++] << 8 | plain[io++] << 16 | plain[io++] << 24) ^ sKey[3];
        let t0;
        let t1;
        let k = ROUND_SUBKEYS;
        for (let R = 0; R < ROUNDS; R += 2) {
          t0 = sBox[x0 << 1 & 510] ^ sBox[(x0 >>> 7 & 510) + 1] ^ sBox[512 + (x0 >>> 15 & 510)] ^ sBox[512 + (x0 >>> 23 & 510) + 1];
          t1 = sBox[x1 >>> 23 & 510] ^ sBox[(x1 << 1 & 510) + 1] ^ sBox[512 + (x1 >>> 7 & 510)] ^ sBox[512 + (x1 >>> 15 & 510) + 1];
          x2 ^= t0 + t1 + sKey[k++];
          x2 = x2 >>> 1 | x2 << 31;
          x3 = x3 << 1 | x3 >>> 31;
          x3 ^= t0 + 2 * t1 + sKey[k++];
          t0 = sBox[x2 << 1 & 510] ^ sBox[(x2 >>> 7 & 510) + 1] ^ sBox[512 + (x2 >>> 15 & 510)] ^ sBox[512 + (x2 >>> 23 & 510) + 1];
          t1 = sBox[x3 >>> 23 & 510] ^ sBox[(x3 << 1 & 510) + 1] ^ sBox[512 + (x3 >>> 7 & 510)] ^ sBox[512 + (x3 >>> 15 & 510) + 1];
          x0 ^= t0 + t1 + sKey[k++];
          x0 = x0 >>> 1 | x0 << 31;
          x1 = x1 << 1 | x1 >>> 31;
          x1 ^= t0 + 2 * t1 + sKey[k++];
        }
        outputBlock(cipher, oo, x2 ^ sKey[4], x3 ^ sKey[5], x0 ^ sKey[6], x1 ^ sKey[7]);
      }
      exports.encrypt = encrypt2;
      function decrypt2(cipher, io, plain, oo, [sBox, sKey]) {
        if (cipher.length < io + 16) {
          throw new Error("Incomplete ciphertext block.");
        }
        if (plain.length < oo + 16) {
          throw new Error("Insufficient space to write plaintext block.");
        }
        let x2 = (cipher[io++] | cipher[io++] << 8 | cipher[io++] << 16 | cipher[io++] << 24) ^ sKey[4];
        let x3 = (cipher[io++] | cipher[io++] << 8 | cipher[io++] << 16 | cipher[io++] << 24) ^ sKey[5];
        let x0 = (cipher[io++] | cipher[io++] << 8 | cipher[io++] << 16 | cipher[io++] << 24) ^ sKey[6];
        let x1 = (cipher[io++] | cipher[io++] << 8 | cipher[io++] << 16 | cipher[io++] << 24) ^ sKey[7];
        let t0;
        let t1;
        let k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
        for (let R = 0; R < ROUNDS; R += 2) {
          t0 = sBox[x2 << 1 & 510] ^ sBox[(x2 >>> 7 & 510) + 1] ^ sBox[512 + (x2 >>> 15 & 510)] ^ sBox[512 + (x2 >>> 23 & 510) + 1];
          t1 = sBox[x3 >>> 23 & 510] ^ sBox[(x3 << 1 & 510) + 1] ^ sBox[512 + (x3 >>> 7 & 510)] ^ sBox[512 + (x3 >>> 15 & 510) + 1];
          x1 ^= t0 + 2 * t1 + sKey[k--];
          x1 = x1 >>> 1 | x1 << 31;
          x0 = x0 << 1 | x0 >>> 31;
          x0 ^= t0 + t1 + sKey[k--];
          t0 = sBox[x0 << 1 & 510] ^ sBox[(x0 >>> 7 & 510) + 1] ^ sBox[512 + (x0 >>> 15 & 510)] ^ sBox[512 + (x0 >>> 23 & 510) + 1];
          t1 = sBox[x1 >>> 23 & 510] ^ sBox[(x1 << 1 & 510) + 1] ^ sBox[512 + (x1 >>> 7 & 510)] ^ sBox[512 + (x1 >>> 15 & 510) + 1];
          x3 ^= t0 + 2 * t1 + sKey[k--];
          x3 = x3 >>> 1 | x3 << 31;
          x2 = x2 << 1 | x2 >>> 31;
          x2 ^= t0 + t1 + sKey[k--];
        }
        outputBlock(plain, oo, x0 ^ sKey[0], x1 ^ sKey[1], x2 ^ sKey[2], x3 ^ sKey[3]);
      }
      exports.decrypt = decrypt2;
    }
  });

  // twofish_entry.js
  var import_twofish_ts = __toESM(require_bin());
  globalThis.twofishMakeSession = import_twofish_ts.makeSession;
  globalThis.twofishEncryptBlock = import_twofish_ts.encrypt;
  globalThis.twofishDecryptBlock = import_twofish_ts.decrypt;
})();


// ============================================================
// Serpent-256  —  bitslice forward block cipher (verified vs BouncyCastle vectors)
// Provides globalThis.serpentMakeSession / globalThis.serpentEncryptBlock
// ============================================================
// Serpent-256 — forward block cipher only (CTR mode needs no decryption).
// Hand-written bitslice implementation, verified against BouncyCastle's 256-bit
// ECB test vectors. Little-endian word convention for both key and block.
// Exposes globalThis.serpentMakeSession(key32) and
// globalThis.serpentEncryptBlock(inArr, inOff, outArr, outOff, session),
// mirroring the Twofish bundle's session API so serpentCTR can copy twofishCTR.
(function () {
  "use strict";
  var SBOX = [
    [3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12],
    [15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],
    [8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2],
    [0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14],
    [1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13],
    [15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],
    [7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0],
    [1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6]
  ];
  var PHI = 0x9e3779b9 | 0;

  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) | 0; }

  function applySbox(box, x) {
    var t = SBOX[box], y0 = 0, y1 = 0, y2 = 0, y3 = 0, j, nib, v;
    for (j = 0; j < 32; j++) {
      nib = ((x[0] >>> j) & 1) | (((x[1] >>> j) & 1) << 1) | (((x[2] >>> j) & 1) << 2) | (((x[3] >>> j) & 1) << 3);
      v = t[nib];
      y0 |= (v & 1) << j;
      y1 |= ((v >>> 1) & 1) << j;
      y2 |= ((v >>> 2) & 1) << j;
      y3 |= ((v >>> 3) & 1) << j;
    }
    x[0] = y0 | 0; x[1] = y1 | 0; x[2] = y2 | 0; x[3] = y3 | 0;
  }

  function LT(x) {
    var x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
    x0 = rotl(x0, 13);
    x2 = rotl(x2, 3);
    x1 = x1 ^ x0 ^ x2;
    x3 = x3 ^ x2 ^ ((x0 << 3) | 0);
    x1 = rotl(x1, 1);
    x3 = rotl(x3, 7);
    x0 = x0 ^ x1 ^ x3;
    x2 = x2 ^ x3 ^ ((x1 << 7) | 0);
    x0 = rotl(x0, 5);
    x2 = rotl(x2, 22);
    x[0] = x0 | 0; x[1] = x1 | 0; x[2] = x2 | 0; x[3] = x3 | 0;
  }

  // key32: Uint8Array(32). Returns the 33 round subkeys (Array of [w,w,w,w]).
  function makeSession(key32) {
    var w = new Array(140), i, o;
    for (i = 0; i < 8; i++) {
      o = i * 4;
      w[i] = (key32[o] | (key32[o+1] << 8) | (key32[o+2] << 16) | (key32[o+3] << 24)) | 0;
    }
    for (i = 8; i < 140; i++) {
      w[i] = rotl((w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ ((i - 8) | 0)) | 0, 11);
    }
    var K = [], g, box, grp;
    for (g = 0; g <= 32; g++) {
      box = (((3 - g) % 8) + 8) % 8;
      grp = [w[8 + 4*g], w[8 + 4*g + 1], w[8 + 4*g + 2], w[8 + 4*g + 3]];
      applySbox(box, grp);
      K.push(grp);
    }
    return K;
  }

  // Encrypt one 16-byte block: inArr[inOff..inOff+15] -> outArr[outOff..outOff+15].
  function encryptBlock(inArr, inOff, outArr, outOff, K) {
    var x = [0,0,0,0], i, o, v;
    for (i = 0; i < 4; i++) {
      o = inOff + i * 4;
      x[i] = (inArr[o] | (inArr[o+1] << 8) | (inArr[o+2] << 16) | (inArr[o+3] << 24)) | 0;
    }
    for (i = 0; i < 32; i++) {
      x[0] ^= K[i][0]; x[1] ^= K[i][1]; x[2] ^= K[i][2]; x[3] ^= K[i][3];
      applySbox(i % 8, x);
      if (i < 31) LT(x);
      else { x[0] ^= K[32][0]; x[1] ^= K[32][1]; x[2] ^= K[32][2]; x[3] ^= K[32][3]; }
    }
    for (i = 0; i < 4; i++) {
      o = outOff + i * 4; v = x[i];
      outArr[o] = v & 0xff; outArr[o+1] = (v >>> 8) & 0xff;
      outArr[o+2] = (v >>> 16) & 0xff; outArr[o+3] = (v >>> 24) & 0xff;
    }
  }

  globalThis.serpentMakeSession  = makeSession;
  globalThis.serpentEncryptBlock = encryptBlock;
})();

// ============================================================
// Argon2id  —  hash-wasm (MIT). Bundled inline; provides globalThis.argon2idHash
// Build: npx esbuild argon2_entry.js --bundle --format=iife --platform=browser --outfile=argon2_bundle.js
// ============================================================
(() => {
  // node_modules/hash-wasm/dist/index.esm.js
  function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P ? value : new P(function(resolve) {
        resolve(value);
      });
    }
    return new (P || (P = Promise))(function(resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator["throw"](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  }
  var Mutex = class {
    constructor() {
      this.mutex = Promise.resolve();
    }
    lock() {
      let begin = () => {
      };
      this.mutex = this.mutex.then(() => new Promise(begin));
      return new Promise((res) => {
        begin = res;
      });
    }
    dispatch(fn) {
      return __awaiter(this, void 0, void 0, function* () {
        const unlock = yield this.lock();
        try {
          return yield Promise.resolve(fn());
        } finally {
          unlock();
        }
      });
    }
  };
  var _a;
  function getGlobal() {
    if (typeof globalThis !== "undefined")
      return globalThis;
    if (typeof self !== "undefined")
      return self;
    if (typeof window !== "undefined")
      return window;
    return global;
  }
  var globalObject = getGlobal();
  var nodeBuffer = (_a = globalObject.Buffer) !== null && _a !== void 0 ? _a : null;
  var textEncoder = globalObject.TextEncoder ? new globalObject.TextEncoder() : null;
  function hexCharCodesToInt(a, b) {
    return (a & 15) + (a >> 6 | a >> 3 & 8) << 4 | (b & 15) + (b >> 6 | b >> 3 & 8);
  }
  function writeHexToUInt8(buf, str) {
    const size = str.length >> 1;
    for (let i = 0; i < size; i++) {
      const index = i << 1;
      buf[i] = hexCharCodesToInt(str.charCodeAt(index), str.charCodeAt(index + 1));
    }
  }
  function hexStringEqualsUInt8(str, buf) {
    if (str.length !== buf.length * 2) {
      return false;
    }
    for (let i = 0; i < buf.length; i++) {
      const strIndex = i << 1;
      if (buf[i] !== hexCharCodesToInt(str.charCodeAt(strIndex), str.charCodeAt(strIndex + 1))) {
        return false;
      }
    }
    return true;
  }
  var alpha = "a".charCodeAt(0) - 10;
  var digit = "0".charCodeAt(0);
  function getDigestHex(tmpBuffer, input, hashLength) {
    let p = 0;
    for (let i = 0; i < hashLength; i++) {
      let nibble = input[i] >>> 4;
      tmpBuffer[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
      nibble = input[i] & 15;
      tmpBuffer[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
    }
    return String.fromCharCode.apply(null, tmpBuffer);
  }
  var getUInt8Buffer = nodeBuffer !== null ? (data) => {
    if (typeof data === "string") {
      const buf = nodeBuffer.from(data, "utf8");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
    }
    if (nodeBuffer.isBuffer(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.length);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    throw new Error("Invalid data type!");
  } : (data) => {
    if (typeof data === "string") {
      return textEncoder.encode(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    throw new Error("Invalid data type!");
  };
  var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var base64Lookup = new Uint8Array(256);
  for (let i = 0; i < base64Chars.length; i++) {
    base64Lookup[base64Chars.charCodeAt(i)] = i;
  }
  function encodeBase64(data, pad = true) {
    const len = data.length;
    const extraBytes = len % 3;
    const parts = [];
    const len2 = len - extraBytes;
    for (let i = 0; i < len2; i += 3) {
      const tmp = (data[i] << 16 & 16711680) + (data[i + 1] << 8 & 65280) + (data[i + 2] & 255);
      const triplet = base64Chars.charAt(tmp >> 18 & 63) + base64Chars.charAt(tmp >> 12 & 63) + base64Chars.charAt(tmp >> 6 & 63) + base64Chars.charAt(tmp & 63);
      parts.push(triplet);
    }
    if (extraBytes === 1) {
      const tmp = data[len - 1];
      const a = base64Chars.charAt(tmp >> 2);
      const b = base64Chars.charAt(tmp << 4 & 63);
      parts.push(`${a}${b}`);
      if (pad) {
        parts.push("==");
      }
    } else if (extraBytes === 2) {
      const tmp = (data[len - 2] << 8) + data[len - 1];
      const a = base64Chars.charAt(tmp >> 10);
      const b = base64Chars.charAt(tmp >> 4 & 63);
      const c = base64Chars.charAt(tmp << 2 & 63);
      parts.push(`${a}${b}${c}`);
      if (pad) {
        parts.push("=");
      }
    }
    return parts.join("");
  }
  function getDecodeBase64Length(data) {
    let bufferLength = Math.floor(data.length * 0.75);
    const len = data.length;
    if (data[len - 1] === "=") {
      bufferLength -= 1;
      if (data[len - 2] === "=") {
        bufferLength -= 1;
      }
    }
    return bufferLength;
  }
  function decodeBase64(data) {
    const bufferLength = getDecodeBase64Length(data);
    const len = data.length;
    const bytes = new Uint8Array(bufferLength);
    let p = 0;
    for (let i = 0; i < len; i += 4) {
      const encoded1 = base64Lookup[data.charCodeAt(i)];
      const encoded2 = base64Lookup[data.charCodeAt(i + 1)];
      const encoded3 = base64Lookup[data.charCodeAt(i + 2)];
      const encoded4 = base64Lookup[data.charCodeAt(i + 3)];
      bytes[p] = encoded1 << 2 | encoded2 >> 4;
      p += 1;
      bytes[p] = (encoded2 & 15) << 4 | encoded3 >> 2;
      p += 1;
      bytes[p] = (encoded3 & 3) << 6 | encoded4 & 63;
      p += 1;
    }
    return bytes;
  }
  var MAX_HEAP = 16 * 1024;
  var WASM_FUNC_HASH_LENGTH = 4;
  var wasmMutex = new Mutex();
  var wasmModuleCache = /* @__PURE__ */ new Map();
  function WASMInterface(binary, hashLength) {
    return __awaiter(this, void 0, void 0, function* () {
      let wasmInstance = null;
      let memoryView = null;
      let initialized = false;
      if (typeof WebAssembly === "undefined") {
        throw new Error("WebAssembly is not supported in this environment!");
      }
      const writeMemory = (data, offset = 0) => {
        memoryView.set(data, offset);
      };
      const getMemory = () => memoryView;
      const getExports = () => wasmInstance.exports;
      const setMemorySize = (totalSize) => {
        wasmInstance.exports.Hash_SetMemorySize(totalSize);
        const arrayOffset = wasmInstance.exports.Hash_GetBuffer();
        const memoryBuffer = wasmInstance.exports.memory.buffer;
        memoryView = new Uint8Array(memoryBuffer, arrayOffset, totalSize);
      };
      const getStateSize = () => {
        const view = new DataView(wasmInstance.exports.memory.buffer);
        const stateSize = view.getUint32(wasmInstance.exports.STATE_SIZE, true);
        return stateSize;
      };
      const loadWASMPromise = wasmMutex.dispatch(() => __awaiter(this, void 0, void 0, function* () {
        if (!wasmModuleCache.has(binary.name)) {
          const asm = decodeBase64(binary.data);
          const promise = WebAssembly.compile(asm);
          wasmModuleCache.set(binary.name, promise);
        }
        const module = yield wasmModuleCache.get(binary.name);
        wasmInstance = yield WebAssembly.instantiate(module, {
          // env: {
          //   emscripten_memcpy_big: (dest, src, num) => {
          //     const memoryBuffer = wasmInstance.exports.memory.buffer;
          //     const memView = new Uint8Array(memoryBuffer, 0);
          //     memView.set(memView.subarray(src, src + num), dest);
          //   },
          //   print_memory: (offset, len) => {
          //     const memoryBuffer = wasmInstance.exports.memory.buffer;
          //     const memView = new Uint8Array(memoryBuffer, 0);
          //     console.log('print_int32', memView.subarray(offset, offset + len));
          //   },
          // },
        });
      }));
      const setupInterface = () => __awaiter(this, void 0, void 0, function* () {
        if (!wasmInstance) {
          yield loadWASMPromise;
        }
        const arrayOffset = wasmInstance.exports.Hash_GetBuffer();
        const memoryBuffer = wasmInstance.exports.memory.buffer;
        memoryView = new Uint8Array(memoryBuffer, arrayOffset, MAX_HEAP);
      });
      const init = (bits = null) => {
        initialized = true;
        wasmInstance.exports.Hash_Init(bits);
      };
      const updateUInt8Array = (data) => {
        let read = 0;
        while (read < data.length) {
          const chunk = data.subarray(read, read + MAX_HEAP);
          read += chunk.length;
          memoryView.set(chunk);
          wasmInstance.exports.Hash_Update(chunk.length);
        }
      };
      const update = (data) => {
        if (!initialized) {
          throw new Error("update() called before init()");
        }
        const Uint8Buffer = getUInt8Buffer(data);
        updateUInt8Array(Uint8Buffer);
      };
      const digestChars = new Uint8Array(hashLength * 2);
      const digest = (outputType, padding = null) => {
        if (!initialized) {
          throw new Error("digest() called before init()");
        }
        initialized = false;
        wasmInstance.exports.Hash_Final(padding);
        if (outputType === "binary") {
          return memoryView.slice(0, hashLength);
        }
        return getDigestHex(digestChars, memoryView, hashLength);
      };
      const save = () => {
        if (!initialized) {
          throw new Error("save() can only be called after init() and before digest()");
        }
        const stateOffset = wasmInstance.exports.Hash_GetState();
        const stateLength = getStateSize();
        const memoryBuffer = wasmInstance.exports.memory.buffer;
        const internalState = new Uint8Array(memoryBuffer, stateOffset, stateLength);
        const prefixedState = new Uint8Array(WASM_FUNC_HASH_LENGTH + stateLength);
        writeHexToUInt8(prefixedState, binary.hash);
        prefixedState.set(internalState, WASM_FUNC_HASH_LENGTH);
        return prefixedState;
      };
      const load = (state) => {
        if (!(state instanceof Uint8Array)) {
          throw new Error("load() expects an Uint8Array generated by save()");
        }
        const stateOffset = wasmInstance.exports.Hash_GetState();
        const stateLength = getStateSize();
        const overallLength = WASM_FUNC_HASH_LENGTH + stateLength;
        const memoryBuffer = wasmInstance.exports.memory.buffer;
        if (state.length !== overallLength) {
          throw new Error(`Bad state length (expected ${overallLength} bytes, got ${state.length})`);
        }
        if (!hexStringEqualsUInt8(binary.hash, state.subarray(0, WASM_FUNC_HASH_LENGTH))) {
          throw new Error("This state was written by an incompatible hash implementation");
        }
        const internalState = state.subarray(WASM_FUNC_HASH_LENGTH);
        new Uint8Array(memoryBuffer, stateOffset, stateLength).set(internalState);
        initialized = true;
      };
      const isDataShort = (data) => {
        if (typeof data === "string") {
          return data.length < MAX_HEAP / 4;
        }
        return data.byteLength < MAX_HEAP;
      };
      let canSimplify = isDataShort;
      switch (binary.name) {
        case "argon2":
        case "scrypt":
          canSimplify = () => true;
          break;
        case "blake2b":
        case "blake2s":
          canSimplify = (data, initParam) => initParam <= 512 && isDataShort(data);
          break;
        case "blake3":
          canSimplify = (data, initParam) => initParam === 0 && isDataShort(data);
          break;
        case "xxhash64":
        // cannot simplify
        case "xxhash3":
        case "xxhash128":
        case "crc64":
          canSimplify = () => false;
          break;
      }
      const calculate = (data, initParam = null, digestParam = null) => {
        if (!canSimplify(data, initParam)) {
          init(initParam);
          update(data);
          return digest("hex", digestParam);
        }
        const buffer = getUInt8Buffer(data);
        memoryView.set(buffer);
        wasmInstance.exports.Hash_Calculate(buffer.length, initParam, digestParam);
        return getDigestHex(digestChars, memoryView, hashLength);
      };
      yield setupInterface();
      return {
        getMemory,
        writeMemory,
        getExports,
        setMemorySize,
        init,
        update,
        digest,
        save,
        load,
        calculate,
        hashLength
      };
    });
  }
  var mutex$l = new Mutex();
  var name$k = "argon2";
  var data$k = "AGFzbQEAAAABKQVgAX8Bf2AAAX9gEH9/f39/f39/f39/f39/f38AYAR/f39/AGACf38AAwYFAAECAwQFBgEBAoCAAgYIAX8BQZCoBAsHQQQGbWVtb3J5AgASSGFzaF9TZXRNZW1vcnlTaXplAAAOSGFzaF9HZXRCdWZmZXIAAQ5IYXNoX0NhbGN1bGF0ZQAECvEyBVgBAn9BACEBAkAgAEEAKAKICCICRg0AAkAgACACayIAQRB2IABBgIB8cSAASWoiAEAAQX9HDQBB/wHADwtBACEBQQBBACkDiAggAEEQdK18NwOICAsgAcALcAECfwJAQQAoAoAIIgANAEEAPwBBEHQiADYCgAhBACgCiAgiAUGAgCBGDQACQEGAgCAgAWsiAEEQdiAAQYCAfHEgAElqIgBAAEF/Rw0AQQAPC0EAQQApA4gIIABBEHStfDcDiAhBACgCgAghAAsgAAvcDgECfiAAIAQpAwAiECAAKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAMIBAgDCkDAIVCIIkiEDcDACAIIBAgCCkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgBCAQIAQpAwCFQiiJIhA3AwAgACAQIAApAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAwgECAMKQMAhUIwiSIQNwMAIAggECAIKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAEIBAgBCkDAIVCAYk3AwAgASAFKQMAIhAgASkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDSAQIA0pAwCFQiCJIhA3AwAgCSAQIAkpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAUgECAFKQMAhUIoiSIQNwMAIAEgECABKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACANIBAgDSkDAIVCMIkiEDcDACAJIBAgCSkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBSAQIAUpAwCFQgGJNwMAIAIgBikDACIQIAIpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIA4gECAOKQMAhUIgiSIQNwMAIAogECAKKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAGIBAgBikDAIVCKIkiEDcDACACIBAgAikDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgDiAQIA4pAwCFQjCJIhA3AwAgCiAQIAopAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAYgECAGKQMAhUIBiTcDACADIAcpAwAiECADKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAPIBAgDykDAIVCIIkiEDcDACALIBAgCykDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgByAQIAcpAwCFQiiJIhA3AwAgAyAQIAMpAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIA8gECAPKQMAhUIwiSIQNwMAIAsgECALKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAHIBAgBykDAIVCAYk3AwAgACAFKQMAIhAgACkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDyAQIA8pAwCFQiCJIhA3AwAgCiAQIAopAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAUgECAFKQMAhUIoiSIQNwMAIAAgECAAKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAPIBAgDykDAIVCMIkiEDcDACAKIBAgCikDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBSAQIAUpAwCFQgGJNwMAIAEgBikDACIQIAEpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAwgECAMKQMAhUIgiSIQNwMAIAsgECALKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAGIBAgBikDAIVCKIkiEDcDACABIBAgASkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgDCAQIAwpAwCFQjCJIhA3AwAgCyAQIAspAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAYgECAGKQMAhUIBiTcDACACIAcpAwAiECACKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACANIBAgDSkDAIVCIIkiEDcDACAIIBAgCCkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgByAQIAcpAwCFQiiJIhA3AwAgAiAQIAIpAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIA0gECANKQMAhUIwiSIQNwMAIAggECAIKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAHIBAgBykDAIVCAYk3AwAgAyAEKQMAIhAgAykDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDiAQIA4pAwCFQiCJIhA3AwAgCSAQIAkpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAQgECAEKQMAhUIoiSIQNwMAIAMgECADKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAOIBAgDikDAIVCMIkiEDcDACAJIBAgCSkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBCAQIAQpAwCFQgGJNwMAC98aAQN/QQAhBEEAIAIpAwAgASkDAIU3A5AIQQAgAikDCCABKQMIhTcDmAhBACACKQMQIAEpAxCFNwOgCEEAIAIpAxggASkDGIU3A6gIQQAgAikDICABKQMghTcDsAhBACACKQMoIAEpAyiFNwO4CEEAIAIpAzAgASkDMIU3A8AIQQAgAikDOCABKQM4hTcDyAhBACACKQNAIAEpA0CFNwPQCEEAIAIpA0ggASkDSIU3A9gIQQAgAikDUCABKQNQhTcD4AhBACACKQNYIAEpA1iFNwPoCEEAIAIpA2AgASkDYIU3A/AIQQAgAikDaCABKQNohTcD+AhBACACKQNwIAEpA3CFNwOACUEAIAIpA3ggASkDeIU3A4gJQQAgAikDgAEgASkDgAGFNwOQCUEAIAIpA4gBIAEpA4gBhTcDmAlBACACKQOQASABKQOQAYU3A6AJQQAgAikDmAEgASkDmAGFNwOoCUEAIAIpA6ABIAEpA6ABhTcDsAlBACACKQOoASABKQOoAYU3A7gJQQAgAikDsAEgASkDsAGFNwPACUEAIAIpA7gBIAEpA7gBhTcDyAlBACACKQPAASABKQPAAYU3A9AJQQAgAikDyAEgASkDyAGFNwPYCUEAIAIpA9ABIAEpA9ABhTcD4AlBACACKQPYASABKQPYAYU3A+gJQQAgAikD4AEgASkD4AGFNwPwCUEAIAIpA+gBIAEpA+gBhTcD+AlBACACKQPwASABKQPwAYU3A4AKQQAgAikD+AEgASkD+AGFNwOICkEAIAIpA4ACIAEpA4AChTcDkApBACACKQOIAiABKQOIAoU3A5gKQQAgAikDkAIgASkDkAKFNwOgCkEAIAIpA5gCIAEpA5gChTcDqApBACACKQOgAiABKQOgAoU3A7AKQQAgAikDqAIgASkDqAKFNwO4CkEAIAIpA7ACIAEpA7AChTcDwApBACACKQO4AiABKQO4AoU3A8gKQQAgAikDwAIgASkDwAKFNwPQCkEAIAIpA8gCIAEpA8gChTcD2ApBACACKQPQAiABKQPQAoU3A+AKQQAgAikD2AIgASkD2AKFNwPoCkEAIAIpA+ACIAEpA+AChTcD8ApBACACKQPoAiABKQPoAoU3A/gKQQAgAikD8AIgASkD8AKFNwOAC0EAIAIpA/gCIAEpA/gChTcDiAtBACACKQOAAyABKQOAA4U3A5ALQQAgAikDiAMgASkDiAOFNwOYC0EAIAIpA5ADIAEpA5ADhTcDoAtBACACKQOYAyABKQOYA4U3A6gLQQAgAikDoAMgASkDoAOFNwOwC0EAIAIpA6gDIAEpA6gDhTcDuAtBACACKQOwAyABKQOwA4U3A8ALQQAgAikDuAMgASkDuAOFNwPIC0EAIAIpA8ADIAEpA8ADhTcD0AtBACACKQPIAyABKQPIA4U3A9gLQQAgAikD0AMgASkD0AOFNwPgC0EAIAIpA9gDIAEpA9gDhTcD6AtBACACKQPgAyABKQPgA4U3A/ALQQAgAikD6AMgASkD6AOFNwP4C0EAIAIpA/ADIAEpA/ADhTcDgAxBACACKQP4AyABKQP4A4U3A4gMQQAgAikDgAQgASkDgASFNwOQDEEAIAIpA4gEIAEpA4gEhTcDmAxBACACKQOQBCABKQOQBIU3A6AMQQAgAikDmAQgASkDmASFNwOoDEEAIAIpA6AEIAEpA6AEhTcDsAxBACACKQOoBCABKQOoBIU3A7gMQQAgAikDsAQgASkDsASFNwPADEEAIAIpA7gEIAEpA7gEhTcDyAxBACACKQPABCABKQPABIU3A9AMQQAgAikDyAQgASkDyASFNwPYDEEAIAIpA9AEIAEpA9AEhTcD4AxBACACKQPYBCABKQPYBIU3A+gMQQAgAikD4AQgASkD4ASFNwPwDEEAIAIpA+gEIAEpA+gEhTcD+AxBACACKQPwBCABKQPwBIU3A4ANQQAgAikD+AQgASkD+ASFNwOIDUEAIAIpA4AFIAEpA4AFhTcDkA1BACACKQOIBSABKQOIBYU3A5gNQQAgAikDkAUgASkDkAWFNwOgDUEAIAIpA5gFIAEpA5gFhTcDqA1BACACKQOgBSABKQOgBYU3A7ANQQAgAikDqAUgASkDqAWFNwO4DUEAIAIpA7AFIAEpA7AFhTcDwA1BACACKQO4BSABKQO4BYU3A8gNQQAgAikDwAUgASkDwAWFNwPQDUEAIAIpA8gFIAEpA8gFhTcD2A1BACACKQPQBSABKQPQBYU3A+ANQQAgAikD2AUgASkD2AWFNwPoDUEAIAIpA+AFIAEpA+AFhTcD8A1BACACKQPoBSABKQPoBYU3A/gNQQAgAikD8AUgASkD8AWFNwOADkEAIAIpA/gFIAEpA/gFhTcDiA5BACACKQOABiABKQOABoU3A5AOQQAgAikDiAYgASkDiAaFNwOYDkEAIAIpA5AGIAEpA5AGhTcDoA5BACACKQOYBiABKQOYBoU3A6gOQQAgAikDoAYgASkDoAaFNwOwDkEAIAIpA6gGIAEpA6gGhTcDuA5BACACKQOwBiABKQOwBoU3A8AOQQAgAikDuAYgASkDuAaFNwPIDkEAIAIpA8AGIAEpA8AGhTcD0A5BACACKQPIBiABKQPIBoU3A9gOQQAgAikD0AYgASkD0AaFNwPgDkEAIAIpA9gGIAEpA9gGhTcD6A5BACACKQPgBiABKQPgBoU3A/AOQQAgAikD6AYgASkD6AaFNwP4DkEAIAIpA/AGIAEpA/AGhTcDgA9BACACKQP4BiABKQP4BoU3A4gPQQAgAikDgAcgASkDgAeFNwOQD0EAIAIpA4gHIAEpA4gHhTcDmA9BACACKQOQByABKQOQB4U3A6APQQAgAikDmAcgASkDmAeFNwOoD0EAIAIpA6AHIAEpA6AHhTcDsA9BACACKQOoByABKQOoB4U3A7gPQQAgAikDsAcgASkDsAeFNwPAD0EAIAIpA7gHIAEpA7gHhTcDyA9BACACKQPAByABKQPAB4U3A9APQQAgAikDyAcgASkDyAeFNwPYD0EAIAIpA9AHIAEpA9AHhTcD4A9BACACKQPYByABKQPYB4U3A+gPQQAgAikD4AcgASkD4AeFNwPwD0EAIAIpA+gHIAEpA+gHhTcD+A9BACACKQPwByABKQPwB4U3A4AQQQAgAikD+AcgASkD+AeFNwOIEEGQCEGYCEGgCEGoCEGwCEG4CEHACEHICEHQCEHYCEHgCEHoCEHwCEH4CEGACUGICRACQZAJQZgJQaAJQagJQbAJQbgJQcAJQcgJQdAJQdgJQeAJQegJQfAJQfgJQYAKQYgKEAJBkApBmApBoApBqApBsApBuApBwApByApB0ApB2ApB4ApB6ApB8ApB+ApBgAtBiAsQAkGQC0GYC0GgC0GoC0GwC0G4C0HAC0HIC0HQC0HYC0HgC0HoC0HwC0H4C0GADEGIDBACQZAMQZgMQaAMQagMQbAMQbgMQcAMQcgMQdAMQdgMQeAMQegMQfAMQfgMQYANQYgNEAJBkA1BmA1BoA1BqA1BsA1BuA1BwA1ByA1B0A1B2A1B4A1B6A1B8A1B+A1BgA5BiA4QAkGQDkGYDkGgDkGoDkGwDkG4DkHADkHIDkHQDkHYDkHgDkHoDkHwDkH4DkGAD0GIDxACQZAPQZgPQaAPQagPQbAPQbgPQcAPQcgPQdAPQdgPQeAPQegPQfAPQfgPQYAQQYgQEAJBkAhBmAhBkAlBmAlBkApBmApBkAtBmAtBkAxBmAxBkA1BmA1BkA5BmA5BkA9BmA8QAkGgCEGoCEGgCUGoCUGgCkGoCkGgC0GoC0GgDEGoDEGgDUGoDUGgDkGoDkGgD0GoDxACQbAIQbgIQbAJQbgJQbAKQbgKQbALQbgLQbAMQbgMQbANQbgNQbAOQbgOQbAPQbgPEAJBwAhByAhBwAlByAlBwApByApBwAtByAtBwAxByAxBwA1ByA1BwA5ByA5BwA9ByA8QAkHQCEHYCEHQCUHYCUHQCkHYCkHQC0HYC0HQDEHYDEHQDUHYDUHQDkHYDkHQD0HYDxACQeAIQegIQeAJQegJQeAKQegKQeALQegLQeAMQegMQeANQegNQeAOQegOQeAPQegPEAJB8AhB+AhB8AlB+AlB8ApB+ApB8AtB+AtB8AxB+AxB8A1B+A1B8A5B+A5B8A9B+A8QAkGACUGICUGACkGICkGAC0GIC0GADEGIDEGADUGIDUGADkGIDkGAD0GID0GAEEGIEBACAkACQCADRQ0AA0AgACAEaiIDIAIgBGoiBSkDACABIARqIgYpAwCFIARBkAhqKQMAhSADKQMAhTcDACADQQhqIgMgBUEIaikDACAGQQhqKQMAhSAEQZgIaikDAIUgAykDAIU3AwAgBEEQaiIEQYAIRw0ADAILC0EAIQQDQCAAIARqIgMgAiAEaiIFKQMAIAEgBGoiBikDAIUgBEGQCGopAwCFNwMAIANBCGogBUEIaikDACAGQQhqKQMAhSAEQZgIaikDAIU3AwAgBEEQaiIEQYAIRw0ACwsL5QcMBX8BfgR/An4BfwF+AX8Bfgd/AX4DfwF+AkBBACgCgAgiAiABQQp0aiIDKAIIIAFHDQAgAygCDCEEIAMoAgAhBUEAIAMoAhQiBq03A7gQQQAgBK0iBzcDsBBBACAFIAEgBUECdG4iCGwiCUECdK03A6gQAkACQAJAAkAgBEUNAEF/IQogBUUNASAIQQNsIQsgCEECdCIErSEMIAWtIQ0gBkF/akECSSEOQgAhDwNAQQAgDzcDkBAgD6chEEIAIRFBACEBA0BBACARNwOgECAPIBGEUCIDIA5xIRIgBkEBRiAPUCITIAZBAkYgEUICVHFxciEUQX8gAUEBakEDcSAIbEF/aiATGyEVIAEgEHIhFiABIAhsIRcgA0EBdCEYQgAhGQNAQQBCADcDwBBBACAZNwOYECAYIQECQCASRQ0AQQBCATcDwBBBkBhBkBBBkCBBABADQZAYQZAYQZAgQQAQA0ECIQELAkAgASAITw0AIAQgGaciGmwgF2ogAWohAwNAIANBACAEIAEbQQAgEVAiGxtqQX9qIRwCQAJAIBQNAEEAKAKACCICIBxBCnQiHGohCgwBCwJAIAFB/wBxIgINAEEAQQApA8AQQgF8NwPAEEGQGEGQEEGQIEEAEANBkBhBkBhBkCBBABADCyAcQQp0IRwgAkEDdEGQGGohCkEAKAKACCECCyACIANBCnRqIAIgHGogAiAKKQMAIh1CIIinIAVwIBogFhsiHCAEbCABIAFBACAZIBytUSIcGyIKIBsbIBdqIAogC2ogExsgAUUgHHJrIhsgFWqtIB1C/////w+DIh0gHX5CIIggG61+QiCIfSAMgqdqQQp0akEBEAMgA0EBaiEDIAggAUEBaiIBRw0ACwsgGUIBfCIZIA1SDQALIBFCAXwiEachASARQgRSDQALIA9CAXwiDyAHUg0AC0EAKAKACCECCyAJQQx0QYB4aiEXIAVBf2oiCkUNAgwBC0EAQgM3A6AQQQAgBEF/aq03A5AQQYB4IRcLIAIgF2ohGyAIQQx0IQhBACEcA0AgCCAcQQFqIhxsQYB4aiEEQQAhAQNAIBsgAWoiAyADKQMAIAIgBCABamopAwCFNwMAIANBCGoiAyADKQMAIAIgBCABQQhyamopAwCFNwMAIAFBCGohAyABQRBqIQEgA0H4B0kNAAsgHCAKRw0ACwsgAiAXaiEbQXghAQNAIAIgAWoiA0EIaiAbIAFqIgRBCGopAwA3AwAgA0EQaiAEQRBqKQMANwMAIANBGGogBEEYaikDADcDACADQSBqIARBIGopAwA3AwAgAUEgaiIBQfgHSQ0ACwsL";
  var hash$k = "e4cdc523";
  var wasmJson$k = {
    name: name$k,
    data: data$k,
    hash: hash$k
  };
  var name$j = "blake2b";
  var data$j = "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";
  var hash$j = "c6f286e6";
  var wasmJson$j = {
    name: name$j,
    data: data$j,
    hash: hash$j
  };
  var mutex$k = new Mutex();
  function validateBits$4(bits) {
    if (!Number.isInteger(bits) || bits < 8 || bits > 512 || bits % 8 !== 0) {
      return new Error("Invalid variant! Valid values: 8, 16, ..., 512");
    }
    return null;
  }
  function getInitParam$1(outputBits, keyBits) {
    return outputBits | keyBits << 16;
  }
  function createBLAKE2b(bits = 512, key = null) {
    if (validateBits$4(bits)) {
      return Promise.reject(validateBits$4(bits));
    }
    let keyBuffer = null;
    let initParam = bits;
    if (key !== null) {
      keyBuffer = getUInt8Buffer(key);
      if (keyBuffer.length > 64) {
        return Promise.reject(new Error("Max key length is 64 bytes"));
      }
      initParam = getInitParam$1(bits, keyBuffer.length);
    }
    const outputSize = bits / 8;
    return WASMInterface(wasmJson$j, outputSize).then((wasm) => {
      if (initParam > 512) {
        wasm.writeMemory(keyBuffer);
      }
      wasm.init(initParam);
      const obj = {
        init: initParam > 512 ? () => {
          wasm.writeMemory(keyBuffer);
          wasm.init(initParam);
          return obj;
        } : () => {
          wasm.init(initParam);
          return obj;
        },
        update: (data) => {
          wasm.update(data);
          return obj;
        },
        // biome-ignore lint/suspicious/noExplicitAny: Conflict with IHasher type
        digest: (outputType) => wasm.digest(outputType),
        save: () => wasm.save(),
        load: (data) => {
          wasm.load(data);
          return obj;
        },
        blockSize: 128,
        digestSize: outputSize
      };
      return obj;
    });
  }
  function encodeResult(salt, options, res) {
    const parameters = [
      `m=${options.memorySize}`,
      `t=${options.iterations}`,
      `p=${options.parallelism}`
    ].join(",");
    return `$argon2${options.hashType}$v=19${parameters}${encodeBase64(salt, false)}${encodeBase64(res, false)}`;
  }
  var uint32View = new DataView(new ArrayBuffer(4));
  function int32LE(x) {
    uint32View.setInt32(0, x, true);
    return new Uint8Array(uint32View.buffer);
  }
  function hashFunc(blake512, buf, len) {
    return __awaiter(this, void 0, void 0, function* () {
      if (len <= 64) {
        const blake = yield createBLAKE2b(len * 8);
        blake.update(int32LE(len));
        blake.update(buf);
        return blake.digest("binary");
      }
      const r = Math.ceil(len / 32) - 2;
      const ret = new Uint8Array(len);
      blake512.init();
      blake512.update(int32LE(len));
      blake512.update(buf);
      let vp = blake512.digest("binary");
      ret.set(vp.subarray(0, 32), 0);
      for (let i = 1; i < r; i++) {
        blake512.init();
        blake512.update(vp);
        vp = blake512.digest("binary");
        ret.set(vp.subarray(0, 32), i * 32);
      }
      const partialBytesNeeded = len - 32 * r;
      let blakeSmall;
      if (partialBytesNeeded === 64) {
        blakeSmall = blake512;
        blakeSmall.init();
      } else {
        blakeSmall = yield createBLAKE2b(partialBytesNeeded * 8);
      }
      blakeSmall.update(vp);
      vp = blakeSmall.digest("binary");
      ret.set(vp.subarray(0, partialBytesNeeded), r * 32);
      return ret;
    });
  }
  function getHashType(type) {
    switch (type) {
      case "d":
        return 0;
      case "i":
        return 1;
      default:
        return 2;
    }
  }
  function argon2Internal(options) {
    return __awaiter(this, void 0, void 0, function* () {
      var _a2;
      const { parallelism, iterations, hashLength } = options;
      const password = getUInt8Buffer(options.password);
      const salt = getUInt8Buffer(options.salt);
      const version = 19;
      const hashType = getHashType(options.hashType);
      const { memorySize } = options;
      const secret = getUInt8Buffer((_a2 = options.secret) !== null && _a2 !== void 0 ? _a2 : "");
      const [argon2Interface, blake512] = yield Promise.all([
        WASMInterface(wasmJson$k, 1024),
        createBLAKE2b(512)
      ]);
      argon2Interface.setMemorySize(memorySize * 1024 + 1024);
      const initVector = new Uint8Array(24);
      const initVectorView = new DataView(initVector.buffer);
      initVectorView.setInt32(0, parallelism, true);
      initVectorView.setInt32(4, hashLength, true);
      initVectorView.setInt32(8, memorySize, true);
      initVectorView.setInt32(12, iterations, true);
      initVectorView.setInt32(16, version, true);
      initVectorView.setInt32(20, hashType, true);
      argon2Interface.writeMemory(initVector, memorySize * 1024);
      blake512.init();
      blake512.update(initVector);
      blake512.update(int32LE(password.length));
      blake512.update(password);
      blake512.update(int32LE(salt.length));
      blake512.update(salt);
      blake512.update(int32LE(secret.length));
      blake512.update(secret);
      blake512.update(int32LE(0));
      const segments = Math.floor(memorySize / (parallelism * 4));
      const lanes = segments * 4;
      const param = new Uint8Array(72);
      const H0 = blake512.digest("binary");
      param.set(H0);
      for (let lane = 0; lane < parallelism; lane++) {
        param.set(int32LE(0), 64);
        param.set(int32LE(lane), 68);
        let position = lane * lanes;
        let chunk = yield hashFunc(blake512, param, 1024);
        argon2Interface.writeMemory(chunk, position * 1024);
        position += 1;
        param.set(int32LE(1), 64);
        chunk = yield hashFunc(blake512, param, 1024);
        argon2Interface.writeMemory(chunk, position * 1024);
      }
      const C = new Uint8Array(1024);
      writeHexToUInt8(C, argon2Interface.calculate(new Uint8Array([]), memorySize));
      const res = yield hashFunc(blake512, C, hashLength);
      if (options.outputType === "hex") {
        const digestChars = new Uint8Array(hashLength * 2);
        return getDigestHex(digestChars, res, hashLength);
      }
      if (options.outputType === "encoded") {
        return encodeResult(salt, options, res);
      }
      return res;
    });
  }
  var validateOptions$3 = (options) => {
    var _a2;
    if (!options || typeof options !== "object") {
      throw new Error("Invalid options parameter. It requires an object.");
    }
    if (!options.password) {
      throw new Error("Password must be specified");
    }
    options.password = getUInt8Buffer(options.password);
    if (options.password.length < 1) {
      throw new Error("Password must be specified");
    }
    if (!options.salt) {
      throw new Error("Salt must be specified");
    }
    options.salt = getUInt8Buffer(options.salt);
    if (options.salt.length < 8) {
      throw new Error("Salt should be at least 8 bytes long");
    }
    options.secret = getUInt8Buffer((_a2 = options.secret) !== null && _a2 !== void 0 ? _a2 : "");
    if (!Number.isInteger(options.iterations) || options.iterations < 1) {
      throw new Error("Iterations should be a positive number");
    }
    if (!Number.isInteger(options.parallelism) || options.parallelism < 1) {
      throw new Error("Parallelism should be a positive number");
    }
    if (!Number.isInteger(options.hashLength) || options.hashLength < 4) {
      throw new Error("Hash length should be at least 4 bytes.");
    }
    if (!Number.isInteger(options.memorySize)) {
      throw new Error("Memory size should be specified.");
    }
    if (options.memorySize < 8 * options.parallelism) {
      throw new Error("Memory size should be at least 8 * parallelism.");
    }
    if (options.outputType === void 0) {
      options.outputType = "hex";
    }
    if (!["hex", "binary", "encoded"].includes(options.outputType)) {
      throw new Error(`Insupported output type ${options.outputType}. Valid values: ['hex', 'binary', 'encoded']`);
    }
  };
  function argon2id(options) {
    return __awaiter(this, void 0, void 0, function* () {
      validateOptions$3(options);
      return argon2Internal(Object.assign(Object.assign({}, options), { hashType: "id" }));
    });
  }
  var mutex$j = new Mutex();
  var mutex$i = new Mutex();
  var mutex$h = new Mutex();
  var mutex$g = new Mutex();
  var polyBuffer = new Uint8Array(8);
  var mutex$f = new Mutex();
  var mutex$e = new Mutex();
  var mutex$d = new Mutex();
  var mutex$c = new Mutex();
  var mutex$b = new Mutex();
  var mutex$a = new Mutex();
  var mutex$9 = new Mutex();
  var mutex$8 = new Mutex();
  var mutex$7 = new Mutex();
  var mutex$6 = new Mutex();
  var mutex$5 = new Mutex();
  var seedBuffer$2 = new Uint8Array(8);
  var mutex$4 = new Mutex();
  var seedBuffer$1 = new Uint8Array(8);
  var mutex$3 = new Mutex();
  var seedBuffer = new Uint8Array(8);
  var mutex$2 = new Mutex();
  var mutex$1 = new Mutex();
  var mutex = new Mutex();

  // argon2_entry.js
  globalThis.argon2idHash = function(passwordBytes, saltBytes, opts) {
    return argon2id({
      password: passwordBytes,
      // Uint8Array
      salt: saltBytes,
      // Uint8Array (>= 8 bytes)
      iterations: opts.iterations,
      // time cost (t)
      memorySize: opts.memorySize,
      // KiB (m)
      parallelism: opts.parallelism,
      // lanes (p)
      hashLength: opts.hashLength,
      // output bytes
      outputType: "binary"
      // -> Uint8Array
    });
  };
})();
/*! Bundled license information:

hash-wasm/dist/index.esm.js:
  (*!
   * hash-wasm (https://www.npmjs.com/package/hash-wasm)
   * (c) Dani Biro
   * @license MIT
   *)
*/


// Twofish-256-CTR  (encrypt = decrypt — both XOR with keystream)
// key32: Uint8Array(32), nonce16: Uint8Array(16), data: Uint8Array → Uint8Array
function twofishCTR(key32, nonce16, data) {
    var session   = twofishMakeSession(key32);
    var out       = new Uint8Array(data.length);
    var counter   = new Uint8Array(16);
    counter.set(nonce16);
    var keystream = new Uint8Array(16);
    for (var i = 0; i < data.length; i += 16) {
        twofishEncryptBlock(counter, 0, keystream, 0, session);
        var blockLen = Math.min(16, data.length - i);
        for (var j = 0; j < blockLen; j++) out[i + j] = data[i + j] ^ keystream[j];
        for (var k = 15; k >= 0; k--) { if (++counter[k] !== 0) break; }
    }
    return out;
}


// Serpent-256-CTR  (encrypt = decrypt — both XOR with keystream)
// key32: Uint8Array(32), nonce16: Uint8Array(16), data: Uint8Array → Uint8Array
function serpentCTR(key32, nonce16, data) {
    var session   = serpentMakeSession(key32);
    var out       = new Uint8Array(data.length);
    var counter   = new Uint8Array(16);
    counter.set(nonce16);
    var keystream = new Uint8Array(16);
    for (var i = 0; i < data.length; i += 16) {
        serpentEncryptBlock(counter, 0, keystream, 0, session);
        var blockLen = Math.min(16, data.length - i);
        for (var j = 0; j < blockLen; j++) out[i + j] = data[i + j] ^ keystream[j];
        for (var k = 15; k >= 0; k--) { if (++counter[k] !== 0) break; }
    }
    return out;
}


// ---- Session state ----
var otpKey           = null;
var timerVar         = null;
var blinkTimer       = null;
var _toastTimer      = null;
var blinkObject      = null;
var deleteEntryName  = null;
// Delete/edit reference the decoded entry by its full record string (content),
// never by line index — a concurrent add/delete from another tab or device
// reorders `lines`, so a sampled index could point at the wrong entry by the
// time the POST lands. post.php matches the exact string and answers 409 if
// the record is gone.
var deleteEntryRecord = null;
var _editRecord       = null;
var _decodedFields   = null;
var currentPassword  = '';
var _allEntries      = [];
var _inactivityTimer = null;
var _lockWarnTimer   = null;
var _INACTIVITY_MS   = 5 * 60 * 1000;  // 5 minutes idle before lock warning
var _WARN_SECS       = 60;              // seconds of warning before locking

// Cache the Argon2id master keys by (password:saltHex) so the expensive
// memory-hard derivation runs only once per (password, record-salt). Each record
// derives just two master keys (one per password); all per-cipher subkeys are
// HKDF-expanded from these (cheap, not cached). A record's name and payload share
// the same two record salts, so clicking an entry after a reveal-all reuses the
// cached master keys instead of re-running Argon2id.
var _mkCache = new Map();

// v5: maps record key (pipe-joined fields without the line index) → decrypted name.
var _v5Names = new Map();

// Reveal-all coordination. _revealGen is bumped whenever the revealed state is
// invalidated (key edit / lock); an in-flight _revealAllV5Names loop captures the
// current value and aborts as soon as it sees a newer one (#8). _lastRevealPw/2
// record the password pair that produced the current reveal so a repeat blur with
// unchanged passwords can skip the work entirely (#7).
var _revealGen     = 0;
var _lastRevealPw  = null;
var _lastRevealPw2 = null;

// Max v6 name decryptions in flight during reveal-all. Each issues two Argon2id
// derivations, which now run on the Web Worker pool (see _argonDerive) rather
// than the main thread — so peak memory is bounded by the POOL size, not by
// this number. It is set to the pool size (so the queue always holds ~2×poolSize
// jobs, keeping every worker busy without the main thread blocking) but LAZILY,
// via _revealConcurrency(): _argonPoolSize() reads _ARGON_POOL_MAX, which is
// assigned further down the file, so calling it during this top-level init would
// read `undefined` and yield NaN. The per-record master-key cache means a
// record's payload click after reveal-all does no further Argon2id work.
var _REVEAL_CONCURRENCY = 0;   // 0 = not yet computed; _revealConcurrency() fills it
function _revealConcurrency() {
    if (!_REVEAL_CONCURRENCY) _REVEAL_CONCURRENCY = _argonPoolSize();
    return _REVEAL_CONCURRENCY;
}

// ============================================================
// Byte / hex utilities
// ============================================================

function bytesToHex(bytes) {
    return Array.from(bytes).map(function(b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
}

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// ============================================================
// Key derivation — Argon2id (memory-hard, via WASM) → HKDF-SHA-256 subkeys
//
// Each record carries two Argon2id salts (one per master password). The two
// 32-byte master keys MK1 = Argon2id(pw1, recSalt1) and MK2 = Argon2id(pw2,
// recSalt2) are derived ONCE per record (and cached), then HKDF-SHA-256 expands
// each into the independent per-cipher subkeys using distinct `info` labels.
// This keeps the cascade's keys independent while running the expensive
// memory-hard step only twice per record instead of once per cipher.
//
// Argon2id parameters are hardcoded (like the old PBKDF2 iteration count): a
// record stores nothing about them, so changing them invalidates every record
// and must be paired with re-encrypting `lines` via the offline migration tool.
// ============================================================

var ARGON2_TIME    = 3;       // t — iterations
var ARGON2_MEM_KIB = 65536;   // m — 64 MiB
var ARGON2_PAR     = 1;       // p — lanes
var ARGON2_HASHLEN = 32;      // 256-bit master key

// HKDF info labels — distinct per derived subkey so they are cryptographically
// independent despite sharing a master key.
var _HK = {
    nameAes:    'v6|name|aes-gcm',
    nameChacha: 'v6|name|chacha20',
    payAes:     'v6|pay|aes-gcm',
    payChacha:  'v6|pay|chacha20',
    payTwofish: 'v6|pay|twofish',
    paySerpent: 'v6|pay|serpent'
};

// ============================================================
// Argon2id Web Worker pool
//
// hash-wasm runs Argon2id synchronously on a single WASM instance behind an
// internal mutex, so awaiting many derivations on the main thread serialises
// them onto one core AND blocks the UI. To get real parallelism — reveal-all
// needs two 64 MiB derivations per entry — each derivation is dispatched to a
// pool of dedicated Web Workers (served as `argon2-worker.js`), each with its
// own WASM instance. The pool is created lazily on first use and torn down on
// lock so its WASM memory (which can only grow, never shrink) is reclaimed.
//
// Peak memory ≈ poolSize × 64 MiB (only while hashing), so the pool is capped.
// If Workers are unavailable (CSP blocks them, ancient browser, or the ctor
// throws) we fall back to the in-process argon2idHash so the app still works —
// inputs are never transferred, so a worker failure can retry on the main
// thread without losing the password/salt buffers.
// ============================================================

var _ARGON_POOL_MAX = 4;          // hard cap (memory = poolSize × 64 MiB)
var _argonPool      = null;       // [{ worker, busy }] once initialised
var _argonQueue     = [];         // pending { password, salt, opts, resolve, reject }
var _argonJobSeq    = 0;
var _argonJobs      = new Map();   // job id → { resolve, reject, slot }
var _argonWorkersOK = true;        // flips false permanently if Workers can't be used

function _argonPoolSize() {
    var hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 2;
    return Math.max(1, Math.min(hc, _ARGON_POOL_MAX));
}

function _initArgonPool() {
    if (_argonPool || !_argonWorkersOK) return;
    if (typeof Worker === 'undefined') { _argonWorkersOK = false; return; }
    try {
        _argonPool = [];
        for (var i = 0; i < _argonPoolSize(); i++) {
            var w = new Worker('argon2-worker.js');
            w.onmessage = _onArgonWorkerMessage;
            w.onerror   = _onArgonWorkerError;
            _argonPool.push({ worker: w, busy: false });
        }
    } catch (e) {
        _argonWorkersOK = false;   // CSP/permissions — fall back to main thread
        _argonPool = null;
    }
}

// Tear the pool down (on lock) so worker WASM heaps are freed and any residual
// password bytes in worker memory are dropped. The pool is lazily re-created on
// the next derivation as long as workers are still enabled (a clean lock leaves
// _argonWorkersOK true; only a worker *crash* clears it, keeping that page on the
// main-thread fallback rather than thrashing on recreate→crash→recreate).
function _terminateArgonPool() {
    var pool = _argonPool;
    _argonPool = null;
    if (pool) pool.forEach(function (s) { try { s.worker.terminate(); } catch (_) {} });
    // Anything still in flight/queued can never complete now — reject so callers
    // fall back to the main thread.
    _argonJobs.forEach(function (j) { j.reject(new Error('argon2 pool terminated')); });
    _argonJobs.clear();
    var q = _argonQueue; _argonQueue = [];
    q.forEach(function (j) { j.reject(new Error('argon2 pool terminated')); });
}

function _onArgonWorkerMessage(e) {
    var d   = e.data;
    var job = _argonJobs.get(d.id);
    if (!job) return;
    _argonJobs.delete(d.id);
    job.slot.busy = false;
    if (d.error) job.reject(new Error(d.error));
    else         job.resolve(d.hash);   // Uint8Array, buffer transferred to us
    _drainArgonQueue();
}

function _onArgonWorkerError(e) {
    try { e.preventDefault && e.preventDefault(); } catch (_) {}
    _argonWorkersOK = false;            // disable workers for this session
    _terminateArgonPool();
}

function _drainArgonQueue() {
    if (!_argonPool) return;
    for (var i = 0; i < _argonPool.length && _argonQueue.length; i++) {
        var slot = _argonPool[i];
        if (slot.busy) continue;
        var job = _argonQueue.shift();
        var id  = ++_argonJobSeq;
        slot.busy = true;
        _argonJobs.set(id, { resolve: job.resolve, reject: job.reject, slot: slot });
        slot.worker.postMessage({ id: id, password: job.password, salt: job.salt, opts: job.opts });
    }
}

function _argonDispatch(passwordBytes, saltBytes, opts) {
    return new Promise(function (resolve, reject) {
        _argonQueue.push({ password: passwordBytes, salt: saltBytes, opts: opts, resolve: resolve, reject: reject });
        _drainArgonQueue();
    });
}

// Run one Argon2id derivation, preferring the worker pool and falling back to
// the in-process implementation if workers are unavailable or error out.
async function _argonDerive(passwordBytes, saltBytes, opts) {
    _initArgonPool();
    if (_argonWorkersOK && _argonPool) {
        try {
            return await _argonDispatch(passwordBytes, saltBytes, opts);
        } catch (e) {
            // Worker path failed for this call — degrade to the main thread.
        }
    }
    return argon2idHash(passwordBytes, saltBytes, opts);
}

// Argon2id master key for (password, salt). Cached so it runs only once per pair.
async function deriveMasterKey(password, saltBytes) {
    var cacheKey = password + ':' + bytesToHex(saltBytes);
    if (_mkCache.has(cacheKey)) return _mkCache.get(cacheKey);
    var mk = await _argonDerive(
        new TextEncoder().encode(password),
        saltBytes,
        { iterations: ARGON2_TIME, memorySize: ARGON2_MEM_KIB, parallelism: ARGON2_PAR, hashLength: ARGON2_HASHLEN }
    );
    _mkCache.set(cacheKey, mk);
    return mk;
}

// HKDF-SHA-256 expand a master key into 32 raw bytes for the given info label.
// (Empty salt is fine: the master key is already a uniform high-entropy key.)
async function hkdfBytes(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(infoLabel) },
        base, 256
    );
    return new Uint8Array(bits);
}

// HKDF-SHA-256 expand a master key into an AES-256-GCM CryptoKey.
async function hkdfAesKey(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(infoLabel) },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
}

// ============================================================
// Encryption / decryption (v6)
// Payload: JSON → ChaCha20-Poly1305 (MK1) → AES-256-GCM (MK1)
//               → Twofish-256-CTR (MK2) → Serpent-256-CTR (MK2)
// Name:    AES-256-GCM (MK1) → ChaCha20-Poly1305 (MK2)
// MK1 = Argon2id(pw1, recSalt1), MK2 = Argon2id(pw2, recSalt2).
// ============================================================

// Encrypt the payload under the record's two master keys (derived from the
// shared record salts). Returns { iv1Hex, nonce2Hex, nonce3Hex, nonce4Hex, encHex }.
async function encryptFields(password, password2, recSalt1, recSalt2, fields) {
    var iv1    = crypto.getRandomValues(new Uint8Array(12));  // AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12));  // ChaCha20
    var nonce3 = crypto.getRandomValues(new Uint8Array(16));  // Twofish-CTR
    var nonce4 = crypto.getRandomValues(new Uint8Array(16));  // Serpent-CTR
    var mks = await Promise.all([ deriveMasterKey(password, recSalt1), deriveMasterKey(password2, recSalt2) ]);
    var mk1 = mks[0], mk2 = mks[1];
    var subs = await Promise.all([
        hkdfAesKey(mk1, _HK.payAes),
        hkdfBytes(mk1, _HK.payChacha),
        hkdfBytes(mk2, _HK.payTwofish),
        hkdfBytes(mk2, _HK.paySerpent)
    ]);
    var aesKey = subs[0], chachaKey = subs[1], twofishKey = subs[2], serpentKey = subs[3];
    var plain = new TextEncoder().encode(JSON.stringify(fields));
    var mid   = chacha20poly1305(chachaKey, nonce2).encrypt(plain);
    var ct    = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv1 }, aesKey, mid));
    var tf    = twofishCTR(twofishKey, nonce3, ct);
    var outer = serpentCTR(serpentKey, nonce4, tf);
    return {
        iv1Hex:    bytesToHex(iv1),    nonce2Hex: bytesToHex(nonce2),
        nonce3Hex: bytesToHex(nonce3), nonce4Hex: bytesToHex(nonce4),
        encHex:    bytesToHex(outer)
    };
}

// Throws on wrong key or tampered ciphertext — caller must catch.
async function decryptFields(password, password2, recSalt1Hex, recSalt2Hex, iv1Hex, nonce2Hex, nonce3Hex, nonce4Hex, encHex) {
    var mks = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex)),
        deriveMasterKey(password2, hexToBytes(recSalt2Hex))
    ]);
    var mk1 = mks[0], mk2 = mks[1];
    var subs = await Promise.all([
        hkdfBytes(mk2, _HK.paySerpent),
        hkdfBytes(mk2, _HK.payTwofish),
        hkdfAesKey(mk1, _HK.payAes),
        hkdfBytes(mk1, _HK.payChacha)
    ]);
    var serpentKey = subs[0], twofishKey = subs[1], aesKey = subs[2], chachaKey = subs[3];
    var tf    = serpentCTR(serpentKey, hexToBytes(nonce4Hex), hexToBytes(encHex));
    var ct    = twofishCTR(twofishKey, hexToBytes(nonce3Hex), tf);
    var mid   = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(iv1Hex) }, aesKey, ct));
    var plain = chacha20poly1305(chachaKey, hexToBytes(nonce2Hex)).decrypt(mid);
    return JSON.parse(new TextDecoder().decode(plain));
}

// v6 name encryption: AES-256-GCM (MK1) then ChaCha20-Poly1305 (MK2).
// Both passwords are required to decrypt. Returns { nameNonce1Hex, nameNonce2Hex, encNameHex }.
async function encryptName(password, password2, recSalt1, recSalt2, name) {
    var nonce1 = crypto.getRandomValues(new Uint8Array(12));  // name AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12));  // name ChaCha20
    var mks = await Promise.all([ deriveMasterKey(password, recSalt1), deriveMasterKey(password2, recSalt2) ]);
    var subs = await Promise.all([ hkdfAesKey(mks[0], _HK.nameAes), hkdfBytes(mks[1], _HK.nameChacha) ]);
    var aesKey = subs[0], chachaKey = subs[1];
    var mid = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce1 }, aesKey, new TextEncoder().encode(name)
    ));
    var ct = chacha20poly1305(chachaKey, nonce2).encrypt(mid);
    return {
        nameNonce1Hex: bytesToHex(nonce1), nameNonce2Hex: bytesToHex(nonce2),
        encNameHex:    bytesToHex(ct)
    };
}

// v6 name decryption. Throws on wrong key or tampered ciphertext.
async function decryptName(password, password2, recSalt1Hex, recSalt2Hex, nameNonce1Hex, nameNonce2Hex, encNameHex) {
    var mks = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex)),
        deriveMasterKey(password2, hexToBytes(recSalt2Hex))
    ]);
    var subs = await Promise.all([ hkdfBytes(mks[1], _HK.nameChacha), hkdfAesKey(mks[0], _HK.nameAes) ]);
    var chachaKey = subs[0], aesKey = subs[1];
    var mid   = chacha20poly1305(chachaKey, hexToBytes(nameNonce2Hex)).decrypt(hexToBytes(encNameHex));
    var plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(nameNonce1Hex) }, aesKey, mid
    ));
    return new TextDecoder().decode(plain);
}

// ============================================================
// TOTP — RFC 6238 via WebCrypto HMAC-SHA-1
// ============================================================

function base32ToBytes(base32) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var bits = '';
    var clean = base32.toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
    for (var i = 0; i < clean.length; i++) {
        var val = alphabet.indexOf(clean[i]);
        if (val < 0) throw new Error('Invalid base32 character: ' + clean[i]);
        bits += val.toString(2).padStart(5, '0');
    }
    var bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    return bytes;
}

// timeOffset: 0 = current window, -1 or +1 for clock-drift tolerance.
async function computeTotp(base32Secret, timeOffset) {
    timeOffset = timeOffset || 0;
    var keyBytes = base32ToBytes(base32Secret);
    var ck = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    var epoch   = Math.floor(Date.now() / 1000);
    var counter = Math.floor(epoch / 30) + timeOffset;
    var timeBytes = new Uint8Array(8);
    timeBytes[4] = (counter >>> 24) & 0xff;
    timeBytes[5] = (counter >>> 16) & 0xff;
    timeBytes[6] = (counter >>>  8) & 0xff;
    timeBytes[7] =  counter         & 0xff;
    var hmac   = new Uint8Array(await crypto.subtle.sign('HMAC', ck, timeBytes));
    var offset = hmac[19] & 0x0f;
    var code   = ((hmac[offset]     & 0x7f) << 24 |
                   hmac[offset + 1]         << 16 |
                   hmac[offset + 2]         <<  8 |
                   hmac[offset + 3])         % 1000000;
    return code.toString().padStart(6, '0');
}

async function updateOtp() {
    if (!otpKey) return;
    try {
        var code = await computeTotp(otpKey, 0);
        document.getElementById('otp').textContent = code;
    } catch (e) {
        stopOtpTimer();
    }
}

function _setOtpArc(countdown) {
    var arc = document.getElementById('otp-arc');
    if (!arc) return;
    arc.style.strokeDashoffset = (50.27 * (1 - countdown / 30)).toFixed(2);
    // Green above 10 s; green → yellow-orange → red over the last 10 s
    if (countdown > 10) {
        arc.style.stroke = '';   // fall back to SVG attribute (var(--green))
    } else {
        var t   = 1 - countdown / 10;              // 0 at 10 s, 1 at 0 s
        var hue = Math.round(152 - 152 * t);       // 152 (teal-green) → 0 (red)
        var sat = Math.round(59  +  41 * t) + '%'; // 59% → 100%
        var lit = Math.round(53  +  13 * t) + '%'; // 53% → 66%
        arc.style.stroke = 'hsl(' + hue + ',' + sat + ',' + lit + ')';
    }
}

// Tracks the 30s TOTP window the displayed code belongs to, so a refresh is
// triggered whenever the window changes rather than only on the exact boundary
// second — which a throttled/drifting 1s interval can skip over entirely.
var _otpWindow = -1;

function tick() {
    var epoch     = Math.floor(Date.now() / 1000);
    var countdown = 30 - (epoch % 30);
    document.getElementById('updatingIn').textContent = countdown;
    _setOtpArc(countdown);
    var win = Math.floor(epoch / 30);
    if (win !== _otpWindow) { _otpWindow = win; updateOtp(); }
}

function startOtpTimer() {
    var epoch = Math.floor(Date.now() / 1000);
    _otpWindow = Math.floor(epoch / 30);
    updateOtp();
    var countdown = 30 - (epoch % 30);
    document.getElementById('updatingIn').textContent = countdown;
    _setOtpArc(countdown);
    var ring = document.getElementById('otp-ring');
    if (ring) ring.style.display = 'block';
    timerVar = setInterval(tick, 1000);
}

function stopOtpTimer() {
    clearInterval(timerVar);
    timerVar = null;
    document.getElementById('otp').textContent        = '------';
    document.getElementById('updatingIn').textContent = '--';
    var ring = document.getElementById('otp-ring');
    if (ring) ring.style.display = 'none';
}

// ============================================================
// Clipboard
// ============================================================

function showToast(msg) {
    var el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(function() { el.classList.remove('show'); }, 1800);
}

// Tracks whether the clipboard currently holds a secret we copied, so that
// lock operations only wipe the clipboard when there is something to wipe.
// Copied secrets are also auto-wiped after _CLIP_CLEAR_MS so a password does
// not sit on the clipboard indefinitely while the vault stays unlocked.
var _clipboardDirty = false;
var _clipClearTimer = null;
var _CLIP_CLEAR_MS  = 45000;

function doCBCopy(what) {
    var text = '', label = '', flashEl = null;
    switch (what) {
        case 'username':
            text    = document.getElementById('decusername').textContent;
            label   = 'Username copied';
            flashEl = document.getElementById('decusername').parentElement;
            break;
        case 'password':
            text    = document.getElementById('decpassword').textContent;
            label   = 'Password copied';
            flashEl = document.getElementById('decpassword').parentElement;
            break;
        case '2fa':
            text    = document.getElementById('otp').textContent;
            label   = 'Token copied';
            flashEl = document.querySelector('.otp-col');
            break;
        case 'current': text = currentPassword; break;
    }
    if (label && (!text.trim() || text.trim() === '------')) {
        showToast('Nothing to copy');
        return;
    }
    if (flashEl) {
        flashEl.classList.remove('copy-flash');
        void flashEl.offsetWidth;
        flashEl.classList.add('copy-flash');
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function() { _fallbackCopy(text); });
    } else {
        _fallbackCopy(text);
    }
    _clipboardDirty = true;
    clearTimeout(_clipClearTimer);
    _clipClearTimer = setTimeout(function() {
        _clearClipboardIfDirty();
        showToast('Clipboard cleared');
    }, _CLIP_CLEAR_MS);
    if (label) showToast(label);
}

// Wipe the clipboard on lock — but only if we put a secret there, so we don't
// clobber unrelated clipboard contents. Best-effort: writeText needs document
// focus, which may be absent on idle auto-lock; failures are ignored.
function _clearClipboardIfDirty() {
    clearTimeout(_clipClearTimer);
    _clipClearTimer = null;
    if (!_clipboardDirty) return;
    _clipboardDirty = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText('').catch(function() {});
    } else {
        _fallbackCopy('');
    }
}

function _fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    document.body.prepend(ta);
    ta.focus();
    ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    ta.remove();
}

// ============================================================
// QR code scan → populate #token
// ============================================================

function scanQRCode() {
    if (typeof BarcodeDetector === 'undefined') {
        showToast('QR scan not supported in this browser');
        return;
    }

    var fileInput = document.createElement('input');
    fileInput.type   = 'file';
    fileInput.accept = 'image/*';
    fileInput.setAttribute('capture', 'environment');
    fileInput.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    document.body.appendChild(fileInput);

    fileInput.addEventListener('change', function() {
        var file = fileInput.files[0];
        document.body.removeChild(fileInput);
        if (!file) return;
        _decodeQRFromFile(file);
    });

    // Clean up orphaned input if file picker is dismissed without selection.
    window.addEventListener('focus', function onFocus() {
        window.removeEventListener('focus', onFocus);
        setTimeout(function() {
            if (fileInput.parentNode) document.body.removeChild(fileInput);
        }, 500);
    }, { once: true });

    fileInput.click();
}

async function _decodeQRFromFile(file) {
    try {
        var img    = await createImageBitmap(file);
        var canvas = document.createElement('canvas');
        canvas.width  = img.width;
        canvas.height = img.height;
        canvas.getContext('2d').drawImage(img, 0, 0);

        var detector = new BarcodeDetector({ formats: ['qr_code'] });
        var results  = await detector.detect(canvas);

        if (!results.length) { showToast('No QR code found in image'); return; }

        var raw = results[0].rawValue;
        if (!raw.startsWith('otpauth://')) { showToast('QR code is not a TOTP URI'); return; }

        var url    = new URL(raw);
        var secret = url.searchParams.get('secret');
        if (!secret) { showToast('No secret found in QR code'); return; }

        // label is the path component: "Issuer:account" or just "account"
        var label   = decodeURIComponent(url.pathname.slice(1));
        var colonAt = label.indexOf(':');
        var labelIssuer  = colonAt >= 0 ? label.slice(0, colonAt).trim() : '';
        var labelAccount = colonAt >= 0 ? label.slice(colonAt + 1).trim() : label.trim();

        var issuer = (url.searchParams.get('issuer') || labelIssuer).trim();

        var nameEl = document.getElementById('name');
        if (nameEl && !nameEl.value && issuer) {
            nameEl.removeAttribute('readonly');
            nameEl.value = issuer;
        }

        var userEl = document.getElementById('username');
        if (userEl && !userEl.value && labelAccount) {
            userEl.removeAttribute('readonly');
            userEl.value = labelAccount;
        }

        var tokenEl = document.getElementById('token');
        tokenEl.removeAttribute('readonly');
        tokenEl.value = secret.toUpperCase().replace(/\s+/g, '');
        showToast('TOTP secret scanned ✓');

    } catch (e) {
        showToast('QR scan error: ' + e.message);
    }
}

// ============================================================
// UI helpers
// ============================================================

function resizeFreezePane() {
    var fixedDiv = document.getElementById('fixedDiv');
    var h = fixedDiv.offsetHeight;
    document.getElementById('content').style.marginTop = h + 'px';
}

function blinkTD(td) {
    clearTimeout(blinkTimer);
    if (blinkObject) blinkObject.classList.remove('btn-flash');
    td.classList.remove('btn-flash');
    void td.offsetWidth;                         // force reflow so animation restarts if same button
    td.classList.add('btn-flash');
    blinkObject = td;
    blinkTimer  = setTimeout(resetBorder, 520);  // slight buffer after 500ms animation
}

function resetBorder() {
    if (blinkObject) blinkObject.classList.remove('btn-flash');
    blinkObject = null;
    clearTimeout(blinkTimer);
    resizeFreezePane();
}

// ── Masked text input ─────────────────────────────────────────────────────────
// Stores the real password in _real; overrides el.value so callers use the
// normal property. While focused: type="password" (browser dots, mobile-safe).
// While unfocused and non-empty: type="text" with 8 fixed ● circles so the
// field looks filled without revealing the password length.
function _setupMaskedInput(el) {
    var _real = '';
    var _show = false;
    var _focused = false;
    var _proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

    function _setDom(v) { _proto.set.call(el, v); }

    function _setDisplay() {
        if (_show) {
            el.type = 'text';
            _setDom(_real);
        } else if (!_focused && _real.length > 0) {
            el.type = 'text';
            _setDom('●●●●●●●●');
        } else {
            el.type = 'password';
            _setDom(_real);
        }
    }

    Object.defineProperty(el, 'value', {
        get: function() { return _real; },
        set: function(v) { _real = String(v == null ? '' : v); _setDisplay(); },
        configurable: true
    });

    el._toggleShow = function() {
        _show = !_show;
        _setDisplay();
    };

    el.addEventListener('focus', function() { _focused = true;  _setDisplay(); });
    el.addEventListener('blur',  function() { _focused = false; _setDisplay(); });

    el.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            var focusable = Array.from(document.querySelectorAll(
                'input:not([disabled]), button:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
            )).filter(function(elem) { return elem.offsetParent !== null; });
            var idx = focusable.indexOf(el);
            if (idx !== -1 && idx + 1 < focusable.length) focusable[idx + 1].focus();
            return;
        }
        if (_show || e.ctrlKey || e.metaKey || e.altKey) return;
        var s = el.selectionStart, en = el.selectionEnd;
        if (e.key === 'Backspace') {
            e.preventDefault();
            if (s !== en) { _real = _real.slice(0, s) + _real.slice(en); _setDom(_real); el.setSelectionRange(s, s); }
            else if (s > 0) { _real = _real.slice(0, s - 1) + _real.slice(s); _setDom(_real); el.setSelectionRange(s - 1, s - 1); }
        } else if (e.key === 'Delete') {
            e.preventDefault();
            if (s !== en) { _real = _real.slice(0, s) + _real.slice(en); _setDom(_real); el.setSelectionRange(s, s); }
            else if (s < _real.length) { _real = _real.slice(0, s) + _real.slice(s + 1); _setDom(_real); el.setSelectionRange(s, s); }
        } else if (e.key.length === 1) {
            e.preventDefault();
            _real = _real.slice(0, s) + e.key + _real.slice(en);
            _setDom(_real);
            el.setSelectionRange(s + 1, s + 1);
        }
    });

    el.addEventListener('paste', function(e) {
        if (_show) return;
        e.preventDefault();
        var text = (e.clipboardData || window.clipboardData).getData('text');
        var s = el.selectionStart, en = el.selectionEnd;
        _real = _real.slice(0, s) + text + _real.slice(en);
        _setDom(_real);
        el.setSelectionRange(s + text.length, s + text.length);
    });

    el.addEventListener('cut', function(e) {
        if (_show) return;
        e.preventDefault();
        var s = el.selectionStart, en = el.selectionEnd;
        if (s !== en && e.clipboardData) {
            e.clipboardData.setData('text', _real.slice(s, en));
            _real = _real.slice(0, s) + _real.slice(en);
            _setDom(_real);
            el.setSelectionRange(s, s);
        }
    });

    // Mobile keyboards write directly into the DOM via input events.
    // Only sync when the DOM holds real content: focused (type=password, browser
    // masks but stores real text) or show mode. When unfocused the DOM holds
    // circles which must not overwrite _real.
    el.addEventListener('input', function() {
        if (_show || _focused) _real = _proto.get.call(el);
    });
}

function _initMaskedInputs() {
    _setupMaskedInput(document.getElementById('aeskey'));
    _setupMaskedInput(document.getElementById('aeskey2'));
}

function toggleKey()  { document.getElementById('aeskey') ._toggleShow(); }
function toggleKey2() { document.getElementById('aeskey2')._toggleShow(); }

function setNotes(text) {
    var el  = document.getElementById('decnotes');
    var row = el.closest('.p-row');
    el.value = text;
    // Keep the entry list visually stationary across the panel resize: measure
    // where #content actually sits in the viewport before and after, and scroll
    // by the difference. Browser scroll anchoring is disabled in CSS
    // (overflow-anchor: none) so this is the only compensation applied.
    var content = document.getElementById('content');
    var oldTop  = content.getBoundingClientRect().top;
    if (text) {
        row.style.display = '';
        el.style.height = 'auto';
        el.style.height = el.scrollHeight + 'px';
    } else {
        row.style.display = 'none';
    }
    resizeFreezePane();
    var delta = content.getBoundingClientRect().top - oldTop;
    if (delta) window.scrollBy(0, delta);
}

function clearDisplay() {
    stopOtpTimer();
    otpKey          = null;
    deleteEntryName   = null;
    deleteEntryRecord = null;
    _decodedFields    = null;
    document.getElementById('decname').textContent     = ' ';
    document.getElementById('decusername').textContent = ' ';
    document.getElementById('decpassword').textContent = ' ';
    setNotes('');
}

function _resetKeyFields() {
    document.getElementById('aeskey').value  = '';
    document.getElementById('aeskey2').value = '';
}

function clearLines(td) {
    blinkTD(td);
    _resetKeyFields();
    _mkCache.clear();
    _terminateArgonPool();
    clearDisplay();
    _editRecord = null;
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
    document.getElementById('newentry-title').textContent     = 'New Entry';
    _clearClipboardIfDirty();
    _relockV5Entries();
}

function renderDecodedFields() {
    if (!_decodedFields) return;
    var f      = _decodedFields;
    var nameEl = document.getElementById('decname');
    if (/^https?:\/\//i.test(f.url)) {
        var a = document.createElement('a');
        a.href = f.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.textContent = f.name;
        nameEl.textContent = '';
        nameEl.appendChild(a);
    } else {
        nameEl.textContent = f.name;
    }
    document.getElementById('decusername').textContent = f.username;
    document.getElementById('decpassword').textContent = f.password;
    setNotes(f.notes);
    if (f.token && !timerVar) { otpKey = f.token; startOtpTimer(); }
}

function cancelEntry() {
    var wasEditing = _editRecord !== null;
    document.getElementById('name').value     = '';
    document.getElementById('url').value      = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('token').value    = '';
    updatePWStrength();
    var notesEl = document.getElementById('notes');
    notesEl.value = '';
    notesEl.style.height = '';
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
    document.getElementById('newentry-title').textContent     = 'New Entry';
    _editRecord = null;
    if (wasEditing) renderDecodedFields();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function _syncScanBtnWidth() {
    var ref = document.getElementById('pw-gen-btns');
    var btn = document.getElementById('btn-scan-qr');
    if (!ref || !btn) return;
    btn.style.width = ref.offsetWidth + 'px';
}

function newEntry(td) {
    blinkTD(td);
    _editRecord = null;
    document.getElementById('newentry-title').textContent = 'New Entry';
    const el = document.getElementById('newentry');
    el.style.display = 'block';
    _syncScanBtnWidth();
    const fixedH = document.getElementById('fixedDiv').offsetHeight;
    const y = el.getBoundingClientRect().top + window.scrollY - fixedH - 8;
    window.scrollTo({ top: y, behavior: 'smooth' });
    document.getElementById('name').focus();
}

function editEntry() {
    if (!_decodedFields) { alert('Decrypt an entry first'); return; }
    _editRecord = deleteEntryRecord;

    document.getElementById('name').value     = _decodedFields.name;
    document.getElementById('url').value      = _decodedFields.url;
    document.getElementById('username').value = _decodedFields.username;
    document.getElementById('password').value = _decodedFields.password;
    updatePWStrength();
    document.getElementById('token').value    = _decodedFields.token;
    var notesEl = document.getElementById('notes');
    notesEl.value = _decodedFields.notes;
    notesEl.style.height = 'auto';
    notesEl.style.height = notesEl.scrollHeight + 'px';

    document.getElementById('newentry-title').textContent = 'Edit Entry';

    const el = document.getElementById('newentry');
    el.style.display = 'block';
    _syncScanBtnWidth();
    const fixedH = document.getElementById('fixedDiv').offsetHeight;
    const y = el.getBoundingClientRect().top + window.scrollY - fixedH - 8;
    window.scrollTo({ top: y, behavior: 'smooth' });
    document.getElementById('name').focus();
}

function showPWSettings() {
    var el = document.getElementById('passwordSettings');
    var visible = el.style.display !== 'none' && el.style.display !== '';
    el.style.display = visible ? 'none' : 'block';
    if (!visible) window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
}

// ============================================================
// Server communication
// ============================================================

function _xhrPost(params) {
    return new Promise(function(resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'post', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.onload  = function() {
            if (xhr.status === 200) { resolve(xhr.responseText); return; }
            var msg;
            if (xhr.status === 401) {
                msg = 'Authentication failed — wrong vault credentials';
            } else if (xhr.status === 403) {
                msg = 'Request blocked (origin check failed)';
            } else if (xhr.status === 409) {
                msg = 'Entry changed elsewhere';
            } else if (xhr.status === 429) {
                var retry = parseInt(xhr.getResponseHeader('Retry-After'), 10);
                msg = 'Too many auth attempts — locked out'
                    + (retry > 0 ? ' for ~' + Math.ceil(retry / 60) + ' min' : '');
            } else {
                msg = 'Server error ' + xhr.status;
            }
            var err = new Error(msg);
            // 409 = the record the client referenced no longer matches `lines`
            // (another tab/device wrote in between); callers resync on this.
            if (xhr.status === 409) err.stale = true;
            reject(err);
        };
        xhr.onerror = function() { reject(new Error('Network error')); };
        xhr.send(params);
    });
}

function _rebuildEntryGrid(entries) {
    // Abort any in-flight _revealAllV5Names: its workers captured an older gen
    // value and will bail before touching the new DOM buttons we're about to create.
    _revealGen++;
    _allEntries = entries.slice();
    var grid = document.querySelector('.entry-grid');
    grid.innerHTML = '';
    entries.forEach(function(row) {
        var parts = row.split('|');
        var btn = document.createElement('button');
        btn.className   = 'entry-btn';
        btn.dataset.row = row;
        btn.onclick = function() { decodeLine(btn, row); };
        if (parts[1] === 'v6') {
            var rowKey = parts.slice(0, -1).join('|');
            var cached = _v5Names.get(rowKey);
            if (cached !== undefined) {
                btn.textContent = cached;
                btn.title       = cached;
            } else {
                btn.classList.add('v5-locked');
                btn.style.display = 'none';
                btn.textContent = '🔒';
            }
        } else {
            btn.textContent = parts[0];
            btn.title       = parts[0];
        }
        grid.appendChild(btn);
    });
    updateEntryCount();
    window.scrollTo(0, 0);
}

function updateEntryCount() {
    var total   = _allEntries.length;
    var visible = document.querySelectorAll('.entry-grid .entry-btn:not(.v5-locked)').length;
    var el = document.getElementById('entry-count');
    if (!el) return;
    el.textContent = 'Displaying ' + visible + ' of ' + total + (total === 1 ? ' entry' : ' entries');
}

function _initEntries() {
    _allEntries = [];
    document.querySelectorAll('.entry-grid .entry-btn').forEach(function(btn) {
        if (btn.dataset.row) {
            _allEntries.push(btn.dataset.row);
            // post.php emits these buttons without an inline onclick (CSP: no
            // 'unsafe-inline' script); wire the click here from data-row, the
            // same way _rebuildEntryGrid does for dynamically-added buttons.
            var row = btn.dataset.row;
            btn.onclick = function() { decodeLine(btn, row); };
        }
    });
    updateEntryCount();
}

function _applyServerResponse(text) {
    var resp = JSON.parse(text);
    if (resp.ok && Array.isArray(resp.entries)) {
        _rebuildEntryGrid(resp.entries);
        return true;
    }
    return false;
}

// ============================================================
// Decode (decrypt) an entry on click
// ============================================================

// v5: encNameHEX|v5|saltN1HEX|nonceN1HEX|saltN2HEX|nonceN2HEX|salt1HEX|iv1HEX|salt2HEX|nonce2HEX|salt3HEX|nonce3HEX|encHEX|lineIndex
async function decodeLine(passedTD, encryptedData) {
    blinkTD(passedTD);
    clearDisplay();

    var parts   = encryptedData.split('|');
    var version = parts[1];

    if (version === 'v6') {
        // v6 fields: encName|v6|recSalt1|recSalt2|nameNonce1|nameNonce2|iv1|nonce2|nonce3|nonce4|enc|lineIndex
        if (parts.length < 12) {
            document.getElementById('decname').textContent = 'Unsupported format';
            return;
        }

        var password  = document.getElementById('aeskey').value;
        var password2 = document.getElementById('aeskey2').value;
        if (!password) {
            document.getElementById('decname').textContent = 'Enter primary password first';
            return;
        }
        if (!password2) {
            document.getElementById('decname').textContent = 'v6 entry requires a secondary password';
            return;
        }

        // Reference the entry by content (the record without its line index);
        // delete/edit send this string so a concurrent vault change can never
        // make the server remove a different record.
        var rowKey = parts.slice(0, -1).join('|');
        deleteEntryRecord = rowKey;
        document.getElementById('decname').textContent = 'Decrypting…';

        try {
            // Reuse the already-decrypted name when reveal-all has cached it, so a
            // click doesn't redo the name's Argon2id derivations. Otherwise decrypt it:
            // ChaCha20(MK2, nameNonce2) → AES-GCM(MK1, nameNonce1)
            var name   = _v5Names.has(rowKey)
                ? _v5Names.get(rowKey)
                : await decryptName(password, password2, parts[2], parts[3], parts[4], parts[5], parts[0]);
            deleteEntryName = name;

            // Cache name, reveal the clicked button, and re-sort to alphabetical order.
            _v5Names.set(rowKey, name);
            passedTD.textContent = name;
            passedTD.title       = name;
            passedTD.classList.remove('v5-locked');
            passedTD.style.display = '';
            _sortEntryGrid();

            // Decrypt payload (Serpent → Twofish → AES-GCM → ChaCha20)
            var fields = await decryptFields(password, password2, parts[2], parts[3], parts[6], parts[7], parts[8], parts[9], parts[10]);

            var url    = (fields.url || '').trim();
            var nameEl = document.getElementById('decname');
            if (/^https?:\/\//i.test(url)) {
                var a = document.createElement('a');
                a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
                a.textContent = name;
                nameEl.textContent = '';
                nameEl.appendChild(a);
            } else {
                nameEl.textContent = name;
            }

            document.getElementById('decusername').textContent = (fields.username || '').trim();
            document.getElementById('decpassword').textContent = (fields.password || '').trim();
            setNotes((fields.notes || '').trim());

            var token = (fields.token || '').trim();
            if (token) { otpKey = token; startOtpTimer(); }

            _decodedFields = {
                name:     name,
                url:      url,
                username: (fields.username || '').trim(),
                password: (fields.password || '').trim(),
                token:    token,
                notes:    (fields.notes    || '').trim()
            };

        } catch (_) {
            document.getElementById('decname').textContent = 'Wrong key or corrupted entry';
            deleteEntryName   = null;
            deleteEntryRecord = null;
        }
        return;
    }

    document.getElementById('decname').textContent = 'Unsupported format';
}

// ============================================================
// v5 — encrypted name helpers
// ============================================================

// Re-hide all revealed v5 buttons and wipe the name cache (called on lock/clear).
function _relockV5Entries() {
    // Invalidate the current reveal: abort any in-flight loop and forget the
    // password pair that produced it.
    _revealGen++;
    _lastRevealPw  = null;
    _lastRevealPw2 = null;
    _v5Names.clear();
    _clearVaultTools();
    document.querySelectorAll('.entry-grid .entry-btn').forEach(function(btn) {
        if (btn.dataset.row && btn.dataset.row.split('|')[1] === 'v6') {
            btn.classList.add('v5-locked');
            btn.style.display = 'none';
            btn.textContent = '🔒';
            btn.title = '';
        }
    });
    updateEntryCount();
}

// Show any v5 buttons whose names are already in _v5Names (after save/edit).
function _revealCachedV5Buttons() {
    document.querySelectorAll('.entry-btn.v5-locked').forEach(function(btn) {
        var rowKey = btn.dataset.row.split('|').slice(0, -1).join('|');
        var cached = _v5Names.get(rowKey);
        if (cached !== undefined) {
            btn.textContent = cached;
            btn.title       = cached;
            btn.classList.remove('v5-locked');
            btn.style.display = '';
        }
    });
    _sortEntryGrid();
    updateEntryCount();
    // If locked buttons remain (a save/delete interrupted an in-flight reveal),
    // start a fresh reveal now that the old workers have been aborted.
    if (document.querySelector('.entry-btn.v5-locked')) {
        var pw  = document.getElementById('aeskey').value;
        var pw2 = document.getElementById('aeskey2').value;
        if (pw && pw2) _revealAllV5Names(pw, pw2);
    }
}

// Sort entry grid alphabetically by button text; hidden (locked) buttons go last.
function _sortEntryGrid() {
    var grid = document.querySelector('.entry-grid');
    if (!grid) return;
    var btns = Array.from(grid.children);
    btns.sort(function(a, b) {
        var aHidden = a.style.display === 'none';
        var bHidden = b.style.display === 'none';
        if (aHidden !== bHidden) return aHidden ? 1 : -1;
        return a.textContent.toLowerCase().localeCompare(b.textContent.toLowerCase());
    });
    btns.forEach(function(btn) { grid.appendChild(btn); });
}

// Decrypt and reveal all hidden v5 entry names using both passwords.
// Called on blur of #aeskey2 so names appear once both passwords are entered.
async function _revealAllV5Names(pw, pw2) {
    var locked = Array.from(document.querySelectorAll('.entry-btn.v5-locked'));
    if (!locked.length) return;
    // Capture this run's generation; if the key fields change mid-loop (which bumps
    // _revealGen via _relockV5Entries) we abort rather than reveal with stale keys.
    var gen   = _revealGen;
    var total = locked.length;
    var bar  = document.getElementById('reveal-progress');
    var fill = document.getElementById('reveal-progress-fill');
    if (bar)  { fill.style.width = '0%'; bar.style.display = ''; }

    var done    = 0;
    var nextIdx = 0;
    var aborted = false;

    // Reveal one button: reuse a cached name or derive it. Returns false if the
    // run has been superseded (keys changed mid-flight) so the worker stops.
    async function reveal(btn) {
        var parts  = btn.dataset.row.split('|');
        var rowKey = parts.slice(0, -1).join('|');
        if (_v5Names.has(rowKey)) {
            var n = _v5Names.get(rowKey);
            btn.textContent = n; btn.title = n;
            btn.classList.remove('v5-locked'); btn.style.display = '';
        } else {
            try {
                var name = await decryptName(pw, pw2, parts[2], parts[3], parts[4], parts[5], parts[0]);
                if (gen !== _revealGen) return false;
                _v5Names.set(rowKey, name);
                btn.textContent = name; btn.title = name;
                btn.classList.remove('v5-locked'); btn.style.display = '';
            } catch (_) {
                // A superseded run can throw because the keys no longer match the
                // in-progress edit; bail instead of marking entries as failed.
                if (gen !== _revealGen) return false;
                /* wrong key — leave hidden */
            }
        }
        done++;
        if (fill) fill.style.width = Math.round((done / total) * 100) + '%';
        return true;
    }

    // Fixed pool of workers pulling from a shared index, so at most
    // _REVEAL_CONCURRENCY name decryptions are in flight at once.
    async function worker() {
        while (nextIdx < locked.length && !aborted) {
            var btn = locked[nextIdx++];
            if (!(await reveal(btn))) { aborted = true; return; }
        }
    }

    var pool = [];
    var conc = _revealConcurrency();
    for (var w = 0; w < conc && w < locked.length; w++) pool.push(worker());
    await Promise.all(pool);

    if (bar) bar.style.display = 'none';
    // Superseded mid-flight: don't sort or record the (now-stale) password pair.
    if (gen !== _revealGen) return;
    _sortEntryGrid();
    updateEntryCount();
    // Record the password pair that produced this reveal so an unchanged repeat
    // blur can skip the whole pass.
    _lastRevealPw  = pw;
    _lastRevealPw2 = pw2;
}

// ============================================================
// Save (encrypt) a new entry
// ============================================================

async function saveEntry() {
    var password = document.getElementById('aeskey').value;
    if (!password) { alert('Enter primary password first'); return; }

    var name = document.getElementById('name').value.trim();
    if (!name) { alert('Name is required'); return; }
    if (name.indexOf('|') !== -1) { alert('Name may not contain "|"'); return; }

    var fields = {
        url:      document.getElementById('url').value,
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        token:    document.getElementById('token').value,
        notes:    document.getElementById('notes').value
    };

    var password2 = document.getElementById('aeskey2').value;
    if (!password2) { alert('Enter secondary password first'); return; }
    try {
        // Two record salts, shared by name + payload — each yields one Argon2id
        // master key (pw1→recSalt1, pw2→recSalt2), so the whole record costs just
        // two memory-hard derivations (cached and reused across name/payload).
        var recSalt1 = crypto.getRandomValues(new Uint8Array(32));
        var recSalt2 = crypto.getRandomValues(new Uint8Array(32));
        var nameEnc = await encryptName(password, password2, recSalt1, recSalt2, name);
        var result  = await encryptFields(password, password2, recSalt1, recSalt2, fields);
        var record  = [nameEnc.encNameHex, 'v6',
                       bytesToHex(recSalt1),   bytesToHex(recSalt2),
                       nameEnc.nameNonce1Hex,  nameEnc.nameNonce2Hex,
                       result.iv1Hex,          result.nonce2Hex,
                       result.nonce3Hex,       result.nonce4Hex,
                       result.encHex].join('|');
        // Cache name so _rebuildEntryGrid can reveal the button immediately.
        _v5Names.set(record, name);
        // Edit = atomic replace: tell the server which record (by content) to
        // remove alongside the insert. See deleteEntryRecord for why content,
        // not line index.
        var params = 'data=' + encodeURIComponent(record);
        if (_editRecord !== null) {
            params = 'delete_rec=' + encodeURIComponent(_editRecord) + '&' + params;
        }
        var responseText = await _xhrPost(params);
        _editRecord = null;
        try {
            if (_applyServerResponse(responseText)) _revealCachedV5Buttons();
        } catch (_) { location.reload(); return; }
        clearDisplay();
        document.getElementById('name').value     = '';
        document.getElementById('url').value      = '';
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('token').value    = '';
        document.getElementById('notes').value    = '';
        document.getElementById('newentry-title').textContent     = 'New Entry';
        document.getElementById('newentry').style.display         = 'none';
        document.getElementById('passwordSettings').style.display = 'none';
    } catch (e) {
        if (e.stale) {
            showToast('Entry was changed elsewhere — reloading');
            setTimeout(function() { location.reload(); }, 1200);
            return;
        }
        showToast('Save failed — ' + e.message);
    }
}

// Alias so any cached index.html that still calls testAES() keeps working
// until post.php regenerates the page.
var testAES = saveEntry;

// ============================================================
// Vault tools — export / audit / master-password change
// ============================================================

// Download the encrypted DB as a file, built from the records already embedded
// in the page (ciphertext only — byte-identical to the server's `lines`).
function exportVault() {
    if (!_allEntries.length) { showToast('Nothing to export'); return; }
    var content = _allEntries.map(function(row) {
        return row.split('|').slice(0, -1).join('|');
    }).join('\n') + '\n';
    var blob = new Blob([content], { type: 'application/octet-stream' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    var d    = new Date();
    var pad  = function(n) { return String(n).padStart(2, '0'); };
    a.href     = url;
    a.download = 'vault-export-' + d.getFullYear() + '-' + pad(d.getMonth() + 1)
               + '-' + pad(d.getDate()) + '.lines';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
    showToast('Encrypted vault exported');
}

// Decrypt every record with the given passwords and feed (record, name, fields)
// to `handler`, with the same bounded concurrency as reveal-all (Argon2id runs
// on the worker pool). All-or-nothing: the first failure aborts the run and
// throws, so callers never act on a partially decrypted vault.
async function _forEachRecordDecrypt(pw, pw2, handler, progressCb) {
    var rows = _allEntries.map(function(row) {
        return row.split('|').slice(0, -1).join('|');
    });
    var results = new Array(rows.length);
    var nextIdx = 0, done = 0, failed = null;
    async function worker() {
        while (nextIdx < rows.length && failed === null) {
            var i = nextIdx++;
            var p = rows[i].split('|');
            try {
                var name   = await decryptName(pw, pw2, p[2], p[3], p[4], p[5], p[0]);
                var fields = await decryptFields(pw, pw2, p[2], p[3], p[6], p[7], p[8], p[9], p[10]);
                results[i] = await handler(rows[i], name, fields, i);
            } catch (e) {
                if (failed === null) failed = { index: i, error: e };
                return;
            }
            done++;
            if (progressCb) progressCb(done, rows.length);
        }
    }
    var pool = [];
    var conc = _revealConcurrency();
    for (var w = 0; w < conc && w < rows.length; w++) pool.push(worker());
    await Promise.all(pool);
    if (failed) {
        throw new Error('record ' + (failed.index + 1) + ' of ' + rows.length
                        + ' failed to decrypt (wrong passwords?)');
    }
    return results;
}

// Decrypt all payloads locally and flag reused / weak / empty passwords.
// Renders entry names only — never the passwords themselves. No network I/O.
async function auditVault() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var out = document.getElementById('audit-result');
    if (!out) return;
    out.style.display = '';
    if (!pw || !pw2) { out.textContent = 'Enter both passwords first.'; return; }
    if (!_allEntries.length) { out.textContent = 'Vault is empty.'; return; }

    out.textContent = 'Auditing… 0 / ' + _allEntries.length;
    var items;
    try {
        items = await _forEachRecordDecrypt(pw, pw2, function(rec, name, fields) {
            return { name: name, password: (fields.password || '').trim() };
        }, function(done, total) {
            out.textContent = 'Auditing… ' + done + ' / ' + total;
        });
    } catch (e) {
        out.textContent = 'Audit failed — ' + e.message;
        return;
    }

    var byPassword = new Map();
    var weak = [], empty = [];
    items.forEach(function(it) {
        if (!it.password) { empty.push(it.name); return; }
        if (_estimateBits(it.password) < 40) weak.push(it.name);
        if (!byPassword.has(it.password)) byPassword.set(it.password, []);
        byPassword.get(it.password).push(it.name);
    });
    var reused = [];
    byPassword.forEach(function(names) { if (names.length > 1) reused.push(names); });

    out.textContent = '';
    function addLine(txt, cls) {
        var d = document.createElement('div');
        d.className = 'audit-line' + (cls ? ' ' + cls : '');
        d.textContent = txt;
        out.appendChild(d);
    }
    if (!reused.length && !weak.length && !empty.length) {
        addLine('✓ No reused, weak, or empty passwords across '
                + items.length + ' entries.', 'audit-ok');
        return;
    }
    reused.forEach(function(names) {
        addLine('⚠ Same password on ' + names.length + ' entries: '
                + names.join(', '), 'audit-bad');
    });
    if (weak.length)  addLine('⚠ Weak (under 40 bits): ' + weak.join(', '), 'audit-warn');
    if (empty.length) addLine('— No password stored: ' + empty.join(', '), 'audit-warn');
}

function toggleChangePw() {
    var f = document.getElementById('chpw-form');
    if (!f) return;
    var visible = f.style.display !== 'none';
    f.style.display = visible ? 'none' : '';
    if (!visible) document.getElementById('newpw1').focus();
}

// Re-encrypt the whole vault under new master passwords. Fully client-side
// decrypt + re-encrypt, then an atomic whole-file replace via post.php's bulk
// mode. The server verifies a hash of the snapshot we re-encrypted and refuses
// (409) if `lines` changed meanwhile, so a concurrent write can never be lost
// and the vault is never half-rekeyed.
async function changeMasterPasswords() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var status = document.getElementById('chpw-status');
    function say(msg) { if (status) status.textContent = msg; }

    if (!pw || !pw2) { say('Enter both current passwords in the key fields first.'); return; }
    if (!_allEntries.length) { say('Vault is empty.'); return; }

    var n1  = document.getElementById('newpw1').value;
    var n1c = document.getElementById('newpw1c').value;
    var n2  = document.getElementById('newpw2').value;
    var n2c = document.getElementById('newpw2c').value;
    if (!n1 || !n2) { say('Both new passwords are required.'); return; }
    if (n1 !== n1c || n2 !== n2c) { say('New passwords do not match their confirmation.'); return; }
    if (n1 === pw && n2 === pw2) { say('New passwords are identical to the current ones.'); return; }

    var btn = document.getElementById('btn-chpw-go');
    if (btn) btn.disabled = true;
    var total = _allEntries.length;
    try {
        say('Re-encrypting… 0 / ' + total);
        // Decrypt with the current passwords and re-encrypt with the new ones,
        // fresh salts/nonces per record (same construction as saveEntry).
        var pairs = await _forEachRecordDecrypt(pw, pw2, async function(rec, name, fields) {
            var recSalt1 = crypto.getRandomValues(new Uint8Array(32));
            var recSalt2 = crypto.getRandomValues(new Uint8Array(32));
            var nameEnc = await encryptName(n1, n2, recSalt1, recSalt2, name);
            var result  = await encryptFields(n1, n2, recSalt1, recSalt2, fields);
            var newRec  = [nameEnc.encNameHex, 'v6',
                           bytesToHex(recSalt1),  bytesToHex(recSalt2),
                           nameEnc.nameNonce1Hex, nameEnc.nameNonce2Hex,
                           result.iv1Hex,         result.nonce2Hex,
                           result.nonce3Hex,      result.nonce4Hex,
                           result.encHex].join('|');
            return { newRec: newRec, name: name };
        }, function(done) { say('Re-encrypting… ' + done + ' / ' + total); });

        // Hash of the snapshot we just re-encrypted: records joined with "\n",
        // no trailing newline — must match post.php's computation exactly.
        var oldJoined = _allEntries.map(function(row) {
            return row.split('|').slice(0, -1).join('|');
        }).join('\n');
        var hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(oldJoined));
        var expectHash = bytesToHex(new Uint8Array(hashBuf));

        say('Saving…');
        var bulkData = pairs.map(function(p) { return p.newRec; }).join('\n');
        var responseText = await _xhrPost('bulk=1&expect_hash=' + expectHash
                                          + '&bulk_data=' + encodeURIComponent(bulkData));

        // Committed server-side: switch this session to the new passwords and
        // pre-seed the name cache so the rebuilt grid reveals instantly.
        document.getElementById('aeskey').value  = n1;
        document.getElementById('aeskey2').value = n2;
        _mkCache.clear();
        _v5Names.clear();
        _lastRevealPw  = null;
        _lastRevealPw2 = null;
        pairs.forEach(function(p) { _v5Names.set(p.newRec, p.name); });
        clearDisplay();
        try { _applyServerResponse(responseText); } catch (_) { location.reload(); return; }
        _revealCachedV5Buttons();
        ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
            document.getElementById(id).value = '';
        });
        say('');
        toggleChangePw();
        showToast('Master passwords changed — ' + total + ' entries re-encrypted');
    } catch (e) {
        if (e.stale) {
            say('The vault changed while re-encrypting — nothing was modified. Close, reload, and retry.');
        } else {
            say('Password change failed — ' + e.message + '. The vault was not modified.');
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Wipe vault-tools state (audit results, half-typed new passwords). Called from
// _relockV5Entries, which runs on every lock / clear / key-field edit.
function _clearVaultTools() {
    var out = document.getElementById('audit-result');
    if (out) { out.textContent = ''; out.style.display = 'none'; }
    ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.value = '';
    });
    var f = document.getElementById('chpw-form');
    if (f) f.style.display = 'none';
    var status = document.getElementById('chpw-status');
    if (status) status.textContent = '';
}

// ============================================================
// Search / filter overlay
// ============================================================

function toggleSearch() {
    var overlay = document.getElementById('search-overlay');
    if (overlay.classList.contains('open')) { hideSearch(); } else { showSearch(); }
}

function showSearch() {
    var overlay = document.getElementById('search-overlay');
    var box     = document.getElementById('search-box');
    var fixedH  = document.getElementById('fixedDiv').offsetHeight;
    box.style.marginTop = (fixedH + 8) + 'px';
    overlay.classList.add('open');
    var inp = document.getElementById('search-input');
    inp.value = '';
    filterSearch('');
    inp.focus();
}

function hideSearch() {
    document.getElementById('search-overlay').classList.remove('open');
}

function filterSearch(query) {
    var results  = document.getElementById('search-results');
    var countEl  = document.getElementById('search-count');
    results.innerHTML = '';
    var q = query.trim().toLowerCase();
    if (!q) {
        if (countEl) countEl.textContent = '';
        return;
    }
    var total   = _allEntries.length;
    var matched = _allEntries.filter(function(row) {
        var parts = row.split('|');
        var name = _v5Names.get(parts.slice(0, -1).join('|')) || '';
        return name.toLowerCase().indexOf(q) !== -1;
    });
    if (countEl) countEl.textContent = matched.length + ' of ' + total + (total === 1 ? ' entry' : ' entries');
    if (matched.length === 0) {
        var msg = document.createElement('div');
        msg.id = 'search-no-match';
        msg.textContent = 'No matches';
        results.appendChild(msg);
        return;
    }
    matched.forEach(function(row) {
        var parts = row.split('|');
        var displayName = _v5Names.get(parts.slice(0, -1).join('|')) || '🔒';
        var btn = document.createElement('button');
        btn.className   = 'entry-btn';
        btn.textContent = displayName;
        btn.title       = displayName;
        btn.onclick = function() { hideSearch(); decodeLine(btn, row); };
        results.appendChild(btn);
    });
}

// ============================================================
// About modal — runtime self-test
// ============================================================

async function runCryptoSelfTest() {
    var PLAIN   = new TextEncoder().encode('CryptoSelfTest-OK');
    var KEY32   = new Uint8Array(32);   // 32 zero bytes — test key only
    var NONCE12 = new Uint8Array(12);
    var NONCE16 = new Uint8Array(16);
    var pass = 0, fail = 0;
    var results = [];

    function setStatus(id, ok, msg) {
        var el = document.getElementById(id);
        if (!el) return;
        el.classList.remove('loading', 'ok', 'fail');
        if (ok === null) { el.classList.add('loading'); el.textContent = '…'; return; }
        el.classList.add(ok ? 'ok' : 'fail');
        el.textContent = ok ? '✓' : '⚠';
        if (!ok && msg) el.title = msg;
    }

    function record(name, id, ok, msg) {
        ok ? pass++ : fail++;
        results.push({ name: name, ok: ok, msg: msg || '' });
        setStatus(id, ok, msg);
    }

    // 1. WebCrypto API presence
    var wcOk = typeof crypto !== 'undefined' &&
               typeof crypto.getRandomValues === 'function' &&
               typeof crypto.subtle === 'object' && crypto.subtle !== null;
    record('WebCrypto API', 'st-webcrypto', wcOk, 'WebCrypto API not available in this browser');

    // 2. ChaCha20-Poly1305 — two separate instances (wrapCipher forbids encrypt() twice per instance)
    var chachaOk = false;
    try {
        var chaCt = globalThis.chacha20poly1305(KEY32, NONCE12).encrypt(PLAIN);
        var chaRt = globalThis.chacha20poly1305(KEY32, NONCE12).decrypt(chaCt);
        chachaOk  = chaRt.length === PLAIN.length &&
                    chaRt.every(function(b, i) { return b === PLAIN[i]; });
    } catch (_) {}
    record('ChaCha20-Poly1305', 'st-chacha', chachaOk, 'ChaCha20-Poly1305 round-trip failed');

    // 3. AES-256-GCM — import raw key directly (bypasses PBKDF2 for speed)
    var aesOk = false;
    try {
        var aesCK = await crypto.subtle.importKey(
            'raw', KEY32, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );
        var aesCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: NONCE12 }, aesCK, PLAIN);
        var aesRt = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'AES-GCM', iv: NONCE12 }, aesCK, aesCt)
        );
        aesOk = aesRt.length === PLAIN.length &&
                aesRt.every(function(b, i) { return b === PLAIN[i]; });
    } catch (_) {}
    record('AES-256-GCM', 'st-aes', aesOk, 'AES-256-GCM round-trip failed');

    // 4. Twofish-256-CTR — CTR is self-inverse: applying it twice recovers the original
    var tfOk = false;
    try {
        var tfCt = twofishCTR(KEY32, NONCE16, PLAIN);
        var tfRt = twofishCTR(KEY32, NONCE16, tfCt);
        tfOk = tfRt.length === PLAIN.length &&
               tfRt.every(function(b, i) { return b === PLAIN[i]; });
    } catch (_) {}
    record('Twofish-256-CTR', 'st-twofish', tfOk, 'Twofish-256-CTR round-trip failed');

    // 5. Serpent-256-CTR — CTR is self-inverse, like Twofish above
    var spOk = false;
    try {
        var spCt = serpentCTR(KEY32, NONCE16, PLAIN);
        var spRt = serpentCTR(KEY32, NONCE16, spCt);
        spOk = spRt.length === PLAIN.length &&
               spRt.every(function(b, i) { return b === PLAIN[i]; });
    } catch (_) {}
    record('Serpent-256-CTR', 'st-serpent', spOk, 'Serpent-256-CTR round-trip failed');

    // 6. Argon2id (WASM) — known-answer with small params (fast). Confirms the WASM
    //    module loaded (CSP 'wasm-unsafe-eval' present) and computes correctly.
    var argonOk = false;
    try {
        var KAT = '561b06cd267388c9b4a815b12023fb73c56d956e121347e758ba941fa4d4b2df';
        var ah  = await argon2idHash(
            new TextEncoder().encode('argon2id-selftest'),
            new TextEncoder().encode('vault-selftest!!'),
            { iterations: 2, memorySize: 256, parallelism: 1, hashLength: 32 }
        );
        argonOk = bytesToHex(ah) === KAT;
    } catch (_) {}
    record('Argon2id (WASM)', 'st-argon2', argonOk, 'Argon2id WASM unavailable (CSP wasm-unsafe-eval?) or wrong output');

    // Overall banner
    var banner = document.getElementById('selftest-banner');
    if (banner) {
        banner.classList.remove('ok', 'fail');
        if (fail === 0) {
            banner.classList.add('ok');
            banner.textContent = '✓ Self-test passed — all ' + pass + ' checks OK';
        } else {
            banner.classList.add('fail');
            banner.textContent = '⚠ Self-test: ' + fail + ' of ' + (pass + fail) +
                                 ' check' + (fail === 1 ? '' : 's') + ' failed';
        }
    }

    return { fail: fail, results: results };
}

async function runPageLoadSelfTest() {
    var r = await runCryptoSelfTest();
    if (r.fail === 0) return;
    var list = document.getElementById('crypto-warn-list');
    if (list) {
        list.innerHTML = '';
        r.results.forEach(function(item) {
            if (!item.ok) {
                var li = document.createElement('li');
                li.textContent = item.name + (item.msg ? ' — ' + item.msg : '');
                list.appendChild(li);
            }
        });
    }
    var overlay = document.getElementById('crypto-warn-overlay');
    if (overlay) overlay.classList.add('open');
}

function closeCryptoWarn() {
    var overlay = document.getElementById('crypto-warn-overlay');
    if (overlay) overlay.classList.remove('open');
}

function openAbout() {
    ['st-webcrypto', 'st-chacha', 'st-aes', 'st-twofish'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.className = 'selftest-status loading';
        el.textContent = '…';
        el.title = '';
    });
    var banner = document.getElementById('selftest-banner');
    if (banner) { banner.className = ''; banner.textContent = '… Running tests'; }
    document.getElementById('about-overlay').classList.add('open');
    runCryptoSelfTest();
}

function closeAbout() {
    document.getElementById('about-overlay').classList.remove('open');
}

// ============================================================
// Password strength indicator
// ============================================================

// Entropy estimate in bits: detected character-class pool size, log2-scaled by
// length. Shared by the strength meter and the vault audit.
function _estimateBits(val) {
    var pool = 0;
    if (/[a-z]/.test(val)) pool += 26;
    if (/[A-Z]/.test(val)) pool += 26;
    if (/[0-9]/.test(val)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(val)) pool += 32;
    return pool > 1 ? Math.log2(pool) * val.length : 0;
}

function updatePWStrength() {
    var val  = document.getElementById('password').value;
    var wrap = document.getElementById('pw-strength-wrap');
    if (!wrap) return;
    if (!val) { wrap.style.display = 'none'; return; }

    var bits = _estimateBits(val);

    var level, label, color;
    if      (bits < 40)  { level = 1; label = 'Weak';        color = '#ff5c5c'; }
    else if (bits < 80)  { level = 2; label = 'Fair';        color = '#f5a623'; }
    else if (bits < 120) { level = 3; label = 'Strong';      color = '#3fcf8e'; }
    else                 { level = 4; label = 'Very Strong';  color = '#4d8eff'; }

    for (var i = 1; i <= 4; i++) {
        var seg = document.getElementById('pw-seg-' + i);
        if (seg) seg.style.background = i <= level ? color : '';
    }
    var lbl = document.getElementById('pw-strength-lbl');
    if (lbl) { lbl.textContent = label; lbl.style.color = color; }
    var ent = document.getElementById('pw-entropy-lbl');
    if (ent) ent.textContent = bits.toFixed(1) + ' bits';

    wrap.style.display = '';
}

function retestCrypto() {
    ['st-webcrypto', 'st-chacha', 'st-aes', 'st-twofish'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.className = 'selftest-status loading';
        el.textContent = '…';
        el.title = '';
    });
    var banner = document.getElementById('selftest-banner');
    if (banner) { banner.className = ''; banner.textContent = '… Running tests'; }
    runCryptoSelfTest();
}

// ============================================================
// Keyboard shortcuts (Escape / double-Escape lock)
// ============================================================

var _lastEscTime = 0;
document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    var now = Date.now();
    if (now - _lastEscTime < 400) {
        // Double rapid Escape — lock and clear everything
        _lastEscTime = 0;
        _resetKeyFields();
        _mkCache.clear();
        _terminateArgonPool();
        clearDisplay();
        _editRecord = null;
        document.getElementById('newentry').style.display         = 'none';
        document.getElementById('passwordSettings').style.display = 'none';
        document.getElementById('newentry-title').textContent     = 'New Entry';
        _clearClipboardIfDirty();
        _relockV5Entries();
        if (document.getElementById('about-overlay').classList.contains('open')) closeAbout();
        if (document.getElementById('search-overlay').classList.contains('open')) hideSearch();
        window.scrollTo({ top: 0, behavior: 'smooth' });
        showToast('Locked');
        return;
    }
    _lastEscTime = now;
    if (document.getElementById('about-overlay').classList.contains('open')) {
        closeAbout(); return;
    }
    if (document.getElementById('search-overlay').classList.contains('open')) {
        hideSearch();
    } else if (document.getElementById('newentry').style.display !== 'none') {
        cancelEntry();
    } else {
        clearDisplay();
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ============================================================
// Auto-lock on inactivity
// ============================================================

function performAutoLock() {
    _resetKeyFields();
    _mkCache.clear();
    _terminateArgonPool();
    clearDisplay();
    _editRecord = null;
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
    document.getElementById('newentry-title').textContent     = 'New Entry';
    _clearClipboardIfDirty();
    _relockV5Entries();
    showToast('Locked due to inactivity');
}

function hideLockWarning() {
    document.getElementById('lock-warning').classList.remove('show');
    clearInterval(_lockWarnTimer);
    _lockWarnTimer = null;
}

function showLockWarning() {
    if (!document.getElementById('aeskey').value && !document.getElementById('aeskey2').value) {
        resetInactivityTimer();
        return;
    }
    var secs = _WARN_SECS;
    document.getElementById('lock-countdown').textContent = secs;
    document.getElementById('lock-warning').classList.add('show');
    _lockWarnTimer = setInterval(function() {
        secs--;
        if (secs <= 0) {
            hideLockWarning();
            performAutoLock();
        } else {
            document.getElementById('lock-countdown').textContent = secs;
        }
    }, 1000);
}

function cancelAutoLock() {
    hideLockWarning();
    resetInactivityTimer();
}

function resetInactivityTimer() {
    clearTimeout(_inactivityTimer);
    if (_lockWarnTimer) hideLockWarning();
    _inactivityTimer = setTimeout(showLockWarning, _INACTIVITY_MS);
}

(function _initActivityListeners() {
    ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(function(ev) {
        document.addEventListener(ev, resetInactivityTimer, { passive: true });
    });
    resetInactivityTimer();
})();

// ============================================================
// Declarative event binding (CSP: no inline on*= handlers)
// ============================================================
// The HTML templates carry no inline event handlers — script-src is locked to
// 'self' with no 'unsafe-inline'. Click targets declare data-action and are
// dispatched here; other event types are bound by id/attribute in
// _bindStaticHandlers(). Entry buttons are wired separately in _initEntries() /
// _rebuildEntryGrid() from their data-row.

// data-action -> handler. The element carrying data-action is passed as `el`
// (replaces the old onclick="fn(this)") so handlers that need their button
// (clearLines, newEntry) still receive it.
var _clickActions = {
    'edit-entry':        function(el) { editEntry(); },
    'delete-entry':      function(el) { deleteEntry(); },
    'copy-username':     function(el) { doCBCopy('username'); },
    'copy-2fa':          function(el) { doCBCopy('2fa'); },
    'copy-password':     function(el) { doCBCopy('password'); },
    'copy-current':      function(el) { doCBCopy('current'); },
    'toggle-key':        function(el) { toggleKey(); },
    'toggle-key2':       function(el) { toggleKey2(); },
    'clear-lines':       function(el) { clearLines(el); },
    'clear-display':     function(el) { blinkTD(el); clearDisplay(); _editRecord = null; },
    'new-entry':         function(el) { newEntry(el); },
    'toggle-search':     function(el) { toggleSearch(); },
    'open-about':        function(el) { openAbout(); },
    'generate':          function(el) { doGenerate(); },
    'scan-qr':           function(el) { scanQRCode(); },
    'show-pw-settings':  function(el) { showPWSettings(); },
    'cancel-entry':      function(el) { cancelEntry(); },
    'save-entry':        function(el) { saveEntry(); },
    'cancel-autolock':   function(el) { cancelAutoLock(); },
    'close-crypto-warn': function(el) { closeCryptoWarn(); },
    'close-about':       function(el) { closeAbout(); },
    'retest-crypto':     function(el) { retestCrypto(); },
    'export-vault':      function(el) { exportVault(); },
    'audit-vault':       function(el) { auditVault(); },
    'toggle-chpw':       function(el) { toggleChangePw(); },
    'do-chpw':           function(el) { changeMasterPasswords(); }
};

document.addEventListener('click', function(e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;
    var fn = _clickActions[el.dataset.action];
    if (fn) fn(el, e);
});

// Bind the non-click and special-case handlers that were previously inline.
function _bindStaticHandlers() {
    // Inputs that drop `readonly` on first focus (anti-autofill honeypot).
    document.querySelectorAll('[data-clear-readonly]').forEach(function(el) {
        el.addEventListener('focus', function() { el.removeAttribute('readonly'); });
    });

    // Inputs that tick a sibling checkbox/radio on first input.
    document.querySelectorAll('[data-check-on-input]').forEach(function(el) {
        el.addEventListener('input', function() {
            var target = document.getElementById(el.dataset.checkOnInput);
            if (target) target.checked = true;
        });
    });

    var pw = document.getElementById('password');
    if (pw) pw.addEventListener('input', updatePWStrength);

    var notes = document.getElementById('notes');
    if (notes) notes.addEventListener('input', function() {
        notes.style.height = 'auto';
        notes.style.height = notes.scrollHeight + 'px';
    });

    // Master-key field: Tab/Enter clears + jumps to the 2nd key.
    var k1 = document.getElementById('aeskey');
    if (k1) k1.addEventListener('keydown', function(e) {
        if (e.key === 'Tab' || e.key === 'Enter') {
            e.preventDefault();
            var k2 = document.getElementById('aeskey2');
            k2.value = '';
            k2.focus();
        }
    });

    // Secondary-key field: Shift+Tab clears + jumps back to the primary key.
    var k2 = document.getElementById('aeskey2');
    if (k2) k2.addEventListener('keydown', function(e) {
        if (e.key === 'Tab' && e.shiftKey) {
            e.preventDefault();
            var k1b = document.getElementById('aeskey');
            k1b.value = '';
            k1b.focus();
        }
    });

    var form = document.querySelector('form.ctrl-form');
    if (form) form.addEventListener('submit', function(e) { e.preventDefault(); });

    var si = document.getElementById('search-input');
    if (si) {
        si.addEventListener('input', function() { filterSearch(si.value); });
        si.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') { hideSearch(); e.stopPropagation(); }
        });
    }

    // Overlay backdrops: close only when the backdrop itself (not a child) is clicked.
    var so = document.getElementById('search-overlay');
    if (so) so.addEventListener('click', function(e) { if (e.target === so) hideSearch(); });
    var ao = document.getElementById('about-overlay');
    if (ao) ao.addEventListener('click', function(e) { if (e.target === ao) closeAbout(); });
}

// Reveal v5 entry names when both passwords are set and the user tabs away from
// the secondary key.  Either field changing invalidates previously revealed names.
document.addEventListener('DOMContentLoaded', function() {
    _bindStaticHandlers();

    var k1 = document.getElementById('aeskey');
    var k2 = document.getElementById('aeskey2');
    if (k1) k1.addEventListener('input', _relockV5Entries);
    if (k2) {
        k2.addEventListener('input', _relockV5Entries);
        k2.addEventListener('blur', function() {
            var pw  = k1 ? k1.value : '';
            var pw2 = k2.value;
            if (!(pw && pw2)) return;
            // Already revealed with this exact pair and nothing has changed since
            // (an edit would have cleared _lastReveal* via _relockV5Entries) — skip
            // the expensive re-derivation of every name.
            if (pw === _lastRevealPw && pw2 === _lastRevealPw2) return;
            clearDisplay();
            _relockV5Entries();
            _revealAllV5Names(pw, pw2);
        });
    }

    // Page-load init sequence (formerly the inline <script> at the end of body).
    initCharsets();
    initCrypto();
    runPageLoadSelfTest();
    _initMaskedInputs();
    var copyBtn = document.getElementById('copy-button');
    if (copyBtn) copyBtn.disabled = true;
    resizeFreezePane();
    _initEntries();
    window.scrollTo(0, 0);
    document.getElementById('aeskey').focus();
});

// ============================================================
// Delete an entry
// ============================================================

function deleteEntry() {
    if (deleteEntryRecord === null) { alert('Select an entry to delete first'); return; }
    if (confirm('Delete "' + deleteEntryName + '"?')) {
        _xhrPost('delete_rec=' + encodeURIComponent(deleteEntryRecord))
            .then(function(text) {
                try { if (_applyServerResponse(text)) _revealCachedV5Buttons(); } catch (_) { location.reload(); return; }
                clearDisplay();
            })
            .catch(function(e) {
                if (e.stale) {
                    showToast('Entry was changed elsewhere — reloading');
                    setTimeout(function() { location.reload(); }, 1200);
                    return;
                }
                alert('Delete failed: ' + e.message);
            });
    }
}

// ============================================================
// Password generator
// ============================================================

var CHARACTER_SETS = [
    ['Uppercase', true,  'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    ['Lowercase', true,  'abcdefghijklmnopqrstuvwxyz'],
    ['Digits',    true,  '0123456789'],
    ['Symbols',   true,  '!#$%&()*+,-./:;<=>?@[]^_{|}~'],
];

function initCharsets() {
    var container = document.getElementById('charset');
    if (!container) return;
    CHARACTER_SETS.forEach(function(entry, i) {
        var cb = document.createElement('input');
        cb.type    = 'checkbox';
        cb.id      = 'charset-' + i;
        cb.checked = entry[1];
        container.appendChild(cb);
        var lbl = document.createElement('label');
        lbl.htmlFor     = 'charset-' + i;
        lbl.textContent = entry[0];
        container.appendChild(lbl);
        var sp = document.createElement('span');
        if (entry[0] === 'Symbols') {
            sp.className   = 'sym-chars';
            sp.textContent = entry[2];
        }
        container.appendChild(sp);
    });
}

function _randomInt(n) {
    var limit = Math.floor(4294967296 / n) * n;
    var buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % n;
}

function doGenerate() {
    var charset = '';
    CHARACTER_SETS.forEach(function(entry, i) {
        if (document.getElementById('charset-' + i).checked) charset += entry[2];
    });
    if (document.getElementById('custom').checked) {
        charset += document.getElementById('customchars').value;
    }
    charset = Array.from(new Set(charset.split(''))).join('');
    if (!charset) { alert('Select at least one character set'); return; }

    var length;
    if (document.getElementById('by-length').checked) {
        length = parseInt(document.getElementById('length').value, 10);
    } else {
        var bits = parseFloat(document.getElementById('entropy').value);
        length = Math.ceil(bits / Math.log2(charset.length));
    }
    if (!length || length < 1 || length > 1000) { alert('Invalid length'); return; }

    var chars = charset.split('');
    currentPassword = Array.from({ length: length }, function() {
        return chars[_randomInt(chars.length)];
    }).join('');

    document.getElementById('password').value = currentPassword;
    updatePWStrength();
    var entropy = Math.log2(charset.length) * length;
    document.getElementById('statistics').textContent =
        'Length = ' + length + ',  Charset = ' + charset.length +
        ' symbols,  Entropy ≈ ' + entropy.toFixed(1) + ' bits';
    document.getElementById('copy-button').disabled = false;
}

function initCrypto() {
    var el = document.getElementById('crypto-getrandomvalues-entropy');
    if (!el) return;
    if (typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.subtle) {
        el.textContent = '✓';
    } else {
        el.textContent = '⚠ NOT available — do not use this browser for password generation';
    }
}
