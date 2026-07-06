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
  var data$j = "AGFzbQEAAAABEQRgAAF/YAJ/fwBgAX8AYAAAAwoJAAECAwECAgABBQQBAQICBg4CfwFBsIsFC38AQYAICwdwCAZtZW1vcnkCAA5IYXNoX0dldEJ1ZmZlcgAACkhhc2hfRmluYWwAAwlIYXNoX0luaXQABQtIYXNoX1VwZGF0ZQAGDUhhc2hfR2V0U3RhdGUABw5IYXNoX0NhbGN1bGF0ZQAIClNUQVRFX1NJWkUDAQrTOAkFAEGACQvrAgIFfwF+AkAgAUEBSA0AAkACQAJAIAFBgAFBACgC4IoBIgJrIgNKDQAgASEEDAELQQBBADYC4IoBAkAgAkH/AEoNACACQeCJAWohBSAAIQRBACEGA0AgBSAELQAAOgAAIARBAWohBCAFQQFqIQUgAyAGQQFqIgZB/wFxSg0ACwtBAEEAKQPAiQEiB0KAAXw3A8CJAUEAQQApA8iJASAHQv9+Vq18NwPIiQFB4IkBEAIgACADaiEAAkAgASADayIEQYEBSA0AIAIgAWohBQNAQQBBACkDwIkBIgdCgAF8NwPAiQFBAEEAKQPIiQEgB0L/flatfDcDyIkBIAAQAiAAQYABaiEAIAVBgH9qIgVBgAJLDQALIAVBgH9qIQQMAQsgBEEATA0BC0EAIQUDQCAFQQAoAuCKAWpB4IkBaiAAIAVqLQAAOgAAIAQgBUEBaiIFQf8BcUoNAAsLQQBBACgC4IoBIARqNgLgigELC78uASR+QQBBACkD0IkBQQApA7CJASIBQQApA5CJAXwgACkDICICfCIDhULr+obav7X2wR+FQiCJIgRCq/DT9K/uvLc8fCIFIAGFQiiJIgYgA3wgACkDKCIBfCIHIASFQjCJIgggBXwiCSAGhUIBiSIKQQApA8iJAUEAKQOoiQEiBEEAKQOIiQF8IAApAxAiA3wiBYVCn9j52cKR2oKbf4VCIIkiC0K7zqqm2NDrs7t/fCIMIASFQiiJIg0gBXwgACkDGCIEfCIOfCAAKQNQIgV8Ig9BACkDwIkBQQApA6CJASIQQQApA4CJASIRfCAAKQMAIgZ8IhKFQtGFmu/6z5SH0QCFQiCJIhNCiJLznf/M+YTqAHwiFCAQhUIoiSIVIBJ8IAApAwgiEHwiFiAThUIwiSIXhUIgiSIYQQApA9iJAUEAKQO4iQEiE0EAKQOYiQF8IAApAzAiEnwiGYVC+cL4m5Gjs/DbAIVCIIkiGkLx7fT4paf9p6V/fCIbIBOFQiiJIhwgGXwgACkDOCITfCIZIBqFQjCJIhogG3wiG3wiHSAKhUIoiSIeIA98IAApA1giCnwiDyAYhUIwiSIYIB18Ih0gDiALhUIwiSIOIAx8Ih8gDYVCAYkiDCAWfCAAKQNAIgt8Ig0gGoVCIIkiFiAJfCIaIAyFQiiJIiAgDXwgACkDSCIJfCIhIBaFQjCJIhYgGyAchUIBiSIMIAd8IAApA2AiB3wiDSAOhUIgiSIOIBcgFHwiFHwiFyAMhUIoiSIbIA18IAApA2giDHwiHCAOhUIwiSIOIBd8IhcgG4VCAYkiGyAZIBQgFYVCAYkiFHwgACkDcCINfCIVIAiFQiCJIhkgH3wiHyAUhUIoiSIUIBV8IAApA3giCHwiFXwgDHwiIoVCIIkiI3wiJCAbhUIoiSIbICJ8IBJ8IiIgFyAYIBUgGYVCMIkiFSAffCIZIBSFQgGJIhQgIXwgDXwiH4VCIIkiGHwiFyAUhUIoiSIUIB98IAV8Ih8gGIVCMIkiGCAXfCIXIBSFQgGJIhR8IAF8IiEgFiAafCIWIBUgHSAehUIBiSIaIBx8IAl8IhyFQiCJIhV8Ih0gGoVCKIkiGiAcfCAIfCIcIBWFQjCJIhWFQiCJIh4gGSAOIBYgIIVCAYkiFiAPfCACfCIPhUIgiSIOfCIZIBaFQiiJIhYgD3wgC3wiDyAOhUIwiSIOIBl8Ihl8IiAgFIVCKIkiFCAhfCAEfCIhIB6FQjCJIh4gIHwiICAiICOFQjCJIiIgJHwiIyAbhUIBiSIbIBx8IAp8IhwgDoVCIIkiDiAXfCIXIBuFQiiJIhsgHHwgE3wiHCAOhUIwiSIOIBkgFoVCAYkiFiAffCAQfCIZICKFQiCJIh8gFSAdfCIVfCIdIBaFQiiJIhYgGXwgB3wiGSAfhUIwiSIfIB18Ih0gFoVCAYkiFiAVIBqFQgGJIhUgD3wgBnwiDyAYhUIgiSIYICN8IhogFYVCKIkiFSAPfCADfCIPfCAHfCIihUIgiSIjfCIkIBaFQiiJIhYgInwgBnwiIiAjhUIwiSIjICR8IiQgFoVCAYkiFiAOIBd8Ig4gDyAYhUIwiSIPICAgFIVCAYkiFCAZfCAKfCIXhUIgiSIYfCIZIBSFQiiJIhQgF3wgC3wiF3wgBXwiICAPIBp8Ig8gHyAOIBuFQgGJIg4gIXwgCHwiGoVCIIkiG3wiHyAOhUIoiSIOIBp8IAx8IhogG4VCMIkiG4VCIIkiISAdIB4gDyAVhUIBiSIPIBx8IAF8IhWFQiCJIhx8Ih0gD4VCKIkiDyAVfCADfCIVIByFQjCJIhwgHXwiHXwiHiAWhUIoiSIWICB8IA18IiAgIYVCMIkiISAefCIeIBogFyAYhUIwiSIXIBl8IhggFIVCAYkiFHwgCXwiGSAchUIgiSIaICR8IhwgFIVCKIkiFCAZfCACfCIZIBqFQjCJIhogHSAPhUIBiSIPICJ8IAR8Ih0gF4VCIIkiFyAbIB98Iht8Ih8gD4VCKIkiDyAdfCASfCIdIBeFQjCJIhcgH3wiHyAPhUIBiSIPIBsgDoVCAYkiDiAVfCATfCIVICOFQiCJIhsgGHwiGCAOhUIoiSIOIBV8IBB8IhV8IAx8IiKFQiCJIiN8IiQgD4VCKIkiDyAifCAHfCIiICOFQjCJIiMgJHwiJCAPhUIBiSIPIBogHHwiGiAVIBuFQjCJIhUgHiAWhUIBiSIWIB18IAR8IhuFQiCJIhx8Ih0gFoVCKIkiFiAbfCAQfCIbfCABfCIeIBUgGHwiFSAXIBogFIVCAYkiFCAgfCATfCIYhUIgiSIXfCIaIBSFQiiJIhQgGHwgCXwiGCAXhUIwiSIXhUIgiSIgIB8gISAVIA6FQgGJIg4gGXwgCnwiFYVCIIkiGXwiHyAOhUIoiSIOIBV8IA18IhUgGYVCMIkiGSAffCIffCIhIA+FQiiJIg8gHnwgBXwiHiAghUIwiSIgICF8IiEgGyAchUIwiSIbIB18IhwgFoVCAYkiFiAYfCADfCIYIBmFQiCJIhkgJHwiHSAWhUIoiSIWIBh8IBJ8IhggGYVCMIkiGSAfIA6FQgGJIg4gInwgAnwiHyAbhUIgiSIbIBcgGnwiF3wiGiAOhUIoiSIOIB98IAZ8Ih8gG4VCMIkiGyAafCIaIA6FQgGJIg4gFSAXIBSFQgGJIhR8IAh8IhUgI4VCIIkiFyAcfCIcIBSFQiiJIhQgFXwgC3wiFXwgBXwiIoVCIIkiI3wiJCAOhUIoiSIOICJ8IAh8IiIgGiAgIBUgF4VCMIkiFSAcfCIXIBSFQgGJIhQgGHwgCXwiGIVCIIkiHHwiGiAUhUIoiSIUIBh8IAZ8IhggHIVCMIkiHCAafCIaIBSFQgGJIhR8IAR8IiAgGSAdfCIZIBUgISAPhUIBiSIPIB98IAN8Ih2FQiCJIhV8Ih8gD4VCKIkiDyAdfCACfCIdIBWFQjCJIhWFQiCJIiEgFyAbIBkgFoVCAYkiFiAefCABfCIZhUIgiSIbfCIXIBaFQiiJIhYgGXwgE3wiGSAbhUIwiSIbIBd8Ihd8Ih4gFIVCKIkiFCAgfCAMfCIgICGFQjCJIiEgHnwiHiAiICOFQjCJIiIgJHwiIyAOhUIBiSIOIB18IBJ8Ih0gG4VCIIkiGyAafCIaIA6FQiiJIg4gHXwgC3wiHSAbhUIwiSIbIBcgFoVCAYkiFiAYfCANfCIXICKFQiCJIhggFSAffCIVfCIfIBaFQiiJIhYgF3wgEHwiFyAYhUIwiSIYIB98Ih8gFoVCAYkiFiAVIA+FQgGJIg8gGXwgCnwiFSAchUIgiSIZICN8IhwgD4VCKIkiDyAVfCAHfCIVfCASfCIihUIgiSIjfCIkIBaFQiiJIhYgInwgBXwiIiAjhUIwiSIjICR8IiQgFoVCAYkiFiAbIBp8IhogFSAZhUIwiSIVIB4gFIVCAYkiFCAXfCADfCIXhUIgiSIZfCIbIBSFQiiJIhQgF3wgB3wiF3wgAnwiHiAVIBx8IhUgGCAaIA6FQgGJIg4gIHwgC3wiGoVCIIkiGHwiHCAOhUIoiSIOIBp8IAR8IhogGIVCMIkiGIVCIIkiICAfICEgFSAPhUIBiSIPIB18IAZ8IhWFQiCJIh18Ih8gD4VCKIkiDyAVfCAKfCIVIB2FQjCJIh0gH3wiH3wiISAWhUIoiSIWIB58IAx8Ih4gIIVCMIkiICAhfCIhIBogFyAZhUIwiSIXIBt8IhkgFIVCAYkiFHwgEHwiGiAdhUIgiSIbICR8Ih0gFIVCKIkiFCAafCAJfCIaIBuFQjCJIhsgHyAPhUIBiSIPICJ8IBN8Ih8gF4VCIIkiFyAYIBx8Ihh8IhwgD4VCKIkiDyAffCABfCIfIBeFQjCJIhcgHHwiHCAPhUIBiSIPIBggDoVCAYkiDiAVfCAIfCIVICOFQiCJIhggGXwiGSAOhUIoiSIOIBV8IA18IhV8IA18IiKFQiCJIiN8IiQgD4VCKIkiDyAifCAMfCIiICOFQjCJIiMgJHwiJCAPhUIBiSIPIBsgHXwiGyAVIBiFQjCJIhUgISAWhUIBiSIWIB98IBB8IhiFQiCJIh18Ih8gFoVCKIkiFiAYfCAIfCIYfCASfCIhIBUgGXwiFSAXIBsgFIVCAYkiFCAefCAHfCIZhUIgiSIXfCIbIBSFQiiJIhQgGXwgAXwiGSAXhUIwiSIXhUIgiSIeIBwgICAVIA6FQgGJIg4gGnwgAnwiFYVCIIkiGnwiHCAOhUIoiSIOIBV8IAV8IhUgGoVCMIkiGiAcfCIcfCIgIA+FQiiJIg8gIXwgBHwiISAehUIwiSIeICB8IiAgGCAdhUIwiSIYIB98Ih0gFoVCAYkiFiAZfCAGfCIZIBqFQiCJIhogJHwiHyAWhUIoiSIWIBl8IBN8IhkgGoVCMIkiGiAcIA6FQgGJIg4gInwgCXwiHCAYhUIgiSIYIBcgG3wiF3wiGyAOhUIoiSIOIBx8IAN8IhwgGIVCMIkiGCAbfCIbIA6FQgGJIg4gFSAXIBSFQgGJIhR8IAt8IhUgI4VCIIkiFyAdfCIdIBSFQiiJIhQgFXwgCnwiFXwgBHwiIoVCIIkiI3wiJCAOhUIoiSIOICJ8IAl8IiIgGyAeIBUgF4VCMIkiFSAdfCIXIBSFQgGJIhQgGXwgDHwiGYVCIIkiHXwiGyAUhUIoiSIUIBl8IAp8IhkgHYVCMIkiHSAbfCIbIBSFQgGJIhR8IAN8Ih4gGiAffCIaIBUgICAPhUIBiSIPIBx8IAd8IhyFQiCJIhV8Ih8gD4VCKIkiDyAcfCAQfCIcIBWFQjCJIhWFQiCJIiAgFyAYIBogFoVCAYkiFiAhfCATfCIahUIgiSIYfCIXIBaFQiiJIhYgGnwgDXwiGiAYhUIwiSIYIBd8Ihd8IiEgFIVCKIkiFCAefCAFfCIeICCFQjCJIiAgIXwiISAiICOFQjCJIiIgJHwiIyAOhUIBiSIOIBx8IAt8IhwgGIVCIIkiGCAbfCIbIA6FQiiJIg4gHHwgEnwiHCAYhUIwiSIYIBcgFoVCAYkiFiAZfCABfCIXICKFQiCJIhkgFSAffCIVfCIfIBaFQiiJIhYgF3wgBnwiFyAZhUIwiSIZIB98Ih8gFoVCAYkiFiAVIA+FQgGJIg8gGnwgCHwiFSAdhUIgiSIaICN8Ih0gD4VCKIkiDyAVfCACfCIVfCANfCIihUIgiSIjfCIkIBaFQiiJIhYgInwgCXwiIiAjhUIwiSIjICR8IiQgFoVCAYkiFiAYIBt8IhggFSAahUIwiSIVICEgFIVCAYkiFCAXfCASfCIXhUIgiSIafCIbIBSFQiiJIhQgF3wgCHwiF3wgB3wiISAVIB18IhUgGSAYIA6FQgGJIg4gHnwgBnwiGIVCIIkiGXwiHSAOhUIoiSIOIBh8IAt8IhggGYVCMIkiGYVCIIkiHiAfICAgFSAPhUIBiSIPIBx8IAp8IhWFQiCJIhx8Ih8gD4VCKIkiDyAVfCAEfCIVIByFQjCJIhwgH3wiH3wiICAWhUIoiSIWICF8IAN8IiEgHoVCMIkiHiAgfCIgIBggFyAahUIwiSIXIBt8IhogFIVCAYkiFHwgBXwiGCAchUIgiSIbICR8IhwgFIVCKIkiFCAYfCABfCIYIBuFQjCJIhsgHyAPhUIBiSIPICJ8IAx8Ih8gF4VCIIkiFyAZIB18Ihl8Ih0gD4VCKIkiDyAffCATfCIfIBeFQjCJIhcgHXwiHSAPhUIBiSIPIBkgDoVCAYkiDiAVfCAQfCIVICOFQiCJIhkgGnwiGiAOhUIoiSIOIBV8IAJ8IhV8IBN8IiKFQiCJIiN8IiQgD4VCKIkiDyAifCASfCIiICOFQjCJIiMgJHwiJCAPhUIBiSIPIBsgHHwiGyAVIBmFQjCJIhUgICAWhUIBiSIWIB98IAt8IhmFQiCJIhx8Ih8gFoVCKIkiFiAZfCACfCIZfCAJfCIgIBUgGnwiFSAXIBsgFIVCAYkiFCAhfCAFfCIahUIgiSIXfCIbIBSFQiiJIhQgGnwgA3wiGiAXhUIwiSIXhUIgiSIhIB0gHiAVIA6FQgGJIg4gGHwgEHwiFYVCIIkiGHwiHSAOhUIoiSIOIBV8IAF8IhUgGIVCMIkiGCAdfCIdfCIeIA+FQiiJIg8gIHwgDXwiICAhhUIwiSIhIB58Ih4gGSAchUIwiSIZIB98IhwgFoVCAYkiFiAafCAIfCIaIBiFQiCJIhggJHwiHyAWhUIoiSIWIBp8IAp8IhogGIVCMIkiGCAdIA6FQgGJIg4gInwgBHwiHSAZhUIgiSIZIBcgG3wiF3wiGyAOhUIoiSIOIB18IAd8Ih0gGYVCMIkiGSAbfCIbIA6FQgGJIg4gFSAXIBSFQgGJIhR8IAx8IhUgI4VCIIkiFyAcfCIcIBSFQiiJIhQgFXwgBnwiFXwgEnwiIoVCIIkiI3wiJCAOhUIoiSIOICJ8IBN8IiIgGyAhIBUgF4VCMIkiFSAcfCIXIBSFQgGJIhQgGnwgBnwiGoVCIIkiHHwiGyAUhUIoiSIUIBp8IBB8IhogHIVCMIkiHCAbfCIbIBSFQgGJIhR8IA18IiEgGCAffCIYIBUgHiAPhUIBiSIPIB18IAJ8Ih2FQiCJIhV8Ih4gD4VCKIkiDyAdfCABfCIdIBWFQjCJIhWFQiCJIh8gFyAZIBggFoVCAYkiFiAgfCADfCIYhUIgiSIZfCIXIBaFQiiJIhYgGHwgBHwiGCAZhUIwiSIZIBd8Ihd8IiAgFIVCKIkiFCAhfCAIfCIhIB+FQjCJIh8gIHwiICAiICOFQjCJIiIgJHwiIyAOhUIBiSIOIB18IAd8Ih0gGYVCIIkiGSAbfCIbIA6FQiiJIg4gHXwgDHwiHSAZhUIwiSIZIBcgFoVCAYkiFiAafCALfCIXICKFQiCJIhogFSAefCIVfCIeIBaFQiiJIhYgF3wgCXwiFyAahUIwiSIaIB58Ih4gFoVCAYkiFiAVIA+FQgGJIg8gGHwgBXwiFSAchUIgiSIYICN8IhwgD4VCKIkiDyAVfCAKfCIVfCACfCIChUIgiSIifCIjIBaFQiiJIhYgAnwgC3wiAiAihUIwiSILICN8IiIgFoVCAYkiFiAZIBt8IhkgFSAYhUIwiSIVICAgFIVCAYkiFCAXfCANfCINhUIgiSIXfCIYIBSFQiiJIhQgDXwgBXwiBXwgEHwiECAVIBx8Ig0gGiAZIA6FQgGJIg4gIXwgDHwiDIVCIIkiFXwiGSAOhUIoiSIOIAx8IBJ8IhIgFYVCMIkiDIVCIIkiFSAeIB8gDSAPhUIBiSINIB18IAl8IgmFQiCJIg98IhogDYVCKIkiDSAJfCAIfCIJIA+FQjCJIgggGnwiD3wiGiAWhUIoiSIWIBB8IAd8IhAgEYUgDCAZfCIHIA6FQgGJIgwgCXwgCnwiCiALhUIgiSILIAUgF4VCMIkiBSAYfCIJfCIOIAyFQiiJIgwgCnwgE3wiEyALhUIwiSIKIA58IguFNwOAiQFBACADIAYgDyANhUIBiSINIAJ8fCICIAWFQiCJIgUgB3wiBiANhUIoiSIHIAJ8fCICQQApA4iJAYUgBCABIBIgCSAUhUIBiSIDfHwiASAIhUIgiSISICJ8IgkgA4VCKIkiAyABfHwiASAShUIwiSIEIAl8IhKFNwOIiQFBACATQQApA5CJAYUgECAVhUIwiSIQIBp8IhOFNwOQiQFBACABQQApA5iJAYUgAiAFhUIwiSICIAZ8IgGFNwOYiQFBACASIAOFQgGJQQApA6CJAYUgAoU3A6CJAUEAIBMgFoVCAYlBACkDqIkBhSAKhTcDqIkBQQAgASAHhUIBiUEAKQOwiQGFIASFNwOwiQFBACALIAyFQgGJQQApA7iJAYUgEIU3A7iJAQvdAgUBfwF+AX8BfgJ/IwBBwABrIgAkAAJAQQApA9CJAUIAUg0AQQBBACkDwIkBIgFBACgC4IoBIgKsfCIDNwPAiQFBAEEAKQPIiQEgAyABVK18NwPIiQECQEEALQDoigFFDQBBAEJ/NwPYiQELQQBCfzcD0IkBAkAgAkH/AEoNAEEAIQQDQCACIARqQeCJAWpBADoAACAEQQFqIgRBgAFBACgC4IoBIgJrSA0ACwtB4IkBEAIgAEEAKQOAiQE3AwAgAEEAKQOIiQE3AwggAEEAKQOQiQE3AxAgAEEAKQOYiQE3AxggAEEAKQOgiQE3AyAgAEEAKQOoiQE3AyggAEEAKQOwiQE3AzAgAEEAKQO4iQE3AzhBACgC5IoBIgVBAUgNAEEAIQRBACECA0AgBEGACWogACAEai0AADoAACAEQQFqIQQgBSACQQFqIgJB/wFxSg0ACwsgAEHAAGokAAv9AwMBfwF+AX8jAEGAAWsiAiQAQQBBgQI7AfKKAUEAIAE6APGKAUEAIAA6APCKAUGQfiEAA0AgAEGAiwFqQgA3AAAgAEH4igFqQgA3AAAgAEHwigFqQgA3AAAgAEEYaiIADQALQQAhAEEAQQApA/CKASIDQoiS853/zPmE6gCFNwOAiQFBAEEAKQP4igFCu86qptjQ67O7f4U3A4iJAUEAQQApA4CLAUKr8NP0r+68tzyFNwOQiQFBAEEAKQOIiwFC8e30+KWn/aelf4U3A5iJAUEAQQApA5CLAULRhZrv+s+Uh9EAhTcDoIkBQQBBACkDmIsBQp/Y+dnCkdqCm3+FNwOoiQFBAEEAKQOgiwFC6/qG2r+19sEfhTcDsIkBQQBBACkDqIsBQvnC+JuRo7Pw2wCFNwO4iQFBACADp0H/AXE2AuSKAQJAIAFBAUgNACACQgA3A3ggAkIANwNwIAJCADcDaCACQgA3A2AgAkIANwNYIAJCADcDUCACQgA3A0ggAkIANwNAIAJCADcDOCACQgA3AzAgAkIANwMoIAJCADcDICACQgA3AxggAkIANwMQIAJCADcDCCACQgA3AwBBACEEA0AgAiAAaiAAQYAJai0AADoAACAAQQFqIQAgBEEBaiIEQf8BcSABSA0ACyACQYABEAELIAJBgAFqJAALEgAgAEEDdkH/P3EgAEEQdhAECwkAQYAJIAAQAQsGAEGAiQELGwAgAUEDdkH/P3EgAUEQdhAEQYAJIAAQARADCwsLAQBBgAgLBPAAAAA=";
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
// Snapshot of the entry being edited (password + history + age), captured in
// editEntry() so saveEntry() reads a stable source even if the user decodes a
// different entry (which mutates _decodedFields) before saving. Only consulted
// while _editRecord !== null, which is set only by editEntry().
var _editSnapshot     = null;
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

// Search index for "#tag" / "@note" queries: record key → { tags, notes } with
// both lowercased. Populated when a payload is decrypted (reveal-all / decodeLine /
// saveEntry) and cleared alongside _v5Names on lock. Lets #/@ search match tags or
// notes vault-wide without re-decrypting, since reveal-all already derives every
// record's keys.
var _searchText  = new Map();
var _entryBadges = new Map(); // rowKey → { passkey: bool, note: bool, stale: bool }

// Build the { tags, notes, extra } lowercased search-index entry from a decrypted
// payload. `extra` flattens every custom field's label + value so a "!" search
// matches either.
function _searchIndex(fields) {
    // Custom fields marked "secret" are excluded from the !field index so a
    // masked value can't be surfaced by searching for it.
    var extra = Array.isArray(fields.extra) ? fields.extra : [];
    return {
        tags:  (fields.tags  || '').toLowerCase(),
        notes: (fields.notes || '').toLowerCase(),
        extra: extra.filter(function(f) { return !f.secret; }).map(function(f) {
            return (f.label || '') + ' ' + (f.value || '');
        }).join(' ').toLowerCase()
    };
}

// Normalize a comma-separated tags string: lowercase, trim, drop empties, dedupe.
function _normalizeTags(str) {
    var seen = {};
    var out  = [];
    (str || '').split(',').forEach(function(t) {
        var tag = t.trim().toLowerCase();
        if (tag && !Object.prototype.hasOwnProperty.call(seen, tag)) {
            seen[tag] = true;
            out.push(tag);
        }
    });
    return out.join(', ');
}

// UI preference: group revealed entries under sticky A–Z (+ '#') headers.
// Toggled by the #group-toggle checkbox, persisted per-instance in localStorage.
// Default on. localStorage can throw (private browsing) — degrade to the default.
var _groupEntries = true;
function _groupStoreKey() {
    return 'groupAZ:' + location.pathname.replace(/index\.html$/, '');
}
function _loadGroupPref() {
    try {
        var v = localStorage.getItem(_groupStoreKey());
        if (v !== null) _groupEntries = (v === '1');
    } catch (_) {}
}
function _saveGroupPref() {
    try { localStorage.setItem(_groupStoreKey(), _groupEntries ? '1' : '0'); } catch (_) {}
}

// Light/dark theme. The palette lives entirely in CSS variables (body.theme-light
// in part1), so toggling is just a class flip. Persisted per-instance, like the
// Group A–Z preference. Default: dark.
function _themeStoreKey() {
    return 'theme:' + location.pathname.replace(/index\.html$/, '');
}
function _applyTheme(name) {
    var light = (name === 'light');
    // Class on <html> (not <body>) so the var overrides reach html { background }
    // — the body is centered, so the strips beside it show the html background,
    // which must follow the theme (matters most in a wide PWA window).
    document.documentElement.classList.toggle('theme-light', light);
    // Keep the PWA chrome (status/title bar + overscroll area, painted from the
    // theme-color meta) in sync with the palette — otherwise it stays the fixed
    // dark #111318 after switching to light, which reads as a stuck dark background.
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', light ? '#f4f5f8' : '#111318');
    var btn = document.getElementById('theme-btn');
    if (btn) {
        btn.textContent = light ? '☀︎' : '🌙︎';
        btn.setAttribute('data-tip', light ? 'Switch to dark theme' : 'Switch to light theme');
    }
    try { localStorage.setItem(_themeStoreKey(), light ? 'light' : 'dark'); } catch (_) {}
}
function _loadTheme() {
    var name = 'dark';
    try { if (localStorage.getItem(_themeStoreKey()) === 'light') name = 'light'; } catch (_) {}
    _applyTheme(name);
}
function toggleTheme() {
    _applyTheme(document.documentElement.classList.contains('theme-light') ? 'dark' : 'light');
}

// UI preference: disable the inactivity auto-lock entirely. Toggled by the
// #autolock-disable-toggle checkbox (About > Auto-lock). Persisted per-instance
// in localStorage, like the Group A–Z / theme preferences — fully sticky: it
// survives both page reloads and vault locks (manual lock, double-Escape, and
// auto-lock itself no longer force it back on). Because a stale "disabled"
// choice would otherwise carry forward invisibly, every fresh page load that
// finds it already disabled re-runs the same confirm dialog as a fresh
// toggle-on (see the init code), so the risk is re-acknowledged each session
// rather than just inherited.
var _autolockDisabled = false;
function _updateAutolockStatus() {
    var el = document.getElementById('autolock-status');
    if (el) el.style.display = _autolockDisabled ? '' : 'none';
}
function _autolockStoreKey() {
    return 'autolockDisabled:' + location.pathname.replace(/index\.html$/, '');
}
function _loadAutolockPref() {
    try {
        var v = localStorage.getItem(_autolockStoreKey());
        if (v !== null) _autolockDisabled = (v === '1');
    } catch (_) {}
}
function _saveAutolockPref() {
    try { localStorage.setItem(_autolockStoreKey(), _autolockDisabled ? '1' : '0'); } catch (_) {}
}

// ── Favorites ──────────────────────────────────────────────────────────────
// Favorited entries sort to the top of the grid (under a ★ group header when
// grouping is on). The preference is per-instance in localStorage, keyed by a
// non-reversible hash of the entry name — NOT the plaintext name — so the at-rest
// confidentiality of names (encrypted in `lines`) is not undone by a localStorage
// leak. The hash is a fast FNV-1a (a local UI identifier, not a security control);
// collisions are astronomically unlikely for a personal vault and at worst would
// co-favorite two names. Favorites survive entry edits (which mint a fresh record
// string) because they key on the name, not the ciphertext.
var _favSet = null;   // Set<string> of name-hashes; lazily loaded
function _favStoreKey() {
    return 'fav:' + location.pathname.replace(/index\.html$/, '');
}
function _favHash(name) {
    var h = 0x811c9dc5;
    var s = String(name);
    for (var i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return ('00000000' + h.toString(16)).slice(-8);
}
function _favs() {
    if (_favSet === null) {
        _favSet = new Set();
        try {
            var raw = localStorage.getItem(_favStoreKey());
            if (raw) { var arr = JSON.parse(raw); if (Array.isArray(arr)) _favSet = new Set(arr); }
        } catch (_) {}
    }
    return _favSet;
}
function _saveFavs() {
    try { localStorage.setItem(_favStoreKey(), JSON.stringify(Array.from(_favs()))); } catch (_) {}
}
function _isFav(name) {
    return !!name && _favs().has(_favHash(name));
}
// Toggle the favorite state of the currently-decoded entry.
function toggleFavorite() {
    if (!_decodedFields || !_decodedFields.name) { showToast('Open an entry first'); return; }
    var key = _favHash(_decodedFields.name);
    var set = _favs();
    var nowFav = !set.has(key);
    if (nowFav) set.add(key); else set.delete(key);
    _saveFavs();
    _updateFavBtn();
    _markFavButtons();
    _sortEntryGrid();
    showToast(nowFav ? '★ Added to favorites' : 'Removed from favorites');
}
// Sync the decode-panel star button to the current entry's favorite state.
function _updateFavBtn() {
    var btn = document.getElementById('fav-btn');
    if (!btn) return;
    // Always show the star in the display panel. With no entry open it renders as
    // an inert ☆ (clicking it just prompts to open an entry).
    btn.style.display = '';
    if (!_decodedFields || !_decodedFields.name) {
        btn.classList.remove('is-fav');
        btn.textContent = '☆';
        btn.title = 'Add to favorites (F)';
        return;
    }
    var fav = _isFav(_decodedFields.name);
    btn.classList.toggle('is-fav', fav);
    btn.textContent = fav ? '★' : '☆';   // ★ / ☆
    btn.title = fav ? 'Remove from favorites (F)' : 'Add to favorites (F)';
}
// Tag each revealed entry button with .entry-fav so the sort/grouping can pin
// favorites to the top. Hidden (still-locked) buttons have no plaintext name yet.
function _markFavButtons() {
    document.querySelectorAll('.entry-grid .entry-btn').forEach(function(b) {
        if (b.style.display === 'none') { b.classList.remove('entry-fav'); return; }
        b.classList.toggle('entry-fav', _isFav(_btnName(b)));
    });
}

// Reveal-all coordination. _revealGen is bumped whenever the revealed state is
// invalidated (key edit / lock); an in-flight _revealAllV5Names loop captures the
// current value and aborts as soon as it sees a newer one (#8). _lastRevealPw/2
// record the password pair that produced the current reveal so a repeat blur with
// unchanged passwords can skip the work entirely (#7).
var _revealGen     = 0;
var _lastRevealPw  = null;
var _lastRevealPw2 = null;
// True while a reveal-all (name decryption) pass is running. Used to (a) show the
// live worker count beside the entry/integrity line and (b) let a refocus / input
// edit abort the in-flight decode.
var _revealActive  = false;

// Show / refresh / hide the live Argon2id worker count in the entry-count row.
// Only meaningful while decoding (the element is hidden otherwise). Counts busy
// pool workers; with the main-thread fallback (no pool) it shows "main thread".
function _showWorkerCount() {
    var el = document.getElementById('worker-count');
    if (el) { el.style.display = ''; _updateWorkerCount(); }
}
function _hideWorkerCount() {
    var el = document.getElementById('worker-count');
    if (el) { el.style.display = 'none'; el.textContent = ''; }
}
function _updateWorkerCount() {
    var el = document.getElementById('worker-count');
    if (!el || el.style.display === 'none') return;
    if (!_argonPool) {
        // Pool is created lazily on the first derivation; until then show a
        // neutral label (or note the main-thread fallback if workers are off).
        el.textContent = _argonWorkersOK ? 'decoding…' : 'main thread';
        return;
    }
    var busy = 0;
    for (var i = 0; i < _argonPool.length; i++) if (_argonPool[i].busy) busy++;
    el.textContent = busy + (busy === 1 ? ' worker' : ' workers');
}

// Stop an in-flight reveal-all decode: supersede the running loop (gen bump) and
// tear down its progress UI. Already-revealed buttons stay revealed; remaining
// locked entries stay locked. _lastRevealPw* are left untouched (they are only
// set on a *completed* pass), so a later blur with the same passwords re-runs.
function _abortReveal() {
    if (!_revealActive) return;
    _revealGen++;
    _revealActive = false;
    var bar = document.getElementById('reveal-progress');
    if (bar) bar.style.display = 'none';
    _hideWorkerCount();
}

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

// Reused, stateless encoder/decoder singletons — avoids re-allocating one per
// call across the per-record crypto paths.
var _TE = new TextEncoder();
var _TD = new TextDecoder();

// Precomputed byte→hex-pair table ('00'..'ff') for fast bytesToHex.
var _HEX = [];
for (var _h = 0; _h < 256; _h++) _HEX[_h] = (_h + 256).toString(16).slice(1);

function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += _HEX[bytes[i]];
    return out;
}

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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
// Argon2id parameters (memory `m` and iterations `t`) are vault-wide and
// user-tunable from Vault Tools → Change KDF Parameters. They are NOT stored per
// record; instead the active params are persisted server-side (`kdfparams`) and
// embedded in index.html (`#vault-kdf`), and read at load into `_vaultKdf`. This
// keeps the read-only/offline copy (index.html + javascript.js, no server) able
// to derive keys. Changing them re-encrypts the whole vault (same flow as a
// master-password change). The DEFAULT_* values below are the fallback when no
// params are embedded (a vault that has never set them) and the historical
// hardcoded cost. Parallelism (p) and hash length stay fixed.
// ============================================================

var DEFAULT_ARGON2_TIME    = 3;       // t — iterations
var DEFAULT_ARGON2_MEM_KIB = 131072;  // m — 128 MiB
var ARGON2_PAR             = 1;       // p — lanes (fixed, not user-tunable)
var ARGON2_HASHLEN         = 32;      // 256-bit master key

// KDF cost bounds — mirrored by is_valid_kdf() in post.php. A user (or a forged
// write) cannot drop below the floor or above the ceiling.
var KDF_MEM_MIN_KIB  = 65536;    // 64 MiB
var KDF_MEM_MAX_KIB  = 1048576;  // 1 GiB
var KDF_TIME_MIN     = 2;
var KDF_TIME_MAX     = 10;

// Active vault-wide Argon2id cost. Initialised from the embedded #vault-kdf span
// at load (see _initVaultKdf), defaulting to the historical hardcoded values.
var _vaultKdf = { iterations: DEFAULT_ARGON2_TIME, memorySize: DEFAULT_ARGON2_MEM_KIB,
                  parallelism: ARGON2_PAR, hashLength: ARGON2_HASHLEN };

// Parse an "a2id|m|t|p" params string into a kdf object, or null if malformed /
// out of bounds. Mirrors post.php's is_valid_kdf().
function _parseKdf(s) {
    if (typeof s !== 'string') return null;
    var p = s.split('|');
    if (p.length !== 4 || p[0] !== 'a2id') return null;
    if (!/^\d{1,10}$/.test(p[1]) || !/^\d{1,10}$/.test(p[2]) || !/^\d{1,10}$/.test(p[3])) return null;
    var m = parseInt(p[1], 10), t = parseInt(p[2], 10), pp = parseInt(p[3], 10);
    if (m < KDF_MEM_MIN_KIB || m > KDF_MEM_MAX_KIB) return null;
    if (t < KDF_TIME_MIN || t > KDF_TIME_MAX) return null;
    if (pp !== 1) return null;
    return { iterations: t, memorySize: m, parallelism: pp, hashLength: ARGON2_HASHLEN };
}

// Serialise a kdf object back to the "a2id|m|t|p" wire/storage form.
function _kdfToString(kdf) {
    return 'a2id|' + kdf.memorySize + '|' + kdf.iterations + '|' + kdf.parallelism;
}

// Read the active vault params from the embedded #vault-kdf span. Called once at
// load; the read path never fetches `kdfparams` over HTTP (offline portability).
function _initVaultKdf() {
    var el = document.getElementById('vault-kdf');
    var parsed = el ? _parseKdf(el.getAttribute('data-kdf') || '') : null;
    if (parsed) _vaultKdf = parsed;
}

// Length-hiding padding. The payload plaintext (the JSON of all entry fields) is
// padded up to a multiple of PAYLOAD_PAD_BUCKET bytes before encryption so the
// stored ciphertext length no longer reveals the plaintext length (e.g. how long
// a password or note is) to anyone who obtains `lines`. Padding is ASCII spaces
// (0x20) appended after the JSON value — valid trailing JSON whitespace, so
// JSON.parse on decode ignores it and NO un-pad step is needed. This also makes
// the change backward-compatible: existing unpadded records still decode, and
// re-encrypting them (Vault Tools → Re-encrypt) brings them up to the new scheme.
var PAYLOAD_PAD_BUCKET = 256; // bytes

// Password history: how many previous passwords to retain per entry (stored in
// the encrypted payload JSON, newest first). Old ones beyond this are dropped.
var HISTORY_MAX = 20;
// Password-age audit: flag entries whose password has not changed in this many
// days. Only entries that carry a pwModified timestamp can be aged.
var _PW_AGE_WARN_DAYS = 365;

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
// needs two 128 MiB derivations per entry — each derivation is dispatched to a
// pool of dedicated Web Workers (served as `argon2-worker.js`), each with its
// own WASM instance. The pool is created lazily on first use and torn down on
// lock so its WASM memory (which can only grow, never shrink) is reclaimed.
//
// Peak memory ≈ poolSize × 128 MiB (only while hashing), so the pool is capped.
// If Workers are unavailable (CSP blocks them, ancient browser, or the ctor
// throws) we fall back to the in-process argon2idHash so the app still works —
// inputs are never transferred, so a worker failure can retry on the main
// thread without losing the password/salt buffers.
// ============================================================

var _ARGON_POOL_MAX = 24;         // hard cap on worker count (CPU-bound ceiling)
var _ARGON_POOL_MAX_MOBILE = 2;   // tighter cap on phones/tablets (limited RAM + thermals)
var _argonPool      = null;       // [{ worker, busy }] once initialised
var _argonQueue     = [];         // pending { password, salt, opts, resolve, reject }
var _argonJobSeq    = 0;
var _argonJobs      = new Map();   // job id → { resolve, reject, slot }
var _argonWorkersOK = true;        // flips false permanently if Workers can't be used
var _ARGON_RETRIES  = 2;          // transient-failure retries before giving up
// Watchdog: a worker that is OOM-killed or wedged often dies WITHOUT firing
// worker.onerror, so its job would never settle and Promise.all() in reveal-all
// would hang forever (strength bar never hides, integrity never verifies). If a
// dispatched job gets no reply within this window we treat the worker as dead,
// terminate+replace it, and reject the job so _argonDerive retries (fresh worker
// or main-thread fallback). Generous so a merely-slow heavy derivation (up to
// m=1 GiB / t=10 on a slow device) is never falsely killed.
var _ARGON_JOB_TIMEOUT_MS = 60000;

// Pool size scales with CPU cores (all reported cores, hard max _ARGON_POOL_MAX)
// BUT is also bounded by a memory budget: each busy worker holds its own ~128 MiB
// Argon2id WASM heap, so peak memory ≈ poolSize × 128 MiB. Spinning up too many
// workers on a many-core / low-RAM device exhausts memory, and a failed
// derivation surfaces as a *swallowed* "wrong key" in reveal-all (variable entry
// counts across runs with the same password). All reported cores are used (the
// browser often under-reports on this box); navigator.deviceMemory (GiB, spec-capped at 8) further
// caps workers so the heaps stay within ~half of device memory.
// Mobile detection — phones/tablets have far less RAM and aggressive thermal
// throttling, so they get a tighter worker cap (_ARGON_POOL_MAX_MOBILE). Prefer
// the UA-Client-Hints `mobile` boolean (Chromium); fall back to a UA-string regex
// (Safari/Firefox, which don't expose userAgentData).
function _isMobileDevice() {
    if (typeof navigator === 'undefined') return false;
    if (navigator.userAgentData && typeof navigator.userAgentData.mobile === 'boolean') {
        return navigator.userAgentData.mobile;
    }
    var ua = navigator.userAgent || '';
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet/i.test(ua);
}

function _argonPoolSize() {
    var hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 2;
    var cap = _isMobileDevice() ? _ARGON_POOL_MAX_MOBILE : _ARGON_POOL_MAX;
    var byCores = Math.max(1, Math.min(hc, cap));
    var devGiB  = (typeof navigator !== 'undefined' && navigator.deviceMemory) || 0;
    if (!devGiB) return byCores;                       // unknown → trust the core count
    var budgetMiB = devGiB * 1024 * 0.5;               // use at most ~half of RAM
    // Divide by the actual per-worker heap (the active vault memory cost) so the
    // budget tracks the parameter — never a hardcoded MiB value. A larger `m`
    // (user-raised cost) automatically shrinks the pool to stay within RAM.
    var byMem     = Math.max(1, Math.floor(budgetMiB / (_vaultKdf.memorySize / 1024)));
    return Math.min(byCores, byMem);
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
    // fall back to the main thread (and cancel each job's watchdog first).
    _argonJobs.forEach(function (j) {
        if (j.timer) clearTimeout(j.timer);
        j.reject(new Error('argon2 pool terminated'));
    });
    _argonJobs.clear();
    var q = _argonQueue; _argonQueue = [];
    q.forEach(function (j) { j.reject(new Error('argon2 pool terminated')); });
}

function _onArgonWorkerMessage(e) {
    var d   = e.data;
    var job = _argonJobs.get(d.id);
    if (!job) return;
    if (job.timer) clearTimeout(job.timer);
    _argonJobs.delete(d.id);
    job.slot.busy = false;
    if (d.error) job.reject(new Error(d.error));
    else         job.resolve(d.hash);   // Uint8Array, buffer transferred to us
    _drainArgonQueue();
    _updateWorkerCount();
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
        var timer = setTimeout(_onArgonJobTimeout.bind(null, id), _ARGON_JOB_TIMEOUT_MS);
        _argonJobs.set(id, { resolve: job.resolve, reject: job.reject, slot: slot, timer: timer });
        slot.worker.postMessage({ id: id, password: job.password, salt: job.salt, opts: job.opts });
    }
    _updateWorkerCount();
}

// A dispatched job exceeded _ARGON_JOB_TIMEOUT_MS with no reply — the worker is
// wedged or was silently killed. Replace it (so the slot isn't lost and a late
// reply from the dead worker can't land on a reused id) and reject the job so
// _argonDerive retries on a fresh worker or the main thread.
function _onArgonJobTimeout(id) {
    var job = _argonJobs.get(id);
    if (!job) return;                    // already completed in the meantime
    _argonJobs.delete(id);
    _replaceArgonWorker(job.slot);
    job.reject(new Error('argon2 worker timeout'));
    _drainArgonQueue();
    _updateWorkerCount();
}

// Terminate a wedged worker and spin up a fresh one in the same pool slot. If the
// respawn fails, drop the slot; if that empties the pool, disable workers for the
// session (subsequent derivations fall back to the main thread).
function _replaceArgonWorker(slot) {
    try { slot.worker.terminate(); } catch (_) {}
    slot.busy = false;
    if (!_argonPool) return;
    try {
        var w = new Worker('argon2-worker.js');
        w.onmessage = _onArgonWorkerMessage;
        w.onerror   = _onArgonWorkerError;
        slot.worker = w;
    } catch (_) {
        var idx = _argonPool.indexOf(slot);
        if (idx >= 0) _argonPool.splice(idx, 1);
        if (!_argonPool.length) { _argonWorkersOK = false; _argonPool = null; }
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
//
// Argon2id is deterministic and never throws on a *wrong* password (it just
// produces a different hash — the mismatch surfaces later as an AEAD failure),
// so any throw here is a transient/environment failure (memory pressure, a
// worker crash). We retry up to _ARGON_RETRIES times: each attempt tries the
// worker pool, then the mutex-serialized main-thread path (which only ever holds
// one 128 MiB heap at a time — the safe path under memory pressure), yielding
// with a short backoff between attempts so busy workers can free their heaps.
// This stops a transient failure from being swallowed as "wrong key" in
// reveal-all, which would silently drop entries from the grid.
async function _argonDerive(passwordBytes, saltBytes, opts) {
    var lastErr;
    for (var attempt = 0; attempt <= _ARGON_RETRIES; attempt++) {
        _initArgonPool();
        if (_argonWorkersOK && _argonPool) {
            try {
                return await _argonDispatch(passwordBytes, saltBytes, opts);
            } catch (e) {
                lastErr = e;   // Worker path failed — degrade to the main thread.
            }
        }
        try {
            return await argon2idHash(passwordBytes, saltBytes, opts);
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

// Argon2id master key for (password, salt) at a given cost. Cached so it runs
// only once per (password, salt, cost) tuple. `kdf` defaults to the active
// vault-wide params; the whole-vault re-encode passes the OLD params to decrypt
// and the NEW params to encrypt, so the cost MUST be part of the cache key (else
// an old-cost key would be reused for a new-cost derivation, or vice versa).
async function deriveMasterKey(password, saltBytes, kdf) {
    if (!kdf) kdf = _vaultKdf;
    var cacheKey = password + ':' + bytesToHex(saltBytes)
                 + ':' + kdf.memorySize + ':' + kdf.iterations + ':' + kdf.parallelism;
    if (_mkCache.has(cacheKey)) return _mkCache.get(cacheKey);
    var mk = await _argonDerive(
        _TE.encode(password),
        saltBytes,
        { iterations: kdf.iterations, memorySize: kdf.memorySize, parallelism: kdf.parallelism, hashLength: kdf.hashLength }
    );
    _mkCache.set(cacheKey, mk);
    return mk;
}

// HKDF-SHA-256 expand a master key into 32 raw bytes for the given info label.
// (Empty salt is fine: the master key is already a uniform high-entropy key.)
async function hkdfBytes(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: _TE.encode(infoLabel) },
        base, 256
    );
    return new Uint8Array(bits);
}

// HKDF-SHA-256 expand a master key into an AES-256-GCM CryptoKey.
async function hkdfAesKey(masterKeyBytes, infoLabel) {
    var base = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: _TE.encode(infoLabel) },
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
// Pad the encoded plaintext up to the next PAYLOAD_PAD_BUCKET multiple with
// trailing ASCII spaces (with a one-bucket floor so tiny entries don't reveal
// they're tiny). Spaces are valid trailing JSON whitespace, so the decode path
// (JSON.parse) needs no change. Padding the byte length (not the string length)
// keeps multibyte UTF-8 entries bucketed correctly.
function _padPlaintext(bytes) {
    var target = Math.max(PAYLOAD_PAD_BUCKET,
                          Math.ceil(bytes.length / PAYLOAD_PAD_BUCKET) * PAYLOAD_PAD_BUCKET);
    var out = new Uint8Array(target);
    out.set(bytes);
    out.fill(0x20, bytes.length);
    return out;
}

async function encryptFields(password, password2, recSalt1, recSalt2, fields, kdf) {
    var iv1    = crypto.getRandomValues(new Uint8Array(12));  // AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12));  // ChaCha20
    var nonce3 = crypto.getRandomValues(new Uint8Array(16));  // Twofish-CTR
    var nonce4 = crypto.getRandomValues(new Uint8Array(16));  // Serpent-CTR
    var mks = await Promise.all([ deriveMasterKey(password, recSalt1, kdf), deriveMasterKey(password2, recSalt2, kdf) ]);
    var mk1 = mks[0], mk2 = mks[1];
    var subs = await Promise.all([
        hkdfAesKey(mk1, _HK.payAes),
        hkdfBytes(mk1, _HK.payChacha),
        hkdfBytes(mk2, _HK.payTwofish),
        hkdfBytes(mk2, _HK.paySerpent)
    ]);
    var aesKey = subs[0], chachaKey = subs[1], twofishKey = subs[2], serpentKey = subs[3];
    var plain = _padPlaintext(_TE.encode(JSON.stringify(fields)));
    var mid   = chacha20poly1305(chachaKey, nonce2).encrypt(plain);
    var ct    = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv1 }, aesKey, mid));
    var tf    = twofishCTR(twofishKey, nonce3, ct);
    var outer = serpentCTR(serpentKey, nonce4, tf);
    var out   = {
        iv1Hex:    bytesToHex(iv1),    nonce2Hex: bytesToHex(nonce2),
        nonce3Hex: bytesToHex(nonce3), nonce4Hex: bytesToHex(nonce4),
        encHex:    bytesToHex(outer)
    };
    _wipe(plain, mid, chachaKey, twofishKey, serpentKey);  // aesKey is a non-extractable CryptoKey; mk1/mk2 are cached
    return out;
}

// Throws on wrong key or tampered ciphertext — caller must catch.
async function decryptFields(password, password2, recSalt1Hex, recSalt2Hex, iv1Hex, nonce2Hex, nonce3Hex, nonce4Hex, encHex, kdf) {
    var mks = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex), kdf),
        deriveMasterKey(password2, hexToBytes(recSalt2Hex), kdf)
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
    var out   = JSON.parse(_TD.decode(plain));
    _wipe(plain, mid, ct, tf, serpentKey, twofishKey, chachaKey);  // mk1/mk2 are cached; the JSON string fields can't be wiped
    return out;
}

// v6 name encryption: AES-256-GCM (MK1) then ChaCha20-Poly1305 (MK2).
// Both passwords are required to decrypt. Returns { nameNonce1Hex, nameNonce2Hex, encNameHex }.
async function encryptName(password, password2, recSalt1, recSalt2, name, kdf) {
    var nonce1 = crypto.getRandomValues(new Uint8Array(12));  // name AES-GCM
    var nonce2 = crypto.getRandomValues(new Uint8Array(12));  // name ChaCha20
    var mks = await Promise.all([ deriveMasterKey(password, recSalt1, kdf), deriveMasterKey(password2, recSalt2, kdf) ]);
    var subs = await Promise.all([ hkdfAesKey(mks[0], _HK.nameAes), hkdfBytes(mks[1], _HK.nameChacha) ]);
    var aesKey = subs[0], chachaKey = subs[1];
    var mid = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce1 }, aesKey, _TE.encode(name)
    ));
    var ct = chacha20poly1305(chachaKey, nonce2).encrypt(mid);
    return {
        nameNonce1Hex: bytesToHex(nonce1), nameNonce2Hex: bytesToHex(nonce2),
        encNameHex:    bytesToHex(ct)
    };
}

// Assemble the 11-field v6 record string from the name + payload ciphertext
// objects and the two raw record salts (Uint8Array). The single source of truth
// for field order (mirrors decodeLine / post.php is_valid_record) — used by every
// encrypt path: saveEntry, the whole-vault re-encrypt flows (password / KDF
// change), bulk-tag, and the CSV/KeePass/1Password importers.
function _assembleRecord(nameEnc, result, recSalt1, recSalt2) {
    return [nameEnc.encNameHex, 'v6',
            bytesToHex(recSalt1),   bytesToHex(recSalt2),
            nameEnc.nameNonce1Hex,  nameEnc.nameNonce2Hex,
            result.iv1Hex,          result.nonce2Hex,
            result.nonce3Hex,       result.nonce4Hex,
            result.encHex].join('|');
}

// Best-effort wipe of raw Uint8Array key/plaintext material after use. NOTE: JS
// strings are immutable and cannot be zeroed, so the decrypted field strings in
// `fields` / `_decodedFields` still live until GC — this only covers byte buffers
// (symmetric subkeys + plaintext). It deliberately never touches the Argon2id
// master keys: those are shared `_mkCache` references, wiped wholesale on lock.
function _wipe() {
    for (var i = 0; i < arguments.length; i++) {
        var b = arguments[i];
        if (b && typeof b.fill === 'function') b.fill(0);
    }
}

// v6 name decryption. Throws on wrong key or tampered ciphertext.
async function decryptName(password, password2, recSalt1Hex, recSalt2Hex, nameNonce1Hex, nameNonce2Hex, encNameHex, kdf) {
    var mks = await Promise.all([
        deriveMasterKey(password, hexToBytes(recSalt1Hex), kdf),
        deriveMasterKey(password2, hexToBytes(recSalt2Hex), kdf)
    ]);
    var subs = await Promise.all([ hkdfBytes(mks[1], _HK.nameChacha), hkdfAesKey(mks[0], _HK.nameAes) ]);
    var chachaKey = subs[0], aesKey = subs[1];
    var mid   = chacha20poly1305(chachaKey, hexToBytes(nameNonce2Hex)).decrypt(hexToBytes(encNameHex));
    var plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(nameNonce1Hex) }, aesKey, mid
    ));
    return _TD.decode(plain);
}

// ============================================================
// TOTP — RFC 6238 via WebCrypto HMAC (SHA-1/256/512) + Steam Guard
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

// Normalize an otpauth algorithm token ("SHA1"/"sha256"/…) to a WebCrypto name.
function _normOtpAlg(a) {
    a = (a || '').toUpperCase().replace(/^SHA([0-9])/, 'SHA-$1');
    return (a === 'SHA-256' || a === 'SHA-512') ? a : 'SHA-1';
}

// Steam Guard codes are 5 chars drawn from this 26-symbol alphabet.
var _STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

// Parse a stored TOTP token into a config object. The token is either a bare
// Base32 secret (the legacy/common case, defaults: 6 digits, 30s, SHA-1) or a
// full `otpauth://` URI carrying digits/period/algorithm. Steam Guard is
// detected from the URI host/issuer/label or an `encoder=steam` param and
// switches to the 5-char base-26 alphabet.
function _parseOtp(token) {
    var cfg = { secret: '', digits: 6, period: 30, algorithm: 'SHA-1', steam: false };
    var raw = (token || '').trim();
    if (/^otpauth:\/\//i.test(raw)) {
      try {
        var u = new URL(raw);
        var p = u.searchParams;
        cfg.secret = (p.get('secret') || '').toUpperCase().replace(/\s+/g, '');
        if (p.get('digits')) cfg.digits = parseInt(p.get('digits'), 10) || cfg.digits;
        if (p.get('period')) cfg.period = parseInt(p.get('period'), 10) || cfg.period;
        if (p.get('algorithm')) cfg.algorithm = _normOtpAlg(p.get('algorithm'));
        var label  = decodeURIComponent(u.pathname.slice(1)).toLowerCase();
        var issuer = (p.get('issuer') || '').toLowerCase();
        var host   = (u.host || '').toLowerCase();           // otpauth://steam/…
        if ((p.get('encoder') || '').toLowerCase() === 'steam' ||
            issuer === 'steam' || host === 'steam' || label.indexOf('steam') === 0) {
            cfg.steam = true;
            cfg.digits = 5;
            cfg.algorithm = 'SHA-1';
        }
      } catch (_) { /* malformed otpauth URI — leave secret empty, surfaces as a stopped timer */ }
    } else {
        cfg.secret = raw.toUpperCase().replace(/\s+/g, '');
    }
    return cfg;
}

// computeTotp(tokenOrCfg, timeOffset) — accepts a raw token string or an
// already-parsed _parseOtp() config. timeOffset: 0 = current window, ±1 for
// clock-drift tolerance. Honors digits/period/algorithm and Steam Guard.
async function computeTotp(token, timeOffset) {
    timeOffset = timeOffset || 0;
    var cfg = (token && token.secret !== undefined) ? token : _parseOtp(token);
    var keyBytes = base32ToBytes(cfg.secret);
    var ck = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: cfg.algorithm }, false, ['sign']
    );
    var epoch   = Math.floor(Date.now() / 1000);
    var counter = Math.floor(epoch / cfg.period) + timeOffset;
    var timeBytes = new Uint8Array(8);
    // 64-bit big-endian counter (high word is non-zero only past year 2106).
    var hi = Math.floor(counter / 0x100000000);
    var lo = counter >>> 0;
    timeBytes[0] = (hi >>> 24) & 0xff; timeBytes[1] = (hi >>> 16) & 0xff;
    timeBytes[2] = (hi >>>  8) & 0xff; timeBytes[3] =  hi         & 0xff;
    timeBytes[4] = (lo >>> 24) & 0xff; timeBytes[5] = (lo >>> 16) & 0xff;
    timeBytes[6] = (lo >>>  8) & 0xff; timeBytes[7] =  lo         & 0xff;
    var hmac   = new Uint8Array(await crypto.subtle.sign('HMAC', ck, timeBytes));
    var offset = hmac[hmac.length - 1] & 0x0f;   // RFC 4226 dynamic truncation
    var bin    = ((hmac[offset]     & 0x7f) << 24 |
                   hmac[offset + 1]         << 16 |
                   hmac[offset + 2]         <<  8 |
                   hmac[offset + 3]) >>> 0;
    if (cfg.steam) {
        var out = '';
        for (var i = 0; i < 5; i++) { out += _STEAM_ALPHABET[bin % 26]; bin = Math.floor(bin / 26); }
        return out;
    }
    var code = bin % Math.pow(10, cfg.digits);
    return code.toString().padStart(cfg.digits, '0');
}

async function updateOtp() {
    if (!_otpCfg) return;
    try {
        var code = await computeTotp(_otpCfg, 0);
        document.getElementById('otp').textContent = code;
    } catch (e) {
        stopOtpTimer();
    }
}

function _setOtpArc(countdown, period) {
    period = period || 30;
    var warn = Math.min(10, period);   // last-N-seconds color ramp
    var arc = document.getElementById('otp-arc');
    if (!arc) return;
    arc.style.strokeDashoffset = (50.27 * (1 - countdown / period)).toFixed(2);
    // Green above the warn window; green → yellow-orange → red over the last N s
    if (countdown > warn) {
        arc.style.stroke = '';   // fall back to SVG attribute (var(--green))
    } else {
        var t   = 1 - countdown / warn;            // 0 at warn s, 1 at 0 s
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
var _otpCfg    = null;   // parsed _parseOtp() config for the active entry

function tick() {
    var period    = (_otpCfg && _otpCfg.period) || 30;
    var epoch     = Math.floor(Date.now() / 1000);
    var countdown = period - (epoch % period);
    document.getElementById('updatingIn').textContent = countdown;
    _setOtpArc(countdown, period);
    var win = Math.floor(epoch / period);
    if (win !== _otpWindow) { _otpWindow = win; updateOtp(); }
}

function startOtpTimer() {
    _otpCfg = _parseOtp(otpKey);
    var period = _otpCfg.period || 30;
    var epoch = Math.floor(Date.now() / 1000);
    _otpWindow = Math.floor(epoch / period);
    updateOtp();
    var countdown = period - (epoch % period);
    document.getElementById('updatingIn').textContent = countdown;
    _setOtpArc(countdown, period);
    var ring = document.getElementById('otp-ring');
    if (ring) ring.style.display = 'block';
    timerVar = setInterval(tick, 1000);
}

function stopOtpTimer() {
    clearInterval(timerVar);
    timerVar = null;
    _otpCfg  = null;
    document.getElementById('otp').textContent        = '------';
    document.getElementById('updatingIn').textContent = '--';
    var ring = document.getElementById('otp-ring');
    if (ring) ring.style.display = 'none';
}

// ============================================================
// Clipboard
// ============================================================

// showToast(msg) — plain transient toast.
// showToast(msg, { actionLabel, onAction, duration }) — adds a clickable action
// button (e.g. "Undo") and keeps the toast up for `duration` ms (default 1800).
function showToast(msg, opts) {
    opts = opts || {};
    var el = document.getElementById('toast');
    el.textContent = msg;            // also clears any button from a prior toast
    el.classList.remove('actionable');
    if (opts.actionLabel) {
        var btn = document.createElement('button');
        btn.className   = 'toast-action';
        btn.textContent = opts.actionLabel;
        btn.onclick = function() {
            el.classList.remove('show', 'actionable');
            clearTimeout(_toastTimer);
            if (typeof opts.onAction === 'function') opts.onAction();
        };
        el.appendChild(btn);
        el.classList.add('actionable');
    }
    el.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(function() {
        el.classList.remove('show', 'actionable');
    }, opts.duration || 1800);
}

// Tracks whether the clipboard currently holds a secret we copied, so that
// lock operations only wipe the clipboard when there is something to wipe.
// Copied secrets are also auto-wiped after _CLIP_CLEAR_MS so a password does
// not sit on the clipboard indefinitely while the vault stays unlocked.
var _clipboardDirty = false;
var _clipClearTimer = null;
var _CLIP_CLEAR_MS  = 45000;

// Write a secret to the clipboard, mark it dirty (so lock/auto-clear know to wipe
// it), and (re)arm the _CLIP_CLEAR_MS auto-clear timer. Shared by every copy path
// so the dirty-flag + auto-clear contract can never drift between them.
function _armClipboard(text) {
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
}

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
    if (!text.trim() || text.trim() === '------') {
        if (label) showToast('Nothing to copy');
        return;
    }
    if (flashEl) {
        flashEl.classList.remove('copy-flash');
        void flashEl.offsetWidth;
        flashEl.classList.add('copy-flash');
    }
    _armClipboard(text);
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
        // Keep just the Base32 secret for plain TOTP; preserve the full
        // otpauth:// URI when it carries non-default params or is Steam Guard,
        // so digits/period/algorithm survive the round-trip.
        var cfg = _parseOtp(raw);
        var isDefault = !cfg.steam && cfg.digits === 6 && cfg.period === 30 &&
                        cfg.algorithm === 'SHA-1';
        tokenEl.value = isDefault ? cfg.secret : raw;
        showToast(cfg.steam ? 'Steam Guard secret scanned ✓' : 'TOTP secret scanned ✓');

    } catch (e) {
        showToast('QR scan failed — ' + e.message);
    }
}

// ============================================================
// UI helpers
// ============================================================

var _rfpRAF = 0;   // pending requestAnimationFrame id for debounced resize
function resizeFreezePane() {
    var fixedDiv = document.getElementById('fixedDiv');
    var content  = document.getElementById('content');
    // Wide-controls mode: above 1000px float the control bar into the empty
    // space to the right of the capped fixed panel (max-width:680px in part1)
    // (see body.wide-controls .ctrl-form in part1).
    var WIDE_BREAKPOINT = 1000;
    var panelW = fixedDiv.offsetWidth;
    var wide = window.innerWidth > WIDE_BREAKPOINT;
    document.body.classList.toggle('wide-controls', wide);
    document.body.style.setProperty('--panel-w', panelW + 'px');
    var h = fixedDiv.offsetHeight;          // read AFTER class toggle (reflow)
    var form = document.querySelector('.ctrl-form');
    if (form) form.style.height = wide ? h + 'px' : '';  // match the display panel
    // Integrity badge + entry count: pinned to the bottom of the control panel
    // in wide mode, restored to its in-flow spot above the grid when narrow.
    var ecRow = document.getElementById('entry-count-row');
    if (form && ecRow) {
        if (wide) {
            if (ecRow.parentNode !== form) form.appendChild(ecRow);
        } else if (ecRow.parentNode !== content) {
            content.insertBefore(ecRow, document.getElementById('reveal-progress'));
        }
    }
    content.style.marginTop = h + 'px';
    // Sticky letter-group headers sit just below the fixed decode panel. In
    // wide-controls mode the panel floats left and the list scrolls under the
    // top edge (offset 0); narrow mode has the full-width panel on top (offset h).
    document.body.style.setProperty('--sticky-top', (wide ? 0 : h) + 'px');
}

var _selectedBtn = null;

function _selectBtn(btn) {
    if (_selectedBtn && _selectedBtn !== btn) _selectedBtn.classList.remove('selected');
    _selectedBtn = btn || null;
    if (_selectedBtn) _selectedBtn.classList.add('selected');
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

    // Force the field back to masked display (cancels "show" mode). Used when the
    // fields are locked after a successful verify so a revealed password can't
    // stay on screen behind the disabled field.
    el._hide = function() {
        _show = false;
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
            _updateVaultKeyBar();
        } else if (e.key === 'Delete') {
            e.preventDefault();
            if (s !== en) { _real = _real.slice(0, s) + _real.slice(en); _setDom(_real); el.setSelectionRange(s, s); }
            else if (s < _real.length) { _real = _real.slice(0, s) + _real.slice(s + 1); _setDom(_real); el.setSelectionRange(s, s); }
            _updateVaultKeyBar();
        } else if (e.key.length === 1) {
            e.preventDefault();
            _real = _real.slice(0, s) + e.key + _real.slice(en);
            _setDom(_real);
            el.setSelectionRange(s + 1, s + 1);
            _updateVaultKeyBar();
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
        _updateVaultKeyBar();
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
            _updateVaultKeyBar();
        }
    });

    // Mobile keyboards write directly into the DOM via input events.
    // Only sync when the DOM holds real content: focused (type=password, browser
    // masks but stores real text) or show mode. When unfocused the DOM holds
    // circles which must not overwrite _real.
    el.addEventListener('input', function() {
        if (_show || _focused) _real = _proto.get.call(el);
        _updateVaultKeyBar();
    });
}

function _initMaskedInputs() {
    _setupMaskedInput(document.getElementById('aeskey'));
    _setupMaskedInput(document.getElementById('aeskey2'));
}

function toggleKey()  { document.getElementById('aeskey') ._toggleShow(); }
function toggleKey2() { document.getElementById('aeskey2')._toggleShow(); }

// Force both key fields back to masked (circles / browser dots), cancelling any
// "show" mode. Called when decoding starts so a password left visible via the eye
// toggle can't stay on screen while entries are being decrypted.
function _maskKeyFields() {
    var k1 = document.getElementById('aeskey');
    var k2 = document.getElementById('aeskey2');
    if (k1 && k1._hide) k1._hide();
    if (k2 && k2._hide) k2._hide();
}

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
    if (delta) window.scrollBy({ top: delta, behavior: 'instant' });
}

// Show/hide the decode-panel Tags row. Like setNotes, toggling it changes the
// fixed panel height, so compensate the scroll position to keep the entry list
// visually stationary.
function _setDecTags(text) {
    var row = document.getElementById('dectags-row');
    var el  = document.getElementById('dectags');
    if (!row || !el) return;
    // Render each tag as its own clickable chip — clicking opens the search
    // popup scoped to that tag (#tag). Tags are stored comma-separated.
    el.textContent = '';
    var tags = (text || '').split(',').map(function(t) { return t.trim(); })
                           .filter(function(t) { return t; });
    if (tags.length) {
        tags.forEach(function(tag, i) {
            var chip = document.createElement('span');
            chip.className   = 'dec-tag';
            chip.textContent = tag;
            chip.title       = 'Search tag \u201c' + tag + '\u201d';
            chip.onclick     = function() { _searchTag(tag); };
            el.appendChild(chip);
            if (i < tags.length - 1) el.appendChild(document.createTextNode(', '));
        });
    } else {
        el.textContent = ' ';
    }
    var content = document.getElementById('content');
    var oldTop  = content.getBoundingClientRect().top;
    row.style.display = tags.length ? '' : 'none';
    resizeFreezePane();
    var delta = content.getBoundingClientRect().top - oldTop;
    if (delta) window.scrollBy({ top: delta, behavior: 'instant' });
}

// Open the search popup pre-filled with a tag-scoped query (#tag) and run it.
function _searchTag(tag) {
    showSearch();   // resets #search-input to '' and focuses it
    var inp = document.getElementById('search-input');
    if (!inp) return;
    inp.value = '#' + tag;
    filterSearch(inp.value);
}

// ── Custom fields (entry form) ──────────────────────────────────────────────
// Arbitrary extra label/value pairs stored inside the encrypted payload JSON as
// fields.extra = [{label, value, secret}] — NOT a new record field, so the v6
// format is unchanged and custom fields are as protected as any other secret.
// `secret:true` masks the value in the decode panel (click to copy).
function _addExtraFieldRow(label, value, secret) {
    var wrap = document.getElementById('extra-fields');
    if (!wrap) return;
    var row = document.createElement('div');
    row.className = 'xf-row';
    var lab = document.createElement('input');
    lab.className = 'finput xf-label';
    lab.type = 'text';
    lab.placeholder = 'Label';
    lab.setAttribute('aria-label', 'Custom field label');
    lab.value = label || '';
    var val = document.createElement('input');
    val.className = 'finput xf-value';
    val.type = 'text';
    val.placeholder = 'Value';
    val.setAttribute('aria-label', 'Custom field value');
    val.value = value || '';
    var sec = document.createElement('label');
    sec.className = 'xf-secret';
    sec.title = 'Hide this value in the panel (click to reveal/copy)';
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!secret;
    sec.appendChild(cb);
    sec.appendChild(document.createTextNode(' secret'));
    var del = document.createElement('button');
    del.className = 'btn-sm xf-del';
    del.type = 'button';
    del.textContent = '✕';   // ✕
    del.title = 'Remove field';
    del.onclick = function() { row.remove(); };
    row.appendChild(lab);
    row.appendChild(val);
    row.appendChild(sec);
    row.appendChild(del);
    wrap.appendChild(row);
    return lab;
}
// Read the custom-field rows back into an array, dropping fully-empty rows.
function _collectExtraFields() {
    var out = [];
    document.querySelectorAll('#extra-fields .xf-row').forEach(function(row) {
        var label = row.querySelector('.xf-label').value.trim();
        var value = row.querySelector('.xf-value').value;
        var secret = row.querySelector('.xf-secret input').checked;
        if (label === '' && value === '') return;
        out.push({ label: label, value: value, secret: secret });
    });
    return out;
}
// Replace the form's custom-field rows with the given array (used by edit/cancel).
function _populateExtraFields(arr) {
    var wrap = document.getElementById('extra-fields');
    if (!wrap) return;
    wrap.innerHTML = '';
    (Array.isArray(arr) ? arr : []).forEach(function(f) {
        _addExtraFieldRow(f.label, f.value, f.secret);
    });
}

// ── Copy arbitrary text (custom field / password-history value) ─────────────
// Uses the shared _armClipboard so the dirty-flag + auto-clear contract matches
// doCBCopy exactly.
function _copyValue(text, label) {
    if (!text) { showToast('Nothing to copy'); return; }
    _armClipboard(text);
    showToast(label || 'Copied');
}

// Short local date for history / trash timestamps (accepts unix seconds).
function _fmtDate(sec) {
    try {
        var d = new Date(sec * 1000);
        var pad = function(n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    } catch (_) { return ''; }
}

// Verbose calendar age from a unix-seconds timestamp to now, e.g.
// "1 year, 2 months and 5 days", "3 months and 12 days", "4 days". Uses
// calendar arithmetic (not fixed 30-day months) so it lines up with the dates.
function _ageBreakdown(sec) {
    var now  = new Date();
    var then = new Date(sec * 1000);
    if (then > now) return 'today';
    var years  = now.getFullYear() - then.getFullYear();
    var months = now.getMonth() - then.getMonth();
    var days   = now.getDate() - then.getDate();
    if (days < 0) {
        // borrow days from the previous (now-relative) month
        days += new Date(now.getFullYear(), now.getMonth(), 0).getDate();
        months--;
    }
    if (months < 0) { months += 12; years--; }
    var parts = [];
    if (years)  parts.push(years  + (years  === 1 ? ' year'  : ' years'));
    if (months) parts.push(months + (months === 1 ? ' month' : ' months'));
    if (days)   parts.push(days   + (days   === 1 ? ' day'   : ' days'));
    if (!parts.length) return 'today';
    if (parts.length === 1) return parts[0];
    return parts.slice(0, -1).join(', ') + ' and ' + parts[parts.length - 1];
}

// Resolve the currently decoded entry's last-modification date into the compact
// "YYYY-MM-DD" shown in the Modified column, plus a "Created: … / Age: …"
// tooltip. The modified date is `pwModified` (stamped on create and on every
// password change), falling back to the creation date when absent. The creation
// date itself uses the `created` stamp when present; for legacy entries that
// predate it, it falls back (best-effort) to the oldest password-history
// timestamp, then to pwModified — both upper bounds on the true creation time,
// so the tooltip prefixes "≤ " and phrases the age "at least …". Returns "—" /
// no tooltip when no timestamp exists at all.
function _decModified() {
    var f = _decodedFields;
    if (!f) return { text: '—', tip: '' };
    var created = (typeof f.created === 'number') ? f.created : null;
    var approx  = false;
    if (created === null && Array.isArray(f.history) && f.history.length) {
        var oldest = f.history[f.history.length - 1];
        if (oldest && typeof oldest.t === 'number') { created = oldest.t; approx = true; }
    }
    if (created === null && typeof f.pwModified === 'number') {
        created = f.pwModified; approx = true;
    }
    var modified = (typeof f.pwModified === 'number') ? f.pwModified : created;
    if (modified === null) return { text: '—', tip: '' };
    var tip = '';
    if (created !== null) {
        tip = 'Created: ' + (approx ? '≤ ' : '') + _fmtDate(created) +
              ' / Age: '  + (approx ? 'at least ' : '') + _ageBreakdown(created);
    }
    return { text: _fmtDate(modified), tip: tip };
}

// Populate the Modified column on the Password line from the decoded entry,
// including its hover tooltip showing the creation date and the entry's age.
function _setDecModified() {
    var el = document.getElementById('decmodified');
    if (!el) return;
    var info = _decModified();
    el.textContent = info.text;
    // The tooltip lives on the column container, not the value span — the span
    // has overflow:hidden (for the ellipsis), which would clip the ::after.
    var col = document.getElementById('decmodified-col');
    if (col) {
        if (info.tip) col.setAttribute('data-tip', info.tip);
        else          col.removeAttribute('data-tip');
    }
}

// ── Decode-panel render of custom fields + password history ─────────────────
// Both rows live in the fixed panel, so their height changes the layout —
// resizeFreezePane() is called after (re)building them.
function _renderDecExtras() {
    var exRow = document.getElementById('decextra-row');
    var exBox = document.getElementById('decextra');
    var hiRow = document.getElementById('dechistory-row');
    var hiBox = document.getElementById('dechistory');
    var hiToggle = document.getElementById('dechistory-toggle');
    if (exBox) exBox.innerHTML = '';
    if (hiBox) hiBox.innerHTML = '';

    var f = _decodedFields;
    var extra   = f && Array.isArray(f.extra)   ? f.extra   : [];
    var history = f && Array.isArray(f.history) ? f.history : [];

    function copyRow(label, valueProvider, masked, copyMsg) {
        var row = document.createElement('div');
        row.className = 'field xf-dec';
        row.setAttribute('data-tip', 'Click to copy');
        var txt = document.createElement('div');
        txt.className = 'field-text';
        var lbl = document.createElement('span');
        lbl.className = 'flbl';
        lbl.textContent = label;
        var vEl = document.createElement('span');
        vEl.className = 'fval';
        vEl.textContent = masked ? '••••••••'
                                 : (valueProvider() || ' ');
        txt.appendChild(lbl);
        txt.appendChild(vEl);
        var glyph = document.createElement('span');
        glyph.className = 'copy-glyph';
        glyph.setAttribute('aria-hidden', 'true');
        glyph.textContent = '⧉︎';
        row.appendChild(txt);
        row.appendChild(glyph);
        row.onclick = function() {
            row.classList.remove('copy-flash'); void row.offsetWidth; row.classList.add('copy-flash');
            _copyValue(valueProvider(), copyMsg);
        };
        return row;
    }

    // Custom fields.
    if (exRow && exBox) {
        if (extra.length) {
            extra.forEach(function(fld) {
                exBox.appendChild(copyRow(
                    fld.label || '(field)',
                    function() { return fld.value || ''; },
                    !!fld.secret,
                    (fld.label || 'Field') + ' copied'));
            });
            exRow.style.display = '';
        } else {
            exRow.style.display = 'none';
        }
    }

    // Password history (collapsed by default).
    if (hiRow && hiBox) {
        if (history.length) {
            history.forEach(function(h) {
                hiBox.appendChild(copyRow(
                    h.t ? _fmtDate(h.t) : 'previous',
                    function() { return h.p || ''; },
                    true,
                    'Old password copied'));
            });
            if (hiToggle) hiToggle.textContent = '⏱︎ Password history (' + history.length + ')';
            hiRow.style.display = '';
            hiBox.style.display = 'none';   // start collapsed
        } else {
            hiRow.style.display = 'none';
        }
    }
    var _content = document.getElementById('content');
    var _oldTop  = _content ? _content.getBoundingClientRect().top : 0;
    resizeFreezePane();
    if (_content) { var _d = _content.getBoundingClientRect().top - _oldTop; if (_d) window.scrollBy({ top: _d, behavior: 'instant' }); }
}
function _toggleHistory() {
    var box = document.getElementById('dechistory');
    if (!box) return;
    box.style.display = (box.style.display === 'none') ? '' : 'none';
    resizeFreezePane();
}

// ── Decode-panel render of a stored passkey (WebAuthn credential) ───────────
// The PWA only *displays* that a passkey is stored and offers to delete it —
// passkeys are created and used (signed) exclusively by the browser extensions
// (the PWA cannot intercept navigator.credentials on relying-party sites). The
// passkey object lives inside the encrypted payload JSON as fields.passkey.
function _renderDecPasskey() {
    var row = document.getElementById('decpasskey-row');
    var val = document.getElementById('decpasskey');
    if (!row || !val) return;
    var pk = _decodedFields && _decodedFields.passkey;
    if (pk && pk.rpId) {
        var bits = [pk.rpId];
        var when = pk.createdAt
            ? new Date(pk.createdAt)
            : (typeof pk.created === 'number' ? new Date(pk.created * 1000) : null);
        if (when && !isNaN(when.getTime())) bits.push('created ' + when.toLocaleDateString());
        val.textContent = bits.join(' · ');
        row.style.display = '';
    } else {
        val.textContent = '';
        row.style.display = 'none';
    }
    var _content = document.getElementById('content');
    var _oldTop  = _content ? _content.getBoundingClientRect().top : 0;
    resizeFreezePane();
    if (_content) { var _d = _content.getBoundingClientRect().top - _oldTop; if (_d) window.scrollBy({ top: _d, behavior: 'instant' }); }
}

// Delete a stored passkey: strip the passkey sub-object and re-save the entry so
// any username/password on it survives. If the entry holds nothing else, offer
// to delete the whole record instead.
function deletePasskey() {
    var f = _decodedFields;
    if (!f || !f.passkey) { return; }
    var rpId = f.passkey.rpId || 'this site';

    // Does the entry carry anything besides the passkey itself?
    var hasOther = !!(
        (f.username && f.username.trim()) ||
        (f.password && f.password.trim()) ||
        (f.token && f.token.trim()) ||
        (f.notes && f.notes.trim()) ||
        (f.tags && f.tags.trim()) ||
        (Array.isArray(f.extra) && f.extra.length)
    );

    if (!hasOther) {
        if (!confirm('This entry only holds a passkey for ' + rpId + '. Delete the whole entry?')) return;
        deleteEntry();
        return;
    }

    if (!confirm('Remove the passkey for ' + rpId + ' from "' + (deleteEntryName || f.name) + '"?\n\nThe username and password on this entry are kept.')) return;

    // Re-save through the normal edit path (atomic delete_rec + data replace),
    // carrying every other field forward but dropping the passkey.
    f.passkey = null;
    editEntry();          // loads the form from _decodedFields (passkey now null)
    saveEntry();          // commits the edit; saveEntry preserves the (now absent) passkey
}

function clearDisplay() {
    stopOtpTimer();
    otpKey          = null;
    deleteEntryName   = null;
    deleteEntryRecord = null;
    _decodedFields    = null;
    _selectBtn(null);
    document.getElementById('decname').textContent     = ' ';
    document.getElementById('decusername').textContent = ' ';
    document.getElementById('decpassword').textContent = ' ';
    document.getElementById('decmodified').textContent  = ' ';
    _setDecTags('');
    setNotes('');
    _applyDecType('login');
    _renderDecExtras();
    _renderDecPasskey();
    _updateFavBtn();
}

function _resetKeyFields() {
    document.getElementById('aeskey').value  = '';
    document.getElementById('aeskey2').value = '';
    _updateVaultKeyBar();
}

// Shared teardown for every lock path (manual clear, double-Esc, idle auto-lock).
// Wipes the derived master keys and decrypted state, tears down the Argon2id
// worker pool, clears the clipboard, and re-locks the entry grid. Callers add
// their own UI chrome (toasts, overlay closing, scroll). Keeping the security-
// sensitive teardown in one place stops the three lock paths from drifting.
function _lockCore() {
    _resetKeyFields();
    _mkCache.clear();
    _terminateArgonPool();
    resetInactivityTimer();
    clearDisplay();
    _editRecord = null; _editSnapshot = null;
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
    document.getElementById('newentry-title').textContent     = 'New Entry';
    _clearClipboardIfDirty();
    _relockV5Entries();
}

function clearLines(td) {
    blinkTD(td);
    _lockCore();
}

function renderDecodedFields() {
    if (!_decodedFields) return;
    var f      = _decodedFields;
    var nameEl = document.getElementById('decname');
    if (/^https?:\/\//i.test(f.url)) {
        var a = document.createElement('a');
        a.href = f.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.title = f.url;
        a.textContent = f.name;
        nameEl.textContent = '';
        nameEl.appendChild(a);
    } else {
        nameEl.textContent = f.name;
    }
    _setDecModified();
    _applyDecType(f.type === 'note' ? 'note' : 'login');
    document.getElementById('decusername').textContent = f.username;
    document.getElementById('decpassword').textContent = f.password;
    _setDecTags(f.tags);
    setNotes(f.notes);
    _renderDecExtras();
    _renderDecPasskey();
    _updateFavBtn();
    if (f.token && !timerVar) { otpKey = f.token; startOtpTimer(); }
}

// ── Entry type: login vs secure note ───────────────────────────────────────
// 'login' (default) carries URL / username / password / 2FA; 'note' is a secure
// note — just a title plus an encrypted body (Notes), tags, and custom fields.
// The type lives inside the encrypted payload JSON as fields.type, so the v6
// record format is unchanged and 'login' is the absent-key default (legacy
// entries need no migration). _applyEntryType() reshapes the entry FORM; the
// decode panel is reshaped by _applyDecType().
var _entryType = 'login';
function _applyEntryType(type) {
    _entryType = (type === 'note') ? 'note' : 'login';
    var note = _entryType === 'note';
    var lo = document.getElementById('type-opt-login');
    var no = document.getElementById('type-opt-note');
    if (lo) lo.classList.toggle('is-on', !note);
    if (no) no.classList.toggle('is-on', note);
    // Hide the credential-only rows (and the generator) for a secure note.
    ['frow-url', 'frow-username', 'frow-password', 'frow-token'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = note ? 'none' : '';
    });
    var gen = document.getElementById('btn-gen-settings');
    if (gen) gen.style.display = note ? 'none' : '';
    if (note) {
        var ps = document.getElementById('passwordSettings');
        if (ps) ps.style.display = 'none';
    }
}

function cancelEntry() {
    var wasEditing = _editRecord !== null;
    document.getElementById('name').value     = '';
    document.getElementById('url').value      = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('token').value    = '';
    document.getElementById('tags').value     = '';
    _populateExtraFields([]);
    updatePWStrength();
    var notesEl = document.getElementById('notes');
    notesEl.value = '';
    notesEl.style.height = '';
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
    document.getElementById('newentry-title').textContent     = 'New Entry';
    _editRecord = null; _editSnapshot = null;
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
    _editRecord = null; _editSnapshot = null;
    _applyEntryType('login');
    _populateExtraFields([]);
    document.getElementById('newentry-title').textContent = 'New Entry';
    const el = document.getElementById('newentry');
    el.style.display = 'block';
    updatePWStrength();
    _syncScanBtnWidth();
    const fixedH = document.getElementById('fixedDiv').offsetHeight;
    const y = el.getBoundingClientRect().top + window.scrollY - fixedH - 8;
    window.scrollTo({ top: y, behavior: 'smooth' });
    document.getElementById('name').focus();
}

function editEntry() {
    if (!_decodedFields) { alert('Decrypt an entry first'); return; }
    _editRecord = deleteEntryRecord;
    _applyEntryType(_decodedFields.type === 'note' ? 'note' : 'login');
    _editSnapshot = {
        password:   _decodedFields.password || '',
        history:    Array.isArray(_decodedFields.history) ? _decodedFields.history : [],
        pwModified: typeof _decodedFields.pwModified === 'number' ? _decodedFields.pwModified : null,
        created:    typeof _decodedFields.created === 'number' ? _decodedFields.created : null,
        // Carry a stored passkey through PWA edits — the PWA never creates or signs
        // passkeys, but it must not silently drop one when the user edits the entry.
        passkey:    (_decodedFields.passkey && typeof _decodedFields.passkey === 'object')
                        ? _decodedFields.passkey : null
    };

    document.getElementById('name').value     = _decodedFields.name;
    document.getElementById('url').value      = _decodedFields.url;
    document.getElementById('username').value = _decodedFields.username;
    document.getElementById('password').value = _decodedFields.password;
    updatePWStrength();
    document.getElementById('token').value    = _decodedFields.token;
    document.getElementById('tags').value     = _decodedFields.tags;
    _populateExtraFields(_decodedFields.extra);
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
        btn.onclick = function() { _onEntryClick(btn, row); };
        if (parts[1] === 'v6') {
            var rowKey = parts.slice(0, -1).join('|');
            var cached = _v5Names.get(rowKey);
            if (cached !== undefined) {
                _setEntryName(btn, cached);
                var _b = _entryBadges.get(rowKey);
                if (_b) { _markPasskeyButton(btn, _b.passkey); _markNoteButton(btn, _b.note); _markStaleButton(btn, _b.stale); }
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
    // The Group A–Z toggle and the multi-select control are only meaningful once
    // entries are unlocked/revealed; keep them hidden while everything is a 🔒.
    var gt = document.getElementById('group-toggle-lbl');
    if (gt) gt.style.display = visible > 0 ? '' : 'none';
    var st = document.getElementById('select-toggle');
    if (st) st.style.display = visible > 0 ? '' : 'none';
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
            btn.onclick = function() { _onEntryClick(btn, row); };
        }
    });
    updateEntryCount();
}

function _applyServerResponse(text) {
    var resp = JSON.parse(text);
    if (resp.ok && Array.isArray(resp.entries)) {
        // Track the server's current integrity manifest (may be null on an
        // unsigned vault); the post-write sign builds its revision from this.
        if ('manifest' in resp) _manifest = resp.manifest;
        _rebuildEntryGrid(resp.entries);
        return true;
    }
    return false;
}

// ============================================================
// Decode (decrypt) an entry on click
// ============================================================

// v6: encNameHEX|v6|recSalt1HEX|recSalt2HEX|nameNonce1HEX|nameNonce2HEX|iv1HEX|nonce2HEX|nonce3HEX|nonce4HEX|encHEX|lineIndex
async function decodeLine(passedTD, encryptedData) {
    blinkTD(passedTD);
    var _dc = document.getElementById('content');
    var _dt = _dc ? _dc.getBoundingClientRect().top : null;
    clearDisplay();

    _selectBtn(passedTD);
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
        // Decoding is starting — mask both key fields so a shown password isn't
        // left on screen during decryption.
        _maskKeyFields();
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
            _setEntryName(passedTD, name);
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
                a.title = url;
                a.textContent = name;
                nameEl.textContent = '';
                nameEl.appendChild(a);
            } else {
                nameEl.textContent = name;
            }

            document.getElementById('decusername').textContent = (fields.username || '').trim();
            document.getElementById('decpassword').textContent = (fields.password || '').trim();
            var tags = (fields.tags || '').trim();
            _setDecTags(tags);
            setNotes((fields.notes || '').trim());

            var token = (fields.token || '').trim();
            if (token) { otpKey = token; startOtpTimer(); }

            // Seed the @-search index now that this record's payload is decrypted.
            _searchText.set(rowKey, _searchIndex(fields));

            var entryType = (fields.type === 'note') ? 'note' : 'login';
            var _hasPk = !!(fields.passkey && fields.passkey.rpId);
            var _stale = _isStaleFields(fields);
            _entryBadges.set(rowKey, { passkey: _hasPk, note: entryType === 'note', stale: _stale });
            _decodedFields = {
                name:       name,
                type:       entryType,
                url:        url,
                username:   (fields.username || '').trim(),
                password:   (fields.password || '').trim(),
                token:      token,
                tags:       tags,
                notes:      (fields.notes    || '').trim(),
                extra:      Array.isArray(fields.extra)   ? fields.extra   : [],
                history:    Array.isArray(fields.history) ? fields.history : [],
                pwModified: typeof fields.pwModified === 'number' ? fields.pwModified : null,
                created:    typeof fields.created === 'number' ? fields.created : null,
                passkey:    (fields.passkey && typeof fields.passkey === 'object') ? fields.passkey : null
            };
            _applyDecType(entryType);
            _markPasskeyButton(passedTD, _hasPk);
            _markNoteButton(passedTD, entryType === 'note');
            _markStaleButton(passedTD, _stale);
            _setDecModified();
            _renderDecExtras();
            _renderDecPasskey();
            _updateFavBtn();
            _markFavButtons();
            // Final drift correction: individual per-function compensations
            // may accumulate sub-pixel errors or be partially offset by
            // async browser scroll-anchoring adjustments. One last comparison
            // against the pre-decode position corrects any residual shift.
            if (_dt !== null && _dc) { var _df = _dc.getBoundingClientRect().top - _dt; if (_df) window.scrollBy({ top: _df, behavior: 'instant' }); }

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
    // password pair that produced it. Also tear down the decode UI immediately so
    // the progress bar / worker count don't linger past a key-field edit.
    _revealGen++;
    _revealActive  = false;
    if (_selectMode) _exitSelectMode();
    var _rp = document.getElementById('reveal-progress');
    if (_rp) _rp.style.display = 'none';
    _hideWorkerCount();
    _lastRevealPw  = null;
    _lastRevealPw2 = null;
    _v5Names.clear();
    _searchText.clear();
    _entryBadges.clear();
    _clearVaultTools();
    _setIntegrityBadge(null);
    document.querySelectorAll('.entry-grid .entry-btn').forEach(function(btn) {
        if (btn.dataset.row && btn.dataset.row.split('|')[1] === 'v6') {
            btn.classList.add('v5-locked');
            btn.style.display = 'none';
            btn.textContent = '🔒';
            btn.title = '';
        }
    });
    // Re-sort so the group headers are dropped: every button is now hidden, so
    // _sortEntryGrid() removes the previous-run .entry-group-hdr rows and adds
    // none back (otherwise stale A–Z headers linger over an empty grid on lock).
    _sortEntryGrid();
    updateEntryCount();
    _updateVaultKeyBar();
}

// Show any v5 buttons whose names are already in _v5Names (after save/edit).
function _revealCachedV5Buttons() {
    document.querySelectorAll('.entry-btn.v5-locked').forEach(function(btn) {
        var rowKey = btn.dataset.row.split('|').slice(0, -1).join('|');
        var cached = _v5Names.get(rowKey);
        if (cached !== undefined) {
            _setEntryName(btn, cached);
            btn.classList.remove('v5-locked');
            btn.style.display = '';
            var _b = _entryBadges.get(rowKey);
            if (_b) { _markPasskeyButton(btn, _b.passkey); _markNoteButton(btn, _b.note); _markStaleButton(btn, _b.stale); }
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

// ---- Entry monogram avatars ("favicons") ---------------------------------
// CSP-safe, no network: a colored circle with the name's first letter. The
// color is a stable FNV-1a hash of the name → hue, so the same entry always
// gets the same avatar. (A third-party favicon service would violate
// connect-src 'self' and leak which sites are in the vault.)
function _avatarLetter(name) {
    var c = (name || '').trim().charAt(0);
    return c ? c.toUpperCase() : '#';
}
function _avatarColor(name) {
    var h = 0x811c9dc5 >>> 0;
    var s = name || '';
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return 'hsl(' + (h % 360) + ',42%,45%)';
}
// Set a revealed entry button's label with a leading monogram avatar. The plain
// name is stored on dataset.name so sort/group never read the avatar glyph.
function _setEntryName(btn, name) {
    btn.dataset.name = name;
    btn.title = name;
    btn.textContent = '';
    var av = document.createElement('span');
    av.className = 'entry-avatar';
    av.textContent = _avatarLetter(name);
    av.style.background = _avatarColor(name);
    av.setAttribute('aria-hidden', 'true');
    var lbl = document.createElement('span');
    lbl.className = 'entry-lbl';
    lbl.textContent = name;
    btn.appendChild(av);
    btn.appendChild(lbl);
}
// Mark/unmark an entry button as holding a passkey (a 🔐 badge via the
// .entry-passkey class). Idempotent; safe to call on every reveal.
function _markPasskeyButton(btn, isPasskey) {
    if (!btn) return;
    if (isPasskey) { btn.classList.add('entry-passkey'); btn.dataset.passkey = '1'; }
    else           { btn.classList.remove('entry-passkey'); delete btn.dataset.passkey; }
}
// Mark/unmark an entry button as a secure note (a 📝 badge via .entry-note).
// Idempotent; safe to call on every reveal (mirrors _markPasskeyButton).
function _markNoteButton(btn, isNote) {
    if (!btn) return;
    if (isNote) { btn.classList.add('entry-note'); btn.dataset.note = '1'; }
    else        { btn.classList.remove('entry-note'); delete btn.dataset.note; }
}
// Mark/unmark an entry button as stale (a ⏳ badge via .entry-stale). Idempotent.
// Uses .entry-lbl::before (passkey/note already occupy ::after, and an entry can
// be both stale and a passkey, so the two badges must not share a pseudo-element).
function _markStaleButton(btn, isStale) {
    if (!btn) return;
    if (isStale) { btn.classList.add('entry-stale'); btn.dataset.stale = '1'; }
    else         { btn.classList.remove('entry-stale'); delete btn.dataset.stale; }
}
// True if an entry's password has not changed in over _PW_AGE_WARN_DAYS — the same
// staleness rule Audit uses. Notes have no password, so they are never stale, and
// an entry without a pwModified stamp can't be aged (treated as not stale).
function _isStaleFields(fields) {
    if (!fields || fields.type === 'note') return false;
    if (typeof fields.pwModified !== 'number') return false;
    var ageCut = Math.floor(Date.now() / 1000) - _PW_AGE_WARN_DAYS * 86400;
    return fields.pwModified < ageCut;
}
// Reshape the decode panel for the decoded entry's type: a secure note hides the
// Username/2FA and Password/Modified rows (it has neither). Called on every decode
// and from clearDisplay (which resets to the login layout).
function _applyDecType(type) {
    var note = type === 'note';
    var u = document.getElementById('decrow-user');
    var p = document.getElementById('decrow-pw');
    var _content = document.getElementById('content');
    var _oldTop  = _content ? _content.getBoundingClientRect().top : 0;
    if (u) u.style.display = note ? 'none' : '';
    if (p) p.style.display = note ? 'none' : '';
    resizeFreezePane();
    if (_content) { var _d = _content.getBoundingClientRect().top - _oldTop; if (_d) window.scrollBy({ top: _d, behavior: 'instant' }); }
}
// Plain name of an entry button for sorting/grouping (avatar-aware).
function _btnName(btn) {
    return btn.dataset.name !== undefined ? btn.dataset.name : btn.textContent;
}

// First-letter group key for a revealed entry name: uppercased first char,
// bucketing digits / symbols / non-Latin under '#'.
function _entryGroupKey(name) {
    var c = (name || '').trim().charAt(0).toUpperCase();
    return (c >= 'A' && c <= 'Z') ? c : '#';
}

// Sort entry grid alphabetically by button text; hidden (locked) buttons go
// last. Revealed buttons are grouped under a sticky first-letter header
// (A, B, C…, '#' for non-letters); hidden 🔒 buttons get no header since they
// have no plaintext name yet.
function _sortEntryGrid() {
    var grid = document.querySelector('.entry-grid');
    if (!grid) return;
    // Drop any headers from a previous run; re-collect only the buttons.
    grid.querySelectorAll('.entry-group-hdr').forEach(function(h) { h.remove(); });
    _markFavButtons();
    var btns = Array.from(grid.querySelectorAll('.entry-btn'));
    btns.sort(function(a, b) {
        var aHidden = a.style.display === 'none';
        var bHidden = b.style.display === 'none';
        if (aHidden !== bHidden) return aHidden ? 1 : -1;
        // Favorites pin to the top, then alphabetical within each group.
        var aFav = a.classList.contains('entry-fav');
        var bFav = b.classList.contains('entry-fav');
        if (aFav !== bFav) return aFav ? -1 : 1;
        return _btnName(a).toLowerCase().localeCompare(_btnName(b).toLowerCase());
    });
    var curKey = null;
    btns.forEach(function(btn) {
        if (_groupEntries && btn.style.display !== 'none') {
            var key = btn.classList.contains('entry-fav') ? '★ Favorites'
                                                          : _entryGroupKey(_btnName(btn));
            if (key !== curKey) {
                curKey = key;
                var h = document.createElement('div');
                h.className = 'entry-group-hdr';
                h.textContent = key;
                h.setAttribute('aria-hidden', 'true');
                grid.appendChild(h);
            }
        }
        grid.appendChild(btn);
    });
}

// Drive `count` items through a fixed pool of at most _revealConcurrency()
// workers, each pulling the next index from a shared counter and awaiting
// itemFn(i). If itemFn resolves to exactly false the whole pool stops — this
// expresses the abort-on-supersede (reveal-all) and all-or-nothing-on-failure
// (_forEachRecordDecrypt) semantics in one place. Caps peak Argon2id memory at
// pool-size × the active KDF cost (the worker pool itself is the real bound).
async function _runPool(count, itemFn) {
    var nextIdx = 0, stopped = false;
    async function worker() {
        while (nextIdx < count && !stopped) {
            var i = nextIdx++;
            if ((await itemFn(i)) === false) { stopped = true; return; }
        }
    }
    var pool = [];
    var conc = _revealConcurrency();
    for (var w = 0; w < conc && w < count; w++) pool.push(worker());
    await Promise.all(pool);
}

// Decrypt and reveal all hidden v5 entry names using both passwords.
// Called on blur of #aeskey2 so names appear once both passwords are entered.
async function _revealAllV5Names(pw, pw2) {
    var locked = Array.from(document.querySelectorAll('.entry-btn.v5-locked'));
    if (!locked.length) return;
    // Decoding is starting — mask both key fields so a shown password isn't left
    // on screen while names are decrypted.
    _maskKeyFields();
    // Capture this run's generation; if the key fields change mid-loop (which bumps
    // _revealGen via _relockV5Entries) we abort rather than reveal with stale keys.
    var gen   = _revealGen;
    var total = locked.length;
    _revealActive = true;
    var bar  = document.getElementById('reveal-progress');
    var fill = document.getElementById('reveal-progress-fill');
    if (bar)  { fill.style.width = '0%'; bar.style.display = ''; }
    _showWorkerCount();

    var done       = 0;
    var revealedOk = 0;   // names actually decrypted/shown — 0 means wrong keys

    // Reveal one button: reuse a cached name or derive it. Returns false if the
    // run has been superseded (keys changed mid-flight) so the worker stops.
    async function reveal(btn) {
        var parts  = btn.dataset.row.split('|');
        var rowKey = parts.slice(0, -1).join('|');
        if (_v5Names.has(rowKey)) {
            var n = _v5Names.get(rowKey);
            _setEntryName(btn, n);
            btn.classList.remove('v5-locked'); btn.style.display = '';
            revealedOk++;
        } else {
            try {
                var name = await decryptName(pw, pw2, parts[2], parts[3], parts[4], parts[5], parts[0]);
                if (gen !== _revealGen) return false;
                _v5Names.set(rowKey, name);
                _setEntryName(btn, name);
                btn.classList.remove('v5-locked'); btn.style.display = '';
                revealedOk++;
            } catch (_) {
                // A superseded run can throw because the keys no longer match the
                // in-progress edit; bail instead of marking entries as failed.
                if (gen !== _revealGen) return false;
                /* wrong key — leave hidden */
            }
        }
        // Populate the @-search index (tags + notes) while this record's keys are
        // hot in _mkCache — adds only HKDF + symmetric layers, no extra Argon2id.
        if (!_searchText.has(rowKey)) {
            try {
                var f = await decryptFields(pw, pw2, parts[2], parts[3], parts[6], parts[7], parts[8], parts[9], parts[10]);
                if (gen !== _revealGen) return false;
                _searchText.set(rowKey, _searchIndex(f));
                var _pk = !!(f.passkey && f.passkey.rpId), _nt = f.type === 'note';
                var _st = _isStaleFields(f);
                _entryBadges.set(rowKey, { passkey: _pk, note: _nt, stale: _st });
                // Flag passkey / secure-note / stale entries in the grid (payload
                // already decrypted here, so the badge costs no extra Argon2id).
                _markPasskeyButton(btn, _pk);
                _markNoteButton(btn, _nt);
                _markStaleButton(btn, _st);
            } catch (_) {
                if (gen !== _revealGen) return false;
                /* wrong key / corrupt — leave unindexed */
            }
        }
        done++;
        if (fill) fill.style.width = Math.round((done / total) * 100) + '%';
        updateEntryCount();
        return true;
    }

    // Fixed pool pulling from a shared index (reveal returns false to abort a
    // superseded run), so at most _revealConcurrency() decryptions run at once.
    await _runPool(locked.length, function(i) { return reveal(locked[i]); });

    _revealActive = false;
    if (bar) bar.style.display = 'none';
    _hideWorkerCount();
    // Superseded mid-flight: don't sort or record the (now-stale) password pair.
    if (gen !== _revealGen) return;
    _sortEntryGrid();
    updateEntryCount();
    // Record the password pair that produced this reveal so an unchanged repeat
    // blur can skip the whole pass.
    _lastRevealPw  = pw;
    _lastRevealPw2 = pw2;
    // Names just decoded and the grid re-sorted into alphabetical order — snap
    // back to the top so the user sees the start of the list, not wherever the
    // pre-reveal 🔒 placeholders happened to leave the scroll. Only when at least
    // one name actually decoded (a wrong-password pass reveals nothing and should
    // leave the view untouched).
    if (revealedOk > 0) window.scrollTo({ top: 0, behavior: 'smooth' });
    // Keys are confirmed good (at least one name decrypted) — check the vault
    // signature against what this page is showing. Wrong-password runs reveal
    // nothing and must not raise a false integrity alarm.
    if (revealedOk > 0) _verifyManifest(pw, pw2);
}

// ============================================================
// Save (encrypt) a new entry
// ============================================================

// Read + validate the entry form's required key/name fields. Returns
// { password, password2, name } or null (after alerting) if anything is missing.
function _validateEntryForm() {
    var password = document.getElementById('aeskey').value;
    if (!password) { alert('Enter primary password first'); return null; }
    var name = document.getElementById('name').value.trim();
    if (!name) { alert('Name is required'); return null; }
    if (name.indexOf('|') !== -1) { alert('Name may not contain "|"'); return null; }
    var password2 = document.getElementById('aeskey2').value;
    if (!password2) { alert('Enter secondary password first'); return null; }
    return { password: password, password2: password2, name: name };
}

// Build the encrypted-payload JSON object from the form, including the password
// history / age / created stamps. All of this lives inside the encrypted payload,
// so the v6 record format is unchanged. _editSnapshot holds the pre-edit values.
function _buildEntryFields() {
    var isNote  = _entryType === 'note';
    var editing = _editRecord !== null && _editSnapshot;
    var nowSec  = Math.floor(Date.now() / 1000);
    var prevMod = editing ? _editSnapshot.pwModified : null;

    // Password history + age: on edit, if the password changed, archive the old
    // one (newest first, capped) and stamp pwModified. New entries stamp the
    // creation time. A secure note has no password, so it skips this entirely.
    var pwVal, history, pwModified;
    if (isNote) {
        pwVal      = '';
        history    = [];
        pwModified = (editing && typeof prevMod === 'number') ? prevMod : nowSec;
    } else {
        pwVal   = document.getElementById('password').value;
        var prevPw = editing ? _editSnapshot.password : '';
        history = (editing && Array.isArray(_editSnapshot.history))
                      ? _editSnapshot.history.slice() : [];
        pwModified = prevMod;
        if (!editing) {
            pwModified = nowSec;                        // new entry
        } else if (pwVal !== prevPw) {
            if (prevPw) history.unshift({ p: prevPw, t: prevMod || null });
            if (history.length > HISTORY_MAX) history = history.slice(0, HISTORY_MAX);
            pwModified = nowSec;                         // password rotated
        }
        // A legacy entry being edited may carry no last-modified stamp at all; if
        // so, backfill it with the post time so the date is no longer empty.
        if (editing && typeof pwModified !== 'number') pwModified = nowSec;
    }
    // Creation time: stamped once on create and carried unchanged through edits.
    // A legacy entry being edited for the first time has no `created`; fall back
    // to its pwModified (the create stamp unless the password was ever rotated),
    // else to now, so it gains the stamp from here on.
    var created = editing
        ? (typeof _editSnapshot.created === 'number' ? _editSnapshot.created
           : (typeof prevMod === 'number' ? prevMod : nowSec))
        : nowSec;

    var fields = {
        url:        isNote ? '' : document.getElementById('url').value,
        username:   isNote ? '' : document.getElementById('username').value,
        password:   pwVal,
        token:      isNote ? '' : document.getElementById('token').value,
        notes:      document.getElementById('notes').value,
        tags:       _normalizeTags(document.getElementById('tags').value),
        extra:      _collectExtraFields(),
        history:    history,
        pwModified: pwModified,
        created:    created
    };
    // 'login' is the absent-key default — only stamp the type for a secure note,
    // so existing login records stay byte-for-byte the same on re-save.
    if (isNote) fields.type = 'note';
    // Preserve a stored passkey across edits (the PWA never edits passkeys, but it
    // must round-trip one that the extension created). Only kept when editing —
    // a brand-new entry has no passkey. _editSnapshot.passkey is set to null by
    // deletePasskey() so a passkey removal is committed by simply omitting it.
    if (editing && _editSnapshot.passkey && typeof _editSnapshot.passkey === 'object') {
        fields.passkey = _editSnapshot.passkey;
    }
    return fields;
}

// Encrypt the name + payload into a fresh v6 record. Two record salts, shared by
// name + payload — each yields one Argon2id master key (pw1→recSalt1, pw2→
// recSalt2), so the whole record costs just two memory-hard derivations (cached
// and reused across name/payload).
async function _buildEntryRecord(password, password2, name, fields) {
    var recSalt1 = crypto.getRandomValues(new Uint8Array(32));
    var recSalt2 = crypto.getRandomValues(new Uint8Array(32));
    var nameEnc = await encryptName(password, password2, recSalt1, recSalt2, name);
    var result  = await encryptFields(password, password2, recSalt1, recSalt2, fields);
    return _assembleRecord(nameEnc, result, recSalt1, recSalt2);
}

// POST the new record. Edit = atomic replace: tell the server which record (by
// content) to remove alongside the insert. See deleteEntryRecord for why content,
// not line index. Returns the server response text.
function _postEntry(record) {
    var params = 'data=' + encodeURIComponent(record);
    if (_editRecord !== null) {
        params = 'delete_rec=' + encodeURIComponent(_editRecord) + '&' + params;
    }
    return _xhrPost(params);
}

// Reset the entry form back to its empty "New Entry" state after a successful save.
function _resetEntryForm() {
    clearDisplay();
    ['name', 'url', 'username', 'password', 'token', 'notes', 'tags'].forEach(function(id) {
        document.getElementById(id).value = '';
    });
    _populateExtraFields([]);
    document.getElementById('newentry-title').textContent     = 'New Entry';
    document.getElementById('newentry').style.display         = 'none';
    document.getElementById('passwordSettings').style.display = 'none';
}

async function saveEntry() {
    var v = _validateEntryForm();
    if (!v) return;
    var fields = _buildEntryFields();
    try {
        var record = await _buildEntryRecord(v.password, v.password2, v.name, fields);
        // Cache name so _rebuildEntryGrid can reveal the button immediately, and
        // seed the @-search index (the record is already decrypted here).
        _v5Names.set(record, v.name);
        _searchText.set(record, _searchIndex(fields));
        _entryBadges.set(record, { passkey: !!(fields.passkey && fields.passkey.rpId), note: fields.type === 'note', stale: _isStaleFields(fields) });
        var responseText = await _postEntry(record);
        var wasEditing = _editRecord !== null;
        _editRecord = null; _editSnapshot = null;
        try {
            if (_applyServerResponse(responseText)) _revealCachedV5Buttons();
        } catch (_) { location.reload(); return; }
        _signAfterWrite();
        _resetEntryForm();
        if (wasEditing) {
            var savedBtn = Array.from(document.querySelectorAll('.entry-grid .entry-btn')).find(function(b) {
                return b.dataset.row && b.dataset.row.split('|').slice(0, -1).join('|') === record;
            });
            if (savedBtn) {
                requestAnimationFrame(async function() {
                    await decodeLine(savedBtn, savedBtn.dataset.row);
                    _scrollGridBtnIntoView(savedBtn);
                });
            }
        }
    } catch (e) {
        if (e.stale) {
            showToast('Entry was changed elsewhere — reloading');
            setTimeout(function() { location.reload(); }, 1200);
            return;
        }
        showToast('Save failed — ' + e.message);
    }
}

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

// Client mirror of post.php's is_valid_record() for v6 — a shape check so a bad
// file is rejected before we decrypt anything or hit the network.
function _isValidV6Record(s) {
    if (typeof s !== 'string' || s.length > 65536) return false;
    var p = s.split('|');
    if (p.length !== 11 || p[1] !== 'v6') return false;
    var hex = /^[0-9a-fA-F]+$/;
    if (p[0] === '' || p[0].length % 2 !== 0 || !hex.test(p[0])) return false;
    var lens = { 2: 64, 3: 64, 4: 24, 5: 24, 6: 24, 7: 24, 8: 32, 9: 32 };
    for (var i in lens) {
        if (p[i].length !== lens[i] || !hex.test(p[i])) return false;
    }
    if (p[10] === '' || p[10].length % 2 !== 0 || !hex.test(p[10])) return false;
    return true;
}

var _importBusy = false;

// Open a file picker for an exported .lines vault, then hand it to the importer.
// Transient hidden input (same idiom as scanQRCode) — no persistent template node.
function _importVaultClick() {
    if (_importBusy) return;
    var fileInput = document.createElement('input');
    fileInput.type   = 'file';
    fileInput.accept = '.lines,text/plain';
    fileInput.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    document.body.appendChild(fileInput);

    fileInput.addEventListener('change', function() {
        var file = fileInput.files[0];
        if (fileInput.parentNode) document.body.removeChild(fileInput);
        if (file) _importVaultFile(file);
    });

    // Clean up the orphaned input if the picker is dismissed without a selection.
    window.addEventListener('focus', function onFocus() {
        window.removeEventListener('focus', onFocus);
        setTimeout(function() {
            if (fileInput.parentNode) document.body.removeChild(fileInput);
        }, 500);
    }, { once: true });

    fileInput.click();
}

function _readFileText(file) {
    return new Promise(function(resolve, reject) {
        var r = new FileReader();
        r.onload  = function() { resolve(String(r.result)); };
        r.onerror = function() { reject(new Error('could not read file')); };
        r.readAsText(file);
    });
}

// Replace the entire vault with the records in an exported .lines file.
// All-or-nothing: the upload is parsed, shape-validated, and FULLY decrypted with
// the current key-field passwords before anything is sent, so a committed import is
// guaranteed readable. Mirrors changeMasterPasswords' bulk-commit + re-sign tail.
async function _importVaultFile(file) {
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }

    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!pw || !pw2) { say('Enter both passwords in the key fields first.'); return; }

    var text;
    try { text = await _readFileText(file); }
    catch (e) { say('Import failed — ' + e.message); return; }

    var rows = text.split(/\r\n|\r|\n/)
                   .map(function(s) { return s.trim(); })
                   .filter(function(s) { return s !== ''; });
    if (!rows.length) { say('That file contains no vault entries.'); return; }
    for (var i = 0; i < rows.length; i++) {
        if (!_isValidV6Record(rows[i])) {
            say('Not a valid vault export — line ' + (i + 1) + ' is malformed.');
            return;
        }
    }

    var curCount = _allEntries.length;
    var plural   = function(n) { return n === 1 ? 'y' : 'ies'; };
    if (!window.confirm('Replace ' + curCount + ' current entr' + plural(curCount)
            + ' with ' + rows.length + ' imported entr' + plural(rows.length)
            + '?\n\nThis overwrites the whole vault. A backup of the current vault '
            + 'is saved on the server before the import.')) {
        say('');
        return;
    }

    _importBusy = true;
    try {
        // Decrypt-verify EVERY imported record with the current passwords before
        // sending — any failure aborts here, nothing is written. The derivations
        // populate _mkCache (kept, since the passwords don't change) so clicking an
        // imported entry afterwards is instant.
        say('Verifying… 0 / ' + rows.length);
        var pairs;
        try {
            pairs = await _forEachRecordDecrypt(pw, pw2, function(rec, name) {
                return { record: rec, name: name };
            }, function(done) { say('Verifying… ' + done + ' / ' + rows.length); }, rows);
        } catch (e) {
            say('Import aborted — these entries do not match the passwords entered ('
                + e.message + '). The vault was not modified.');
            return;
        }

        // expect_hash over the CURRENT vault — identical computation to
        // changeMasterPasswords / post.php (records joined with "\n", no trailing NL).
        var oldJoined = _allEntries.map(function(row) {
            return row.split('|').slice(0, -1).join('|');
        }).join('\n');
        var hashBuf    = await crypto.subtle.digest('SHA-256', _TE.encode(oldJoined));
        var expectHash = bytesToHex(new Uint8Array(hashBuf));

        say('Importing…');
        var responseText = await _xhrPost('restore=1&expect_hash=' + expectHash
                                          + '&bulk_data=' + encodeURIComponent(rows.join('\n')));

        // Committed server-side. The old vault's names are gone, so drop the stale
        // name cache and pre-seed it with the imported ones so the grid reveals
        // instantly. Passwords are unchanged, so _mkCache is left intact.
        _v5Names.clear();
        pairs.forEach(function(p) { _v5Names.set(p.record, p.name); });
        _lastRevealPw  = pw;
        _lastRevealPw2 = pw2;
        clearDisplay();
        try { _applyServerResponse(responseText); } catch (_) { location.reload(); return; }
        _revealCachedV5Buttons();
        _signAfterWrite();   // re-sign the restored set → fresh monotonic revision
        say('');
        showToast('Vault imported — ' + rows.length + ' entries restored');
    } catch (e) {
        if (e.stale) {
            say('The vault changed during import — nothing was modified. Reload and retry.');
        } else {
            say('Import failed — ' + e.message + '. The vault was not modified.');
        }
    } finally {
        _importBusy = false;
    }
}

// ============================================================
// Plaintext CSV export / import — interoperability with other
// password managers. UNLIKE the .lines path these handle CLEARTEXT:
// export writes every secret in the clear (hard-gated behind a warning
// + confirm), and import re-encrypts each CSV row into a fresh v6
// record and MERGES it into the vault (the .lines import replaces the
// whole vault; CSV adds to it — the usual "migrate in" shape).
// ============================================================

// RFC 4180 CSV parser → array of string-array rows. Handles quoted
// fields, embedded commas/newlines, "" escapes, a leading BOM, and
// CR / CRLF / LF line endings.
function _csvParse(text) {
    var rows = [], row = [], field = '', inQ = false;
    var i = 0, n = text.length;
    if (text.charCodeAt(0) === 0xFEFF) i = 1;                 // strip BOM
    function endRow() { row.push(field); field = ''; rows.push(row); row = []; }
    while (i < n) {
        var c = text[i];
        if (inQ) {
            if (c === '"') {
                if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
                inQ = false; i++; continue;
            }
            field += c; i++; continue;
        }
        if (c === '"')  { inQ = true; i++; continue; }
        if (c === ',')  { row.push(field); field = ''; i++; continue; }
        if (c === '\r') { endRow(); if (text[i + 1] === '\n') i++; i++; continue; }
        if (c === '\n') { endRow(); i++; continue; }
        field += c; i++;
    }
    if (field !== '' || row.length) endRow();
    return rows;
}

// Quote one CSV field (always-quote — valid and simplest; doubles "). Also
// neutralizes spreadsheet formula / CSV injection: a value whose first visible
// character is = + - @ (or a leading tab/CR/LF that Excel trims away to expose
// the next one) is evaluated as a formula by Excel / LibreOffice / Sheets when
// the exported file is reopened — e.g. =HYPERLINK(...) or =cmd|... — which can
// exfiltrate data or run commands. Quoting alone does NOT stop this (Excel still
// evaluates "=..."). Prefixing such values with an apostrophe makes the
// spreadsheet import them as literal text; _csvUnguard() strips it back off on
// import so an export→import round-trip stays lossless.
function _csvField(v) {
    var s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r\n]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
}

// Reverse of the _csvField formula guard: drop a single leading apostrophe only
// when it directly shields a formula-trigger character, so a value we (or another
// tool) defanged on export imports verbatim. A legitimate leading apostrophe in
// front of any other character is left untouched.
function _csvUnguard(s) {
    return /^'[=+\-@\t\r\n]/.test(s) ? s.slice(1) : s;
}

// Export columns. `extra` carries the custom-fields array as JSON so our own
// CSV round-trips; other managers simply ignore the column.
var _CSV_COLS = ['name', 'url', 'username', 'password', 'totp', 'notes', 'tags', 'extra'];

// Download every entry as a PLAINTEXT CSV. Gated behind _isVaultUnlocked()
// (so the passwords are known-correct) and a hard warning + confirm, because
// the output has none of the vault's protection.
async function exportVaultCSV(btn) {
    if (!_isVaultUnlocked()) {
        showToast('Enter both passwords and unlock the vault first.');
        return;
    }
    if (!_allEntries.length) { showToast('Nothing to export'); return; }

    if (!window.confirm(
            '⚠︎ Export UNENCRYPTED CSV?\n\n'
          + 'This writes every entry — passwords, TOTP secrets, and notes — to '
          + 'a plain-text file with NO encryption and NONE of this vault’s '
          + 'protection. Anyone who can read the file sees everything.\n\n'
          + 'Only do this to migrate into another password manager, then DELETE '
          + 'the file immediately afterwards.\n\n'
          + 'Continue and export all secrets in clear text?')) {
        return;
    }

    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }

    say('Decrypting all entries… 0 / ' + _allEntries.length);
    if (btn) btn.disabled = true;
    var rows;
    try {
        rows = await _forEachRecordDecrypt(pw, pw2, function(rec, name, fields) {
            return {
                name:     name,
                url:      fields.url || '',
                username: fields.username || '',
                password: fields.password || '',
                totp:     fields.token || '',
                notes:    fields.notes || '',
                tags:     fields.tags || '',
                extra:    (Array.isArray(fields.extra) && fields.extra.length)
                              ? JSON.stringify(fields.extra) : ''
            };
        }, function(done, total) { say('Decrypting all entries… ' + done + ' / ' + total); });
    } catch (e) {
        say('CSV export failed — ' + e.message);
        return;
    } finally {
        if (btn) btn.disabled = false;
    }

    var lines = [_CSV_COLS.join(',')];
    rows.forEach(function(r) {
        lines.push(_CSV_COLS.map(function(c) { return _csvField(r[c]); }).join(','));
    });
    var content = lines.join('\r\n') + '\r\n';

    var blob = new Blob([content], { type: 'text/csv' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    var d    = new Date();
    var pad  = function(x) { return String(x).padStart(2, '0'); };
    a.href     = url;
    a.download = 'vault-export-' + d.getFullYear() + '-' + pad(d.getMonth() + 1)
               + '-' + pad(d.getDate()) + '.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
    say('');
    showToast('⚠︎ Exported ' + rows.length + ' entries as UNENCRYPTED CSV — delete the file when done');
}

// Header-name aliases → our field keys, so common manager exports
// (Bitwarden's login_*, Chrome's name/url/username/password/note, etc.)
// map onto our schema without the user renaming columns.
var _CSV_ALIASES = {
    name:     ['name', 'title', 'account', 'entry', 'item'],
    url:      ['url', 'uri', 'website', 'site', 'web site', 'login_uri', 'urls'],
    username: ['username', 'user', 'login', 'login_username', 'user name', 'email', 'e-mail'],
    password: ['password', 'pass', 'pwd', 'login_password'],
    totp:     ['totp', 'otp', 'login_totp', 'token', '2fa', 'otpauth', 'authenticator key'],
    notes:    ['notes', 'note', 'comment', 'comments'],
    tags:     ['tags', 'tag', 'labels', 'folder', 'category', 'grouping'],
    extra:    ['extra', 'custom fields', 'fields']
};

// Open a file picker for a CSV, then hand it to the importer (transient
// hidden input — same idiom as scanQRCode / _importVaultClick).
function _importCsvClick() {
    if (_importBusy) return;
    var fileInput = document.createElement('input');
    fileInput.type   = 'file';
    fileInput.accept = '.csv,text/csv,text/plain';
    fileInput.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    document.body.appendChild(fileInput);

    fileInput.addEventListener('change', function() {
        var file = fileInput.files[0];
        if (fileInput.parentNode) document.body.removeChild(fileInput);
        if (file) _importCsvFile(file);
    });
    window.addEventListener('focus', function onFocus() {
        window.removeEventListener('focus', onFocus);
        setTimeout(function() {
            if (fileInput.parentNode) document.body.removeChild(fileInput);
        }, 500);
    }, { once: true });

    fileInput.click();
}

// Parse a CSV file and ADD its rows to the vault (merge, not replace).
// Gated on _isVaultUnlocked() so the entered passwords are known-correct —
// otherwise we'd encrypt the new rows under a different key than the rest of
// the vault. Each row is re-encrypted into a fresh v6 record, then the whole
// (existing + new) set is committed in one count-flexible `restore` write.
async function _importCsvFile(file) {
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }

    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!_isVaultUnlocked()) { say('Enter both passwords and unlock the vault first.'); return; }

    var text;
    try { text = await _readFileText(file); }
    catch (e) { say('Import failed — ' + e.message); return; }

    var grid = _csvParse(text).filter(function(r) {
        return r.some(function(c) { return c.trim() !== ''; });   // drop blank lines
    });
    if (grid.length < 2) { say('That CSV has no data rows.'); return; }

    var header = grid[0].map(function(h) { return h.trim().toLowerCase(); });
    var col = {};
    Object.keys(_CSV_ALIASES).forEach(function(key) {
        for (var a = 0; a < _CSV_ALIASES[key].length; a++) {
            var idx = header.indexOf(_CSV_ALIASES[key][a]);
            if (idx !== -1) { col[key] = idx; break; }
        }
    });
    if (col.name === undefined && col.username === undefined && col.url === undefined) {
        say('Unrecognized CSV — needs at least a "name", "username", or "url" column.');
        return;
    }

    function cell(r, key) {
        return (col[key] !== undefined && r[col[key]] != null) ? _csvUnguard(String(r[col[key]])) : '';
    }
    var nowSec = Math.floor(Date.now() / 1000);
    var parsed = [], skipped = 0;
    for (var i = 1; i < grid.length; i++) {
        var r = grid[i];
        var name = (cell(r, 'name').trim() || cell(r, 'username').trim()
                    || cell(r, 'url').trim()).replace(/\|/g, ' ').trim();
        if (!name) { skipped++; continue; }

        var extra = [], rawExtra = cell(r, 'extra').trim();
        if (rawExtra) {
            try {
                var ex = JSON.parse(rawExtra);
                if (Array.isArray(ex)) {
                    extra = ex.filter(function(f) { return f && (f.label || f.value); })
                              .map(function(f) {
                                  return { label: String(f.label || ''),
                                           value: String(f.value || ''),
                                           secret: !!f.secret };
                              });
                }
            } catch (_) { /* not our JSON extra column — ignore */ }
        }

        parsed.push({
            name: name,
            fields: {
                url:        cell(r, 'url'),
                username:   cell(r, 'username'),
                password:   cell(r, 'password'),
                token:      cell(r, 'totp').trim(),
                notes:      cell(r, 'notes'),
                tags:       _normalizeTags(cell(r, 'tags')),
                extra:      extra,
                history:    [],
                pwModified: nowSec,
                created:    nowSec
            }
        });
    }
    if (!parsed.length) { say('No importable rows found in that CSV.'); return; }
    return _importParsedEntries(parsed, skipped, 'CSV');
}

// Shared tail for every "merge these parsed entries into the vault" importer
// (CSV / KeePass XML / 1Password 1pux). `parsed` is [{name, fields}], already
// validated; `sourceLabel` names the format for the prompts. Confirms, encrypts
// each entry into a fresh v6 record under the CURRENT passwords (so the new rows
// share the vault's key pair), and commits existing+new in one count-flexible
// `restore` write — identical guarantees to the old CSV path.
async function _importParsedEntries(parsed, skipped, sourceLabel) {
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!_isVaultUnlocked()) { say('Enter both passwords and unlock the vault first.'); return; }
    if (!parsed.length) { say('No importable entries found in that ' + sourceLabel + '.'); return; }

    var curCount = _allEntries.length;
    var msg = 'Add ' + parsed.length + ' entr' + (parsed.length === 1 ? 'y' : 'ies')
            + ' from this ' + sourceLabel + ' to your vault?\n\n'
            + 'Your ' + curCount + ' existing entr' + (curCount === 1 ? 'y is' : 'ies are')
            + ' kept — the imported entries are added alongside them and '
            + 're-encrypted with the passwords in the key fields. A backup of the '
            + 'current vault is saved on the server first.';
    if (skipped) msg += '\n\n(' + skipped + ' incomplete entr' + (skipped === 1 ? 'y' : 'ies')
                      + ' with no name/username/url will be skipped.)';
    if (!window.confirm(msg)) { say(''); return; }

    _importBusy = true;
    try {
        // Encrypt every parsed row into a fresh v6 record, bounded-concurrency so
        // the Argon2id derivations spread across the worker pool (each row uses two
        // fresh master keys, so _mkCache can't help — but the pool still parallelises).
        say('Encrypting… 0 / ' + parsed.length);
        var records = new Array(parsed.length);
        var names   = new Array(parsed.length);
        var nextIdx = 0, done = 0, failed = null;
        async function enc() {
            while (nextIdx < parsed.length && failed === null) {
                var k = nextIdx++;
                try {
                    var s1 = crypto.getRandomValues(new Uint8Array(32));
                    var s2 = crypto.getRandomValues(new Uint8Array(32));
                    var ne = await encryptName(pw, pw2, s1, s2, parsed[k].name);
                    var rf = await encryptFields(pw, pw2, s1, s2, parsed[k].fields);
                    records[k] = _assembleRecord(ne, rf, s1, s2);
                    names[k] = parsed[k].name;
                } catch (e) {
                    if (failed === null) failed = e;
                    return;
                }
                done++;
                say('Encrypting… ' + done + ' / ' + parsed.length);
            }
        }
        var pool = [], conc = _revealConcurrency();
        for (var w = 0; w < conc && w < parsed.length; w++) pool.push(enc());
        await Promise.all(pool);
        if (failed) { say(sourceLabel + ' import failed — ' + failed.message + '. The vault was not modified.'); return; }

        // Merge: existing canonical records + the new ones, committed in one
        // count-flexible `restore` write (expect_hash catches a concurrent change).
        var existing   = _allEntries.map(function(row) {
            return row.split('|').slice(0, -1).join('|');
        });
        var merged     = existing.concat(records);
        var hashBuf    = await crypto.subtle.digest('SHA-256', _TE.encode(existing.join('\n')));
        var expectHash = bytesToHex(new Uint8Array(hashBuf));

        say('Importing…');
        var responseText = await _xhrPost('restore=1&expect_hash=' + expectHash
                              + '&bulk_data=' + encodeURIComponent(merged.join('\n')));

        // Existing entries keep their cached names; seed the new ones so they
        // reveal instantly. Passwords unchanged → _mkCache and the rest stay.
        for (var m = 0; m < records.length; m++) _v5Names.set(records[m], names[m]);
        _lastRevealPw  = pw;
        _lastRevealPw2 = pw2;
        clearDisplay();
        try { _applyServerResponse(responseText); } catch (_) { location.reload(); return; }
        _revealCachedV5Buttons();
        _signAfterWrite();
        say('');
        showToast('Imported ' + records.length + ' entries from ' + sourceLabel
                  + (skipped ? ' (' + skipped + ' skipped)' : ''));
    } catch (e) {
        if (e.stale) {
            say('The vault changed during import — nothing was modified. Reload and retry.');
        } else {
            say(sourceLabel + ' import failed — ' + e.message + '. The vault was not modified.');
        }
    } finally {
        _importBusy = false;
    }
}

// Generic transient hidden-input file picker (same idiom as scanQRCode /
// _importCsvClick), parameterised by accept filter and the handler to run.
function _pickImportFile(accept, handler) {
    if (_importBusy) return;
    var fileInput = document.createElement('input');
    fileInput.type   = 'file';
    fileInput.accept = accept;
    fileInput.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    document.body.appendChild(fileInput);
    fileInput.addEventListener('change', function() {
        var file = fileInput.files[0];
        if (fileInput.parentNode) document.body.removeChild(fileInput);
        if (file) handler(file);
    });
    window.addEventListener('focus', function onFocus() {
        window.removeEventListener('focus', onFocus);
        setTimeout(function() { if (fileInput.parentNode) document.body.removeChild(fileInput); }, 500);
    }, { once: true });
    fileInput.click();
}

// ---- KeePass 2 XML import -------------------------------------------------
// The unencrypted "File → Export → KeePass XML (2.x)" format from KeePass /
// KeePassXC. (The encrypted .kdbx binary is intentionally NOT supported — a
// full KDBX crypto parser can't be loaded under our CSP; export to XML or CSV
// from KeePass first.)
async function _importKeepassFile(file) {
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }
    if (!_isVaultUnlocked()) { say('Enter both passwords and unlock the vault first.'); return; }
    var text;
    try { text = await _readFileText(file); }
    catch (e) { say('Import failed — ' + e.message); return; }
    var res;
    try { res = _parseKeepassXml(text); }
    catch (e) { say('Could not parse that file as KeePass XML — ' + e.message); return; }
    if (!res.parsed.length) {
        say('No entries found. In KeePass/KeePassXC use File → Export → KeePass XML (2.x).');
        return;
    }
    return _importParsedEntries(res.parsed, res.skipped, 'KeePass XML');
}

function _parseKeepassXml(text) {
    var doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new Error('malformed XML');
    if (!doc.getElementsByTagName('KeePassFile').length) throw new Error('not a KeePass XML export');
    var nowSec = Math.floor(Date.now() / 1000);
    var STD = { title: 1, username: 1, password: 1, url: 1, notes: 1 };
    var parsed = [], skipped = 0;
    var entries = doc.getElementsByTagName('Entry');
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        // Skip history snapshots (an <Entry> nested inside a <History>).
        var anc = e.parentNode, inHist = false;
        while (anc) { if (anc.nodeName === 'History') { inHist = true; break; } anc = anc.parentNode; }
        if (inHist) continue;

        var map = {}, extra = [], token = '';
        var kids = e.children || [];
        for (var s = 0; s < kids.length; s++) {
            if (kids[s].nodeName !== 'String') continue;
            var keyEl = kids[s].getElementsByTagName('Key')[0];
            var valEl = kids[s].getElementsByTagName('Value')[0];
            if (!keyEl) continue;
            var key = (keyEl.textContent || '').trim();
            var val = valEl ? (valEl.textContent || '') : '';
            var lk  = key.toLowerCase();
            if (lk === 'otp' || lk === 'otpauth') { if (val.trim()) token = val.trim(); continue; }
            if (lk === 'totp seed')     { if (val.trim() && !token) token = val.trim().replace(/\s+/g, ''); continue; }
            if (lk === 'totp settings') { continue; }
            if (STD[lk]) { map[lk] = val; continue; }
            if (key && val) {
                var prot = valEl && valEl.getAttribute('ProtectInMemory') === 'True';
                extra.push({ label: key, value: val, secret: !!prot });
            }
        }
        // Tags: a <Tags> child plus the containing group names (skipping "Root").
        var tagParts = [];
        for (var t = 0; t < kids.length; t++) {
            if (kids[t].nodeName === 'Tags' && kids[t].textContent) tagParts.push(kids[t].textContent.replace(/;/g, ','));
        }
        var g = e.parentNode;
        while (g && g.nodeName === 'Group') {
            var gKids = g.children || [];
            for (var gi = 0; gi < gKids.length; gi++) {
                if (gKids[gi].nodeName === 'Name') {
                    var gn = (gKids[gi].textContent || '').trim();
                    if (gn && gn.toLowerCase() !== 'root') tagParts.push(gn);
                    break;
                }
            }
            g = g.parentNode;
        }

        var name = ((map.title || '').trim() || (map.username || '').trim()
                    || (map.url || '').trim()).replace(/\|/g, ' ').trim();
        if (!name && !token) { skipped++; continue; }
        if (!name) name = 'Untitled';
        parsed.push({
            name: name,
            fields: {
                url: map.url || '', username: map.username || '', password: map.password || '',
                token: token, notes: map.notes || '',
                tags: _normalizeTags(tagParts.join(',')),
                extra: extra, history: [], pwModified: nowSec, created: nowSec
            }
        });
    }
    return { parsed: parsed, skipped: skipped };
}

// ---- 1Password .1pux import -----------------------------------------------
// .1pux is a ZIP archive holding an `export.data` JSON. We read it with a tiny
// dependency-free ZIP reader + the browser's DecompressionStream (no library,
// CSP-clean). Attachments inside the archive are ignored.
async function _import1puxFile(file) {
    var out = document.getElementById('import-status');
    function say(msg) { if (out) { out.style.display = ''; out.textContent = msg; } }
    if (!_isVaultUnlocked()) { say('Enter both passwords and unlock the vault first.'); return; }
    if (typeof DecompressionStream === 'undefined') {
        say('This browser can’t read .1pux (no DecompressionStream). Export 1Password as CSV instead.');
        return;
    }
    var buf;
    try { buf = await file.arrayBuffer(); }
    catch (e) { say('Import failed — ' + e.message); return; }
    var jsonBytes;
    try { jsonBytes = await _zipReadEntry(buf, function(n) { return /(^|\/)export\.data$/.test(n); }); }
    catch (e) { say('Could not read that .1pux archive — ' + e.message); return; }
    if (!jsonBytes) { say('That .1pux has no export.data — is it a 1Password export?'); return; }
    var res;
    try { res = _parse1pux(new TextDecoder().decode(jsonBytes)); }
    catch (e) { say('Could not parse the 1Password data — ' + e.message); return; }
    if (!res.parsed.length) { say('No entries found in that .1pux.'); return; }
    return _importParsedEntries(res.parsed, res.skipped, '1Password');
}

// Minimal ZIP reader: find one entry by name predicate and return its bytes.
// Reads the End-Of-Central-Directory + central directory (no ZIP64). Supports
// stored (method 0) and deflate (method 8 via DecompressionStream).
async function _zipReadEntry(buf, predicate) {
    var dv = new DataView(buf), u8 = new Uint8Array(buf), dec = new TextDecoder();
    var eocd = -1, min = Math.max(0, u8.length - 22 - 65536);
    for (var i = u8.length - 22; i >= min; i--) {
        if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('not a ZIP file');
    var cdCount = dv.getUint16(eocd + 10, true);
    var p = dv.getUint32(eocd + 16, true);
    for (var c = 0; c < cdCount; c++) {
        if (dv.getUint32(p, true) !== 0x02014b50) break;
        var method   = dv.getUint16(p + 10, true);
        var compSize = dv.getUint32(p + 20, true);
        var fnLen    = dv.getUint16(p + 28, true);
        var extraLen = dv.getUint16(p + 30, true);
        var cmtLen   = dv.getUint16(p + 32, true);
        var loOff    = dv.getUint32(p + 42, true);
        var name     = dec.decode(u8.subarray(p + 46, p + 46 + fnLen));
        if (predicate(name)) {
            if (dv.getUint32(loOff, true) !== 0x04034b50) throw new Error('bad local header');
            var lfn   = dv.getUint16(loOff + 26, true);
            var lext  = dv.getUint16(loOff + 28, true);
            var start = loOff + 30 + lfn + lext;
            var comp  = u8.subarray(start, start + compSize);
            if (method === 0) return comp.slice();
            if (method === 8) return await _inflateRaw(comp);
            throw new Error('unsupported compression method ' + method);
        }
        p += 46 + fnLen + extraLen + cmtLen;
    }
    return null;
}

async function _inflateRaw(bytes) {
    var ds = new DecompressionStream('deflate-raw');
    var stream = new Blob([bytes]).stream().pipeThrough(ds);
    var ab = await new Response(stream).arrayBuffer();
    return new Uint8Array(ab);
}

// Parse a 1Password export.data JSON into [{name, fields}]. Defensive against
// schema variation across 1pux versions: anything it can't map is skipped.
function _parse1pux(jsonText) {
    var data = JSON.parse(jsonText);
    var nowSec = Math.floor(Date.now() / 1000);
    var parsed = [], skipped = 0;
    var accounts = (data && data.accounts) || [];
    accounts.forEach(function(acc) {
        ((acc && acc.vaults) || []).forEach(function(vault) {
            ((vault && vault.items) || []).forEach(function(wrap) {
                var it = (wrap && wrap.item) ? wrap.item : wrap;
                if (!it || it.trashed === true || it.state === 'trashed') return;
                var ov = it.overview || {}, det = it.details || {};
                var title = (ov.title || '').trim();
                var url = ov.url || '';
                if (!url && Array.isArray(ov.urls) && ov.urls.length) url = ov.urls[0].url || ov.urls[0].u || '';

                var username = '', password = '', token = '';
                (det.loginFields || []).forEach(function(f) {
                    var des = (f.designation || f.name || '').toLowerCase();
                    if (des === 'username' && !username) username = f.value || '';
                    else if (des === 'password' && !password) password = f.value || '';
                });
                if (!password && det.password) password = det.password;

                var extra = [];
                (det.sections || []).forEach(function(sec) {
                    (sec.fields || []).forEach(function(f) {
                        var v = f.value || {};
                        if (v.totp && !token) { token = v.totp; return; }
                        var label = (f.title || f.id || '').trim();
                        var val = v.string != null ? v.string
                                : v.concealed != null ? v.concealed
                                : v.email != null ? v.email
                                : v.url != null ? v.url
                                : v.phone != null ? v.phone
                                : (typeof v === 'string' ? v : '');
                        if (label && val) extra.push({ label: label, value: String(val), secret: v.concealed != null });
                    });
                });

                var notes = det.notesPlain || '';
                var tags  = Array.isArray(ov.tags) ? ov.tags.join(',') : (ov.tags || '');
                var name  = (title || username || url).replace(/\|/g, ' ').trim();
                if (!name && !password && !token) { skipped++; return; }
                if (!name) name = 'Untitled';
                parsed.push({
                    name: name,
                    fields: {
                        url: url, username: username, password: password, token: token,
                        notes: notes, tags: _normalizeTags(tags),
                        extra: extra, history: [], pwModified: nowSec, created: nowSec
                    }
                });
            });
        });
    });
    return { parsed: parsed, skipped: skipped };
}

// Decrypt every record with the given passwords and feed (record, name, fields)
// to `handler`, with the same bounded concurrency as reveal-all (Argon2id runs
// on the worker pool). All-or-nothing: the first failure aborts the run and
// throws, so callers never act on a partially decrypted vault.
async function _forEachRecordDecrypt(pw, pw2, handler, progressCb, rowsIn) {
    // Default to the current vault (canonical form: trailing line index stripped);
    // callers may pass an explicit rows array (e.g. import verifies uploaded rows).
    var rows = rowsIn || _allEntries.map(function(row) {
        return row.split('|').slice(0, -1).join('|');
    });
    var results = new Array(rows.length);
    var done = 0, failed = null;
    // All-or-nothing: returning false from the item fn stops the whole pool.
    await _runPool(rows.length, async function(i) {
        var p = rows[i].split('|');
        try {
            var name   = await decryptName(pw, pw2, p[2], p[3], p[4], p[5], p[0]);
            var fields = await decryptFields(pw, pw2, p[2], p[3], p[6], p[7], p[8], p[9], p[10]);
            results[i] = await handler(rows[i], name, fields, i);
        } catch (e) {
            if (failed === null) failed = { index: i, error: e };
            return false;
        }
        done++;
        if (progressCb) progressCb(done, rows.length);
    });
    if (failed) {
        throw new Error('record ' + (failed.index + 1) + ' of ' + rows.length
                        + ' failed to decrypt (wrong passwords?)');
    }
    return results;
}

// Decrypt all payloads locally and flag reused / weak / fair / empty passwords.
// Renders entry names only — never the passwords themselves. No network I/O.
async function auditVault(btn) {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var out    = document.getElementById('audit-result');
    var locked = document.getElementById('audit-locked');
    if (!out) return;
    if (!_isVaultUnlocked()) {
        out.style.display = 'none';
        if (locked) locked.style.display = '';
        return;
    }
    if (locked) locked.style.display = 'none';
    out.style.display = '';
    if (!_allEntries.length) { out.textContent = 'Vault is empty.'; return; }

    out.textContent = 'Auditing… 0 / ' + _allEntries.length;
    if (btn) btn.disabled = true;
    var items;
    try {
        items = await _forEachRecordDecrypt(pw, pw2, function(rec, name, fields) {
            return {
                name: name,
                isNote: fields.type === 'note',
                password: (fields.password || '').trim(),
                pwModified: (typeof fields.pwModified === 'number') ? fields.pwModified : null,
                hasPasskey: !!(fields.passkey && fields.passkey.rpId)
            };
        }, function(done, total) {
            out.textContent = 'Auditing… ' + done + ' / ' + total;
        });
    } catch (e) {
        out.textContent = 'Audit failed — ' + e.message;
        return;
    } finally {
        if (btn) btn.disabled = false;
    }

    var byPassword = new Map();
    var weak = [], fair = [], empty = [], old = [];
    var ageCut = Math.floor(Date.now() / 1000) - _PW_AGE_WARN_DAYS * 86400;
    items.forEach(function(it) {
        // A secure note has no password to audit — skip it entirely.
        if (it.isNote) return;
        // Password age: only entries that carry a pwModified stamp can be aged
        // (legacy entries get one the next time they're saved).
        if (it.pwModified && it.pwModified < ageCut) old.push(it.name);
        // A passkey-only entry legitimately has no password — don't flag it as empty.
        if (!it.password) { if (!it.hasPasskey) empty.push(it.name); return; }
        var bits = _estimateBits(it.password);
        if (bits < 40) weak.push(it.name);
        else if (bits < 80) fair.push(it.name);
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
    if (!reused.length && !weak.length && !fair.length && !empty.length && !old.length) {
        addLine('✓ No reused, weak, fair, empty, or stale passwords across '
                + items.length + ' entries.', 'audit-ok');
        return;
    }
    reused.forEach(function(names) {
        addLine('⚠︎ Same password on ' + names.length + ' entries: '
                + names.join(', '), 'audit-bad');
    });
    if (weak.length)  addLine('⚠︎ Weak (under 40 bits): ' + weak.join(', '), 'audit-warn');
    if (fair.length)  addLine('⚠︎ Fair (40–80 bits): ' + fair.join(', '), 'audit-warn');
    if (empty.length) addLine('— No password stored: ' + empty.join(', '), 'audit-warn');
    if (old.length)   addLine('⏱ Not changed in over a year: ' + old.join(', '), 'audit-warn');
}

// Inventory of stored passkeys: decrypt every payload locally and list the
// entries whose payload carries a passkey sub-object (name + rpId only — never
// any key material). Mirrors auditVault()'s locked-check + _forEachRecordDecrypt
// pattern. The PWA only views/deletes passkeys; creation + signing live in the
// browser extensions.
async function listPasskeys(btn) {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var out    = document.getElementById('passkey-result');
    var locked = document.getElementById('passkey-locked');
    if (!out) return;
    if (!_isVaultUnlocked()) {
        out.style.display = 'none';
        if (locked) locked.style.display = '';
        return;
    }
    if (locked) locked.style.display = 'none';
    out.style.display = '';
    if (!_allEntries.length) { out.textContent = 'Vault is empty.'; return; }

    out.textContent = 'Scanning… 0 / ' + _allEntries.length;
    if (btn) btn.disabled = true;
    var items;
    try {
        items = await _forEachRecordDecrypt(pw, pw2, function(rec, name, fields) {
            var pk = fields.passkey;
            if (!pk || !pk.rpId) return null;
            return { name: name, rpId: pk.rpId, createdAt: pk.createdAt || null };
        }, function(done, total) {
            out.textContent = 'Scanning… ' + done + ' / ' + total;
        });
    } catch (e) {
        out.textContent = 'Passkey scan failed — ' + e.message;
        return;
    } finally {
        if (btn) btn.disabled = false;
    }

    var found = items.filter(function(it) { return it; });
    out.textContent = '';
    if (!found.length) {
        var none = document.createElement('div');
        none.className = 'audit-line audit-ok';
        none.textContent = 'No passkeys stored in this vault.';
        out.appendChild(none);
        return;
    }

    var hdr = document.createElement('div');
    hdr.className = 'pk-hdr';
    var icon = document.createElement('span');
    icon.className = 'pk-hdr-icon';
    icon.textContent = '🔐';
    var cnt = document.createElement('span');
    cnt.textContent = found.length + (found.length === 1 ? ' passkey stored' : ' passkeys stored');
    hdr.appendChild(icon);
    hdr.appendChild(cnt);
    out.appendChild(hdr);

    found.forEach(function(it) {
        var row = document.createElement('div');
        row.className = 'pk-row';
        var info = document.createElement('div');
        info.className = 'pk-info';
        var nm = document.createElement('span');
        nm.className = 'pk-name';
        nm.textContent = it.name;
        var meta = document.createElement('span');
        meta.className = 'pk-meta';
        var when = it.createdAt ? new Date(it.createdAt) : null;
        meta.textContent = it.rpId
            + (when && !isNaN(when.getTime()) ? ' · created ' + when.toLocaleDateString() : '');
        info.appendChild(nm);
        info.appendChild(meta);
        row.appendChild(info);
        out.appendChild(row);
    });
}

// ── Trash (soft delete) ─────────────────────────────────────────────────────
// Deleted entries are kept server-side in `trash` (see post.php). This lists them
// (names decrypted locally), and restores or permanently purges them. Both
// passwords are required to read the names.
var _trashBusy = false;
async function openTrash() {
    var out    = document.getElementById('trash-result');
    var locked = document.getElementById('trash-locked');
    if (!out) return;
    if (!_isVaultUnlocked()) {
        out.style.display = 'none';
        if (locked) locked.style.display = '';
        return;
    }
    if (locked) locked.style.display = 'none';
    out.style.display = '';
    if (_trashBusy) return;
    _trashBusy = true;
    out.textContent = 'Loading trash…';
    try {
        var resp = JSON.parse(await _xhrPost('trash=1'));
        var rows = (resp && Array.isArray(resp.trash)) ? resp.trash : [];
        await _renderTrash(rows);
    } catch (e) {
        out.textContent = 'Could not load trash — ' + e.message;
    } finally {
        _trashBusy = false;
    }
}

async function _renderTrash(rows) {
    var out = document.getElementById('trash-result');
    if (!out) return;
    out.textContent = '';
    if (!rows.length) { out.textContent = 'Trash is empty.'; return; }

    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;

    var hdr = document.createElement('div');
    hdr.className = 'trash-hdr';
    var cnt = document.createElement('span');
    cnt.textContent = rows.length + (rows.length === 1 ? ' deleted entry' : ' deleted entries');
    var emptyBtn = document.createElement('button');
    emptyBtn.className = 'btn btn-ghost';
    emptyBtn.textContent = '🗑 Empty Trash';
    emptyBtn.onclick = function() { _emptyTrash(); };
    hdr.appendChild(cnt);
    hdr.appendChild(emptyBtn);
    out.appendChild(hdr);

    // Decrypt every trashed entry's name (worker pool throttles the Argon2id work);
    // a wrong key / corrupt record leaves a locked placeholder rather than failing.
    await Promise.all(rows.map(async function(item) {
        try {
            var p = item.record.split('|');
            item._name = await decryptName(pw, pw2, p[2], p[3], p[4], p[5], p[0]);
        } catch (_) {
            item._name = '🔒 (locked)';
        }
    }));

    rows.forEach(function(item) {
        var locked = item._name === '🔒 (locked)';
        var row = document.createElement('div');
        row.className = 'trash-row';
        var info = document.createElement('div');
        info.className = 'trash-info';
        var nm = document.createElement('span');
        nm.className = 'trash-name';
        nm.textContent = item._name;
        var dt = document.createElement('span');
        dt.className = 'trash-date';
        dt.textContent = 'deleted ' + _fmtDate(item.ts);
        info.appendChild(nm);
        info.appendChild(dt);
        var restore = document.createElement('button');
        restore.className = 'btn-sm';
        restore.textContent = 'Restore';
        restore.onclick = function() { _restoreTrash(item.record, locked ? null : item._name); };
        var del = document.createElement('button');
        del.className = 'btn-sm trash-del';
        del.textContent = 'Delete';
        del.title = 'Delete permanently';
        del.onclick = function() {
            if (confirm('Permanently delete ' + (locked ? 'this entry' : '"' + item._name + '"')
                        + '? This cannot be undone.')) _purgeTrash(item.record);
        };
        row.appendChild(info);
        row.appendChild(restore);
        row.appendChild(del);
        out.appendChild(row);
    });
}

function _restoreTrash(record, name) {
    if (name) _v5Names.set(record, name);   // pre-seed for instant reveal
    _xhrPost('untrash_rec=' + encodeURIComponent(record))
        .then(function(text) {
            try { if (_applyServerResponse(text)) _revealCachedV5Buttons(); }
            catch (_) { location.reload(); return; }
            _signAfterWrite();
            showToast('Restored "' + (name || 'entry') + '"');
            openTrash();
        })
        .catch(function(e) {
            if (e.stale) {
                showToast('Vault changed elsewhere — reloading');
                setTimeout(function() { location.reload(); }, 1200);
                return;
            }
            showToast('Restore failed — ' + e.message);
        });
}

function _purgeTrash(record) {
    _xhrPost('purge_trash=' + encodeURIComponent(record))
        .then(function() { showToast('Permanently deleted'); openTrash(); })
        .catch(function(e) { showToast('Delete failed — ' + e.message); });
}

function _emptyTrash() {
    if (!confirm('Permanently delete everything in the trash? This cannot be undone.')) return;
    _xhrPost('purge_trash=__all__')
        .then(function() { showToast('Trash emptied'); openTrash(); })
        .catch(function(e) { showToast('Empty trash failed — ' + e.message); });
}

// True only when both key fields are filled AND those passwords have already
// unlocked the vault (a successful reveal-all with the same pair). An empty
// vault counts as unlocked once both passwords are present — there is nothing
// to reveal. Used to gate Audit and Change Passwords, which both need a
// known-good password pair before they decrypt the whole vault.
function _isVaultUnlocked() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!pw || !pw2) return false;
    if (!_allEntries.length) return true;
    return _lastRevealPw === pw && _lastRevealPw2 === pw2;
}

function toggleChangePw() {
    var f = document.getElementById('chpw-form');
    if (!f) return;
    var locked  = document.getElementById('chpw-locked');
    var visible = f.style.display !== 'none' || (locked && locked.style.display !== 'none');
    if (visible) {
        f.style.display = 'none';
        if (locked) locked.style.display = 'none';
        return;
    }
    if (!_isVaultUnlocked()) {
        if (locked) locked.style.display = '';
        return;
    }
    if (locked) locked.style.display = 'none';
    f.style.display = '';
    updateChpwMatch();
    var first = document.getElementById('newpw1');
    first.focus();
    first.select();
    // Scroll the form fully into view so the Re-encrypt (submit) button at
    // its bottom isn't left below the fold of the About modal.
    var btn = document.getElementById('btn-chpw-go');
    if (btn && btn.scrollIntoView) btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Show/hide the plaintext of the four new-password fields in the Change
// Passwords form, driven by the #chpw-show checkbox.
function toggleChpwShow(cb) {
    var show = cb ? cb.checked : false;
    ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.type = show ? 'text' : 'password';
    });
}

// Shared whole-vault re-encrypt + atomic bulk-replace core, used by both Change
// Passwords and Change KDF Parameters. Decrypts every record with the dec*
// passwords (at the active _vaultKdf), re-encrypts each with the enc* passwords
// and `opts.kdf` (fresh salts/nonces per record), then commits one bulk write.
// The server verifies a SHA-256 of the snapshot we re-encrypted and refuses (409)
// if `lines` changed meanwhile, so a concurrent write can never be lost and the
// vault is never half-rewritten. `opts.onCommitted` runs after the write succeeds
// but before the name-cache reseed/reveal, so the caller can switch session state
// (new passwords, or the new KDF cost) at exactly the right moment. Returns
// { reloaded } — when true the page is navigating away and the caller must bail.
// Throws on failure (err.stale === true on a 409); nothing is changed in that case.
async function _reencryptVault(opts) {
    var statusEl = opts.statusEl;
    function say(m) { if (statusEl) statusEl.textContent = m; }
    var total = _allEntries.length;
    say('Re-encrypting… 0 / ' + total);
    var pairs = await _forEachRecordDecrypt(opts.decPw1, opts.decPw2, async function(rec, name, fields) {
        var s1 = crypto.getRandomValues(new Uint8Array(32));
        var s2 = crypto.getRandomValues(new Uint8Array(32));
        var ne = await encryptName(opts.encPw1, opts.encPw2, s1, s2, name, opts.kdf);
        var rf = await encryptFields(opts.encPw1, opts.encPw2, s1, s2, fields, opts.kdf);
        return { newRec: _assembleRecord(ne, rf, s1, s2), name: name };
    }, function(done) { say('Re-encrypting… ' + done + ' / ' + total); });

    // expect_hash over the snapshot we just re-encrypted — same canonical join
    // post.php uses (records minus trailing index, "\n"-joined, no trailing NL).
    var expectHash = (await _currentVaultHash()).hash;

    say('Saving…');
    var body = 'bulk=1&expect_hash=' + expectHash
             + '&bulk_data=' + encodeURIComponent(pairs.map(function(p) { return p.newRec; }).join('\n'));
    if (opts.kdf) body += '&kdf=' + encodeURIComponent(_kdfToString(opts.kdf));
    var responseText = await _xhrPost(body);

    // Committed server-side — let the caller switch session state first.
    if (opts.onCommitted) opts.onCommitted();

    // Pre-seed the name cache so the rebuilt grid reveals instantly.
    _v5Names.clear();
    pairs.forEach(function(p) { _v5Names.set(p.newRec, p.name); });
    clearDisplay();
    try { _applyServerResponse(responseText); } catch (_) { location.reload(); return { reloaded: true }; }
    _revealCachedV5Buttons();
    _signAfterWrite();
    // Old-key ciphertext cleanup: `trash` still holds records encrypted under the
    // pre-change passwords/cost. After a password change that is exactly the
    // material the change was meant to retire, and in both flows restoring such a
    // record would re-add an entry the current keys can no longer decrypt (a
    // trap). Empty it now, best-effort — the re-encrypt itself already committed.
    // (Server-side bak/ also retains pre-change snapshots for up to
    // VAULT_BAK_MAX_AGE_DAYS; the callers surface that in their status line.)
    _xhrPost('purge_trash=__all__').catch(function() {});
    return { reloaded: false };
}

// Re-encrypt the whole vault under new master passwords (see _reencryptVault).
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
        var r = await _reencryptVault({
            decPw1: pw, decPw2: pw2, encPw1: n1, encPw2: n2, statusEl: status,
            onCommitted: function() {
                // Switch this session to the new passwords before the cache reseed,
                // so the reveal (and the re-sign under the NEW passwords — old
                // manifest salts reused, revision chain unbroken) use the new keys.
                document.getElementById('aeskey').value  = n1;
                document.getElementById('aeskey2').value = n2;
                _mkCache.clear();
                _lastRevealPw  = null;
                _lastRevealPw2 = null;
            }
        });
        if (r.reloaded) return;
        ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
            document.getElementById(id).value = '';
        });
        say('');
        toggleChangePw();
        // Trash was emptied by _reencryptVault (old-key records); bak/ is
        // server-side only, so tell the operator it still holds old-key copies.
        showToast('Master passwords changed — ' + total + ' entries re-encrypted. Trash emptied; '
                  + 'server bak/ keeps pre-change backups readable with the OLD passwords for up '
                  + 'to 60 days (VAULT_BAK_MAX_AGE_DAYS) — delete them if those are compromised.',
                  { duration: 12000 });
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

// The five device-class presets shown in the Change KDF Parameters table, in
// slider order (index 1..5). Each preset's mem (MiB) + iterations mirror a row
// of the #about-kdf table so the slider and the table stay in lockstep.
var _KDF_PRESETS = [
    { mem: 64,   time: 3, label: 'Small portable' },
    { mem: 128,  time: 3, label: 'Laptop / desktop' },
    { mem: 256,  time: 4, label: 'Modern desktop' },
    { mem: 512,  time: 4, label: 'Large workstation' },
    { mem: 1024, time: 5, label: 'Workstation, max' }
];

// Slider index (1-based) for a given mem/iterations pair: an exact match if the
// params sit on a preset, else the nearest preset by memory (so the slider still
// lands somewhere sensible after a manual edit or a non-preset vault cost).
function _kdfPresetIndexFor(memMiB, iters) {
    for (var i = 0; i < _KDF_PRESETS.length; i++) {
        if (_KDF_PRESETS[i].mem === memMiB && _KDF_PRESETS[i].time === iters) return i + 1;
    }
    var best = 0, bestDiff = Infinity;
    for (var j = 0; j < _KDF_PRESETS.length; j++) {
        var d = Math.abs(_KDF_PRESETS[j].mem - memMiB);
        if (d < bestDiff) { bestDiff = d; best = j; }
    }
    return best + 1;
}

// Apply slider preset `idx` (1-based) to the mem/iterations number inputs and
// refresh the slider's text label.
function _kdfSliderApply(idx) {
    var p = _KDF_PRESETS[idx - 1];
    if (!p) return;
    var memEl = document.getElementById('kdf-mem');
    var tEl   = document.getElementById('kdf-time');
    if (memEl) memEl.value = p.mem;
    if (tEl)   tEl.value   = p.time;
    var lbl = document.getElementById('kdf-slider-lbl');
    if (lbl) lbl.textContent = p.label + ' — ' + p.mem + ' MiB, ' + p.time + ' iter';
}

// Sync the slider position + label to the current mem/iterations input values.
function _kdfSyncSlider() {
    var memEl = document.getElementById('kdf-mem');
    var tEl   = document.getElementById('kdf-time');
    var idx = _kdfPresetIndexFor(
        parseInt(memEl && memEl.value, 10) || 128,
        parseInt(tEl && tEl.value, 10) || 3
    );
    var slider = document.getElementById('kdf-slider');
    if (slider) slider.value = String(idx);
    var lbl = document.getElementById('kdf-slider-lbl');
    var p = _KDF_PRESETS[idx - 1];
    if (lbl && p) lbl.textContent = p.label + ' — ' + p.mem + ' MiB, ' + p.time + ' iter';
}

// Show/hide the Change KDF Parameters form, gating on a successfully unlocked
// vault (same gate as Change Passwords). Pre-fills the inputs with the active
// vault params each time it opens.
function toggleChangeKdf() {
    var f = document.getElementById('kdf-form');
    if (!f) return;
    var locked  = document.getElementById('kdf-locked');
    var visible = f.style.display !== 'none' || (locked && locked.style.display !== 'none');
    if (visible) {
        f.style.display = 'none';
        if (locked) locked.style.display = 'none';
        return;
    }
    if (!_isVaultUnlocked()) {
        if (locked) locked.style.display = '';
        return;
    }
    if (locked) locked.style.display = 'none';
    // Pre-fill from the active params (memory shown in MiB).
    var memEl = document.getElementById('kdf-mem');
    var tEl   = document.getElementById('kdf-time');
    if (memEl) memEl.value = Math.round(_vaultKdf.memorySize / 1024);
    if (tEl)   tEl.value   = _vaultKdf.iterations;
    _kdfSyncSlider();
    f.style.display = '';
    var btn = document.getElementById('btn-kdf-go');
    if (btn && btn.scrollIntoView) btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Benchmark Argon2id on THIS device and suggest an iteration count that lands
// near a target wall-clock time, holding the chosen memory fixed. Argon2id cost
// is ~linear in iterations, so we time one hash at the minimum t and scale up.
// Writes the suggestion into the mem/iterations inputs (the user still presses
// Re-encrypt). Uses the in-process argon2idHash (single derivation = single
// thread, which matches the per-record cost the user actually pays).
async function _kdfCalibrate() {
    var status = document.getElementById('kdf-cal-status');
    function say(m) { if (status) status.textContent = m; }
    var btn = document.getElementById('btn-kdf-cal');

    var memMiB = parseInt(document.getElementById('kdf-mem').value, 10);
    if (!isFinite(memMiB)) memMiB = Math.round(_vaultKdf.memorySize / 1024);
    memMiB = Math.min(KDF_MEM_MAX_KIB / 1024, Math.max(KDF_MEM_MIN_KIB / 1024, memMiB));
    var targetMs = parseInt(document.getElementById('kdf-target').value, 10);
    if (!isFinite(targetMs) || targetMs < 100) targetMs = 500;

    if (typeof argon2idHash !== 'function') { say('Argon2id is not available in this browser.'); return; }
    if (btn) btn.disabled = true;
    say('Benchmarking at ' + memMiB + ' MiB…');
    try {
        var pw   = new TextEncoder().encode('calibration-benchmark');
        var salt = crypto.getRandomValues(new Uint8Array(32));
        var memKiB = memMiB * 1024;
        var opts = { iterations: KDF_TIME_MIN, memorySize: memKiB, parallelism: 1, hashLength: 32 };
        // Warm-up run (compiles/primes the WASM) is discarded; then a timed run.
        await argon2idHash(pw, salt, opts);
        var t0 = performance.now();
        await argon2idHash(pw, salt, opts);
        var perIter = (performance.now() - t0) / KDF_TIME_MIN;

        var iters = Math.round(targetMs / perIter);
        iters = Math.min(KDF_TIME_MAX, Math.max(KDF_TIME_MIN, iters));
        document.getElementById('kdf-mem').value  = memMiB;
        document.getElementById('kdf-time').value = iters;
        _kdfSyncSlider();
        var est = Math.round(perIter * iters);
        say('Suggested: ' + memMiB + ' MiB, ' + iters + ' iter (~' + est + ' ms per derivation here). '
            + 'Adjust memory and re-Calibrate, then Re-encrypt.');
    } catch (e) {
        say('Calibration failed — ' + (e && e.message ? e.message : e));
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Re-encrypt the whole vault at a new Argon2id cost. Identical shape to
// changeMasterPasswords (same atomic bulk replace + 409 staleness handling), but
// the passwords are unchanged: each record is decrypted with the OLD params
// (the default in _forEachRecordDecrypt → _vaultKdf) and re-encrypted with the
// NEW params, fresh salts/nonces. The new params ride along in the bulk write so
// `lines` and `kdfparams` change atomically; the manifest is re-signed at the new
// cost afterwards (so integrity follows, and a later downgrade is detectable).
async function changeKdfParams() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    var status = document.getElementById('kdf-status');
    function say(msg) { if (status) status.textContent = msg; }

    if (!_isVaultUnlocked()) { say('Enter both passwords and unlock the vault first.'); return; }
    if (!_allEntries.length) { say('Vault is empty — nothing to re-encrypt.'); return; }

    var memMiB = parseInt(document.getElementById('kdf-mem').value, 10);
    var iters  = parseInt(document.getElementById('kdf-time').value, 10);
    if (!isFinite(memMiB) || !isFinite(iters)) { say('Enter valid numbers for memory and iterations.'); return; }
    var newKdf = _parseKdf('a2id|' + (memMiB * 1024) + '|' + iters + '|1');
    if (!newKdf) {
        say('Out of range — memory ' + (KDF_MEM_MIN_KIB / 1024) + '–' + (KDF_MEM_MAX_KIB / 1024)
            + ' MiB, iterations ' + KDF_TIME_MIN + '–' + KDF_TIME_MAX + '.');
        return;
    }
    if (newKdf.memorySize === _vaultKdf.memorySize && newKdf.iterations === _vaultKdf.iterations) {
        say('Those are already the current parameters.'); return;
    }

    var oldKdf = _vaultKdf;
    var btn = document.getElementById('btn-kdf-go');
    if (btn) btn.disabled = true;
    var total = _allEntries.length;
    try {
        // Records are decrypted at the OLD cost (the _vaultKdf default inside
        // _reencryptVault → _forEachRecordDecrypt) and re-encrypted at newKdf,
        // which also rides the bulk write so lines + kdfparams change atomically.
        var r = await _reencryptVault({
            decPw1: pw, decPw2: pw2, encPw1: pw, encPw2: pw2, kdf: newKdf, statusEl: status,
            onCommitted: function() {
                // Passwords unchanged, so the reveal throttle stays valid; only
                // the cost switches. Done after decrypt completes (decrypt used
                // the old cost) and before the reseed/re-sign (which use the new).
                _vaultKdf = newKdf;
                _mkCache.clear();       // every cached key was derived at the old cost
                _terminateArgonPool();  // rebuild the worker pool sized for the new memory cost
            }
        });
        if (r.reloaded) return;
        say('');
        toggleChangeKdf();
        // Trash was emptied by _reencryptVault: its records were encrypted at the
        // OLD cost, so restoring one would fail to decrypt at the new params.
        showToast('KDF parameters changed — ' + total + ' entries re-encrypted. Trash emptied '
                  + '(old-cost records); server bak/ keeps pre-change backups up to 60 days.',
                  { duration: 8000 });
    } catch (e) {
        _vaultKdf = oldKdf;        // nothing committed — restore the active cost
        if (e.stale) {
            say('The vault changed while re-encrypting — nothing was modified. Close, reload, and retry.');
        } else {
            say('KDF change failed — ' + e.message + '. The vault was not modified.');
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
    var auditLocked = document.getElementById('audit-locked');
    if (auditLocked) auditLocked.style.display = 'none';
    var pkOut = document.getElementById('passkey-result');
    if (pkOut) { pkOut.textContent = ''; pkOut.style.display = 'none'; }
    var pkLocked = document.getElementById('passkey-locked');
    if (pkLocked) pkLocked.style.display = 'none';
    ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) { el.value = ''; el.type = 'password'; }
    });
    var showCb = document.getElementById('chpw-show');
    if (showCb) showCb.checked = false;
    updateChpwStrength();
    updateChpwMatch();
    var f = document.getElementById('chpw-form');
    if (f) f.style.display = 'none';
    var locked = document.getElementById('chpw-locked');
    if (locked) locked.style.display = 'none';
    var status = document.getElementById('chpw-status');
    if (status) status.textContent = '';
    var imp = document.getElementById('import-status');
    if (imp) { imp.textContent = ''; imp.style.display = 'none'; }
    var kf = document.getElementById('kdf-form');
    if (kf) kf.style.display = 'none';
    var kl = document.getElementById('kdf-locked');
    if (kl) kl.style.display = 'none';
    var ks = document.getElementById('kdf-status');
    if (ks) ks.textContent = '';
    var tr = document.getElementById('trash-result');
    if (tr) { tr.textContent = ''; tr.style.display = 'none'; }
    var tl = document.getElementById('trash-locked');
    if (tl) tl.style.display = 'none';
}

// ============================================================
// Vault integrity manifest (vm2; vm1 still verified for migration)
//
// A keyed signature over the whole record set, stored server-side as the
// `manifest` file and embedded in index.html (#vault-manifest):
//
//   vm2|salt1HEX|salt2HEX|revision|timestamp|kdf|hmacHEX   (current)
//   vm1|salt1HEX|salt2HEX|revision|timestamp|hmacHEX       (legacy, still parsed)
//
// hmac = HMAC-SHA-256(vaultKey, "vm2|salt1|salt2|revision|timestamp|kdf"
//                              + "\n" + sortedRecords.join("\n"))
// vaultKey = HKDF(Argon2id(pw1,salt1) || Argon2id(pw2,salt2), 'v6|manifest|hmac')
//
// vm2 binds `kdf` (the vault-wide Argon2id cost "a2id|m|t|p") into the signature,
// so a server that swaps the served #vault-kdf after signing is detected — both
// at verify time (the cost mismatch) and at load via _checkKdfBinding (password-
// free). The manifest keys derive at the *signed* cost, so verification does not
// trust the embedded params the server controls.
//
// The server stores it opaquely and can never forge it (no passwords). Verified
// on unlock (after reveal-all); re-signed automatically after every successful
// write (always as vm2). `revision` is monotonic — each device keeps a high-water
// mark in localStorage, so serving an older-but-validly-signed vault (rollback) is
// detected too. Detection only: a compromised server can still serve modified
// JS — this guards `lines`/params integrity, not the code itself.
// ============================================================

var _manifest    = null;    // current manifest string, as served
var _signPending = false;   // suppress verify while a post-write sign is in flight

// Per-instance localStorage key (multiple vaults can share this host).
function _revStoreKey() {
    return 'vaultRev:' + location.pathname.replace(/index\.html$/, '');
}

// localStorage can throw (private browsing) — degrade to no rollback memory.
function _revGet() {
    try { return parseInt(localStorage.getItem(_revStoreKey()) || '0', 10) || 0; }
    catch (_) { return 0; }
}
function _revSet(n) {
    try { localStorage.setItem(_revStoreKey(), String(n)); } catch (_) {}
}

// Accepts both manifest versions:
//   vm1  | salt1 | salt2 | revision | timestamp | hmac            (legacy, 6 fields)
//   vm2  | salt1 | salt2 | revision | timestamp | kdf | hmac      (7 fields; binds the cost)
// vm2 carries the Argon2id params it was signed under, so verification can derive
// at the *signed* cost (decoupled from the possibly-tampered embedded #vault-kdf)
// and flag a server that swapped the served params. vm1 is still parsed so a vault
// signed before this change keeps verifying; the next write re-signs it as vm2.
function _parseManifest(s) {
    if (typeof s !== 'string' || s === '') return null;
    var p = s.split('|');
    if (p[0] === 'vm1') {
        if (p.length !== 6) return null;
        if (!/^[0-9a-f]{64}$/.test(p[1]) || !/^[0-9a-f]{64}$/.test(p[2])) return null;
        if (!/^\d{1,15}$/.test(p[3])    || !/^\d{1,15}$/.test(p[4]))    return null;
        if (!/^[0-9a-f]{64}$/.test(p[5])) return null;
        return { version: 'vm1', salt1Hex: p[1], salt2Hex: p[2], revision: parseInt(p[3], 10),
                 timestamp: parseInt(p[4], 10), kdfStr: null, hmacHex: p[5] };
    }
    if (p[0] === 'vm2') {
        // The kdf field is itself "a2id|m|t|p" (4 pipe-separated tokens), so a vm2
        // manifest splits into 10 fields; the kdf occupies indices 5–8.
        if (p.length !== 10) return null;
        if (!/^[0-9a-f]{64}$/.test(p[1]) || !/^[0-9a-f]{64}$/.test(p[2])) return null;
        if (!/^\d{1,15}$/.test(p[3])    || !/^\d{1,15}$/.test(p[4]))    return null;
        var kdfStr = p.slice(5, 9).join('|');
        if (!_parseKdf(kdfStr))           return null;
        if (!/^[0-9a-f]{64}$/.test(p[9])) return null;
        return { version: 'vm2', salt1Hex: p[1], salt2Hex: p[2], revision: parseInt(p[3], 10),
                 timestamp: parseInt(p[4], 10), kdfStr: kdfStr, hmacHex: p[9] };
    }
    return null;
}

// Records in canonical server form: trailing line index stripped, sorted —
// exactly the byte sequence post.php hashes and stores (records are ASCII, so
// the default JS sort matches PHP's SORT_STRING ordering).
function _canonicalRecords() {
    return _allEntries.map(function(row) {
        return row.split('|').slice(0, -1).join('|');
    }).sort();
}

async function _sha256Hex(str) {
    var buf = await crypto.subtle.digest('SHA-256', _TE.encode(str));
    return bytesToHex(new Uint8Array(buf));
}

// Constant-time equality of two equal-length hex strings. Marginal value here —
// the manifest HMAC compare runs client-side with no remotely observable timing
// channel, and forging a manifest needs the password-derived vaultKey anyway —
// but it's cheap hygiene for the one place an attacker-influenced HMAC (from the
// served manifest) meets a locally derived one.
function _constTimeHexEq(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

// kdfStr selects the manifest version and the cost the manifest keys derive at:
//   null   → legacy vm1: derive at the active _vaultKdf, sign "vm1|s1|s2|rev|ts".
//   string → vm2: derive at the params named by kdfStr (its own declared cost) and
//            sign "vm2|s1|s2|rev|ts|kdf". Deriving at the declared cost is what
//            lets a verifier check a vm2 manifest without trusting the embedded
//            #vault-kdf the server can tamper.
async function _manifestHmacHex(pw, pw2, salt1Hex, salt2Hex, revision, timestamp, kdfStr, records) {
    var kdf = kdfStr ? (_parseKdf(kdfStr) || _vaultKdf) : _vaultKdf;
    var mks = await Promise.all([
        deriveMasterKey(pw,  hexToBytes(salt1Hex), kdf),
        deriveMasterKey(pw2, hexToBytes(salt2Hex), kdf)
    ]);
    var ikm = new Uint8Array(64);
    ikm.set(mks[0], 0);
    ikm.set(mks[1], 32);
    var keyBytes = await hkdfBytes(ikm, 'v6|manifest|hmac');
    var ck = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    var header = kdfStr
        ? 'vm2|' + salt1Hex + '|' + salt2Hex + '|' + revision + '|' + timestamp + '|' + kdfStr
        : 'vm1|' + salt1Hex + '|' + salt2Hex + '|' + revision + '|' + timestamp;
    var msg = header + '\n' + records.join('\n');
    var sig = await crypto.subtle.sign('HMAC', ck, _TE.encode(msg));
    return bytesToHex(new Uint8Array(sig));
}

// Lock or unlock the key input fields and their show/hide buttons.
// Locked after a successful integrity check; unlocked whenever the badge is cleared.
function _setKeyFieldsLocked(locked) {
    ['aeskey', 'aeskey2'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        // Cancel any "show" reveal before disabling so the cleartext password
        // is never left visible behind a locked field.
        if (locked && el._hide) el._hide();
        el.disabled = locked;
    });
    ['toggle-key', 'toggle-key2'].forEach(function(action) {
        var btn = document.querySelector('[data-action="' + action + '"]');
        if (btn) btn.disabled = locked;
    });
    _updateVaultKeyBar();
}

// Update both badge locations (entry-list line + About → Vault Tools).
// cls = 'vi-ok' | 'vi-warn' | 'vi-fail' | null (hide).
function _setIntegrityBadge(cls, text) {
    ['vault-integrity', 'integrity-status'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        if (!cls) { el.style.display = 'none'; el.textContent = ''; el.className = ''; return; }
        el.className     = cls;
        el.textContent   = text;
        el.style.display = '';
    });
    _setKeyFieldsLocked(cls === 'vi-ok');
}

// Password-free tamper check, run at load. A vm2 manifest names the Argon2id cost
// it was signed under; if the served #vault-kdf (what the client will actually
// derive at) no longer matches, the server altered the cost after signing. Worth
// flagging up front because a downgraded cost also makes every record fail to
// decrypt — which would otherwise read as a wrong password, not as tampering. No
// password is needed: it is a plain string compare of two embedded values.
function _checkKdfBinding() {
    var m = _parseManifest(_manifest);
    if (!m || m.version !== 'vm2') return;
    if (m.kdfStr !== _kdfToString(_vaultKdf)) {
        _setIntegrityBadge('vi-fail', '✖ KDF parameters altered — signed under ' + m.kdfStr
            + ', served as ' + _kdfToString(_vaultKdf));
        showToast('Vault KDF parameters were altered');
    }
}

// Verify the served manifest against the records on the page. Called after a
// successful reveal-all (the only point where both passwords are known-good).
async function _verifyManifest(pw, pw2) {
    if (_signPending) return;
    var gen     = _revealGen;
    var records = _canonicalRecords();
    var m       = _parseManifest(_manifest);
    var stored  = _revGet();
    if (!m) {
        if (stored > 0) {
            // This device has seen a signed vault before — a now-missing
            // manifest is itself a tampering signal, not a fresh install.
            _setIntegrityBadge('vi-fail', '✖ Manifest missing (this device last saw rev ' + stored + ')');
            showToast('Vault integrity manifest is missing!');
        } else {
            _setIntegrityBadge('vi-warn', '⚠︎ Vault not signed yet — use Sign in About → Vault Tools');
        }
        return;
    }
    var h;
    try {
        h = await _manifestHmacHex(pw, pw2, m.salt1Hex, m.salt2Hex, m.revision, m.timestamp, m.kdfStr, records);
    } catch (_) {
        return;   // derivation aborted (lock mid-check) — leave badge untouched
    }
    // Keys changed or a write landed while we were hashing — result is stale.
    if (gen !== _revealGen || _signPending) return;
    if (!_constTimeHexEq(h, m.hmacHex)) {
        _setIntegrityBadge('vi-fail', '✖ CHECK FAILED — Rev ' + m.revision + ' signature fail');
        showToast('Vault integrity check FAILED');
        return;
    }
    // vm2 binds the Argon2id cost it was signed under. The HMAC above verified at
    // that *declared* cost; if the cost the client will actually use (the embedded
    // #vault-kdf → _vaultKdf) differs, the server changed the served params after
    // signing — a downgrade/tamper the per-record AEAD can't catch.
    if (m.version === 'vm2' && m.kdfStr !== _kdfToString(_vaultKdf)) {
        _setIntegrityBadge('vi-fail', '✖ KDF parameters altered — signed under ' + m.kdfStr
            + ', served as ' + _kdfToString(_vaultKdf));
        showToast('Vault KDF parameters were altered');
        return;
    }
    if (m.revision < stored) {
        _setIntegrityBadge('vi-fail', '✖ Rollback detected — server has rev ' + m.revision + ', this device last saw rev ' + stored);
        showToast('Vault rollback detected');
        return;
    }
    _revSet(m.revision);
    _setIntegrityBadge('vi-ok', '✓ Verified · rev ' + m.revision + ' · ' + new Date(m.timestamp * 1000).toLocaleString());
}

// Sign the current record set and store the manifest server-side. Throws on
// failure; err.stale means another client wrote since our last sync.
async function _signVault(pw, pw2) {
    var records = _canonicalRecords();
    var old     = _parseManifest(_manifest);
    // Reuse the manifest salts when present so the two Argon2id master keys hit
    // _mkCache and signing is cheap; fresh salts only for a first-ever sign.
    var salt1Hex = old ? old.salt1Hex : bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    var salt2Hex = old ? old.salt2Hex : bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    var revision = (old ? old.revision : 0) + 1;
    // Stay monotonic past a restore: never sign below this device's high-water mark.
    var stored = _revGet();
    if (stored >= revision) revision = stored + 1;
    var ts     = Math.floor(Date.now() / 1000);
    // Bind the active vault-wide cost into the signature (always sign as vm2).
    var kdfStr = _kdfToString(_vaultKdf);
    var hmac = await _manifestHmacHex(pw, pw2, salt1Hex, salt2Hex, revision, ts, kdfStr, records);
    var manifest = ['vm2', salt1Hex, salt2Hex, String(revision), String(ts), kdfStr, hmac].join('|');
    var expect   = await _sha256Hex(records.join('\n'));
    await _xhrPost('sign=1&expect_hash=' + expect + '&manifest=' + encodeURIComponent(manifest));
    _manifest = manifest;
    _revSet(revision);
    _setIntegrityBadge('vi-ok', '✓ Signed · rev ' + revision + ' · ' + new Date(ts * 1000).toLocaleString());
}

// Re-sign after every successful write (save / delete / bulk). Fire-and-forget:
// failures surface on the badge, never block the write that already happened.
async function _signAfterWrite() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!pw || !pw2) return;
    _signPending = true;
    _setIntegrityBadge('vi-warn', '… signing');
    try {
        await _signVault(pw, pw2);
    } catch (e) {
        if (e.stale) {
            // Another client wrote between our write and our sign. Resync to
            // the server's current state and sign that instead — their record
            // change is included, nothing is lost.
            try {
                var text = await _xhrPost('regen=1');
                if (_applyServerResponse(text)) _revealCachedV5Buttons();
                await _signVault(pw, pw2);
            } catch (_) {
                _setIntegrityBadge('vi-warn', '⚠︎ Vault changed elsewhere — not signed (unlock again to re-check)');
            }
        } else {
            _setIntegrityBadge('vi-warn', '⚠︎ Sign failed — ' + e.message);
        }
    } finally {
        _signPending = false;
    }
}

// Manual sign from About → Vault Tools — the explicit acknowledgement path
// after a deliberate manual `lines` edit or a backup restore.
async function resignVault() {
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!pw || !pw2) { showToast('Enter both passwords first'); return; }
    if (!confirm('Sign the current vault contents as authentic?\n\nOnly do this after you have verified the entries — e.g. after a deliberate manual edit or a backup restore. It resets the integrity baseline.')) return;
    _signPending = true;
    try {
        await _signVault(pw, pw2);
        showToast('Vault signed');
    } catch (e) {
        showToast('Sign failed — ' + e.message);
        if (e.stale) setTimeout(function() { location.reload(); }, 1200);
    } finally {
        _signPending = false;
    }
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
    box.style.marginTop = ((fixedH + 8) / 2) + 'px';
    overlay.classList.add('open');
    var inp = document.getElementById('search-input');
    inp.value = '';
    filterSearch('');
    _palAfterRender();
    inp.focus();
}

function hideSearch() {
    document.getElementById('search-overlay').classList.remove('open');
}

// ── Command-palette additions (Ctrl-K) ──────────────────────────────
// The search overlay doubles as a command palette: fuzzy entry search +
// keyboard navigation + copy/edit chords + a ">" command mode. All of it
// reuses the existing decode/copy/edit paths — no new crypto.

// Subsequence fuzzy matcher → {hit, score} (higher score = better). A
// contiguous substring scores highest; otherwise every query char must
// appear in order, with bonuses for consecutive runs and word-boundary
// starts. Empty query matches everything (score 0).
function _fuzzyMatch(query, text) {
    var q = (query || '').toLowerCase();
    var t = (text  || '').toLowerCase();
    if (!q) return { hit: true, score: 0 };
    var sub = t.indexOf(q);
    if (sub !== -1) {
        var b = sub === 0 || /[^a-z0-9]/.test(t.charAt(sub - 1));
        return { hit: true, score: 10000 - sub + (b ? 500 : 0) };
    }
    var ti = 0, score = 0, prev = -2;
    for (var qi = 0; qi < q.length; qi++) {
        var c = q.charAt(qi);
        while (ti < t.length && t.charAt(ti) !== c) ti++;
        if (ti >= t.length) return { hit: false, score: 0 };
        if (ti === prev + 1) score += 8;                                   // consecutive
        if (ti === 0 || /[^a-z0-9]/.test(t.charAt(ti - 1))) score += 6;    // word boundary
        score += Math.max(0, 4 - ti / 8);                                  // earlier is better
        prev = ti;
        ti++;
    }
    return { hit: true, score: score };
}

// Global actions for ">" command mode. Each wires to an existing function /
// _clickActions handler. needUnlock entries are disabled while locked.
// Open the About modal, optionally run an action and scroll the relevant
// section into view inside #about-body. openAbout() resets the body to the top
// and an action's output renders into a section far down the modal, so without
// this the user lands on the modal header and sees nothing happen. Deferred to
// a double rAF so the open animation + layout (and openAbout's own scrollTop=0)
// settle before we scroll. openAbout() also focuses #about-body so the keyboard
// scrolls the modal — its focus runs first (preventScroll), then this scroll.
function _palAbout(targetId, fn) {
    openAbout();
    if (fn) fn();
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            var el = targetId && document.getElementById(targetId);
            if (el) el.scrollIntoView({ block: 'start', behavior: 'smooth' });
        });
    });
}

var _PALETTE_COMMANDS = [
    { label: 'New entry',                 hint: 'N', needUnlock: true, run: function() { var b = document.querySelector('[data-action="new-entry"]'); if (b && !b.disabled) newEntry(b); } },
    { label: 'Lock vault',                hint: 'X', run: function() { _lockAndClearVault(); } },
    { label: 'Toggle Group A–Z',          needUnlock: true, run: function() { var gt = document.getElementById('group-toggle'); if (gt) { gt.checked = !gt.checked; gt.dispatchEvent(new Event('change')); } } },
    { label: 'Toggle theme',              run: function() { toggleTheme(); } },
    { label: 'Toggle auto-lock',          run: function() { _palAbout('autolock-disable-toggle', function() { var alt = document.getElementById('autolock-disable-toggle'); if (alt) { alt.checked = !alt.checked; alt.dispatchEvent(new Event('change')); } }); } },
    { label: 'Export vault (.lines)',     needUnlock: true, run: function() { exportVault(); } },
    { label: 'Export CSV',                needUnlock: true, run: function() { exportVaultCSV(); } },
    { label: 'Import / Restore (.lines)', needUnlock: true, run: function() { _importVaultClick(); } },
    { label: 'Import CSV',                needUnlock: true, run: function() { _importCsvClick(); } },
    { label: 'Import KeePass (XML)',      needUnlock: true, run: function() { _pickImportFile('.xml,text/xml,application/xml', _importKeepassFile); } },
    { label: 'Import 1Password (.1pux)',  needUnlock: true, run: function() { _pickImportFile('.1pux,application/zip,application/octet-stream', _import1puxFile); } },
    { label: 'Audit passwords',           needUnlock: true, run: function() { _palAbout('audit-result', auditVault); } },
    { label: 'Passkeys',                  needUnlock: true, run: function() { _palAbout('passkey-result', listPasskeys); } },
    { label: 'Trash',                     needUnlock: true, run: function() { _palAbout('trash-result', openTrash); } },
    { label: 'Change passwords',          needUnlock: true, run: function() { _palAbout('chpw-form', toggleChangePw); } },
    { label: 'Change KDF parameters',     needUnlock: true, run: function() { _palAbout('about-kdf', toggleChangeKdf); } },
    { label: 'Sign vault',                needUnlock: true, run: function() { resignVault(); } },
    { label: 'Run crypto self-test',      run: function() { _palAbout('about-selftest', retestCrypto); } },
    { label: 'About',                     hint: 'A', run: function() { _palAbout(); } }
];

var _palItems = [];   // [{el, type:'entry'|'cmd', row?, cmd?}] — selectable rows, DOM order
var _palIndex = -1;   // active row in _palItems, or -1

function _palSyncHint(mode) {
    var el = document.getElementById('search-hint');
    if (!el) return;
    el.textContent = mode === 'command'
        ? '↑↓ navigate · ↵ run · esc close'
        : '↑↓ navigate · ↵ open · ⌘/^C copy pw · ⌘/^U user · ⌘/^E edit · > commands';
}

// Rebuild _palItems from whatever filterSearch just rendered (decouples
// keyboard nav from filterSearch's internals; called after every render).
function _palReindex() {
    _palItems = [];
    _palIndex = -1;
    var results = document.getElementById('search-results');
    if (!results) return;
    results.querySelectorAll('.entry-btn').forEach(function(b) {
        if (b.classList.contains('pal-disabled')) return;
        if (b.dataset.palRow !== undefined) _palItems.push({ el: b, type: 'entry', row: b.dataset.palRow });
        else if (b.dataset.palCmd !== undefined) _palItems.push({ el: b, type: 'cmd', cmd: _PALETTE_COMMANDS[+b.dataset.palCmd] });
    });
}

function _palSetActive(i) {
    if (_palIndex >= 0 && _palItems[_palIndex]) _palItems[_palIndex].el.classList.remove('pal-active');
    if (!_palItems.length) { _palIndex = -1; return; }
    if (i < 0) i = 0;
    if (i >= _palItems.length) i = _palItems.length - 1;
    _palIndex = i;
    var it = _palItems[_palIndex];
    it.el.classList.add('pal-active');
    it.el.scrollIntoView({ block: 'nearest' });
}

function _palMove(delta) {
    if (!_palItems.length) return;
    _palSetActive((_palIndex < 0 ? 0 : _palIndex + delta));
}

// Enter: just click the active row — entries reuse their existing onclick
// (decode + jump + scroll), commands reuse theirs (hideSearch + run).
function _palActivate() {
    if (_palIndex < 0 || !_palItems[_palIndex]) return;
    _palItems[_palIndex].el.click();
}

// ⌘/Ctrl chord on the active entry: decode it (reusing the search-result
// decode path), then copy a field / open edit.
function _palChord(action) {
    if (_palIndex < 0 || !_palItems[_palIndex]) return;
    var it = _palItems[_palIndex];
    if (it.type !== 'entry') return;
    _palEntryAction(it.row, action);
}

function _palEntryAction(row, action) {
    var gridBtn = _findGridBtn(row);
    hideSearch();
    Promise.resolve(decodeLine(gridBtn, row)).then(function() {
        if (action === 'edit') editEntry();
        else doCBCopy(action);   // 'password' | 'username'
    });
}

// Called after every filterSearch() render to refresh the hint bar and the
// keyboard-nav index + initial highlight.
function _palAfterRender() {
    var si = document.getElementById('search-input');
    var cmd = !!si && si.value.trim().charAt(0) === '>';
    _palSyncHint(cmd ? 'command' : 'entry');
    _palReindex();
    _palSetActive(0);
}

// ">" command mode: fuzzy-filter _PALETTE_COMMANDS into the results list.
function _renderCommandResults(q) {
    var results = document.getElementById('search-results');
    var countEl = document.getElementById('search-count');
    var unlocked = _isVaultUnlocked();
    var scored = [];
    _PALETTE_COMMANDS.forEach(function(cmd, i) {
        var m = _fuzzyMatch(q, cmd.label);
        if (m.hit) scored.push({ cmd: cmd, i: i, score: m.score });
    });
    scored.sort(function(a, b) {
        if (b.score !== a.score) return b.score - a.score;
        return a.cmd.label.localeCompare(b.cmd.label);
    });
    if (countEl) {
        countEl.textContent = '';
        var scopeEl = document.createElement('span');
        scopeEl.className   = 'search-scope';
        scopeEl.textContent = 'Commands';
        var countTxt = document.createElement('span');
        countTxt.textContent = scored.length + (scored.length === 1 ? ' command' : ' commands');
        countEl.appendChild(scopeEl);
        countEl.appendChild(countTxt);
    }
    if (!scored.length) {
        var msg = document.createElement('div');
        msg.id = 'search-no-match';
        msg.textContent = 'No commands';
        results.appendChild(msg);
        return;
    }
    scored.forEach(function(s) {
        var cmd = s.cmd;
        var disabled = !!cmd.needUnlock && !unlocked;
        var btn = document.createElement('button');
        btn.className = 'entry-btn pal-cmd';
        btn.title     = cmd.label;
        var gl = document.createElement('span');
        gl.className   = 'entry-avatar pal-cmd-glyph';
        gl.textContent = '›';
        gl.setAttribute('aria-hidden', 'true');
        btn.appendChild(gl);
        var lbl = document.createElement('span');
        lbl.className   = 'entry-btn-lbl';
        lbl.textContent = cmd.label;
        btn.appendChild(lbl);
        if (cmd.hint) {
            var h = document.createElement('span');
            h.className   = 'pal-cmd-hint';
            h.textContent = cmd.hint;
            btn.appendChild(h);
        }
        if (disabled) {
            btn.classList.add('pal-disabled');
            btn.disabled = true;
        } else {
            btn.dataset.palCmd = s.i;
            btn.onclick = function() { hideSearch(); cmd.run(); };
        }
        results.appendChild(btn);
    });
}

function filterSearch(query) {
    var results  = document.getElementById('search-results');
    var countEl  = document.getElementById('search-count');
    results.innerHTML = '';
    // A leading "#" searches tags, "@" searches notes, "!" searches custom fields
    // (all via the _searchText index, populated on reveal/decode); otherwise match
    // the entry name as before.
    var raw   = query.trim();
    var first = raw.charAt(0);
    // ">" → command mode (global actions); handled entirely by _renderCommandResults.
    if (first === '>') { _renderCommandResults(raw.slice(1).trim().toLowerCase()); return; }
    var mode  = first === '#' ? 'tags'
              : first === '@' ? 'notes'
              : first === '!' ? 'extra'
              : 'name';
    var q     = (mode === 'name' ? raw : raw.slice(1)).trim().toLowerCase();
    if (!q) {
        if (countEl) countEl.textContent = '';
        return;
    }
    var total   = _allEntries.length;
    var matched = _allEntries.filter(function(row) {
        var key = row.split('|').slice(0, -1).join('|');
        // Name search is fuzzy (subsequence); scoped searches stay substring.
        if (mode === 'name') return _fuzzyMatch(q, _v5Names.get(key) || '').hit;
        var idx = _searchText.get(key);
        return !!idx && (idx[mode] || '').indexOf(q) !== -1;
    });
    // Name mode: rank by fuzzy score (best first), display name as tiebreak.
    // Scoped modes: alphabetical by display name (locked 🔒 entries sink last).
    matched.sort(function(a, b) {
        var na = (_v5Names.get(a.split('|').slice(0, -1).join('|')) || '￿');
        var nb = (_v5Names.get(b.split('|').slice(0, -1).join('|')) || '￿');
        if (mode === 'name') {
            var sa = _fuzzyMatch(q, na).score, sb = _fuzzyMatch(q, nb).score;
            if (sb !== sa) return sb - sa;
        }
        return na.localeCompare(nb, undefined, { sensitivity: 'base' });
    });
    if (countEl) {
        var scope = mode === 'tags' ? 'tags'
                  : mode === 'notes' ? 'notes'
                  : mode === 'extra' ? 'custom fields'
                  : 'names';
        countEl.textContent = '';
        var scopeEl = document.createElement('span');
        scopeEl.className   = 'search-scope';
        scopeEl.textContent = 'Searching ' + scope + '…';
        var countTxt = document.createElement('span');
        countTxt.textContent = matched.length + ' of ' + total + (total === 1 ? ' entry' : ' entries');
        countEl.appendChild(scopeEl);
        countEl.appendChild(countTxt);
    }
    if (matched.length === 0) {
        var msg = document.createElement('div');
        msg.id = 'search-no-match';
        msg.textContent = 'No matches';
        results.appendChild(msg);
        return;
    }
    // When Group A–Z is on, insert sticky first-letter headers before each
    // letter run (same scheme as the main entry grid).
    var curKey = null;
    matched.forEach(function(row) {
        var parts = row.split('|');
        var displayName = _v5Names.get(parts.slice(0, -1).join('|')) || '🔒';
        // Group headers only make sense in alphabetical order; fuzzy name mode
        // is ranked by score, so skip them there (scoped modes stay grouped).
        if (_groupEntries && mode !== 'name' && displayName !== '🔒') {
            var key = _entryGroupKey(displayName);
            if (key !== curKey) {
                curKey = key;
                var h = document.createElement('div');
                h.className = 'entry-group-hdr';
                h.textContent = key;
                h.setAttribute('aria-hidden', 'true');
                results.appendChild(h);
            }
        }
        var btn = document.createElement('button');
        btn.className   = 'entry-btn';
        btn.title       = displayName;
        btn.dataset.palRow = row;   // keyboard-nav handle (see _palReindex)
        if (displayName !== '🔒') {
            var sav = document.createElement('span');
            sav.className   = 'entry-avatar';
            sav.textContent = _avatarLetter(displayName);
            sav.style.background = _avatarColor(displayName);
            sav.setAttribute('aria-hidden', 'true');
            btn.appendChild(sav);
        }
        var lbl = document.createElement('span');
        lbl.className   = 'entry-btn-lbl';
        lbl.textContent = displayName;
        btn.appendChild(lbl);
        btn.onclick = function() {
            // Selecting a search result should decode (and highlight/scroll-to)
            // the matching button in the main grid, not this disposable overlay
            // button — _selectBtn/blinkTD inside decodeLine only have lasting
            // effect on a button that's still in the DOM after hideSearch().
            var gridBtn = _findGridBtn(row);
            hideSearch();
            // Scroll only AFTER decodeLine resolves: it expands the decode panel
            // (notes/tags/custom-field rows) and re-sorts the grid, both of which
            // move things and call resizeFreezePane(). The gridBtn node reference
            // survives the re-sort (nodes are re-appended, not recreated), so it
            // still points at the right button afterward.
            //
            // The panel growth enlarges #content's margin-top — i.e. content
            // *above* the viewport grows — so the browser's scroll-anchoring adds
            // to scrollTop to keep the visible anchor stable. That adjustment lands
            // a frame later, *after* a scroll computed in this microtask, and being
            // positive it cancels an upward (negative) scroll — so the target stays
            // parked behind a tall panel when scrolling up (worse the taller the
            // panel). Defer to a double rAF so the margin change is laid out and
            // anchoring has settled before we measure + do the single smooth scroll;
            // nothing resizes after that, so the scroll lands and stays.
            Promise.resolve(decodeLine(gridBtn || btn, row)).then(function() {
                requestAnimationFrame(function() {
                    requestAnimationFrame(function() {
                        _scrollGridBtnIntoView(gridBtn);
                    });
                });
            });
        };
        results.appendChild(btn);
    });
}

// Locate the main-grid button for a given full record string (data-row is set
// verbatim from _allEntries, so an exact string match is sufficient).
function _findGridBtn(row) {
    var found = null;
    document.querySelectorAll('.entry-grid .entry-btn').forEach(function(b) {
        if (b.dataset.row === row) found = b;
    });
    return found;
}

// Native scrollIntoView has no notion of #fixedDiv (position:fixed, sits on
// top of the grid) or the sticky letter-group header, so a plain
// scrollIntoView({block:'nearest'}) can park the target right behind either —
// "selected but not scrolled to completely". Compute the obscured band
// ourselves and scroll just far enough that the button clears it.
function _scrollGridBtnIntoView(btn) {
    if (!btn) return;
    var wide    = document.body.classList.contains('wide-controls');
    var fixedDiv = document.getElementById('fixedDiv');
    // The fixed top band covers [0, panelH] full-width in BOTH layouts and the
    // grid (#content margin-top = panelH) scrolls under it: narrow = the panel
    // alone; wide = the panel on the left + the floated .ctrl-form on the right,
    // both height panelH. So the obscured band is the panel height either way —
    // using 0 in wide mode parked the target behind that band when scrolling up.
    var topGap  = fixedDiv ? fixedDiv.offsetHeight : 0;
    // Narrow mode pins group headers just below the panel (--sticky-top =
    // panelH), so add the pinned header height; wide mode pins them at 0 (behind
    // the band, --sticky-top = 0), so they add nothing to the visible band.
    var hdr     = document.querySelector('.entry-grid .entry-group-hdr');
    if (!wide && hdr) topGap += hdr.offsetHeight;
    var GAP  = 8;
    var rect = btn.getBoundingClientRect();
    if (rect.top < topGap + GAP) {
        window.scrollBy({ top: rect.top - topGap - GAP, behavior: 'smooth' });
    } else if (rect.bottom > window.innerHeight - GAP) {
        window.scrollBy({ top: rect.bottom - window.innerHeight + GAP, behavior: 'smooth' });
    }
}

// ============================================================
// About modal — runtime self-test
// ============================================================

// All six self-test status chips. Reset together to the loading state before a
// run so none keep a stale ✓/⚠ from a previous run (see openAbout/retestCrypto).
var _SELFTEST_IDS = ['st-webcrypto', 'st-chacha', 'st-aes', 'st-twofish', 'st-serpent', 'st-argon2'];

function _resetSelftestChips() {
    _SELFTEST_IDS.forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.className = 'selftest-status loading';
        el.textContent = '…';
        el.title = '';
    });
    var banner = document.getElementById('selftest-banner');
    if (banner) { banner.className = ''; banner.textContent = '… Running tests'; }
}

async function runCryptoSelfTest() {
    var PLAIN   = _TE.encode('CryptoSelfTest-OK');
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
        el.textContent = ok ? '✓' : '⚠︎';
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
            _TE.encode('argon2id-selftest'),
            _TE.encode('vault-selftest!!'),
            { iterations: 2, memorySize: 256, parallelism: 1, hashLength: 32 }
        );
        argonOk = bytesToHex(ah) === KAT;
    } catch (_) {}
    record('Argon2id (WASM)', 'st-argon2', argonOk, 'Argon2id WASM unavailable (CSP wasm-unsafe-eval?) or wrong output');

    // Overall banner
    var banner = document.getElementById('selftest-banner');
    if (banner) {
        banner.classList.remove('ok', 'fail');
        var stamp = new Date().toLocaleString();
        if (fail === 0) {
            banner.classList.add('ok');
            banner.textContent = '✓ Self-test passed — all ' + pass + ' checks OK · ' + stamp;
        } else {
            banner.classList.add('fail');
            banner.textContent = '⚠︎ Self-test: ' + fail + ' of ' + (pass + fail) +
                                 ' check' + (fail === 1 ? '' : 's') + ' failed · ' + stamp;
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
    _resetSelftestChips();
    var auditOut = document.getElementById('audit-result');
    if (auditOut) { auditOut.textContent = ''; auditOut.style.display = 'none'; }
    var auditLocked = document.getElementById('audit-locked');
    if (auditLocked) auditLocked.style.display = 'none';
    var pkOut = document.getElementById('passkey-result');
    if (pkOut) { pkOut.textContent = ''; pkOut.style.display = 'none'; }
    var pkLocked = document.getElementById('passkey-locked');
    if (pkLocked) pkLocked.style.display = 'none';
    var trashOut = document.getElementById('trash-result');
    if (trashOut) { trashOut.textContent = ''; trashOut.style.display = 'none'; }
    var trashLocked = document.getElementById('trash-locked');
    if (trashLocked) trashLocked.style.display = 'none';
    document.getElementById('about-overlay').classList.add('open');
    document.body.classList.add('modal-open');
    var aboutBody = document.getElementById('about-body');
    if (aboutBody) aboutBody.scrollTop = 0;
    _loadAboutVersion();
    _loadAboutKdf();
    runCryptoSelfTest();
    // Land the keyboard inside the modal so arrow keys / PageUp-Down / Home-End
    // scroll it. #about-body has tabindex="-1"; defer so the open animation +
    // the scrollTop=0 above settle first, and preventScroll so focusing doesn't
    // fight a scroll position a caller (e.g. _palAbout) set in the same frame.
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            var b = document.getElementById('about-body');
            if (b) b.focus({ preventScroll: true });
        });
    });
}

// Populate the Standards Alignment Argon2 line from the active vault-wide cost
// (_vaultKdf) so it tracks the Change KDF Parameters flow instead of a baked-in
// default. The HTML carries the default fallback for the offline/read-only copy.
function _loadAboutKdf() {
    var el = document.getElementById('std-argon-params');
    if (!el) return;
    var memMiB = Math.round(_vaultKdf.memorySize / 1024);
    el.innerHTML = 'm&nbsp;=&nbsp;' + memMiB + '&nbsp;MiB, t&nbsp;=&nbsp;' +
        _vaultKdf.iterations + ', p&nbsp;=&nbsp;' + _vaultKdf.parallelism;
}

// Populate the About modal's version line from the served PWA manifest so it
// stays in sync with manifest.json. The HTML carries a baked-in fallback, so the
// offline/read-only copy (no manifest fetch) still shows a version.
function _loadAboutVersion() {
    var el = document.getElementById('about-version');
    if (!el) return;
    fetch('manifest.json', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (m) { if (m && m.version) el.textContent = m.version; })
        .catch(function () { /* keep the baked-in fallback */ });
}

function closeAbout() {
    document.getElementById('about-overlay').classList.remove('open');
    document.body.classList.remove('modal-open');
    _hideAboutTip();
}

// About-modal tooltips. The CSS ::after tooltip is clipped by the modal's scroll
// container (#about-body) / overflow:hidden box (#about-box), so for controls
// inside the modal we render the tip into a single position:fixed element on
// <body> (#js-tooltip) that escapes all overflow ancestors. Delegated hover with
// the same ~1.2s reveal delay as the CSS tooltips; clamped to the viewport.
var _aboutTipEl    = null;
var _aboutTipTimer = null;
var _aboutTipFor   = null;
function _hideAboutTip() {
    if (_aboutTipTimer) { clearTimeout(_aboutTipTimer); _aboutTipTimer = null; }
    _aboutTipFor = null;
    if (_aboutTipEl) { _aboutTipEl.classList.remove('show'); _aboutTipEl.style.display = 'none'; }
}
function _positionAboutTip(el) {
    var tip = _aboutTipEl;
    var r   = el.getBoundingClientRect();
    tip.style.display = 'block';        // make it measurable
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var pad = 8, gap = 7;
    var vw = document.documentElement.clientWidth;
    var vh = document.documentElement.clientHeight;
    var top = r.top - th - gap;         // prefer above
    if (top < pad) top = r.bottom + gap;            // no room → below
    if (top + th > vh - pad) top = Math.max(pad, vh - pad - th);
    var left = r.left + r.width / 2 - tw / 2;        // centered on the trigger
    if (left < pad) left = pad;
    if (left + tw > vw - pad) left = vw - pad - tw;
    tip.style.top  = top + 'px';
    tip.style.left = left + 'px';
    tip.classList.add('show');
}
function _initAboutTooltips() {
    var overlay = document.getElementById('about-overlay');
    var body    = document.getElementById('about-body');
    if (!overlay || !body) return;
    if (!_aboutTipEl) {
        _aboutTipEl = document.createElement('div');
        _aboutTipEl.id = 'js-tooltip';
        document.body.appendChild(_aboutTipEl);
    }
    overlay.addEventListener('mouseover', function(e) {
        var el = e.target.closest ? e.target.closest('[data-tip]') : null;
        if (!el || !body.contains(el) || el === _aboutTipFor) return;
        _hideAboutTip();
        _aboutTipFor = el;
        var text = el.getAttribute('data-tip');
        _aboutTipTimer = setTimeout(function() {
            _aboutTipEl.textContent = text;
            _positionAboutTip(el);
        }, 1200);
    });
    overlay.addEventListener('mouseout', function(e) {
        if (!_aboutTipFor) return;
        var to = e.relatedTarget;
        if (to && _aboutTipFor.contains(to)) return;   // still within the trigger
        _hideAboutTip();
    });
    // Scrolling the modal would leave a stale fixed tip floating — drop it.
    body.addEventListener('scroll', _hideAboutTip);
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

// Shared six-tier strength palette (label + bar colour), single source of
// truth for both strength meters below. The bit thresholds differ per meter
// (single field vs. summed two-key bar) but the tier colours/labels are common.
var _STRENGTH_TIERS = [
    { label: 'Weak',        color: '#ff5c5c' },
    { label: 'Fair',        color: '#f5a623' },
    { label: 'Strong',      color: '#3fcf8e' },
    { label: 'Very Strong', color: '#4d8eff' },
    { label: 'Exceptional', color: '#a878ff' },
    { label: 'Paranoid',    color: '#ff5cc8' }
];

// Render a six-segment strength bar for `val` into the elements named by the
// `ids` prefixes (wrap container, `seg` segment-id prefix, label, entropy).
// Shared by the new-entry password field and the Change Passwords form fields.
function _renderStrengthBar(val, ids) {
    var wrap = document.getElementById(ids.wrap);
    if (!wrap) return;
    if (!val) { wrap.style.display = 'none'; return; }

    var bits = _estimateBits(val);

    var level;
    if      (bits < 40)  level = 1;
    else if (bits < 80)  level = 2;
    else if (bits < 120) level = 3;
    else if (bits < 160) level = 4;
    else if (bits < 200) level = 5;
    else                 level = 6;
    var label = _STRENGTH_TIERS[level - 1].label, color = _STRENGTH_TIERS[level - 1].color;

    for (var i = 1; i <= 6; i++) {
        var seg = document.getElementById(ids.seg + i);
        if (seg) seg.style.background = i <= level ? color : '';
    }
    var lbl = document.getElementById(ids.lbl);
    if (lbl) { lbl.textContent = label; lbl.style.color = color; }
    var ent = document.getElementById(ids.ent);
    if (ent) ent.textContent = bits.toFixed(1) + ' bits';

    wrap.style.display = '';
}

function updatePWStrength() {
    _renderStrengthBar(document.getElementById('password').value, {
        wrap: 'pw-strength-wrap', seg: 'pw-seg-', lbl: 'pw-strength-lbl', ent: 'pw-entropy-lbl'
    });
}

// Single combined strength bar for the primary (newpw1) + secondary (newpw2)
// new passwords in the Change Passwords form. Uses the same combined-bits
// method as the main-page vault-key bar (see _renderCombinedKeyBar).
function updateChpwStrength() {
    _renderCombinedKeyBar(
        document.getElementById('newpw1').value,
        document.getElementById('newpw2').value,
        { bar: 'chpw-strength-bar', seg: 'chpw-vkb-', lbl: 'chpw-strength-lbl' }
    );
}

// Per-pair "passwords match" indicator for the Change Passwords form. Shown
// only once the confirm field has content; green when it matches its password,
// red otherwise. Also gates the Re-encrypt button: it stays disabled until both
// new passwords are non-empty and each equals its confirmation.
function updateChpwMatch() {
    var allOk = true;
    [['newpw1', 'newpw1c', 'chpw-match-1'], ['newpw2', 'newpw2c', 'chpw-match-2']].forEach(function(t) {
        var pw  = document.getElementById(t[0]);
        var cf  = document.getElementById(t[1]);
        var out = document.getElementById(t[2]);
        if (!pw || !cf || !out) { allOk = false; return; }
        if (!pw.value || pw.value !== cf.value) allOk = false;
        if (!cf.value) { out.textContent = ''; out.className = 'chpw-match'; return; }
        if (pw.value === cf.value) { out.textContent = '✓ Passwords match';   out.className = 'chpw-match match'; }
        else                       { out.textContent = '✗ Passwords differ';  out.className = 'chpw-match nomatch'; }
    });
    var btn = document.getElementById('btn-chpw-go');
    if (btn) btn.disabled = !allOk;
}

// Combined two-key strength bar — renders the *summed* estimated bits of both
// passwords into the elements named by `ids` (bar container, `seg` id prefix,
// label). Shared by the main-page vault-key bar and the Change Passwords form.
// Colour thresholds use combined raw bits across both keys. They are set
// deliberately high: _estimateBits is charset×length and badly overestimates
// dictionary words, so the scale assumes the estimate is ~2× optimistic.
// Argon2id's time-hardening is treated as margin, not credited as bits.
// nLit is decoupled from colour so segments fill in every ~30 raw bits.
function _renderCombinedKeyBar(pw1, pw2, ids) {
    var bar = document.getElementById(ids.bar);
    if (!bar) return 0;
    var bits = _estimateBits(pw1) + _estimateBits(pw2);
    if (!pw1 && !pw2) { bar.style.opacity = '0'; return bits; }
    bar.style.opacity = '1';
    var idx;
    if      (bits < 45)  idx = 0;
    else if (bits < 80)  idx = 1;
    else if (bits < 115) idx = 2;
    else if (bits < 150) idx = 3;
    else if (bits < 185) idx = 4;
    else                 idx = 5;
    var color = _STRENGTH_TIERS[idx].color, label = _STRENGTH_TIERS[idx].label;
    var nLit = bits > 0 ? Math.min(6, Math.floor(bits / 30) + 1) : 0;
    for (var i = 1; i <= 6; i++) {
        var seg = document.getElementById(ids.seg + i);
        if (seg) seg.style.background = i <= nLit ? color : '';
    }
    var lbl = document.getElementById(ids.lbl);
    if (lbl) { lbl.textContent = label; lbl.style.color = color; }
    return bits;
}

// Main-page vault-key bar: also gates the New button on combined strength.
// Colour thresholds use combined raw bits across both keys. They are set
// deliberately high: _estimateBits is charset×length and badly overestimates
// dictionary words, so the scale assumes the estimate is ~2× optimistic.
// Argon2id's time-hardening is treated as margin, not credited as bits.
// nLit is decoupled from colour so segments fill in every ~30 raw bits.
function _updateVaultKeyBar() {
    var bar    = document.getElementById('vault-key-bar');
    var newBtn = document.querySelector('[data-action="new-entry"]');
    if (!bar) return;
    var k1  = document.getElementById('aeskey');
    var k2  = document.getElementById('aeskey2');
    var pw1 = k1 ? k1.value : '';
    var pw2 = k2 ? k2.value : '';
    var locked  = (k1 && k1.disabled) || (k2 && k2.disabled);
    var bits    = _estimateBits(pw1) + _estimateBits(pw2);
    var tooWeak = bits < 45;
    if (newBtn) {
        newBtn.disabled    = tooWeak;
        newBtn.textContent = tooWeak ? 'Too Weak' : '＋ New';
    }
    if (locked) { bar.style.opacity = '0'; return; }
    _renderCombinedKeyBar(pw1, pw2, { bar: 'vault-key-bar', seg: 'vkb-', lbl: 'vault-key-lbl' });
}

function retestCrypto() {
    _resetSelftestChips();
    runCryptoSelfTest();
}

// ============================================================
// Keyboard shortcuts (Escape / double-Escape lock)
// ============================================================

// Full lock-and-clear: wipes key fields + caches, hides all decoded data, closes
// any open modal, and toasts "Locked". Shared by double-Escape and the X hotkey.
function _lockAndClearVault() {
    _lockCore();
    if (document.getElementById('about-overlay').classList.contains('open')) closeAbout();
    if (document.getElementById('search-overlay').classList.contains('open')) hideSearch();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    showToast('Locked');
}

var _lastEscTime = 0;
document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    var now = Date.now();
    if (now - _lastEscTime < 400) {
        // Double rapid Escape — lock and clear everything
        _lastEscTime = 0;
        _lockAndClearVault();
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

// Suppressed while typing (any input/textarea/select/contenteditable) or while
// a Ctrl/Cmd/Alt modifier is held (so Cmd+N, select-all, etc. stay native;
// Shift is allowed since '?' needs it). Shared by the page shortcuts below and
// the About-modal-only 'u' shortcut.
function _isTypingOrModifier(e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return true;
    var t = document.activeElement;
    return !!(t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable));
}

// Global single-key shortcuts. Suppressed while typing/modifier (see above) and
// while the About modal is open (Escape closes it; 'u' and 'a'/'i' are handled
// separately below so they can reach the modal — 'u' toggles its Disable-auto-lock
// checkbox, 'a'/'i' close it). The search
// overlay needs no special-case — it keeps focus in #search-input, so the
// typing guard already bails while it's open.
function _isShortcutBlocked(e) {
    if (_isTypingOrModifier(e)) return true;
    if (document.getElementById('about-overlay').classList.contains('open')) return true;
    return false;
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') return;          // handled by the listener above
    // Ctrl/⌘-K opens (or closes) the command palette. Placed above the typing /
    // _isShortcutBlocked guards so it fires even from inside an input, and it is
    // intentionally reachable while the About modal is open — the palette renders
    // above About (see #search-overlay z-index) so it isn't buried.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        toggleSearch();
        return;
    }
    // '?' opens the palette too, and like Ctrl-K it stays reachable while About
    // is open (so it's special-cased here, ahead of the _isShortcutBlocked gate
    // that otherwise suppresses every single-key shortcut for the whole modal).
    // The typing guard still applies, mirroring the 'a'/'i'/'u' special-cases.
    if (e.key === '?') {
        if (_isTypingOrModifier(e)) return;
        e.preventDefault();
        toggleSearch();
        return;
    }
    // 'U' toggles About > Auto-lock's Disable-auto-lock checkbox while the
    // modal is open — one of the few single-key shortcuts reachable there (with
    // 'a'/'i' below), since _isShortcutBlocked otherwise bails for the whole modal.
    if (e.key.toLowerCase() === 'u' &&
        document.getElementById('about-overlay').classList.contains('open')) {
        if (_isTypingOrModifier(e)) return;
        e.preventDefault();
        var alt = document.getElementById('autolock-disable-toggle');
        if (alt) { alt.checked = !alt.checked; alt.dispatchEvent(new Event('change')); }
        return;
    }
    // 'A'/'I' toggle the About modal — reachable while it's open (unlike the
    // other shortcuts, which _isShortcutBlocked bails on for the whole modal),
    // so the same key that opened it also closes it.
    if ((e.key.toLowerCase() === 'a' || e.key.toLowerCase() === 'i') &&
        document.getElementById('about-overlay').classList.contains('open')) {
        if (_isTypingOrModifier(e)) return;
        e.preventDefault();
        closeAbout();
        return;
    }
    if (_isShortcutBlocked(e)) return;
    switch (e.key.toLowerCase()) {
        case 'n': {
            var nb = document.querySelector('[data-action="new-entry"]');
            if (nb && !nb.disabled) { e.preventDefault(); newEntry(nb); }
            break;
        }
        case 'c': {
            e.preventDefault();
            var cb = document.querySelector('[data-action="clear-display"]');
            if (cb) blinkTD(cb);
            clearDisplay();
            _editRecord = null; _editSnapshot = null;
            break;
        }
        case 'x': {
            e.preventDefault();
            var xb = document.querySelector('[data-action="clear-lines"]');
            if (xb) blinkTD(xb);
            _lockAndClearVault();
            break;
        }
        case 'e': {
            // Edit the currently selected (decoded) entry, if any.
            if (deleteEntryRecord === null) break;
            e.preventDefault();
            var eb = document.querySelector('[data-action="edit-entry"]');
            if (eb) blinkTD(eb);
            editEntry();
            break;
        }
        case 'd': {
            // Delete the currently selected entry (deleteEntry() confirms first).
            // Requires Shift to avoid an accidental single-key delete.
            if (!e.shiftKey || deleteEntryRecord === null) break;
            e.preventDefault();
            var db = document.querySelector('[data-action="delete-entry"]');
            if (db) blinkTD(db);
            deleteEntry();
            break;
        }
        case 'f': {
            // Toggle favorite on the currently selected (decoded) entry.
            if (!_decodedFields || !_decodedFields.name) break;
            e.preventDefault();
            toggleFavorite();
            break;
        }
        case 'i':
        case 'a':
            e.preventDefault();
            openAbout();
            break;
    }
});

// ============================================================
// Auto-lock on inactivity
// ============================================================

function performAutoLock() {
    _lockCore();
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
    if (_autolockDisabled) return;
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
    'set-entry-type':    function(el) { _applyEntryType(el.dataset.type); },
    'toggle-select-mode':function(el) { _toggleSelectMode(); },
    'bulk-select-all':   function(el) { _bulkSelectAll(); },
    'bulk-fav':          function(el) { _bulkFav(); },
    'bulk-tag':          function(el) { _bulkTag(); },
    'bulk-tag-apply':    function(el) { _bulkTagApply(); },
    'bulk-tag-cancel':   function(el) { _bulkTagCancel(); },
    'bulk-delete':       function(el) { _bulkDelete(); },
    'delete-passkey':    function(el) { deletePasskey(); },
    'toggle-fav':        function(el) { toggleFavorite(); },
    'add-extra-field':   function(el) { var i = _addExtraFieldRow('', '', false); if (i) i.focus(); },
    'open-trash':        function(el) { openTrash(); },
    'toggle-history':    function(el) { _toggleHistory(); },
    'copy-username':     function(el) { doCBCopy('username'); },
    'copy-2fa':          function(el) { doCBCopy('2fa'); },
    'copy-password':     function(el) { doCBCopy('password'); },
    'copy-current':      function(el) { doCBCopy('current'); },
    'toggle-key':        function(el) { toggleKey(); },
    'toggle-key2':       function(el) { toggleKey2(); },
    'clear-lines':       function(el) { clearLines(el); },
    'clear-display':     function(el) { blinkTD(el); clearDisplay(); _editRecord = null; _editSnapshot = null; },
    'new-entry':         function(el) { newEntry(el); },
    'toggle-search':     function(el) { toggleSearch(); },
    'open-about':        function(el) { openAbout(); },
    'toggle-theme':      function(el) { toggleTheme(); },
    'generate':          function(el) { doGenerate(); },
    'set-gen-mode':      function(el) { _setGenMode(); },
    'scan-qr':           function(el) { scanQRCode(); },
    'show-pw-settings':  function(el) { showPWSettings(); },
    'cancel-entry':      function(el) { cancelEntry(); },
    'save-entry':        function(el) { saveEntry(); },
    'cancel-autolock':   function(el) { cancelAutoLock(); },
    'close-crypto-warn': function(el) { closeCryptoWarn(); },
    'close-about':       function(el) { closeAbout(); },
    'retest-crypto':     function(el) { retestCrypto(); },
    'export-vault':      function(el) { exportVault(); },
    'import-vault':      function(el) { _importVaultClick(); },
    'export-csv':        function(el) { exportVaultCSV(el); },
    'import-csv':        function(el) { _importCsvClick(); },
    'import-keepass':    function(el) { _pickImportFile('.xml,text/xml,application/xml', _importKeepassFile); },
    'import-1pux':       function(el) { _pickImportFile('.1pux,application/zip,application/octet-stream', _import1puxFile); },
    'audit-vault':       function(el) { auditVault(el); },
    'list-passkeys':     function(el) { listPasskeys(el); },
    'toggle-chpw':       function(el) { toggleChangePw(); },
    'toggle-chpw-show':  function(el) { toggleChpwShow(el); },
    'do-chpw':           function(el) { changeMasterPasswords(); },
    'toggle-kdf':        function(el) { toggleChangeKdf(); },
    'do-kdf':            function(el) { changeKdfParams(); },
    'kdf-calibrate':     function(el) { _kdfCalibrate(); },
    'resign-vault':      function(el) { resignVault(); }
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

    ['newpw1', 'newpw1c', 'newpw2', 'newpw2c'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.addEventListener('input', function() {
            updateChpwStrength();
            updateChpwMatch();
        });
    });

    var notes = document.getElementById('notes');
    if (notes) notes.addEventListener('input', function() {
        notes.style.height = 'auto';
        notes.style.height = notes.scrollHeight + 'px';
    });

    // Shift+Enter saves the new/edit entry from any field in the form. The Notes
    // textarea is exempt: there Shift+Enter (and plain Enter) insert a newline as
    // usual. #newentry is a div, so keydown bubbles up from the child inputs here.
    var newentry = document.getElementById('newentry');
    if (newentry) newentry.addEventListener('keydown', function(e) {
        if (e.target && e.target.id === 'notes') return;   // let Notes keep Shift+Enter as a newline
        if (e.key === 'Enter' && e.shiftKey) {
            e.preventDefault();
            saveEntry();
        }
    });

    // Change KDF Parameters: the 5-step slider drives the mem/iterations inputs
    // from the preset table; typing in either input snaps the slider to match.
    var kdfSlider = document.getElementById('kdf-slider');
    if (kdfSlider) kdfSlider.addEventListener('input', function() {
        _kdfSliderApply(parseInt(kdfSlider.value, 10) || 2);
    });
    ['kdf-mem', 'kdf-time'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.addEventListener('input', _kdfSyncSlider);
    });

    // Master-key field: Tab/Enter clears + jumps to the 2nd key.
    var k1 = document.getElementById('aeskey');
    if (k1) k1.addEventListener('input', _updateVaultKeyBar);
    if (k1) k1.addEventListener('keydown', function(e) {
        if (e.key === 'Tab' || e.key === 'Enter') {
            e.preventDefault();
            var k2 = document.getElementById('aeskey2');
            k2.value = '';
            _updateVaultKeyBar();
            k2.focus();
        }
    });

    // Secondary-key field: Shift+Tab clears + jumps back to the primary key.
    var k2 = document.getElementById('aeskey2');
    if (k2) k2.addEventListener('input', _updateVaultKeyBar);
    if (k2) k2.addEventListener('keydown', function(e) {
        if (e.key === 'Tab' && e.shiftKey) {
            e.preventDefault();
            var k1b = document.getElementById('aeskey');
            k1b.value = '';
            _updateVaultKeyBar();
            k1b.focus();
        }
    });

    // Group-by-first-letter toggle: reflect the stored pref, then re-sort the
    // grid (re-emitting or stripping headers) whenever it changes.
    _loadGroupPref();
    var gt = document.getElementById('group-toggle');
    if (gt) {
        gt.checked = _groupEntries;
        gt.addEventListener('change', function() {
            _groupEntries = gt.checked;
            _saveGroupPref();
            _sortEntryGrid();
        });
    }

    // Disable-auto-lock toggle (About > Auto-lock): persisted per-instance in
    // localStorage — fully sticky, surviving both reloads and vault locks.
    // Turning it ON (whether via the checkbox or by loading a page that finds
    // it already on) requires the same explicit confirmation, since it leaves
    // the vault unlocked indefinitely; cancelling reverts to enabled (and
    // persists that) without further changes.
    var _autolockConfirmMsg =
        'Disabling auto-lock means this vault will stay unlocked indefinitely ' +
        'while this tab is open, even if you walk away from your device.\n\n' +
        'Are you sure you want to turn off auto-lock?';
    _loadAutolockPref();
    if (_autolockDisabled && !window.confirm(_autolockConfirmMsg)) {
        _autolockDisabled = false;
    }
    _saveAutolockPref();
    var alt = document.getElementById('autolock-disable-toggle');
    if (alt) {
        alt.checked = _autolockDisabled;
        alt.addEventListener('change', function() {
            if (alt.checked && !window.confirm(_autolockConfirmMsg)) {
                alt.checked = false;
                return;
            }
            _autolockDisabled = alt.checked;
            _saveAutolockPref();
            _updateAutolockStatus();
            resetInactivityTimer();
        });
    }
    _updateAutolockStatus();
    resetInactivityTimer();

    var form = document.querySelector('form.ctrl-form');
    if (form) form.addEventListener('submit', function(e) { e.preventDefault(); });

    var si = document.getElementById('search-input');
    if (si) {
        si.addEventListener('input', function() { filterSearch(si.value); _palAfterRender(); });
        si.addEventListener('keydown', function(e) {
            if (e.key === 'Escape')    { hideSearch(); e.stopPropagation(); return; }
            if (e.key === 'ArrowDown') { e.preventDefault(); _palMove(1);  return; }
            if (e.key === 'ArrowUp')   { e.preventDefault(); _palMove(-1); return; }
            if (e.key === 'Enter')     { e.preventDefault(); _palActivate(); return; }
            // ⌘/Ctrl chords act on the active entry (copy pw / user, edit).
            if ((e.ctrlKey || e.metaKey) && !e.altKey) {
                var k = e.key.toLowerCase();
                if (k === 'c') { e.preventDefault(); _palChord('password'); return; }
                if (k === 'u') { e.preventDefault(); _palChord('username'); return; }
                if (k === 'e') { e.preventDefault(); _palChord('edit');     return; }
            }
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
    _loadTheme();
    _bindStaticHandlers();

    // (_updateVaultKeyBar is bound to both key fields' `input` in
    // _bindStaticHandlers; here we only add the reveal/relock behaviour.)
    var k1 = document.getElementById('aeskey');
    var k2 = document.getElementById('aeskey2');
    // Stop an in-flight name-decode if the user changes focus back to a key input
    // or edits its value (an edit already routes through _relockV5Entries below,
    // which aborts; the focus handlers cover a plain refocus with no edit).
    if (k1) {
        k1.addEventListener('input', _relockV5Entries);
        k1.addEventListener('focus', _abortReveal);
    }
    if (k2) {
        k2.addEventListener('input', _relockV5Entries);
        k2.addEventListener('focus', _abortReveal);
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
    // Read the active vault-wide Argon2id params from the embedded #vault-kdf span
    // FIRST — every key derivation below depends on it, and the read-only/offline
    // copy has only this embedded value (no server to query).
    _initVaultKdf();
    _initAboutTooltips();
    initCharsets();
    initCrypto();
    runPageLoadSelfTest();
    _initMaskedInputs();
    _updateVaultKeyBar();
    var copyBtn = document.getElementById('copy-button');
    if (copyBtn) copyBtn.disabled = true;
    resizeFreezePane();
    window.addEventListener('resize', function () {
        if (_rfpRAF) cancelAnimationFrame(_rfpRAF);
        _rfpRAF = requestAnimationFrame(resizeFreezePane);
    });
    _initEntries();
    // Pick up the integrity manifest embedded by post.php (verified on unlock).
    var mEl = document.getElementById('vault-manifest');
    _manifest = (mEl && mEl.dataset.manifest) ? mEl.dataset.manifest : null;
    // Password-free early tamper check: catches a server that swapped the served
    // KDF cost after signing, even before (and when) records fail to decrypt.
    _checkKdfBinding();
    window.scrollTo(0, 0);
    document.getElementById('aeskey').focus();
    _initServiceWorker();
});

// Register the service worker (faster repeat loads of the heavy code assets +
// installable-PWA offline fallback). Secure-context only; failures are silent
// so a blocked/old browser just runs without it. The SW never caches the vault
// document — see sw.js.
function _initServiceWorker() {
    if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('sw.js').catch(function() {});
    });
}

// ============================================================
// Delete an entry
// ============================================================

function deleteEntry() {
    if (deleteEntryRecord === null) { alert('Select an entry to delete first'); return; }
    if (confirm('Delete "' + deleteEntryName + '"?')) {
        // Capture before clearDisplay() nulls them, so Undo can re-insert the record.
        var rec = deleteEntryRecord;
        var nm  = deleteEntryName;
        _xhrPost('delete_rec=' + encodeURIComponent(rec))
            .then(function(text) {
                try { if (_applyServerResponse(text)) _revealCachedV5Buttons(); } catch (_) { location.reload(); return; }
                _signAfterWrite();
                clearDisplay();
                showToast('Deleted "' + nm + '"', {
                    actionLabel: 'Undo',
                    duration: 7000,
                    onAction: function() { _undoDelete(rec, nm); }
                });
            })
            .catch(function(e) {
                if (e.stale) {
                    showToast('Entry was changed elsewhere — reloading');
                    setTimeout(function() { location.reload(); }, 1200);
                    return;
                }
                alert('Delete failed — ' + e.message);
            });
    }
}

// Re-insert a just-deleted record. A plain data= add can't 409 (only
// delete/bulk/sign send expect_hash), so undo is always safe. Mirrors the
// post-save path: cache the name for instant reveal, then re-sign.
function _undoDelete(record, name) {
    _v5Names.set(record, name);
    _xhrPost('data=' + encodeURIComponent(record))
        .then(function(text) {
            try { if (_applyServerResponse(text)) _revealCachedV5Buttons(); } catch (_) { location.reload(); return; }
            _signAfterWrite();
            showToast('Restored "' + name + '"');
        })
        .catch(function(e) { alert('Undo failed — ' + e.message); });
}

// ============================================================
// Multi-select / bulk operations (delete · tag · favorite)
// ============================================================
// A grid-wide selection mode: while active, clicking an entry toggles its
// selection instead of decoding it, and the bulk-action bar applies one action
// to all selected entries at once. Selection is purely in-DOM (the .entry-selected
// class) — it is cleared whenever the grid rebuilds, the vault locks, or the mode
// is exited, so it never outlives the unlocked session.
var _selectMode = false;

// Central entry-button click handler: select-toggle in select mode, else decode.
function _onEntryClick(btn, row) {
    if (_selectMode) { _toggleSelect(btn); return; }
    if (btn === _selectedBtn) { clearDisplay(); } else { decodeLine(btn, row); }
}

function _selectedButtons() {
    return Array.from(document.querySelectorAll('.entry-grid .entry-btn.entry-selected'));
}
function _clearSelection() {
    document.querySelectorAll('.entry-btn.entry-selected').forEach(function(b) {
        b.classList.remove('entry-selected');
    });
}
function _toggleSelect(btn) {
    btn.classList.toggle('entry-selected');
    _updateBulkBar();
}
function _updateBulkBar() {
    var el = document.getElementById('bulk-count');
    if (el) {
        var n = _selectedButtons().length;
        el.textContent = n + ' selected';
    }
}
function _hideBulkTagRow() {
    var row = document.getElementById('bulk-tag-row');
    if (row) row.style.display = 'none';
}

function _toggleSelectMode() {
    if (_selectMode) { _exitSelectMode(); return; }
    // Only meaningful with at least one revealed (decryptable) entry.
    if (!document.querySelector('.entry-grid .entry-btn:not(.v5-locked)')) {
        showToast('Unlock the vault to select entries'); return;
    }
    _selectMode = true;
    hideSearch();
    clearDisplay();
    var grid = document.querySelector('.entry-grid');
    if (grid) grid.classList.add('select-mode');
    var tgl = document.getElementById('select-toggle');
    if (tgl) { tgl.classList.add('is-on'); tgl.textContent = '☑︎ Selecting'; }
    var bar = document.getElementById('bulk-bar');
    if (bar) bar.style.display = '';
    _hideBulkTagRow();
    _updateBulkBar();
}
function _exitSelectMode() {
    if (!_selectMode) return;
    _selectMode = false;
    _clearSelection();
    var grid = document.querySelector('.entry-grid');
    if (grid) grid.classList.remove('select-mode');
    var tgl = document.getElementById('select-toggle');
    if (tgl) { tgl.classList.remove('is-on'); tgl.textContent = '☑︎ Select'; }
    var bar = document.getElementById('bulk-bar');
    if (bar) bar.style.display = 'none';
    _hideBulkTagRow();
}

// Toggle-select every visible (revealed, not search-hidden) entry.
function _bulkSelectAll() {
    var vis = Array.from(document.querySelectorAll('.entry-grid .entry-btn:not(.v5-locked)'))
                   .filter(function(b) { return b.style.display !== 'none'; });
    var allSel = vis.length && vis.every(function(b) { return b.classList.contains('entry-selected'); });
    vis.forEach(function(b) { b.classList.toggle('entry-selected', !allSel); });
    _updateBulkBar();
}

// Bulk favorite: pure localStorage, no crypto/network. Toggles — if every selected
// entry is already a favorite, remove them all; otherwise add them all.
function _bulkFav() {
    var btns = _selectedButtons();
    if (!btns.length) { showToast('Select entries first'); return; }
    var set = _favs();
    var allFav = btns.every(function(b) { return set.has(_favHash(_btnName(b))); });
    btns.forEach(function(b) {
        var h = _favHash(_btnName(b));
        if (allFav) set.delete(h); else set.add(h);
    });
    _saveFavs();
    _markFavButtons();
    _sortEntryGrid();
    showToast(allFav ? 'Removed ' + btns.length + ' from favorites'
                     : '★ Added ' + btns.length + ' to favorites');
}

// Canonical record (trailing line index stripped) for each selected button.
function _selectedRecords() {
    return _selectedButtons().map(function(b) {
        return b.dataset.row.split('|').slice(0, -1).join('|');
    });
}
// SHA-256 (hex) over the current vault's canonical records joined with "\n" —
// the expect_hash a bulk/restore write checks for a concurrent modification.
async function _currentVaultHash() {
    var current = _allEntries.map(function(row) {
        return row.split('|').slice(0, -1).join('|');
    });
    var buf = await crypto.subtle.digest('SHA-256', _TE.encode(current.join('\n')));
    return { records: current, hash: bytesToHex(new Uint8Array(buf)) };
}

// Bulk delete: commit the surviving records in one count-flexible `restore` write
// (atomic, single re-sign, pre-write bak/ backup — see Write Protocol). Offers an
// Undo that restores the pre-delete record set the same way.
async function _bulkDelete() {
    var keys = _selectedRecords();
    if (!keys.length) { showToast('Select entries first'); return; }
    // A `restore` write can't empty the vault (post.php rejects an empty payload),
    // so deleting every entry at once is refused — leave at least one, or delete
    // the final entry individually.
    if (keys.length >= _allEntries.length) {
        showToast('Can’t delete every entry at once — leave at least one selected off');
        return;
    }
    if (!confirm('Delete ' + keys.length + ' selected '
                 + (keys.length === 1 ? 'entry' : 'entries') + '?')) return;
    var drop = {};
    keys.forEach(function(k) { drop[k] = true; });
    try {
        var snap = await _currentVaultHash();
        var remaining = snap.records.filter(function(r) { return !drop[r]; });
        var responseText = await _xhrPost('restore=1&expect_hash=' + snap.hash
                              + '&bulk_data=' + encodeURIComponent(remaining.join('\n')));
        _exitSelectMode();
        clearDisplay();
        try { if (_applyServerResponse(responseText)) _revealCachedV5Buttons(); }
        catch (_) { location.reload(); return; }
        _signAfterWrite();
        var n = keys.length;
        showToast('Deleted ' + n + ' ' + (n === 1 ? 'entry' : 'entries'), {
            actionLabel: 'Undo', duration: 8000,
            onAction: function() { _bulkRestoreSet(snap.records); }
        });
    } catch (e) {
        if (e.stale) {
            showToast('Vault changed elsewhere — reloading');
            setTimeout(function() { location.reload(); }, 1200);
            return;
        }
        showToast('Bulk delete failed — ' + e.message);
    }
}

// Restore a previously-captured record set (Undo for bulk delete). The deleted
// records' names are still in _v5Names (never cleared on delete), so they reveal
// instantly. Mirrors the restore-write tail used by Import / Restore.
async function _bulkRestoreSet(records) {
    try {
        var snap = await _currentVaultHash();
        var responseText = await _xhrPost('restore=1&expect_hash=' + snap.hash
                              + '&bulk_data=' + encodeURIComponent(records.join('\n')));
        try { if (_applyServerResponse(responseText)) _revealCachedV5Buttons(); }
        catch (_) { location.reload(); return; }
        _signAfterWrite();
        showToast('Restored ' + records.length + ' ' + (records.length === 1 ? 'entry' : 'entries'));
    } catch (e) {
        showToast('Undo failed — ' + e.message);
    }
}

// Bulk tag: reveal the tag-input row (the actual write runs from _bulkTagApply).
function _bulkTag() {
    if (!_selectedButtons().length) { showToast('Select entries first'); return; }
    if (!_isVaultUnlocked()) { showToast('Unlock the vault first'); return; }
    var row = document.getElementById('bulk-tag-row');
    if (row) row.style.display = '';
    var inp = document.getElementById('bulk-tag-input');
    if (inp) { inp.value = ''; inp.focus(); }
}
function _bulkTagCancel() { _hideBulkTagRow(); }

// Add the typed tag(s) to every selected entry: decrypt each, merge the tags,
// re-encrypt with fresh salts/nonces, and commit the unchanged + re-encrypted
// records in one count-flexible `restore` write. All-or-nothing — any decrypt
// failure aborts before anything is sent.
async function _bulkTagApply() {
    var keys = _selectedRecords();
    if (!keys.length) { showToast('Select entries first'); return; }
    var addTags = _normalizeTags(document.getElementById('bulk-tag-input').value);
    if (!addTags) { showToast('Enter at least one tag'); return; }
    var pw  = document.getElementById('aeskey').value;
    var pw2 = document.getElementById('aeskey2').value;
    if (!_isVaultUnlocked()) { showToast('Unlock the vault first'); return; }

    try {
        var pairs = await _forEachRecordDecrypt(pw, pw2, async function(rec, name, fields) {
            fields.tags = _normalizeTags((fields.tags || '') + ',' + addTags);
            var s1 = crypto.getRandomValues(new Uint8Array(32));
            var s2 = crypto.getRandomValues(new Uint8Array(32));
            var ne = await encryptName(pw, pw2, s1, s2, name);
            var rf = await encryptFields(pw, pw2, s1, s2, fields);
            var newRec = _assembleRecord(ne, rf, s1, s2);
            return { old: rec, newRec: newRec, name: name, fields: fields };
        }, null, keys);

        var changed = {};
        pairs.forEach(function(p) { changed[p.old] = p.newRec; });
        var snap   = await _currentVaultHash();
        var merged = snap.records.map(function(r) { return changed[r] || r; });
        var responseText = await _xhrPost('restore=1&expect_hash=' + snap.hash
                              + '&bulk_data=' + encodeURIComponent(merged.join('\n')));

        // Seed the name + @-search caches for the re-encrypted records so the
        // rebuilt grid reveals them instantly (passwords unchanged → _mkCache kept).
        pairs.forEach(function(p) {
            _v5Names.set(p.newRec, p.name);
            _searchText.set(p.newRec, _searchIndex(p.fields));
            _entryBadges.set(p.newRec, { passkey: !!(p.fields.passkey && p.fields.passkey.rpId), note: p.fields.type === 'note', stale: _isStaleFields(p.fields) });
        });
        _exitSelectMode();
        clearDisplay();
        try { if (_applyServerResponse(responseText)) _revealCachedV5Buttons(); }
        catch (_) { location.reload(); return; }
        _signAfterWrite();
        showToast('Tagged ' + pairs.length + ' ' + (pairs.length === 1 ? 'entry' : 'entries'));
    } catch (e) {
        if (e.stale) {
            showToast('Vault changed elsewhere — reloading');
            setTimeout(function() { location.reload(); }, 1200);
            return;
        }
        showToast('Bulk tag failed — ' + e.message);
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
    // Generator has two modes; the passphrase (diceware) mode is a separate path.
    var pm = document.getElementById('gen-mode-phrase');
    if (pm && pm.checked) { doGeneratePassphrase(); return; }
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

// Flatten the space-joined wordlist chunks into a word array once, on first use
// (the list is ~7.8k words, so we avoid the work until the passphrase mode runs).
var _wordlistCache = null;
function _wordlist() {
    if (!_wordlistCache) _wordlistCache = _WORDLIST_CHUNKS.join(' ').split(' ');
    return _wordlistCache;
}

// Diceware / passphrase generator. Each word is an independent uniform draw from
// the wordlist via _randomInt (same rejection-sampled CSPRNG as the char mode), so
// entropy is exactly count × log2(listSize) — plus log2(10) for an appended digit.
function doGeneratePassphrase() {
    var words = _wordlist();
    var count = parseInt(document.getElementById('word-count').value, 10);
    if (!count || count < 1 || count > 100) { alert('Invalid word count'); return; }
    var sep    = document.getElementById('word-sep').value;
    var caps   = document.getElementById('word-caps').checked;
    var addNum = document.getElementById('word-num').checked;

    var tokens = [];
    for (var i = 0; i < count; i++) {
        var w = words[_randomInt(words.length)];
        if (caps) w = w.charAt(0).toUpperCase() + w.slice(1);
        tokens.push(w);
    }
    var extraBits = 0;
    if (addNum) { tokens.push(String(_randomInt(10))); extraBits = Math.log2(10); }

    currentPassword = tokens.join(sep);
    document.getElementById('password').value = currentPassword;
    updatePWStrength();
    var entropy = Math.log2(words.length) * count + extraBits;
    document.getElementById('statistics').textContent =
        count + ' words from a ' + words.length + '-word list,  Entropy ≈ ' +
        entropy.toFixed(1) + ' bits';
    document.getElementById('copy-button').disabled = false;
}

// Toggle the generator panel between character and passphrase option blocks.
function _setGenMode() {
    var phrase = document.getElementById('gen-mode-phrase').checked;
    document.getElementById('gen-chars').style.display  = phrase ? 'none' : '';
    document.getElementById('gen-phrase').style.display = phrase ? '' : 'none';
}

function initCrypto() {
    var el = document.getElementById('crypto-getrandomvalues-entropy');
    if (!el) return;
    if (typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.subtle) {
        el.textContent = '✓';
    } else {
        el.textContent = '⚠︎ NOT available — do not use this browser for password generation';
    }
}

// EFF-style diceware wordlist: 7776 words (12.925 bits/word), derived from the
// system dictionary (american-english), filtered to [a-z]{4,6}, deduped, profanity
// removed. NOT the EFF list. Stored as space-joined chunks to keep the source
// compact; _WORDLIST flattens them once on first use. See doGeneratePassphrase().
var _WORDLIST_CHUNKS = [
  'abaci aback abacus abaft abase abash abate abbey abbot abbr abeam abed abet abets abhor abhors abide able',
  'abler ably abode abort aborts about above abuse abuses abut abuts abuzz abyss acct aced aces acetic ache',
  'ached aches achoo achy acid acids acing acme acmes acne acorn acre acres acrid acted active actor acts acute',
  'adage adapt added addend adder addle adds adept adieu adjoin adman admen admin admit adobe adopt adore adorn',
  'adorns adult advt adze adzes aegis aeon aeons aerate aerie aery afar affix afire aflame afoot afoul after',
  'again agape agar agate agave aged agent ages aghast agile aging agism aglow agog agony agree ague ahead ahem',
  'ahoy aide aided aides aids ailed ails aimed aims aired airing airs airy aisle ajar akin alarm alas albs',
  'album alder alders alert ales alga algae alias alibi alien align alike aline alit alive allay allege alley',
  'allot allow alloy ally almost alms aloe aloes aloft aloha alone along aloof aloud alpha also altar alter',
  'altho alto altos alts alum alums amass amaze amazed amber amble ameba ameer amen amend amends amid amigo',
  'amino amir amirs amiss amity ammo amok among amour ample amply amps ampul ampuls amuck amuse anew angel',
  'anger angina angle angry angst anime anion anise ankh ankhs ankle anneal annex annoy annul anode anon anons',
  'ante anted antes anther anti antic antis ants anvil aorta apace apart apathy aped apes apex aphid aping',
  'appal appeal apple apply apps apron apse apses apter aptly aqua aquae aquas arbor arcane arced arch arcs',
  'ardor area areas arena arenas ares argon argot argue aria arias arid arise arks armed armies armor arms army',
  'aroma arose array arrays arrow arson arts artsy arty ascent ascot ashed ashen ashes ashy aside asked askew',
  'asks asleep aspen aspic asps assay asset assets assn assoc asst aster astir astral atlas atoll atom atoms',
  'atone atop atria attach attar attic atty audio audit auger augers aught augur auks aunt aunts aura aurae',
  'aural auras auto autos avail avast avdp avenge aver avers avert avian avid avoid avow avows await awake',
  'awaked award aware awash away awed awes awful awing awls awoke awol awry axed axes axial axing axiom axis',
  'axle axles axon axons ayes azure azures baaed baas babe babel babes baby back backs backup bacon bade badge',
  'badly bagel baggy bags bail bails bait baits baize bake baked baker bakery bakes bald balds bale baled bales',
  'balk balks balky ball ballot balls balm balms balmy balsa banal band bands bandy bane banes bang bangs bani',
  'banish banjo bank banks banns bans barb barbed barbs bard bards bare bared barer bares barf barfs barge bark',
  'barker barks barn barns baron bars barter basal base based baser bases bash basic basil basin basis bask',
  'basket basks bass bassi basso bast baste batch bate bated bates bath bathe baths batik bating baton bats',
  'batty baud bauds bawdy bawl bawls bayed bayou bays beach beacon bead beads beady beak beaks beam beams bean',
  'beans bear beard bears beast beat beaten beats beau beaus beaux bebop beck becks bedded beds beech beef',
  'beefs beefy been beep beeps beer beers bees beet beets befall befit befog began begat beget begin begone',
  'begot begs begun beige being belay belch belfry belie bell belle bells belly below belt belts bench bend',
  'bender bends bent bents beret berg bergs berm berms berry berth beryl beset besom besoms besot best bests',
  'beta betas bets betted bevel bevy bias bible bibles bibs bicep biddy bide bided bides bidet bids bier biers',
  'biff biffs biggie bight bigot bike biked biker bikes bile bilge bilk bilks bill billet bills billy bimbo',
  'bind binds binge bingo bins biped bipeds birch bird birds birth bison bite bites bitmap bits blab blabs',
  'black blade blah blame bland blank blanks blare blast blat blats blaze bldg bleak bleat bleats bled bleed',
  'bleep blend blent bless blest blew blimp blind bling blink blintz blip blips bliss blitz bloat blob blobs',
  'bloc block blocs blog blogs blond blood bloom blot blotch blots blow blown blows blue blued bluer blues',
  'bluff blunt blunts blur blurb blurs blurt blush blvd boar board boars boas boast boat boats bobby bobcat',
  'bobs bode boded bodes body boga bogey boggy bogie bogied bogon bogs bogus bogy boil boils boink bola bolas',
  'bold bole boles boll bolls bolt bolts bomb bomber bombs bond bonds bone boned boner bones boney bong bongo',
  'bongs bonnie bonny bonus bony booby booed book books boom booms boon boons boor boors boos boost boot booted',
  'booth boots booty booze boozy bops borax bore bored borer bores boring born borne boron bosh bosom boss',
  'bossy bosun botch both bottom bough bound bout bouts bowed bowel bower bowing bowl bowls bows boxed boxen',
  'boxer boxes boys bozo bozos brace braces bract brad brads brag brags braid brain brake bran brand brandy',
  'bras brash brass brat brats brave bravo brawl brawn bray brays brazen bread break bred breed brew brewed',
  'brews briar bribe brick bride brief briefs brier brig brigs brim brims brine bring brink briny brisk broad',
  'broil broke broken brood brook broom broth brow brown brows browse bruin brunt brush brusk brute buck bucket',
  'bucks buddy budge buds buff buffs bugged buggy bugle bugs build built bulb bulbs bulge bulgy bulk bulks',
  'bulky bull bulls bully bumble bump bumps bumpy bums bunch bung bungs bunk bunker bunks bunny buns bunt bunts',
  'buoy buoys burg burgs buries burka burly burn burns burnt burp burps burr burro burrs burs burst bursts bury',
  'busby bused buses bush bushy buss bussed bust busts busy butch buts butt butte button butts buxom buyer buys',
  'buzz byes bylaw byline byte bytes byway cabal cabby cabin cabins cable cabs cacao cache cacti caddy cadet',
  'cadets cadge cadre cads cage caged cages cagey cagy cairn cajole cake caked cakes calf calfs calif calk',
  'calks call calls calm calmed calms calve calyx came camel cameo camp camped camps campy cams canal candle',
  'candy cane caned canes canny canoe canon canons cans cant canto cants cape caped caper capes caplet capon',
  'caps carat carbs card cards care cared career cares caret cargo carol carom carp carped carpi carps carry',
  'cars cart carts carve carver case cased cases cash cask casks cast caste caster casts catch cater catnap',
  'cats catty caulk cause caused cave caved caves cavil cawed caws cease ceased cedar cede ceded cedes cell',
  'celli cello cells cent center cents chad chads chafe chaff chain chair chaise chalk champ chant chanty chaos',
  'chap chaps chapt char charm chars chart chary chase chasm chat chats chatty cheap cheat check cheek cheep',
  'cheer chef chefs chem cherry chess chest chew chews chewy chic chick chid chide chides chief child chile',
  'chili chill chime chimp chin china chink chino chinos chins chip chips chirp chit chits chive chock choir',
  'choke choker chomp chop chops chord chore chorus chose chow chows chuck chug chugs chum chump chums chunk',
  'church churl churn chute cider cigar cilia cinch cinema circa cite cited cites city civet civets civic civil',
  'clack clad claim clam clamp clams clan clang clank clans clap claps claret clash clasp class claw claws clay',
  'clean clear cleat clef clefs cleft clench clerk clew clews click cliff clii climb climbs clime cling clink',
  'clip clips clipt clit clits clix cloak clock clocks clod clods clog clogs clomp clone clop clops close clot',
  'cloth clots cloud clouds clout clove clown cloy cloys club clubs cluck clue clued clues clump clumps clung',
  'clunk clvi clvii clxi clxii clxiv clxix clxvi coach coal coals coast coat coats coax coaxed cobra cobs cocci',
  'cocky cocoa cocoas coda codas code coded codes codex cods coed coeds coffer cogs coif coifs coil coils coin',
  'coins coitus coke coked cokes cola colas cold colds colic colon color cols colt colts coma comas comb combat',
  'combo combs come comer comes comet comfy comic comm comma commas compo conch condo condos cone cones conga',
  'conic conj conk conks cons cont contd convey cooed cook cooks cooky cool cools coons coop cooped coops coos',
  'coot coots cope coped copes copra cops copse copses copy coral cord cords core cored cores cork corks corm',
  'corms corn corner corns corny corp corps cosign cost costs cosy cote cotes cots couch cough coughs could',
  'count coup coupe coups court cove coven cover covers coves covet covey cowed cower cowl cowls cows coyer',
  'coyly cozen cozens cozy crab crabs crack craft crag crags cram cramp cramps crams crane crank crape craps',
  'crash crass crate crater crave craw crawl craws cray crays craze crazy creak creaks cream credo creed creek',
  'creel creels creep crepe crept cress crest crew crews crib cribs crick cried crier cries crime crimes crimp',
  'crisp croak croci crock crofts crone crony crook croon crop crops cross croup crow crowd crown crows crud',
  'cruddy crude cruel cruet cruft crumb crush crust crusts crux crypt cube cubed cubes cubic cubit cubs cuckoo',
  'cuds cued cues cuff cuffs cuing cull culls cult cults cumin cums cunts cupid cupola cups curb curbs curd',
  'curds cure cured curer cures curie curio curl curled curls curly curry curs curse curst curt curve curves',
  'curvy cushy cusp cusps cuss cute cuter cuts cutter cutup cycle cynic cyst cysts czar czars dabble dabs dacha',
  'daddy dado dados dads daffy daft daily dairy dais daisy dale dales dally damage dame dames damns damp damps',
  'dams dance danced dandy dank dapple dare dared dares dark darn darns dart darts dash data date dated dates',
  'dative datum daub daubs daunt davit dawn dawns days daze dazed dazes dded dding dead deaden deaf deal deals',
  'dealt dean deans dear dears death deaves debar debit debs debt debts debug debut debuts decaf decal decay',
  'deck deckle decks decor decoy decry deed deeds deem deems deep deepen deeps deer deers defer defies deft',
  'defy deice deicer deify deign deism deity delay deli delis dell dells delta delve delved demo demon demos',
  'demur denial denim dens dense dent dents denude deny depot dept depth deputy derby desk desks despot deter',
  'detox deuce devil devils dewy dhoti dial dialed dials diary dice diced dices dicey dicky dicta dictum died',
  'dies diet diets diff diffs digit digs dike diked dikes diking dill dills dilly dime dimer dimes dimly dims',
  'dine dined diner dines ding dingo dings dingy dining dink dinky dins dint diode dips dire direr direst dirge',
  'dirk dirks dirt dirty disc disco discs dish disk disks disown diss ditch ditto ditty diva divan divas dive',
  'dived diver divert dives divot divvy dizzy djinn dock docked docks docs dodge dodgy dodo dodos doer doers',
  'does doff doffs doggie doggy dogie dogma dogs doily doing dole doled doles doll dolls dolly dolt dolts dome',
  'domed domes doming done donor dons donut doom doomed dooms door doors dope doped dopes dopey dopy dork dorks',
  'dorky dorm dorms dory dose dosed doses dote doted dotes doth doting dots dotty doubt dough dour douse douses',
  'dove doves dowdy dowel down downs downy dowry dowse doyen doze dozed dozen dozes drab drabs draft drafty',
  'drag drags drain drake dram drama drams drank drape draw drawl drawn draws dray drays dread dream dreams',
  'dregs dress drew dried drier dries drift drill drily drink drinks drip drips drive droid droll drone drool',
  'droop droops drop drops dross drove drown drub drubs drug drugs druid druids drum drums drunk dryad dryer',
  'dryly drys dual dubs ducal ducat duchy duck ducks duct ducts dude duded dudes duds duel dueled duels dues',
  'duet duets duff duke dukes dull dulls dully duly dumb dummy dump dumps dumpy dunce dune dunes dung dungs',
  'dunk dunked dunks dunno duns duos dupe duped dupes dusk dusky dust dusts dusty duty duvet dwarf dwarfs dweeb',
  'dwell dwelt dyed dyer dyers dyes dying dyked dykes each eager eagle earful earl earls early earn earns ears',
  'earth ease eased easel eases easing east easy eaten eater eats eave eaves ebbed ebbs ebony echo echos ecru',
  'eddy edema edge edged edger edges edgier edgy edict edify edit edits eels eerie eery effete egged eggs egis',
  'egos egret eider eight eighth eject eked ekes eking elate elbow elder elect elects elegy elfin elide elite',
  'elks ells elms elope else elude eluded elves email embed ember emboss emcee emend emery emir emirs emit',
  'emits emoji emos emote empire empty emus enact endear ended endow ends endue enema enemy engage enjoy ennui',
  'enrich enrol ensue enter entire entry enure envoy envy eons epic epics epilog epoch epoxy equal equip eras',
  'erase erect erects ergo ergs erode erred error errs erupt erupts espy essay ester esters etch ether ethic',
  'ethos euro euros evade evades even evens event ever every eves evict evil evils evoke evolve ewer ewers ewes',
  'exact exalt exam exams excel excl exec execs exempt exert exes exile exist exit exits exotic expel expo',
  'expos extant extol extra exude exult eyed eyeful eyes eying fable face faced faces facet facile fact facts',
  'fade faded fades fads fagot fail fails fain faint fair fairer fairs fairy faith fake faked faker fakes fakir',
  'fall falls false falter fame famed fancy fang fangs fanny fans farce fare fared fares faring farm farms',
  'farts fast fasts fatal fate fated fates fating fats fatty fault faun fauna fauns favor fawn fawns faxed',
  'faxes faxing faze fazed fazes fear fears feast feat feats fecal feds feed feeds feel feeler feels fees feet',
  'feign feint fell fells felon felt felted felts femur fence fend fends fens feral fern ferns ferric ferry',
  'fest fests feta fetal fetch feted fetid fetus feud feudal feuds fever fewer fezes fiat fiats fiber fibs',
  'fiche fiches fief fiefs field fiend fiery fife fifes fifth fifty fight fights figs filch file filed files',
  'filet fill fills filly film films filmy filter filth final finch find finds fine fined finer fines finis',
  'finish fink finks finny fins fiord fire fired fires firm firms firs first firth fish fished fishy fist fists',
  'fitly fits five fiver fives fixed fixer fixes fizz fizzed fizzy fjord flab flack flag flags flail flair flak',
  'flake flakes flaky flame flan flank flap flaps flare flash flask flat flatly flats flaw flaws flax flay',
  'flays flea fleas fleck fled flee flees fleet flesh fleshy flew flex flick flied flier flies fling flint',
  'flints flip flips flirt flit flits float flock floe floes flog flogs flood floor flop flops flora florae',
  'floss flour flout flow flown flows flub flubs flue flues fluff fluffs fluid fluke fluky flume flung flunk',
  'flush flute flutes flux flyby flyer foal foals foam foams foamy fobs focal foci focus foes foetal fogey',
  'foggy fogs fogy foil foils foist fold folds folio folios folk folks folly fond fondu font fonts food foods',
  'fool fooled fools foot foots fops fora foray force ford fords fore fores forest forge forgo fork forks form',
  'forms fort forte fortes forth forts forty forum foul fouls found fount four fours fourth fowl fowls foxed',
  'foxes foxy foyer frack frag frags frail frame franc francs frank frat frats fraud fray frays freak free',
  'freed freer frees frenzy fresh fret frets friar fried frier fries frill frilly frisk frizz frock frog frogs',
  'from frond front frost frosty froth frown froze fruit frump frumpy fryer ftps fudge fuel fuels fugue fulcra',
  'full fulls fully fume fumed fumes fums fund funds fungi funk funks funky funnel funny furl furls furor furry',
  'furs fury furze fuse fused fuses fuss fusses fussy fusty futon futz fuze fuzed fuzes fuzz fuzzy gabble gabby',
  'gable gabs gads gaff gaffe gaffs gage gaged gages gaging gags gaily gain gains gait gaits gala galas gale',
  'gales gall galls galore gals game gamed gamer games gamey gamin gamins gamma gamut gamy gang gangs gape',
  'gaped gapes gaps garb garbed garbs garter gases gash gasp gasps gassy gate gated gates gaucho gaudy gauge',
  'gaunt gauze gauzy gave gavel gawk gawks gawky gayer gayly gays gaze gazed gazer gazes gear geared gears',
  'gecko geed geek geeks geeky gees geese geez geld gelds gelid gels gelt gems gene genes genial genie genii',
  'genre gens gent gents genus geode germ germs gets getup gewgaw ghost ghoul giant gibe gibed gibes giblet',
  'giddy gift gifts gigs gild gilds gill gills gilt gilts gimme gimpy ginkgo gins gipsy gird girds girl girls',
  'girt girth girts gismo gist give given gives gizmo gizmos glad glade glads gland glare glass glaze glazes',
  'gleam glean glee glen glens glib glide glint glitz gloat gloats glob globe globs gloom glop glory gloss',
  'glove glow glows glue glued glues gluey gluier glum glut gluts glyph gnarl gnash gnat gnats gnaw gnawn gnaws',
  'gnome gnus goad goads goal goals goat goatee goats gobs godly gods goes gofer going goiter gold golds golf',
  'golfs golly gonad gone goner gong gongs gonk gonks gonna gonzo good goodie goods goody gooey goof goofs',
  'goofy gook gooks goon goons goop goose gore gored gores gorge gorier gorp gorps gorse gory gosh gotta gouge',
  'gourd gout gouty govern govt gown gowns grab grabs grace grad grade grads graft grail grain gram grams grand',
  'grands grant grape graph grasp grass grate gratis grave gravy gray grays graze grease great grebe greed',
  'green greet grep greps grew grey greys grid grids grief grieve grill grim grime grimy grin grind grins grip',
  'gripe grippe grips grist grit grits groan grog groin grok groks groom grope groped gross group grout grove',
  'grow grower growl grown grows grub grubs grue gruel grues gruff grunt guano guard guava guavas guess guest',
  'guff guide guild guile guilt guise gulag gulch gulf gulfs gull gulled gulls gully gulp gulps gumbo gummy',
  'gums gunk gunny guns guppy gurgle guru gurus gush gushy gust gusto gusts gusty guts gutsy guyed guys guzzle',
  'gybe gybed gybes gyms gyps gypsy gyro gyros habit hack hacks haft hafts hags haiku hail hailed hails hair',
  'hairs hairy hake hakes hale haled haler hales half hall halls halo halon halos halt halts halve halved hams',
  'hand hands handy hang hanger hangs hank hanks hanky happy hard hardy hare hared harem hares haring hark',
  'harks harm harms harp harps harpy harry harsh hart harts hash hasp hasps haste hasted hasty hatch hate hated',
  'hater hates hath hats haul hauls haunch haunt have haven haves havoc hawed hawk hawks haws hayed hays hazard',
  'haze hazed hazel hazes hazy head heads heady heal heals health heap heaps hear heard hears heart heat heath',
  'heats heave heaved heavy heck hedge heed heeds heel heeled heels heft hefts hefty heir heirs heist held',
  'helix hello helm helms helot help helps hemmed hemp hems hence henna hens herb herbs herd herds here hereof',
  'hero heron heros hers hertz hewed hewer hewers hewn hews hexed hexes hick hicks hide hided hides hied hies',
  'high higher highs hike hiked hiker hikes hill hills hilly hilt hilts hims hind hinds hing hinge hings hint',
  'hints hipper hippo hippy hips hire hired hires hiss hitch hits hive hived hives hoagy hoard hoards hoary',
  'hoax hobby hobo hobos hobs hock hocks hods hoed hoeing hoes hogan hogs hoist hokey hokum hold holds hole',
  'holed holes hollow holly holy home homed homer homes homey homie homy honcho hone honed hones honey honk',
  'honks honor hooch hood hoods hooey hoof hoofed hoofs hook hooks hooky hoop hoops hoot hootch hoots hope',
  'hoped hopes hops horde horn hornet horns horse horsy hose hosed hoses host hosts hotel hotkey hotly hound',
  'hour hours house hove hovel hover howdy howl howled howls hows hubby hubs hued hues huff huffs huffy huge',
  'huger hugs hula hulas hulk hulks hull hulled hulls human humid humor humped humps hums humus hunch hung hunk',
  'hunks hunt hunts hurl hurls hurray hurry hurt hurts hush husk husks husky hussy hutch huts hybrid hydra',
  'hyena hying hymen hymn hymns hype hyped hyper hypes hypo hypos iamb iambs ibex ibexes ibid ibis iced ices',
  'icier icily icing icky icon icons idea ideal ideas ides idiom idioms idiot idle idled idler idles idly idol',
  'idols idyl idyll idyls iffy igloo iguana ikon ikons ilks ills illus image imam imams imbed imbue impair',
  'impel imply imps impugn inane inapt inbox inced inch incite incs incur index induct indue inept inert infer',
  'infix info inform ingot inked inkier inks inky inlay inlet inner inning inns input inset insole intel inter',
  'interj into intro inure invert ioctl ions iota iotas irate iris irked irking irks iron irons irony isle',
  'isles islet isms issue itch itches itchy item items ivies ivory jabot jabs jack jacks jade jaded jades jags',
  'jaguar jail jails jamb jambs jams japan jape japed japes jarred jars jaunt jawed jaws jays jazz jazzy jeans',
  'jeep jeeps jeer jeers jeez jehad jell jelled jello jells jelly jerks jerky jest jests jets jetty jewel',
  'jibbed jibe jibed jibes jibs jiffy jigs jihad jilt jilts jimmy jinn jinni jinns jinx jinxed jive jived jives',
  'jobs jock jocks joggle jogs john johns join joins joint joist joke joked joker jokes jolly jolt jolts josh',
  'jostle jots joule joust jowl jowls joyed joys judge judges judo jugs juice juicy julep jumbo jump jumped',
  'jumps jumpy junco junk junks junky junta juries juror jury just jute juts kabob kale kaolin kapok kaput',
  'karat karma kayak kazoo kebab kebob keel keels keen keenly keens keep keeps kegs kelp kens kept ketch keto',
  'keyed keys khaki khan khans kick kicker kicks kicky kiddo kiddy kids kill kills kiln kilns kilo kilos kilt',
  'kilter kilts kind kinda kinds king kings kink kinks kinky kiosk kiss kissed kite kited kites kith kits kitty',
  'kiwi kiwis kluge klutz knack knacks knave knead knee kneed kneel knees knell knelt knew knife knit knits',
  'knobs knock knocks knoll knot knots know known knows koala koan koans kook kooks kooky kopek krone kronor',
  'kudos kudzu label labor labs lace laced laces lack lacks lacuna lacy lade laded laden lades ladle lads lady',
  'lager lags laid lain lair lairs laity lake lakes lama lamas lamb lambda lambs lame lamed lamer lames lamp',
  'lamps lams lance lances land lands lane lanes lank lanky lapel laps lapse larch lard larded lards large',
  'largo lark larks larva larynx lase lased laser lases lash lass lasso last lasts latch late lately later',
  'latex lath lathe laths lats latte laud lauds laugh launch lava lawn lawns laws laxer laxly layer layoff lays',
  'laze lazed lazes lazy leach lead leads leaf leafed leafs leafy leak leaks leaky lean leans leap leaps leapt',
  'learn leas lease leash least leave leaved ledge leech leek leeks leer leers leery lees left lefts lefty',
  'legacy legal leggy legit legs legume leis lemma lemme lemon lemur lend lends lens lent leper lept lesion',
  'less lest lets letup levee level lever levers levy lewd lexer liar liars libel libels lice licit lick licks',
  'lids lied lief liege lien liens lies lieu life lifer lift lifts light lights like liked liken liker likes',
  'lilac lilt lilts lily limb limbo limbs lime limed limes limier limit limn limns limo limos limp limps limy',
  'linden line lined linen liner lines lingo link linker links lint lints lion lions lipid lips lira liras lire',
  'lisle lisp lisps list listen lists lite liter lithe live lived liven liver livers lives livid llama llano',
  'load loads loaf loafer loafs loam loamy loan loans loath lobby lobe lobed lobes lobs local loci lock locker',
  'locks loco locus lode lodes lodge loft lofts lofty loge loges logic login logins logo logon logos logs loin',
  'loins loll lolls lone loner long longed longs look looks loom looms loon loons loony loop loops loopy loose',
  'loosen loot loots lope loped lopes lops lord lords lore lorn lorry lose loser loses loss losses lost loth',
  'lots lotto lotus loud louse lousy lout louts love loved lover loves lowed lower lowers lowly lows loxes',
  'loyal luau luaus lube lubed lubes lucid luck lucks lucky lucre lugs lull lulls lumber lump lumps lumpy lunar',
  'lunch lung lunge lungs lupin lupus lurch lure lured lures lurid lurk lurker lurks lush lust lusts lusty lute',
  'lutes lvii lxii lxiv lxix lxvi lxvii lying lymph lynch lynx lyre lyres lyric lyrics macaw mace maced maces',
  'macho macro madam made madly madman mads magic magma maid maids mail mails maim maimed maims main mains',
  'maize major make maker makes male males mall mallet malls malt malts mama mamas mambo mamma mane manes manga',
  'mange manger mango mangy mania manic manly manna manor mans manse mantel many maple maps maraca march mare',
  'mares maria mark marks marlin marry mars marsh mart marts masc mascot mash mask masks mason mass mast masts',
  'match mate mated mates math mating mats matt matte matts matzo matzot maul mauls mauve maven mavin maws',
  'maxed maxes maxim maybe mayhem mayo mayor maze mazes mead meal meals mealy mean means meant meat meats meaty',
  'mecca medal media medial medic meek meet meets megs meld melds melody melon melt melts meme memes memo memos',
  'mend mends menial menu menus meow meows mercy mere meres merge merit merits merry mesa mesas mesh mess messy',
  'meta metal mete meted meter meters metes metro mewed mewl mewls mews miaow mica mice mickey micra middy',
  'midge midst mien miens miff miffs might mike miked mikes miking milch mild mile miler miles milf milfs milk',
  'milks milky mill millet mills mils mime mimed mimes mimic mince mind minds mine mined miner mines mini minim',
  'minims minis mink minks minor mint mints minty minus minx mire mired mires miring mirth misc misdo miser',
  'miss missed mist mists misty mite miter mites mitt mitts mixed mixer mixes mkay moan moaned moans moat moats',
  'mobs mocha mock mocks modal mode model modem modern modes mods mogul moire moist molar molars mold molds',
  'moldy mole moles moll molls molt molts momma mommy moms money monk monkey monks mono month mooch mood moods',
  'moody mooed moon moons moor moors moos moose moot moots mope moped mopes mops moral morale moray more mores',
  'morn morns moron mortar mosey moss mossy most mote motel motes moth moths motif motion motor motto mound',
  'mount mourn mouse mouser mousy mouth move moved mover moves movie mowed mower mown mows much muck mucked',
  'mucks mucky mucus muddy muff muffs mufti muggle muggy mugs mulch mule mules mull mulls multi mummy mumps',
  'munch mung mungs mural murder murk murks murky muse mused muses mush mushy music musk musky muslin muss',
  'mussy must musts musty mute muted muter mutes mutt mutter mutts myna mynah mynas myrrh myself myth myths',
  'nabob nabs nacho nacre nadir nags naiad nail nails naive naiver naked name named names nanny nape napes',
  'nappy naps narc narcs nark narks nary nasal nasty natal native natl natty naval nave navel naves navy nays',
  'near nears neat neater neath neck necks need needs needy neigh neocon neon nerd nerds nerdy nerve nervy nest',
  'nests nets neuron never newel newer newly news newsy newt newts next nexus nibs nice nicer nicety niche nick',
  'nicks niece nifty nigh night nights nimbi nine nines ninja ninny ninth nippy nips nite niter nites nits',
  'nitwit nixed nixes noble nobly nodal noddy node nodes nods noel noels noes noise noisy nomad nomads nonce',
  'none nook nooks noon noose nope norm norms north nose nosed noses nosey nosh nosy notary notch note noted',
  'notes noun nouns nous nova novae novas novel noway nozzle nubs nuder nudge nuke nuked nukes nuking null',
  'nulls numb numbs nuns nurse nuts nutty nuzzle nylon nymph oafs oaken oaks oakum oared oars oases oasis oaten',
  'oath oaths oats obese obey obeys obit obits oblong oboe oboes occur ocean ocher ochre octal octane octet',
  'odder oddly odds odes odium odor odors offal offed offer office offs often ogle ogled ogles ogre ogres ohms',
  'oiled oils oily oink oinks okay okays okra okras olden older oldie oleo olive olives omega omen omens omit',
  'omits once ones onion only onset onto onus onyx oops ooze oozed oozes oozing opal opals open opens opera',
  'opine opium oppose opted optic opts opus oral orals orate orates orbit orbs orcs order ores organ orient',
  'osier other others otter ouch ought ounce ours oust ousts outdo outed outer outfit outgo outs oval ovals',
  'ovary oven ovens over overdo overs overt ovoid ovule ovum owed owes owing owlet owls owned owner owns oxbow',
  'oxen oxide oxides ozone pace paced paces pack packs pact pacts paddy padre padres pads paean pagan page',
  'paged pager pages paid pail pails pain pains paint pair pairs palate pale paled paler pales pall palls palm',
  'palms palmy pals palsy pamper panda pane panel panes pang pangs panic pans pansy pant pants panty papa',
  'papacy papal papas papaw paper paps parch pare pared pares pariah park parka parks parred parry pars parse',
  'part parts party pasha pass passed past pasta paste pastry pasts pasty patch pate pates path paths patio',
  'pats patsy patted patty pause pave paved paves pawed pawl pawls pawn pawns paws payday payed payee payer',
  'pays peace peach peak peaks peal peals pear pearl pearls pears peas pease peat pecan peck pecks pecs pedal',
  'peed peeing peek peeks peel peels peep peeps peer peers pees peeve pegs pekoe pellet pelt pelts penal pence',
  'pend pends penes penny pens pent penury peon peons peony peppy peps perch peril perk perks perky perm permed',
  'perms pert pesky peso pesos pest pests petal petard peter pets petty pewee pews phage phalli phase phial',
  'phish phlox phone phones phony photo phyla piano piazze pica pick picks picky piece pieced pied pier piers',
  'pies piety piggy pigmy pigs piing pike piked piker pikers pikes pilaf pilau pilaw pile piled piles pill',
  'pilled pills pilot pimp pimps pinch pine pined pines ping pings pink pinked pinks pinky pins pint pinto',
  'pints pinup pious pipe piped piper pipes pipit pippin pips pique pita pitch pith pithy piton pitons pits',
  'pity pivot pixel pixie pixy pizza place placid plaid plain plait plan plane planet plank plans plant plate',
  'play plays plaza plazas plea plead pleas pleat pled plied plies plinth plod plods plonk plop plops plot',
  'plots plow plows ploy ploys pluck plug plugs plum plumb plume plumes plump plums plunk plus plush poach pock',
  'pocks podded podia pods poem poems poesy poet poets point poise poke poked poker pokes pokey pokeys poky',
  'polar pole poled poles polio polka polkas poll polls polo pols polyp pomp pond ponds pone pones ponies pony',
  'pooch pooh poohs pool pools poops poor pope popes poppa poppas poppy pops porch pore pored pores pork port',
  'ports pose posed poser poses posh posher posit poss posse post posts posy potato pots potty pouch pound pour',
  'pours pout pouts powder power poxes pram prank prate prawn pray prayer prays preen prep preps pres press',
  'presto prey preys price pricy pride prides pried pries prig prigs prim prime primp print prior priors prism',
  'privy prize probe prod prods prof profit profs prom promo proms pron prone prong proof prop props pros prose',
  'prosy proton proud prove prow prowl prows proxy prude prune psalm pshaw pshaws psst psych pubic pubs puck',
  'pucks pudgy puff puffin puffs puffy pugs puke puked pukes pull pulls pulp pulps pulpy pulse pulses puma',
  'pumas pump pumps punch punk punks punned puns punt punts puny pupa pupae pupal pupas pupil puppy pups pure',
  'puree purer purge purged purl purls purr purrs purse purser push pushy puss puts putt putted putts putty',
  'pwned pwns pygmy pylon pyre pyres pyxes quack quad quads quaff quail quails quake qualm quark quart quartz',
  'quash quasi quay quays queen quell query ques quest queue queues quick quid quids quiet quill quilt quine',
  'quip quips quire quirk quit quite quits quiver quiz quoit quota quote quoth rabbi rabid race raced raceme',
  'racer races rack racks racy radar radial radii radio radon raft rafts raga ragas rage raged rages raging',
  'rags raid raids rail rails rain rains rainy raise raisin raja rajah rajas rake raked rakes rally ramp ramps',
  'rams ranch random randy rang range rangy rank ranks rant rants rapid rapids raps rapt rare rared rarer rares',
  'rarity rash rasp rasps raspy rate rated rates ratio ration rats ratty rave raved ravel raven raves rawer',
  'rawest rayon rays raze razed razes razor razz reach react read reads ready real realm realms reals ream',
  'reams reap reaps rear rearm rears rebel rebels rebus rebut recap recd recede recta rector recur redid redo',
  'reds reduce reed reeds reedy reef reefs reek reeks reel reels reeve refer refine refit refs regal regale',
  'rehab reheat rehi reign rein reins reis relax relay relic relics rely remand remit renal rend rends renege',
  'renew rent rents reorg repair repay repel reply reps reran reread rerun reset resin resins resp rest rests',
  'retch retell retry reuse reused revel revise revs revue rework rhea rheas rheum rhino rhyme ribs rice riced',
  'rices rich riches rick ricks ride rider rides ridge riding rids rife rifer riff riffs rifle rift rifts right',
  'rigid rigor rigs rile riled riles riling rill rills rime rimed rimes rims rind rinds ring rings rink rinks',
  'rinse riot riots ripe ripen ripens riper rips rise risen riser rises risk risks risky rite rites ritual',
  'ritzy rival riven river rivet roach road roads roam roams roan roans roar roars roast robe robed robes robin',
  'robing robot robs rock rocks rocky rode rodeo rods roes roger rogers rogue roil roils role roles roll rolls',
  'roman romp romps rood roods roof roofs rook rooks room roomed rooms roomy roost root roots rope roped ropes',
  'rose roses rosin roster rosy rote rotor rots rouge rough roughs round rouse rout route routs rove roved',
  'rover roves rowdy rowed rowel rower rowers rows royal rube rubes ruble rubs ruby ruckus ruddy rude ruder',
  'rued rues ruff ruffs rugby rugs ruin ruing ruins rule ruled ruler rulers rules rumba rummy rumor rump rumps',
  'rums rune runes rung rungs runic runny runs runt runts runway rupee rural ruse ruses rush rusk rusks rust',
  'rusts rusty ruts saber sable sables sabre sack sacks sacs sades sadist sadly safe safer safes saga sagas',
  'sage sager sages sago sags sahib said sail sails saint saints saith sake saki salad sale sales sally salon',
  'saloon salsa salt salts salty salve salvo samba same sames sampan sand sands sandy sane saner sang sank sans',
  'sappy saps sarape saree sari saris sash sass sassy satay sate sated sates satin satrap satyr sauce saucy',
  'sauna save saved saver saves saving savor savvy sawed sawn saws saxes says scab scabs scad scads scag scags',
  'scald scale scaled scalp scaly scam scamp scams scan scans scant scar scare scares scarf scars scary scat',
  'scats scene scent school schwa scion scoff scold scone scoop scoot scoots scope score scorn scour scout scow',
  'scowl scowls scows scram scrap screw scrimp scrip scrod scrog scrub scuba scud scuds scuff scuffs scull scum',
  'scums scurf seal sealed seals seam seams seamy sear sears seas seat seats secede secs sect sects secy sedan',
  'sedge seed seeds seedy seek seeker seeks seem seems seen seep seeps seer seers sees segue seize select self',
  'sell sells semi semis send sends senna sense sensor sent sepal sepia septa sera seraph sere serer serf serfs',
  'serge serum serve serves servo sets setup seven sever sewage sewed sewer sewn sews sexed sexes sexton shack',
  'shad shade shads shady shaft shag shags shah shahs shake shaken shaky shale shall shalt sham shame shams',
  'shank shape shapes shard share shark sharp shave shaves shawl sheaf shear shed sheds sheen sheep sheer sheet',
  'sheik shekel shelf shell sherd shes shied shies shift shill shim shims shin shine shined shins shiny ship',
  'ships shire shirk shirr shirt shlep shlepp shoal shock shod shoe shoed shoes shone shoo shook shoon shoos',
  'shoot shop shops shore shores shorn short shot shots shout shove show shown shows showy shred shrew shrewd',
  'shroud shrub shrug shtik shuck shun shuns shunt shush shut shuts shyer shying shyly sibyl sick sicks sics',
  'side sided sides sidle siege sieges sieve sift sifts sigh sighs sight sigma sign signed signs silk silks',
  'silky sill sills silly silo silos silt silts simian sims since sine sinew sing singe singer sings sink sinks',
  'sins sinus sips sire sired siren sires sirs sirup sirups sisal sises sissy sitar site sited sites sits situ',
  'sixes sixth sixty size sized sizer sizes skate skater skeet skein skew skews skid skids skied skier skies',
  'skiff skill skim skimp skimps skims skin skins skip skips skirt skis skit skits skulk skull skunk skyed slab',
  'slabs slack slacks slag slags slain slake slam slams slang slant slap slaps slash slat slate slats slave',
  'slaves slaw slay slays sled sleds sleek sleep sleet sleeve slept slew slews slice slick slid slide slier',
  'slight slily slim slime slims slimy sling slink slip slips slit slits slob slobs sloe sloes slog slogs sloop',
  'slop slope slops slosh slot sloth sloths slots slow slows slue slued slues slug slugs slum slump slumps',
  'slums slung slunk slur slurp slurs slush slyer slyly smack small smart smash smear smell smelly smelt smile',
  'smirk smit smite smith smithy smock smog smoke smoky smote smug smugly smurf smut smuts snack snafu snag',
  'snags snail snake snaky snap snaps snare snares snarf snark snarl sneak sneer snide snider sniff snip snipe',
  'snips snit snits snob snobs snoop snoopy snoot snore snort snot snots snout snow snowed snows snowy snub',
  'snubs snuck snuff snug snugs soak soaks soap soaps soapy soar soars sober sobs sock socked socks soda sodas',
  'sods sofa sofas soft softy soggy soil soiled soils solar sold sole soled soles soli solid solo solos sols',
  'solve solves some sonar song songs sonic sonny sons soon soot sooth sooty soppy sops sore sorely sorer sores',
  'sorry sort sorta sorts sots sough soul souls sound soup souped soups soupy sour sours souse south sowed',
  'sower sown sows soya space spaced spacy spade spake spam spams span spank spans spar spare spark spars',
  'sparse spas spasm spat spate spats spawn spay spays speak spear spec speck specs sped speed speeds spell',
  'spelt spend spent spew spews spice spicy spider spied spiel spies spike spiky spill spilt spin spine spins',
  'spiny spiral spire spit spite spits splat splay spline split spoil spoke spoof spook spooks spool spoon',
  'spoor spore sport spot spots spouse spout sprat spray spree sprier sprig spry spryly spud spuds spume spun',
  'spur spurn spurs spurt squab squad squall squat squaw squid squirm stab stabs stack staff stag stage stags',
  'staid stain stair stairs stake stale stalk stall stamp stance stand stank staph star stare stark stars start',
  'starve stash stat state stats stave stay stays stdio stead steads steak steal steam steed steel steep steer',
  'steers stein stem stems stent step steps stern stew stews stick sties stiff stiffs stile still stilt sting',
  'stink stint stir stirs stitch stoat stock stoic stoke stole stoles stomp stone stony stood stool stoop stop',
  'stops store stored stork storm story stout stove stow stows strait strap straw stray strep strew strewn',
  'strip strive strop strum strut struts stub stubs stuck stud studs study stuff stump stun stung stunk stuns',
  'stunt stupid stye styes style styli suave subj sublet subs such suck sucker sucks suds sudsy sued suede sues',
  'suet sugar suing suit suite suits sulfur sulk sulks sulky sully sumac sumo sump sumps sums sundae sung sunk',
  'sunny suns sunup super supped sups sure surer surf surfs surge surges surly sushi swab swabs swag swags',
  'swain swam swami swamp swan swank swanks swans swap swaps sward swarm swash swat swath swats sway sways',
  'swear sweat sweaty sweep sweet swell swept swift swig swigs swill swim swims swine swing swipe swipes swirl',
  'swish swoon swoop swop swops sword swore sworn swum swung sylph symbol sync synch syncs synod syrup sysop',
  'tabbed tabby table taboo tabs tabu tabus tacit tack tacks tacky taco tacos tact tads taffy tags tail tailor',
  'tails taint take taken taker takes talc tale tales talk talks tall tally talon tamale tame tamed tamer tames',
  'tamp tamps tams tang tango tangos tangs tangy tank tanks tans tansy tape taped taper tapes tapir taps tardy',
  'tare tared tares target taro taros tarot tarp tarps tarry tars tart tartly tarts taser task tasks taste',
  'tasty tats tattoo tatty taunt taupe taut tawny taxed taxes taxi taxis tbsp teach teacup teak teaks teal',
  'teals team teams tear tears teary teas tease teat teats tech techno techs teed teem teems teen teens teeny',
  'tees teeth telex tell tells temp temped tempi tempo temps tempt tend tends tenet tennis tenon tenor tens',
  'tense tent tenth tents tenure tepee tepid term terms tern terns terry terse test tests testy text texts than',
  'thank thanks that thaw thaws thee thees theft their them theme then there these theses theta they thick',
  'thief thigh thin thine thing think thins third this thong thorax thorn those thou thous three threw thrice',
  'throb throe throw thrown thru thrum thud thuds thug thugs thumb thump thunk thus thyme thymi thymus tiara',
  'tibia tick ticks tics tidal tide tided tides tidier tidy tied tier tiers ties tiff tiffs tiger tight tike',
  'tikes tilde tile tiled tiles till tilled tills tilt tilts time timed timer times timid tine tines ting tinge',
  'tingle tings tinny tins tint tints tiny tipi tipis tipple tips tipsy tire tired tires tiro tiros titan tithe',
  'title titled tizzy toad toads toady toast today toddy toed toes toffy tofu toga togae togas toggle togs toil',
  'toils toke toked token tokes told toll tolls tomb tombs tomcat tome tomes toms tonal tone toned toner tones',
  'tong tongs tonic tonne tons tony took tool tools toot tooth toots topaz topic topics tops toque torch tore',
  'torn tors torsi torso tort torte torts torus toss tossed tost total tote toted totem totes tots touch tough',
  'toupee tour tours tout touts towed towel tower town towns tows toxic toxin toyed toys trace traced track',
  'tract trade trail train trains trait tram tramp trams trans trap traps trash trawl tray trays tread treas',
  'treat treaty tree treed trees trek treks trend tress triad trial tribe tribes trice trick tried tries trig',
  'trike trill trim trims trio trios trip tripe tripos trips trite trod troll tromp tron trons troop trope',
  'tropic trot troth trots trout troy troys truce truck true trued truer trues truing truly trump trunk truss',
  'trust truth tryst tsar tsars ttys tuba tubas tubby tube tubed tuber tubers tubes tubs tuck tucks tuft tufts',
  'tugs tulip tulle tumid tummy tumor tuna tunas tundra tune tuned tuner tunes tunic tunny tuns turds turf',
  'turfs turgid turn turns tush tusk tusks tussle tutor tutu tutus tuxes twain twang tweak twee tweed tweet',
  'twerk twerp twerps twice twig twigs twill twin twine twink twins twirl twist twit twits twos tycoon tying',
  'tyke tykes type typed types typo typos tyro tyros tzar tzars udder ugly ulcer ulna ulnae ulnas ultra ultras',
  'umbel umber umiak umped umps unbar unbind uncle uncut under undid undo undue unease unfit unhurt unify union',
  'unit unite units unity unless unman unpin unpins unsay unsays unset untidy untie until unto unwed unwise',
  'unzip upend upland upon upped upper upset upside urban urea urge urged urges uric urine urns usage usages',
  'used user users uses usher using usual usurp usury uteri utter uvula uvular vacua vague vain vale vales',
  'valet valid valise valor value valve vamp vamps vane vanes vanned vans vape vaped vapes vapid vapor vars',
  'vary vase vases vast vasts vats vault vaults vaunt veal veep veeps veer veers vegan veil veils vein veins',
  'veld velds veldt velour venal vend vends venom vent vents venue verb verbal verbs verge verse versus verve',
  'very vest vests vetch veto vets vexed vexes viable vial vials viand vibe vibes vicar vice viced vices video',
  'vied vies view views vigil vigor viii vile vilely viler villa vine vines vinyl viol viola viols viper viral',
  'vireo vireos virus visa visas vise vised vises visit visits visor vista vital viva vivas vivid vixen vizor',
  'vocal vocals vodka vogue voice void voids voile vole voles vols volt volts vomit vote voted voter voters',
  'votes vouch vowed vowel vows vying wabbit wack wacko wacks wacky wade waded wader wades wadi wadis wads',
  'wafer waft wafts wage waged wager wagers wages wagon wags waif waifs wail wails waist wait waits waive',
  'waiver wake waked waken wakes waldo wale waled wales walk walks wall wallop walls waltz wand wands wane',
  'waned wanes wanks wanly wanna want wanted wants ward wards ware wares warez warm warmer warms warn warns',
  'warp warps wars wart warts warty wary wash wasp wasps waste waster watch water watt watts wave waved waver',
  'waves wavy waxed waxen waxes waxy waylay ways weak weal weals wean weans wear wears weary weave weaver webs',
  'wedge weds weed weeder weeds weedy week weeks weep weeps weepy weer wees weest weft wefts weigh weir weird',
  'weirs welch weld welder welds well wells welsh welt welts wench wend wends wens went wept were west wetly',
  'wets whack whale whaled wham whams wharf what whats wheal wheat wheel whelk whelp when whence whens where',
  'whet whets whew whey which whiff while whim whims whine whinny whiny whip whips whir whirl whirr whirs whisk',
  'whist whit white whits whiz whizz whoa whole whom whoop whoops whorl whose whys wick wicks wide widen wider',
  'widow widows width wield wife wight wigs wigwag wiki wikis wild wilds wile wiled wiles will wills wilt wilts',
  'wily wimp wimple wimps wimpy wince winch wind winds windy wine wined wines wing wings wink winked winks wino',
  'winos wins wipe wiped wiper wipes wire wired wires wiry wise wisely wiser wises wish wisp wisps wispy wist',
  'witch with wits witty wive wives wizes wkly wobble woes woke woken woks wolf wolfs woman womb wombs women',
  'wonky wont wood wooden woods woody wooed wooer woof woofs wool wooly woos woozy word words wordy wore work',
  'worked works world worm worms wormy worn worry worse worst worth would wound wove woven wowed wows wrack',
  'wraith wrap wraps wrapt wrath wreak wreck wren wrens wrest wrier wring wrist wrists writ write writs wrong',
  'wrote wroth wrung wryer wryly wuss xcii xciv xcix xcvi xcvii xenon xiii xref xrefs xterm xvii xviii xxii',
  'xxiii xxiv xxix xxvi xxvii xxxi xxxii xxxiv xxxix xxxv xxxvi xylem yacht yack yacked yacks yahoo yaks yams',
  'yank yanks yaps yard yards yarn yarns yawed yawl yawls yawn yawns yaws yeah yeahs year yearn years yeas',
  'yeast yeasts yell yells yelp yelps yens yeps yeses yest yeti yews yield yippee yips yock yocks yodel yoga',
  'yogi yogin yogis yoke yoked yokel yokes yolk yolks yore young your yours yous youth yowl yowls yucca yuck',
  'yucked yucks yucky yuks yule yummy yuppy yups zany zaps zeal zebra zebu zebus zeds zenned zens zero zeros',
  'zest zests zeta zilch zinc zincs zing zings zipped zippy zips zits zombi zonal zone zoned zones zoom zooms',
  'zoos zorch'
];
