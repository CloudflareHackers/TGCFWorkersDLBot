/**
 * Browser shim for Node.js `crypto` module — used by teleproto.
 * Provides AES-256-ECB and AES-256-CTR via pure JS AES implementation.
 * Uses Web Crypto API for hashing and PBKDF2.
 */

// ===== AES-256 Pure JavaScript Implementation =====
// Needed because Web Crypto API doesn't support ECB mode,
// and teleproto's IGE layer needs synchronous single-block AES-ECB.

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function subWord(w) {
  return ((SBOX[(w >>> 24) & 0xff] << 24) |
          (SBOX[(w >>> 16) & 0xff] << 16) |
          (SBOX[(w >>> 8) & 0xff] << 8) |
          (SBOX[w & 0xff])) >>> 0;
}

function rotWord(w) {
  return ((w << 8) | (w >>> 24)) >>> 0;
}

function expandKey256(key) {
  const Nk = 8, Nr = 14;
  const W = new Uint32Array(4 * (Nr + 1));
  for (let i = 0; i < Nk; i++) {
    W[i] = ((key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]) >>> 0;
  }
  for (let i = Nk; i < W.length; i++) {
    let temp = W[i - 1];
    if (i % Nk === 0) {
      temp = (subWord(rotWord(temp)) ^ (RCON[(i / Nk) - 1] << 24)) >>> 0;
    } else if (i % Nk === 4) {
      temp = subWord(temp);
    }
    W[i] = (W[i - Nk] ^ temp) >>> 0;
  }
  return W;
}

function aesEncryptBlock(block, roundKeys) {
  const Nr = 14;
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[i];

  // AddRoundKey
  for (let i = 0; i < 4; i++) {
    const rk = roundKeys[i];
    s[4*i] ^= (rk >>> 24) & 0xff;
    s[4*i+1] ^= (rk >>> 16) & 0xff;
    s[4*i+2] ^= (rk >>> 8) & 0xff;
    s[4*i+3] ^= rk & 0xff;
  }

  for (let round = 1; round <= Nr; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    // ShiftRows
    let t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    // MixColumns (skip in last round)
    if (round < Nr) {
      for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        s[i]   = gf2(a0) ^ gf3(a1) ^ a2 ^ a3;
        s[i+1] = a0 ^ gf2(a1) ^ gf3(a2) ^ a3;
        s[i+2] = a0 ^ a1 ^ gf2(a2) ^ gf3(a3);
        s[i+3] = gf3(a0) ^ a1 ^ a2 ^ gf2(a3);
      }
    }
    // AddRoundKey
    for (let i = 0; i < 4; i++) {
      const rk = roundKeys[round * 4 + i];
      s[4*i] ^= (rk >>> 24) & 0xff;
      s[4*i+1] ^= (rk >>> 16) & 0xff;
      s[4*i+2] ^= (rk >>> 8) & 0xff;
      s[4*i+3] ^= rk & 0xff;
    }
  }
  return Buffer.from(s);
}

function aesDecryptBlock(block, roundKeys) {
  const Nr = 14;
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[i];

  // AddRoundKey (last round key)
  for (let i = 0; i < 4; i++) {
    const rk = roundKeys[Nr * 4 + i];
    s[4*i] ^= (rk >>> 24) & 0xff;
    s[4*i+1] ^= (rk >>> 16) & 0xff;
    s[4*i+2] ^= (rk >>> 8) & 0xff;
    s[4*i+3] ^= rk & 0xff;
  }

  for (let round = Nr - 1; round >= 0; round--) {
    // InvShiftRows
    let t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
    // InvSubBytes
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    // AddRoundKey
    for (let i = 0; i < 4; i++) {
      const rk = roundKeys[round * 4 + i];
      s[4*i] ^= (rk >>> 24) & 0xff;
      s[4*i+1] ^= (rk >>> 16) & 0xff;
      s[4*i+2] ^= (rk >>> 8) & 0xff;
      s[4*i+3] ^= rk & 0xff;
    }
    // InvMixColumns (skip in first round)
    if (round > 0) {
      for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        s[i]   = gf14(a0) ^ gf11(a1) ^ gf13(a2) ^ gf9(a3);
        s[i+1] = gf9(a0)  ^ gf14(a1) ^ gf11(a2) ^ gf13(a3);
        s[i+2] = gf13(a0) ^ gf9(a1)  ^ gf14(a2) ^ gf11(a3);
        s[i+3] = gf11(a0) ^ gf13(a1) ^ gf9(a2)  ^ gf14(a3);
      }
    }
  }
  return Buffer.from(s);
}

// GF(2^8) multiplication helpers
function gfMul(a, b) {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return r;
}
function gf2(a)  { return gfMul(a, 2); }
function gf3(a)  { return gfMul(a, 3); }
function gf9(a)  { return gfMul(a, 9); }
function gf11(a) { return gfMul(a, 11); }
function gf13(a) { return gfMul(a, 13); }
function gf14(a) { return gfMul(a, 14); }

// ===== createCipheriv / createDecipheriv =====

export function createCipheriv(algorithm, key, iv) {
  const algo = algorithm.toLowerCase().replace(/-/g, '');
  key = Buffer.from(key);

  if (algo === 'aes256ecb' || algo === 'aes256ecb') {
    const roundKeys = expandKey256(key);
    let pending = Buffer.alloc(0);
    let autoPadding = true;
    return {
      setAutoPadding(v) { autoPadding = v; return this; },
      update(data) {
        data = Buffer.from(data);
        pending = Buffer.concat([pending, data]);
        const blocks = Math.floor(pending.length / 16);
        if (blocks === 0) return Buffer.alloc(0);
        const out = [];
        for (let i = 0; i < blocks; i++) {
          out.push(aesEncryptBlock(pending.subarray(i * 16, (i + 1) * 16), roundKeys));
        }
        pending = pending.subarray(blocks * 16);
        return Buffer.concat(out);
      },
      final() {
        if (pending.length > 0 && autoPadding) {
          const padLen = 16 - pending.length;
          const padded = Buffer.alloc(16, padLen);
          pending.copy(padded);
          return aesEncryptBlock(padded, roundKeys);
        }
        return Buffer.alloc(0);
      }
    };
  }

  if (algo === 'aes256ctr') {
    iv = Buffer.from(iv);
    const roundKeys = expandKey256(key);
    const counter = Buffer.from(iv);
    let pending = Buffer.alloc(0);
    let keystreamBuf = Buffer.alloc(0);
    let ksOffset = 0;

    function incrementCounter() {
      for (let i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] !== 0) break;
      }
    }

    return {
      setAutoPadding() { return this; },
      update(data) {
        data = Buffer.from(data);
        const out = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) {
          if (ksOffset >= keystreamBuf.length) {
            keystreamBuf = aesEncryptBlock(counter, roundKeys);
            incrementCounter();
            ksOffset = 0;
          }
          out[i] = data[i] ^ keystreamBuf[ksOffset++];
        }
        return out;
      },
      final() { return Buffer.alloc(0); }
    };
  }

  throw new Error(`Unsupported cipher algorithm: ${algorithm}`);
}

export function createDecipheriv(algorithm, key, iv) {
  const algo = algorithm.toLowerCase().replace(/-/g, '');
  key = Buffer.from(key);

  if (algo === 'aes256ecb' || algo === 'aes256ecb') {
    const roundKeys = expandKey256(key);
    let pending = Buffer.alloc(0);
    let autoPadding = true;
    return {
      setAutoPadding(v) { autoPadding = v; return this; },
      update(data) {
        data = Buffer.from(data);
        pending = Buffer.concat([pending, data]);
        const blocks = Math.floor(pending.length / 16);
        if (blocks === 0) return Buffer.alloc(0);
        const out = [];
        for (let i = 0; i < blocks; i++) {
          out.push(aesDecryptBlock(pending.subarray(i * 16, (i + 1) * 16), roundKeys));
        }
        pending = pending.subarray(blocks * 16);
        return Buffer.concat(out);
      },
      final() {
        if (pending.length > 0 && autoPadding) {
          return aesDecryptBlock(pending, roundKeys);
        }
        return Buffer.alloc(0);
      }
    };
  }

  if (algo === 'aes256ctr') {
    // CTR mode decryption is the same as encryption
    return createCipheriv(algorithm, key, iv);
  }

  throw new Error(`Unsupported decipher algorithm: ${algorithm}`);
}

// ===== randomBytes =====

export function randomBytes(size) {
  const buf = Buffer.alloc(size);
  crypto.getRandomValues(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  return buf;
}

// ===== createHash =====

export function createHash(algorithm) {
  const algo = algorithm.toLowerCase().replace('-', '');
  const algoMap = { sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
  const webAlgo = algoMap[algo];
  let data = null;

  return {
    update(input) {
      const buf = input instanceof Uint8Array ? input : Buffer.from(input);
      data = data ? Buffer.concat([data, buf]) : Buffer.from(buf);
      return this;
    },
    async digest() {
      if (!data) return Buffer.alloc(0);
      if (webAlgo) {
        const hashBuffer = await globalThis.crypto.subtle.digest(webAlgo, data);
        return Buffer.from(hashBuffer);
      }
      return Buffer.alloc(32);
    }
  };
}

// ===== pbkdf2 =====

export async function pbkdf2Sync(password, salt, iterations, ...args) {
  const keylen = typeof args[0] === 'number' ? args[0] : 64;
  const digest = typeof args[1] === 'string' ? args[1] : (typeof args[0] === 'string' ? args[0] : 'sha512');
  const hashMap = { sha512: 'SHA-512', sha256: 'SHA-256', sha1: 'SHA-1' };
  const hashAlgo = hashMap[(digest || 'sha512').toLowerCase()] || 'SHA-512';

  const passwordKey = await globalThis.crypto.subtle.importKey(
    'raw',
    password instanceof Uint8Array ? password : Buffer.from(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derived = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: hashAlgo,
      salt: salt instanceof Uint8Array ? salt : Buffer.from(salt),
      iterations,
    },
    passwordKey,
    keylen * 8
  );

  return Buffer.from(derived);
}

export function pbkdf2(password, salt, iterations, keylen, digest, callback) {
  try {
    const result = pbkdf2Sync(password, salt, iterations, keylen, digest);
    if (callback) result.then(r => callback(null, r)).catch(e => callback(e));
    return result;
  } catch (e) {
    if (callback) callback(e);
    else throw e;
  }
}

export default { randomBytes, createHash, createCipheriv, createDecipheriv, pbkdf2Sync, pbkdf2 };
