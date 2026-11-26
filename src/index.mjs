/*
 * csrfshield core.
 *
 * Signed double-submit CSRF protection with fetch metadata defense in depth.
 * This file has no static imports: it runs on Node.js, Deno, Bun and edge
 * runtimes with the same behavior. Node 18's Web Crypto implementation is
 * loaded conditionally because it predates globalThis.crypto. The CommonJS
 * build is generated from this file by scripts/build-cjs.mjs so both module
 * formats cannot drift.
 */

export const CODE = Object.freeze({
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED_TOKEN: 'EXPIRED_TOKEN',
  SESSION_MISMATCH: 'SESSION_MISMATCH',
  CROSS_SITE_REQUEST: 'CROSS_SITE_REQUEST',
  ORIGIN_MISMATCH: 'ORIGIN_MISMATCH',
  MISSING_COOKIE: 'MISSING_COOKIE',
  WEAK_SECRET: 'WEAK_SECRET',
  INVALID_CONFIG: 'INVALID_CONFIG',
  INVALID_SESSION: 'INVALID_SESSION',
  RNG_UNAVAILABLE: 'RNG_UNAVAILABLE'
});

export class CsrfShieldError extends Error {
  constructor(code, reason, meta) {
    super(code + ': ' + reason);
    this.name = 'CsrfShieldError';
    this.code = code;
    this.reason = reason;
    this.meta = meta || undefined;
    this.status = code === CODE.WEAK_SECRET || code === CODE.INVALID_CONFIG ? 500 : 403;
  }

  toJSON() {
    return { name: this.name, code: this.code, message: this.message, status: this.status };
  }
}

function fail(code, reason, meta) {
  throw new CsrfShieldError(code, reason, meta);
}

/* ------------------------------------------------------------------ *
 * UTF-8 / base64url helpers. No platform APIs are required.
 * ------------------------------------------------------------------ */

const ENCODER = typeof TextEncoder === 'function' ? new TextEncoder() : null;
const DECODER = typeof TextDecoder === 'function' ? new TextDecoder('utf-8', { fatal: true }) : null;

function utf8Encode(value) {
  if (typeof value !== 'string') fail(CODE.INVALID_CONFIG, 'expected a string for UTF-8 encoding');
  if (ENCODER) return ENCODER.encode(value);
  const out = [];
  for (let i = 0; i < value.length; i++) {
    let cp = value.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < value.length) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00);
        i++;
      }
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(bytes) {
  if (DECODER) {
    try {
      return DECODER.decode(bytes);
    } catch (_) {
      fail(CODE.INVALID_TOKEN, 'token contains invalid UTF-8');
    }
  }
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b < 0x80) out += String.fromCharCode(b);
    else if (b < 0xe0) out += String.fromCharCode(((b & 31) << 6) | (bytes[++i] & 63));
    else if (b < 0xf0) out += String.fromCharCode(((b & 15) << 12) | ((bytes[++i] & 63) << 6) | (bytes[++i] & 63));
    else out += String.fromCharCode(((b & 7) << 18) | ((bytes[++i] & 63) << 12) | ((bytes[++i] & 63) << 6) | (bytes[++i] & 63));
  }
  return out;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Encode bytes as unpadded base64url. */
export function base64urlEncode(input) {
  const bytes = toBytes(input);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const c = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += B64URL[a >> 2];
    out += B64URL[((a & 3) << 4) | ((b === undefined ? 0 : b) >> 4)];
    if (b === undefined) break;
    out += B64URL[((b & 15) << 2) | ((c === undefined ? 0 : c) >> 6)];
    if (c === undefined) break;
    out += B64URL[c & 63];
  }
  return out;
}

/** Decode unpadded base64url, rejecting padding and non-canonical forms. */
export function base64urlDecodeStrict(text) {
  if (typeof text !== 'string' || text.length === 0 || !B64URL_RE.test(text)) {
    fail(CODE.INVALID_TOKEN, 'malformed base64url input');
  }
  if (text.length % 4 === 1) fail(CODE.INVALID_TOKEN, 'malformed base64url length');
  const out = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const index = B64URL.indexOf(text[i]);
    if (index < 0) fail(CODE.INVALID_TOKEN, 'malformed base64url character');
    acc = (acc << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 255);
    }
  }
  const bytes = new Uint8Array(out);
  if (base64urlEncode(bytes) !== text) fail(CODE.INVALID_TOKEN, 'non-canonical base64url input');
  return bytes;
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return utf8Encode(input);
  if (typeof ArrayBuffer !== 'undefined' && input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer && ArrayBuffer.isView && ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  fail(CODE.INVALID_CONFIG, 'expected Uint8Array, ArrayBuffer or string');
}

/* ------------------------------------------------------------------ *
 * SHA-256 and HMAC-SHA256. Implemented in plain JavaScript so the
 * library needs no imports at all. Node users may pass nodeCrypto from
 * the ./node entry point to use the native implementation instead.
 * ------------------------------------------------------------------ */

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(value, shift) {
  return ((value >>> shift) | (value << (32 - shift))) >>> 0;
}

/** SHA-256 over bytes, returning 32 bytes. */
export function sha256(input) {
  const bytes = toBytes(input);
  const bitLength = bytes.length * 8;
  if (!Number.isSafeInteger(bitLength)) fail(CODE.INVALID_CONFIG, 'input is too long for SHA-256');
  const paddedLength = (Math.ceil((bytes.length + 9) / 64) * 64);
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  padded[paddedLength - 8] = (high >>> 24) & 255;
  padded[paddedLength - 7] = (high >>> 16) & 255;
  padded[paddedLength - 6] = (high >>> 8) & 255;
  padded[paddedLength - 5] = high & 255;
  padded[paddedLength - 4] = (low >>> 24) & 255;
  padded[paddedLength - 3] = (low >>> 16) & 255;
  padded[paddedLength - 2] = (low >>> 8) & 255;
  padded[paddedLength - 1] = low & 255;

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
      const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (s0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  const words = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i++) {
    digest[i * 4] = (words[i] >>> 24) & 255;
    digest[i * 4 + 1] = (words[i] >>> 16) & 255;
    digest[i * 4 + 2] = (words[i] >>> 8) & 255;
    digest[i * 4 + 3] = words[i] & 255;
  }
  return digest;
}

/** HMAC-SHA256 over data using key, returning 32 bytes. */
export function hmacSha256(key, data) {
  const keyBytes = toBytes(key);
  const dataBytes = toBytes(data);
  let normalized = keyBytes;
  if (keyBytes.length > 64) normalized = sha256(keyBytes);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const k = i < normalized.length ? normalized[i] : 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  const inner = new Uint8Array(64 + dataBytes.length);
  inner.set(ipad);
  inner.set(dataBytes, 64);
  const innerDigest = sha256(inner);
  const outer = new Uint8Array(96);
  outer.set(opad);
  outer.set(innerDigest, 64);
  return sha256(outer);
}

/** Constant-time byte comparison. Length is compared as public data. */
export function constantTimeDiff(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return -1;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff;
}

/** Constant-time equality with the same signature as node:crypto timingSafeEqual. */
export function timingSafeEqual(a, b) {
  const diff = constantTimeDiff(a, b);
  return diff === 0;
}

let runtimeCrypto = globalThis.crypto;
if ((!runtimeCrypto || typeof runtimeCrypto.getRandomValues !== 'function') && typeof process !== 'undefined' && process.versions && process.versions.node) {
  runtimeCrypto = (await import('node:crypto')).webcrypto;
}

/** Default crypto adapter: Web Crypto randomness plus portable HMAC. */
export const webCrypto = Object.freeze({
  name: 'web-crypto',
  randomBytes(length) {
    if (!Number.isInteger(length) || length < 1) fail(CODE.INVALID_CONFIG, 'randomBytes length must be a positive integer');
    const source = globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function' ? globalThis.crypto : runtimeCrypto;
    if (!source || typeof source.getRandomValues !== 'function') {
      fail(CODE.RNG_UNAVAILABLE, 'no cryptographically secure random source is available');
    }
    const out = new Uint8Array(length);
    source.getRandomValues(out);
    return out;
  },
  hmac(key, data) {
    return hmacSha256(key, data);
  },
  timingEqual(a, b) {
    return timingSafeEqual(a, b);
  }
});

/* ------------------------------------------------------------------ *
 * BREACH-safe masking. A fresh random mask is used for every call.
 * ------------------------------------------------------------------ */

export function maskToken(token, crypto = webCrypto) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) fail(CODE.INVALID_TOKEN, 'cannot mask a malformed token');
  const payload = utf8Encode(token);
  const maskBytes = crypto.randomBytes(payload.length);
  const masked = new Uint8Array(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ maskBytes[i];
  return 'm1.' + base64urlEncode(maskBytes) + '.' + base64urlEncode(masked);
}

export function unmaskToken(value) {
  if (typeof value !== 'string') fail(CODE.INVALID_TOKEN, 'masked token must be a string');
  const parts = value.split('.');
  if (parts.length !== 3 || parts[0] !== 'm1') fail(CODE.INVALID_TOKEN, 'malformed masked token');
  const mask = base64urlDecodeStrict(parts[1]);
  const masked = base64urlDecodeStrict(parts[2]);
  if (mask.length === 0 || mask.length !== masked.length) fail(CODE.INVALID_TOKEN, 'mask length mismatch');
  const plain = new Uint8Array(masked.length);
  for (let i = 0; i < masked.length; i++) plain[i] = masked[i] ^ mask[i];
  const token = utf8Decode(plain);
  if (!TOKEN_RE.test(token)) fail(CODE.INVALID_TOKEN, 'unmasked token is malformed');
  return token;
}

export function isMaskedToken(value) {
  return typeof value === 'string' && value.startsWith('m1.');
}

/* ------------------------------------------------------------------ *
 * Token format: v1.<session>.<nonce>.<expiry base36>.<signature>
 * ------------------------------------------------------------------ */

const VERSION = 'v1';
const TOKEN_RE = /^v1\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[0-9a-z]+\.[A-Za-z0-9_-]+$/;
const COOKIE_VALUE_RE = /^[A-Za-z0-9._~-]+$/;
const SESSION_RE = /^[\x21-\x7e]*$/;
const SESSION_MAX_LENGTH = 256;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Parse a token without verifying its signature. */
export function parseToken(token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) fail(CODE.INVALID_TOKEN, 'malformed csrf token');
  const parts = token.split('.');
  const sessionPart = parts[1];
  const noncePart = parts[2];
  const signaturePart = parts[4];
  const session = sessionPart === '' ? '' : utf8Decode(base64urlDecodeStrict(sessionPart));
  const nonce = base64urlDecodeStrict(noncePart);
  if (session.length > SESSION_MAX_LENGTH || !SESSION_RE.test(session)) fail(CODE.INVALID_TOKEN, 'malformed token session');
  if (nonce.length < 16 || nonce.length > 64) fail(CODE.INVALID_TOKEN, 'malformed token nonce');
  const expiresAt = Number.parseInt(parts[3], 36);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) fail(CODE.INVALID_TOKEN, 'malformed token expiry');
  const signature = base64urlDecodeStrict(parts[4]);
  if (signature.length !== 32) fail(CODE.INVALID_TOKEN, 'malformed token signature');
  return { version: VERSION, session, nonce, expiresAt, signature, raw: token, data: signingInput(parts[1], parts[2], parts[3]) };
}

function signingInput(sessionPart, noncePart, expiryPart) {
  return VERSION + '|' + sessionPart + '|' + noncePart + '|' + expiryPart + '|';
}

/* ------------------------------------------------------------------ *
 * Cookie handling. Duplicate same-name cookies are always rejected.
 * ------------------------------------------------------------------ */

/** Parse one cookie by exact name from a Cookie header value. */
export function parseCookieHeader(headerValue, name, options = {}) {
  if (typeof name !== 'string' || name.length === 0) fail(CODE.INVALID_CONFIG, 'cookie name must be a non-empty string');
  let source = headerValue;
  if (Array.isArray(source)) {
    if (options.rejectDuplicateHeaders && source.length > 1) fail(CODE.INVALID_TOKEN, 'duplicate Cookie header');
    source = source.join('; ');
  }
  if (source === undefined || source === null) return null;
  if (typeof source !== 'string') fail(CODE.INVALID_TOKEN, 'Cookie header must be a string');
  if (source.indexOf('\r') !== -1 || source.indexOf('\n') !== -1 || source.indexOf('\0') !== -1) {
    fail(CODE.INVALID_TOKEN, 'control character in Cookie header');
  }
  const matches = [];
  for (const segment of source.split(';')) {
    const separator = segment.indexOf('=');
    if (separator < 0) continue;
    if (segment.slice(0, separator).trim() === name) matches.push(segment.slice(separator + 1).trim());
  }
  if (matches.length === 0) return null;
  if (matches.length > 1) fail(CODE.INVALID_TOKEN, 'duplicate csrf cookie');
  const value = matches[0];
  if (value.length === 0) fail(CODE.INVALID_TOKEN, 'empty csrf cookie');
  if (options.strictValues !== false && !COOKIE_VALUE_RE.test(value)) {
    fail(CODE.INVALID_TOKEN, 'malformed csrf cookie value');
  }
  return value;
}

/* ------------------------------------------------------------------ *
 * Request normalization for Node IncomingMessage and Fetch Request.
 * ------------------------------------------------------------------ */

function headerBag(source) {
  const map = new Map();
  const push = (key, value) => {
    const name = String(key).toLowerCase();
    const values = map.get(name) || [];
    values.push(typeof value === 'string' ? value : String(value));
    map.set(name, values);
  };
  if (source && typeof source.forEach === 'function' && typeof source.get === 'function' && typeof source.has === 'function') {
    source.forEach((value, key) => push(key, value));
  } else if (source && typeof source === 'object') {
    for (const key of Object.keys(source)) {
      const value = source[key];
      if (Array.isArray(value)) value.forEach((item) => push(key, item));
      else if (value !== undefined && value !== null) push(key, value);
    }
  }
  return Object.freeze({
    forEach(callback) {
      map.forEach((values, name) => {
        values.forEach((value) => callback(value, name));
      });
    },
    get(name) {
      const values = map.get(String(name).toLowerCase());
      return values ? values.join(', ') : null;
    },
    getAll(name) {
      const values = map.get(String(name).toLowerCase());
      return values ? values.slice() : [];
    },
    has(name) {
      return map.has(String(name).toLowerCase());
    }
  });
}

function normalizeRequest(input, options = {}) {
  const raw = input && typeof input === 'object' ? input : {};
  const method = String(options.method || raw.method || 'GET').toUpperCase();
  const headers = headerBag(options.headers || raw.headers);
  const body = options.body !== undefined ? options.body : raw.body;
  const cookieHeader = options.cookie !== undefined ? options.cookie : (raw.cookie !== undefined ? raw.cookie : headers.get('cookie'));
  return Object.freeze({
    raw,
    method,
    headers,
    url: String(options.url || raw.url || ''),
    body,
    cookieHeader
  });
}

function isFetchRequest(raw) {
  return Boolean(raw && typeof raw.clone === 'function' && typeof raw.text === 'function' && raw.headers);
}

async function readFetchBody(request) {
  try {
    const clone = request.clone();
    const contentType = String(clone.headers.get('content-type') || '').toLowerCase();
    if (contentType.indexOf('multipart/form-data') !== -1) {
      const form = await clone.formData();
      const result = {};
      form.forEach((value, key) => { result[key] = value; });
      return result;
    }
    const text = await clone.text();
    if (contentType.indexOf('application/json') !== -1) return JSON.parse(text);
    return text;
  } catch (_) {
    return null;
  }
}

function fieldFromBody(body, field) {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string') {
    if (body.charAt(0) === '{') {
      try {
        return fieldFromBody(JSON.parse(body), field);
      } catch (_) {
        return null;
      }
    }
    try {
      return new URLSearchParams(body).get(field);
    } catch (_) {
      return null;
    }
  }
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return body.get(field);
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const value = body.get(field);
    return typeof value === 'string' ? value : null;
  }
  if (typeof body === 'object') {
    const value = body[field];
    return typeof value === 'string' ? value : null;
  }
  return null;
}

/** Canonicalize an origin value to scheme://host[:port], rejecting odd inputs. */
export function canonicalOrigin(value, fromReferer = false) {
  if (typeof value !== 'string' || value.length === 0) fail(CODE.ORIGIN_MISMATCH, 'origin must be a non-empty string');
  if (value.trim() !== value) fail(CODE.ORIGIN_MISMATCH, 'origin contains surrounding whitespace');
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_) {
    fail(CODE.ORIGIN_MISMATCH, 'origin is not a valid URL');
  }
  if (parsed.origin === 'null' || parsed.username || parsed.password) {
    fail(CODE.ORIGIN_MISMATCH, 'origin must be a bare scheme and authority');
  }
  if (!fromReferer) {
    if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
      fail(CODE.ORIGIN_MISMATCH, 'Origin must be a bare scheme and authority');
    }
  } else if (!['http:', 'https:'].includes(parsed.protocol)) {
    fail(CODE.ORIGIN_MISMATCH, 'referer must use http or https');
  }
  return parsed.origin;
}

export function isSafeMethod(method) {
  return SAFE_METHODS.has(String(method).toUpperCase());
}

/* ------------------------------------------------------------------ *
 * Configuration and shield factory.
 * ------------------------------------------------------------------ */

/**
 * Build a node:crypto backed adapter from the module passed by ./node.
 * Keeping this factory import-free lets the CJS build expose the same API.
 */
export function createNodeCrypto(nodeModule) {
  if (!nodeModule || typeof nodeModule.createHmac !== 'function' || typeof nodeModule.timingSafeEqual !== 'function' || typeof nodeModule.randomBytes !== 'function') {
    fail(CODE.INVALID_CONFIG, 'node crypto module must provide createHmac, timingSafeEqual and randomBytes');
  }
  const encode = (value) => {
    if (typeof value === 'string') return Buffer.from(value, 'utf8');
    if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    fail(CODE.INVALID_CONFIG, 'node crypto adapter received an unsupported value');
  };
  return Object.freeze({
    name: 'node-crypto',
    randomBytes(length) {
      if (!Number.isInteger(length) || length < 1) fail(CODE.INVALID_CONFIG, 'randomBytes length must be a positive integer');
      return new Uint8Array(nodeModule.randomBytes(length));
    },
    hmac(key, data) {
      return new Uint8Array(nodeModule.createHmac('sha256', encode(key)).update(encode(data)).digest());
    },
    timingEqual(a, b) {
      const left = encode(a);
      const right = encode(b);
      if (left.length === right.length) return nodeModule.timingSafeEqual(left, right);
      const hash = (value) => {
        const hasher = nodeModule.createHash && nodeModule.createHash('sha256');
        if (hasher) return hasher.update(value).digest();
        return nodeModule.createHmac('sha256', Buffer.alloc(32)).update(value).digest();
      };
      return nodeModule.timingSafeEqual(hash(left), hash(right));
    }
  });
}

function normalizeSecrets(input) {
  const values = Array.isArray(input) ? input : [input];
  if (values.length === 0 || values.some((value) => typeof value !== 'string')) {
    fail(CODE.WEAK_SECRET, 'secrets must be a non-empty array of strings');
  }
  for (const secret of values) {
    if (secret.length < 32) fail(CODE.WEAK_SECRET, 'each secret must be at least 32 bytes');
  }
  return Object.freeze(values.slice());
}

function normalizeCookie(input) {
  const source = input && typeof input === 'object' ? input : {};
  const name = typeof source.name === 'string' && source.name.length ? source.name : '__Host-csrf';
  const path = typeof source.path === 'string' && source.path.startsWith('/') ? source.path : '/';
  const secure = source.secure !== false;
  const httpOnly = source.httpOnly !== false;
  const sameSite = source.sameSite === undefined ? 'Lax' : source.sameSite;
  if (['Lax', 'Strict', 'None'].indexOf(sameSite) === -1) fail(CODE.INVALID_CONFIG, 'sameSite must be Lax, Strict or None');
  if (sameSite === 'None' && !secure) fail(CODE.INVALID_CONFIG, 'SameSite=None requires Secure');
  if (name.startsWith('__Host-') && (!secure || path !== '/' || source.domain)) {
    fail(CODE.INVALID_CONFIG, '__Host- cookies require Secure, Path=/ and no Domain');
  }
  if (name.startsWith('__Secure-') && !secure) fail(CODE.INVALID_CONFIG, '__Secure- cookies require Secure');
  if (!/^[A-Za-z0-9_-]+$/.test(name)) fail(CODE.INVALID_CONFIG, 'cookie name contains invalid characters');
  let maxAge = source.maxAge === undefined ? null : source.maxAge;
  if (maxAge !== null && (!Number.isInteger(maxAge) || maxAge < 0)) fail(CODE.INVALID_CONFIG, 'cookie maxAge must be a non-negative integer');
  return Object.freeze({ name, path, secure, httpOnly, sameSite, domain: source.domain || null, maxAge });
}

function normalizeCrypto(input) {
  if (input === undefined) return webCrypto;
  if (!input || typeof input.randomBytes !== 'function' || typeof input.hmac !== 'function' || typeof input.timingEqual !== 'function') {
    fail(CODE.INVALID_CONFIG, 'crypto adapter must provide randomBytes, hmac and timingEqual');
  }
  return input;
}

/**
 * Create a configured shield instance.
 *
 * Options:
 *   secrets: string[]                  at least one secret of 32+ bytes, first signs, all verify
 *   getSessionId(req): string          trusted server session id (defaults to anonymous)
 *   origin: string | string[] | fn     exact allowed origins
 *   originCheck: { enabled, strict, allowNull, refererFallback }
 *   fetchMetadata: { enabled, strictness, allowNone }
 *   cookie: { name, path, secure, httpOnly, sameSite, maxAge, domain }
 *   header: string                     default x-csrf-token
 *   bodyField: string                  default _csrf
 *   tokenTtlMs: number                 default 3600000
 *   clockSkewMs: number                default 30000
 *   mask: boolean                      require masked tokens on verification
 *   extractToken(req, ctx): string     custom token source
 *   crypto: adapter                    defaults to webCrypto, nodeCrypto is available
 */
export function createShield(options = {}) {
  if (!options || typeof options !== 'object') fail(CODE.INVALID_CONFIG, 'options must be an object');
  if (options.secrets === undefined && options.secret === undefined) fail(CODE.WEAK_SECRET, 'secrets are required');
  const secrets = normalizeSecrets(options.secrets !== undefined ? options.secrets : options.secret);
  const cookie = normalizeCookie(options.cookie);
  const crypto = normalizeCrypto(options.crypto);
  const header = typeof options.header === 'string' && options.header.length ? options.header : 'x-csrf-token';
  const bodyField = typeof options.bodyField === 'string' && options.bodyField.length ? options.bodyField : '_csrf';
  const tokenTtlMs = options.tokenTtlMs === undefined ? 3600000 : options.tokenTtlMs;
  const clockSkewMs = options.clockSkewMs === undefined ? 30000 : options.clockSkewMs;
  if (!Number.isSafeInteger(tokenTtlMs) || tokenTtlMs < 1) fail(CODE.INVALID_CONFIG, 'tokenTtlMs must be a positive integer');
  if (!Number.isSafeInteger(clockSkewMs) || clockSkewMs < 0) fail(CODE.INVALID_CONFIG, 'clockSkewMs must be a non-negative integer');
  if (clockSkewMs >= tokenTtlMs) fail(CODE.INVALID_CONFIG, 'clockSkewMs must be smaller than tokenTtlMs');
  if (options.getSessionId !== undefined && typeof options.getSessionId !== 'function') fail(CODE.INVALID_CONFIG, 'getSessionId must be a function');
  if (options.extractToken !== undefined && typeof options.extractToken !== 'function') fail(CODE.INVALID_CONFIG, 'extractToken must be a function');

  const originInput = options.origin;
  let allowedOrigins;
  let isAllowedOrigin;
  if (typeof originInput === 'function') {
    allowedOrigins = null;
    isAllowedOrigin = originInput;
  } else {
    const values = originInput === undefined || originInput === null ? [] : (Array.isArray(originInput) ? originInput : [originInput]);
    allowedOrigins = Object.freeze(values.map((value) => canonicalOrigin(value)));
    isAllowedOrigin = null;
  }
  const originRaw = options.originCheck && typeof options.originCheck === 'object' ? options.originCheck : {};
  const originCheck = Object.freeze({
    enabled: originRaw.enabled === undefined ? (allowedOrigins !== null && allowedOrigins.length > 0) || isAllowedOrigin !== null : originRaw.enabled === true,
    strict: originRaw.strict !== false,
    allowNull: originRaw.allowNull === true,
    refererFallback: originRaw.refererFallback !== false
  });
  const metadataRaw = options.fetchMetadata && typeof options.fetchMetadata === 'object' ? options.fetchMetadata : {};
  const strictness = metadataRaw.strictness === undefined ? 'same-site' : metadataRaw.strictness;
  if (['same-origin', 'same-site'].indexOf(strictness) === -1) fail(CODE.INVALID_CONFIG, 'fetchMetadata.strictness must be same-origin or same-site');
  const fetchMetadata = Object.freeze({
    enabled: metadataRaw.enabled !== false,
    strictness,
    allowNone: metadataRaw.allowNone !== false
  });
  const requireMask = options.mask === true;

  function resolveSession(context, raw) {
    let session = '';
    if (options.getSessionId) session = options.getSessionId(raw || context, context);
    if (session === undefined || session === null) session = '';
    if (typeof session !== 'string' || session.length > SESSION_MAX_LENGTH || !SESSION_RE.test(session)) {
      fail(CODE.INVALID_SESSION, 'session id must be printable ASCII of at most 256 characters');
    }
    return session;
  }

  function signWith(secret, data) {
    return crypto.hmac(secret, data);
  }

  function issueToken(context = {}, settings = {}) {
    const session = settings.sessionId !== undefined ? settings.sessionId : resolveSession(context, context.raw || context);
    if (typeof session !== 'string' || session.length > SESSION_MAX_LENGTH || !SESSION_RE.test(session)) {
      fail(CODE.INVALID_SESSION, 'session id must be printable ASCII of at most 256 characters');
    }
    const now = settings.now === undefined ? Date.now() : settings.now;
    if (!Number.isSafeInteger(now)) fail(CODE.INVALID_CONFIG, 'now must be an integer');
    const expiresAt = now + tokenTtlMs;
    const nonce = settings.nonce ? toBytes(settings.nonce) : crypto.randomBytes(18);
    if (nonce.length < 16 || nonce.length > 64) fail(CODE.INVALID_CONFIG, 'nonce must be 16 to 64 bytes');
    const sessionPart = base64urlEncode(session);
    const noncePart = base64urlEncode(nonce);
    const expiryPart = expiresAt.toString(36);
    const signature = signWith(secrets[0], signingInput(sessionPart, noncePart, expiryPart));
    return VERSION + '.' + sessionPart + '.' + noncePart + '.' + expiryPart + '.' + base64urlEncode(signature);
  }

  function verifyToken(token, settings = {}) {
    const parsed = parseToken(token);
    const now = settings.now === undefined ? Date.now() : settings.now;
    if (!Number.isSafeInteger(now)) fail(CODE.INVALID_CONFIG, 'now must be an integer');
    let diff = -1;
    for (const secret of secrets) {
      const expected = signWith(secret, parsed.data);
      const current = constantTimeDiff(expected, parsed.signature);
      if (current !== -1 && (diff === -1 || current < diff)) diff = current;
    }
    if (diff !== 0) fail(CODE.INVALID_TOKEN, 'csrf token signature is invalid');
    if (now > parsed.expiresAt + clockSkewMs) fail(CODE.EXPIRED_TOKEN, 'csrf token has expired');
    if (parsed.expiresAt > now + tokenTtlMs + clockSkewMs) fail(CODE.INVALID_TOKEN, 'csrf token expiry is too far in the future');
    const expectedSession = settings.sessionId === undefined ? '' : settings.sessionId;
    if (!crypto.timingEqual(parsed.session, expectedSession)) fail(CODE.SESSION_MISMATCH, 'csrf token belongs to a different session');
    return Object.freeze({
      ok: true,
      token: parsed.raw,
      sessionId: parsed.session,
      expiresAt: parsed.expiresAt,
      ttlMs: tokenTtlMs
    });
  }

  function serializeCookie(token, settings = {}) {
    if (typeof token !== 'string' || token.length === 0) fail(CODE.INVALID_TOKEN, 'cookie token must be a non-empty string');
    const segments = [cookie.name + '=' + token, 'Path=' + cookie.path];
    if (cookie.domain) segments.push('Domain=' + cookie.domain);
    if (cookie.secure) segments.push('Secure');
    if (cookie.httpOnly) segments.push('HttpOnly');
    segments.push('SameSite=' + cookie.sameSite);
    const maxAge = settings.maxAge === undefined ? cookie.maxAge : settings.maxAge;
    if (maxAge !== null) segments.push('Max-Age=' + maxAge);
    return segments.join('; ');
  }

  function clearCookie() {
    return cookie.name + '=; Path=' + cookie.path + '; Max-Age=0' +
      (cookie.secure ? '; Secure' : '') + (cookie.httpOnly ? '; HttpOnly' : '') + '; SameSite=' + cookie.sameSite;
  }

  function issueCookie(context = {}, settings = {}) {
    return serializeCookie(issueToken(context, settings), settings);
  }

  function issueTokenPair(context = {}, settings = {}) {
    const token = issueToken(context, settings);
    return Object.freeze({
      token,
      maskedToken: maskToken(token, crypto),
      cookie: serializeCookie(token, settings),
      setCookie: serializeCookie(token, settings),
      expiresAt: settings.now === undefined ? Date.now() + tokenTtlMs : settings.now + tokenTtlMs
    });
  }

  async function checkOrigin(ctx) {
    if (!originCheck.enabled) return;
    const originValues = ctx.headers.getAll('origin');
    const refererValues = ctx.headers.getAll('referer');
    if (originValues.length > 1 || refererValues.length > 1) fail(CODE.ORIGIN_MISMATCH, 'duplicate Origin or Referer header');
    const origin = originValues.length ? originValues[0] : null;
    const referer = refererValues.length ? refererValues[0] : null;
    if (origin !== null) {
      if (origin === 'null') {
        if (originCheck.allowNull) return;
        fail(CODE.ORIGIN_MISMATCH, 'null origin is not allowed');
      }
      const canonical = canonicalOrigin(origin);
      await assertOriginAllowed(canonical, ctx);
      return;
    }
    if (referer !== null && originCheck.refererFallback) {
      if (referer === 'null') {
        if (originCheck.allowNull) return;
        fail(CODE.ORIGIN_MISMATCH, 'null referer is not allowed');
      }
      let canonical;
      try {
        canonical = canonicalOrigin(referer, true);
      } catch (_) {
        fail(CODE.ORIGIN_MISMATCH, 'referer is not a valid origin');
      }
      await assertOriginAllowed(canonical, ctx);
      return;
    }
    if (originCheck.strict) fail(CODE.ORIGIN_MISMATCH, 'missing Origin and Referer on a state-changing request');
  }

  async function assertOriginAllowed(canonical, ctx) {
    if (isAllowedOrigin) {
      let allowed = isAllowedOrigin(canonical, ctx.raw, ctx);
      if (allowed && typeof allowed.then === 'function') allowed = await allowed;
      if (allowed !== true) fail(CODE.ORIGIN_MISMATCH, 'origin is not allowed');
      return;
    }
    if (allowedOrigins.indexOf(canonical) === -1) fail(CODE.ORIGIN_MISMATCH, 'origin is not allowed');
  }

  function checkFetchMetadata(ctx) {
    if (!fetchMetadata.enabled) return;
    const values = ctx.headers.getAll('sec-fetch-site');
    if (values.length > 1) fail(CODE.CROSS_SITE_REQUEST, 'duplicate Sec-Fetch-Site header');
    if (values.length === 0) return;
    const site = values[0].toLowerCase();
    if (site === 'same-origin') return;
    if (site === 'same-site') {
      if (fetchMetadata.strictness === 'same-origin') fail(CODE.CROSS_SITE_REQUEST, 'same-site requests are rejected by policy');
      return;
    }
    if (site === 'none') {
      if (fetchMetadata.allowNone) return;
      fail(CODE.CROSS_SITE_REQUEST, 'requests without a site context are rejected by policy');
    }
    fail(CODE.CROSS_SITE_REQUEST, 'cross-site or unknown fetch context is not allowed');
  }

  async function extractSubmittedToken(ctx, settings) {
    if (settings.extractToken) {
      const custom = await settings.extractToken(ctx.raw, ctx);
      if (custom === undefined || custom === null) fail(CODE.INVALID_TOKEN, 'custom extractor returned no token');
      return String(custom);
    }
    if (settings.token !== undefined && settings.token !== null) return String(settings.token);
    const headerValues = ctx.headers.getAll(header);
    if (headerValues.length > 1) fail(CODE.INVALID_TOKEN, 'duplicate csrf token header');
    if (headerValues.length === 1) {
      const value = headerValues[0];
      if (value.indexOf(',') !== -1) fail(CODE.INVALID_TOKEN, 'multiple csrf tokens in one header');
      return value.trim();
    }
    let body = ctx.body;
    if (isFetchRequest(ctx.raw)) body = await readFetchBody(ctx.raw);
    const value = fieldFromBody(body, bodyField);
    if (value === null || value === undefined) fail(CODE.INVALID_TOKEN, 'no csrf token in header or body');
    return value;
  }

  async function verifyRequest(input, settings = {}) {
    const ctx = normalizeRequest(input, settings);
    if (isSafeMethod(ctx.method)) {
      return Object.freeze({ ok: true, skipped: true, method: ctx.method, url: ctx.url });
    }
    checkFetchMetadata(ctx);
    await checkOrigin(ctx);
    const session = settings.sessionId !== undefined ? settings.sessionId : resolveSession(ctx, ctx.raw);
    const cookieToken = parseCookieHeader(ctx.cookieHeader, cookie.name, { rejectDuplicateHeaders: true });
    if (cookieToken === null) fail(CODE.MISSING_COOKIE, 'csrf cookie is missing');
    const cookieVerified = verifyToken(cookieToken, { sessionId: session, now: settings.now });
    let submitted = await extractSubmittedToken(ctx, settings);
    if (isMaskedToken(submitted)) submitted = unmaskToken(submitted);
    else if (requireMask) fail(CODE.INVALID_TOKEN, 'masked token is required by policy');
    const submittedVerified = verifyToken(submitted, { sessionId: session, now: settings.now });
    if (!crypto.timingEqual(submitted, cookieToken)) fail(CODE.INVALID_TOKEN, 'csrf token does not match the cookie');
    return Object.freeze({
      ok: true,
      skipped: false,
      method: ctx.method,
      url: ctx.url,
      token: cookieToken,
      sessionId: session,
      expiresAt: cookieVerified.expiresAt,
      verifiedAt: submittedVerified.expiresAt
    });
  }

  function appendSetCookie(response, value) {
    if (typeof response.appendHeader === 'function') {
      response.appendHeader('Set-Cookie', value);
      return;
    }
    if (typeof response.setHeader !== 'function') return;
    const existing = response.getHeader && response.getHeader('Set-Cookie');
    if (!existing) {
      response.setHeader('Set-Cookie', value);
      return;
    }
    response.setHeader('Set-Cookie', Array.isArray(existing) ? existing.concat([value]) : [String(existing), value]);
  }

  async function middleware(request, response, next) {
    if (typeof next !== 'function') fail(CODE.INVALID_CONFIG, 'middleware requires a next callback');
    try {
      const ctx = normalizeRequest(request);
      if (!isSafeMethod(ctx.method)) {
        const verified = await verifyRequest(ctx);
        if (response.locals) response.locals.csrfVerified = verified;
        return next();
      }
      let existing = null;
      try {
        existing = parseCookieHeader(ctx.cookieHeader, cookie.name, { rejectDuplicateHeaders: true });
        if (existing !== null) {
          // Never hand a token to the page that the server has not signed.
          // A well formed but forged or expired cookie is replaced instead of
          // being reflected back, which stops cookie tossing from fixing a
          // token the attacker already knows.
          verifyToken(existing, { sessionId: resolveSession(ctx, ctx.raw) });
        }
      } catch (_) {
        existing = null;
      }
      const token = existing || issueToken(ctx);
      if (!existing) appendSetCookie(response, serializeCookie(token));
      if (response.locals) response.locals.csrfToken = token;
      return next();
    } catch (error) {
      return next(error);
    }
  }

  function errorResponse(error, settings = {}) {
    if (typeof settings.onError === 'function') return settings.onError(error);
    const ResponseClass = globalThis.Response;
    if (typeof ResponseClass !== 'function') fail(CODE.INVALID_CONFIG, 'global Response is required for fetch adapters');
    return new ResponseClass(JSON.stringify({ error: error.code || CODE.INVALID_TOKEN, message: error.message }), {
      status: error.status || 403,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
    });
  }

  async function protectFetch(request, settings = {}) {
    const verified = await verifyRequest(request, settings);
    return Object.freeze({ verified, request });
  }

  function withFetch(handler, settings = {}) {
    if (typeof handler !== 'function') fail(CODE.INVALID_CONFIG, 'handler must be a function');
    return async function csrfFetchHandler(request, ...rest) {
      let verified;
      try {
        verified = await verifyRequest(request, settings);
      } catch (error) {
        // Only CSRF failures become CSRF responses. Application errors thrown
        // by the handler (or by a custom extractor) must propagate to the
        // framework, otherwise internal messages leak in a 403 body.
        if (error instanceof CsrfShieldError) return errorResponse(error, settings);
        throw error;
      }
      return await handler(request, verified, ...rest);
    };
  }

  function createFetchTokenResponse(token, settings = {}) {
    if (typeof token !== 'string') fail(CODE.INVALID_TOKEN, 'token must be a string');
    const ResponseClass = globalThis.Response;
    if (typeof ResponseClass !== 'function') fail(CODE.INVALID_CONFIG, 'global Response is required for fetch adapters');
    const body = settings.body === undefined ? { csrfToken: token } : settings.body;
    return new ResponseClass(JSON.stringify(body), {
      status: 200,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'set-cookie': serializeCookie(token, settings)
      }
    });
  }

  return Object.freeze({
    secrets,
    cookie,
    header,
    bodyField,
    tokenTtlMs,
    clockSkewMs,
    originCheck,
    fetchMetadata,
    allowedOrigins,
    issueToken,
    verifyToken,
    serializeCookie,
    clearCookie,
    issueCookie,
    issueTokenPair,
    verifyRequest,
    verify: verifyRequest,
    middleware,
    nodeMiddleware: middleware,
    protectFetch,
    withFetch,
    fetchHandler: withFetch,
    errorResponse,
    createFetchTokenResponse,
    parseCookie: (headerValue) => parseCookieHeader(headerValue, cookie.name, { rejectDuplicateHeaders: true })
  });
}

export default {
  CODE,
  CsrfShieldError,
  createShield,
  webCrypto,
  nodeCrypto: undefined
};
