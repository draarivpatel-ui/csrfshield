import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const esmUrl = pathToFileURL(path.join(root, 'src', 'index.mjs')).href;
const esm = await import(esmUrl);
const nodeEsm = await import(pathToFileURL(path.join(root, 'src', 'node.mjs')).href);
const cjs = require(path.join(root, 'cjs', 'index.cjs'));
const cjsNode = require(path.join(root, 'cjs', 'node.cjs'));

/** Native adapter with fully deterministic HMAC for exact token reproduction. */
export const nativeCrypto = {
  name: 'test-node-crypto',
  randomBytes: (length) => new Uint8Array(randomBytes(length)),
  hmac: (key, data) => new Uint8Array(createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest()),
  timingEqual: (a, b) => {
    const left = Buffer.from(a);
    const right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
  }
};

/** Fully deterministic adapter for reproducible tokens. */
export function fixedCrypto(nonce = new Uint8Array(24).fill(7)) {
  return {
    name: 'fixed-test-crypto',
    randomBytes: () => new Uint8Array(nonce),
    hmac: nativeCrypto.hmac,
    timingEqual: nativeCrypto.timingEqual
  };
}

export const SECRET = 'a'.repeat(32);
export const SECRET2 = 'b'.repeat(32);
export const ORIGIN = 'https://app.example.com';

export function baseOptions(overrides = {}) {
  return Object.assign({
    secrets: [SECRET],
    origin: ORIGIN,
    crypto: nativeCrypto,
    getSessionId: (req) => (req && req.sessionId) || ''
  }, overrides);
}

export function makeShield(overrides = {}) {
  return esm.createShield(baseOptions(overrides));
}

export function postRequest(tokenValue, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (options.cookie !== undefined) headers.cookie = options.cookie;
  const req = {
    method: options.method || 'POST',
    url: options.url || ORIGIN + '/transfer',
    headers,
    sessionId: options.sessionId || 'session-1',
    body: options.body || { _csrf: tokenValue }
  };
  if (options.duplicateCookieHeader) req.cookie = options.duplicateCookieHeader;
  return req;
}

export function expectCode(test, fn, code, label) {
  try {
    const result = fn();
    if (result && typeof result.then === 'function') {
      return result.then(
        () => assert.fail(label + ': expected ' + code + ' but resolved'),
        (error) => {
          assert.equal(error.name, 'CsrfShieldError', label + ': error type');
          assert.equal(error.code, code, label + ': error code');
          return error;
        }
      );
    }
    assert.fail(label + ': expected ' + code + ' but no error was thrown');
  } catch (error) {
    assert.equal(error.name, 'CsrfShieldError', label + ': error type');
    assert.equal(error.code, code, label + ': error code');
    return error;
  }
}

export async function expectCodeAsync(test, fn, code, label) {
  try {
    await fn();
    assert.fail(label + ': expected ' + code + ' but resolved');
  } catch (error) {
    assert.equal(error.name, 'CsrfShieldError', label + ': error type');
    assert.equal(error.code, code, label + ': error code');
    return error;
  }
}

export { esm, nodeEsm, cjs, cjsNode, createHash, randomBytes };
