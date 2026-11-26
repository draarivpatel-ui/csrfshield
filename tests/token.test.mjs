import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esm, cjs, makeShield, fixedCrypto, nativeCrypto, SECRET, SECRET2, ORIGIN, expectCode } from './helpers.mjs';

const { CODE, parseToken, maskToken, unmaskToken, isMaskedToken, webCrypto } = esm;

const deterministic = fixedCrypto();

test('issueToken emits the documented v1 format', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1700000000000 });
  const parts = token.split('.');
  assert.equal(parts.length, 5);
  assert.equal(parts[0], 'v1');
  assert.equal(parts[1], Buffer.from('alice').toString('base64url'));
  assert.equal(parts[3], (1700000000000 + 3600000).toString(36));
  assert.equal(parts[4].length, 43);
});

test('issueToken uses a fresh nonce for each token', () => {
  const shield = makeShield();
  const first = shield.issueToken({}, { sessionId: 'alice' });
  const second = shield.issueToken({}, { sessionId: 'alice' });
  assert.notEqual(first, second);
});

test('verifyToken accepts a freshly issued token', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const result = shield.verifyToken(token, { sessionId: 'alice', now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(result.sessionId, 'alice');
  assert.equal(result.ttlMs, 3600000);
});

test('verifyToken rejects a tampered signature', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const parts = token.split('.');
  parts[4] = (parts[4][0] === 'A' ? 'B' : 'A') + parts[4].slice(1);
  expectCode(test, () => shield.verifyToken(parts.join('.'), { sessionId: 'alice', now: 1000001 }), CODE.INVALID_TOKEN, 'tampered signature');
});

test('verifyToken rejects truncation and appended junk', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'a', now: 1000000 });
  expectCode(test, () => shield.verifyToken(token.slice(0, -3), { sessionId: 'a', now: 1000001 }), CODE.INVALID_TOKEN, 'truncated');
  expectCode(test, () => shield.verifyToken(token + 'junk', { sessionId: 'a', now: 1000001 }), CODE.INVALID_TOKEN, 'appended');
  expectCode(test, () => shield.verifyToken('v2' + token.slice(2), { sessionId: 'a', now: 1000001 }), CODE.INVALID_TOKEN, 'wrong version');
});

test('verifyToken rejects expired tokens', () => {
  const shield = makeShield({ crypto: deterministic, tokenTtlMs: 1000, clockSkewMs: 100 });
  const token = shield.issueToken({}, { sessionId: 'a', now: 1000 });
  assert.equal(shield.verifyToken(token, { sessionId: 'a', now: 2000 }).ok, true);
  expectCode(test, () => shield.verifyToken(token, { sessionId: 'a', now: 2101 }), CODE.EXPIRED_TOKEN, 'expired');
});

test('verifyToken rejects expiry far in the future', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'a', now: 1000000 });
  expectCode(test, () => shield.verifyToken(token, { sessionId: 'a', now: -10000000 }), CODE.INVALID_TOKEN, 'future expiry');
});

test('verifyToken rejects a session mismatch', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'victim', now: 1000000 });
  expectCode(test, () => shield.verifyToken(token, { sessionId: 'attacker', now: 1000001 }), CODE.SESSION_MISMATCH, 'session mismatch');
});

test('parseToken rejects malformed token encodings', () => {
  for (const value of ['', 'v1', 'v1.a.b.c.d', 'v1.!!!.AAAAAAAAAAAAAAAAAAAAAA.1.AAAA', 'v1.YQ.AAAAAAAAAAAAAAAAAAAAAA.zz.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']) {
    assert.throws(() => parseToken(value), (error) => error.code === CODE.INVALID_TOKEN, value);
  }
});

test('parseToken exposes the exact signing input', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'x', now: 1000 });
  const parsed = parseToken(token);
  assert.equal(parsed.data, token.split('.').slice(0, 4).join('|') + '|');
  assert.equal(parsed.expiresAt, 1000 + 3600000);
  assert.equal(parsed.nonce.length, 24);
});

test('maskToken produces a fresh random mask and unmaskToken recovers the token', () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000 });
  const maskedA = maskToken(token, nativeCrypto);
  const maskedB = maskToken(token, nativeCrypto);
  assert.equal(maskedA.startsWith('m1.'), true);
  assert.notEqual(maskedA, maskedB);
  assert.equal(unmaskToken(maskedA), token);
  assert.equal(unmaskToken(maskedB), token);
  assert.equal(isMaskedToken(maskedA), true);
  assert.equal(isMaskedToken(token), false);
});

test('unmaskToken rejects malformed and non-canonical masked values', () => {
  for (const value of ['', 'm1', 'm1.a', 'm1.a.b.c', 'm2.a.b', 'm1.!!!!.AAAA', 'm1.AA.A', 'm1.A.A']) {
    assert.throws(() => unmaskToken(value), (error) => error.code === CODE.INVALID_TOKEN, value);
  }
});

test('maskToken rejects malformed tokens', () => {
  assert.throws(() => maskToken('not-a-token'), (error) => error.code === CODE.INVALID_TOKEN);
});

test('webCrypto adapter uses Web Crypto randomness and portable HMAC', () => {
  const bytes = webCrypto.randomBytes(24);
  assert.equal(bytes.length, 24);
  assert.equal(bytes.some((b) => b !== 0), true);
  const expected = esm.hmacSha256('k'.repeat(32), 'data');
  assert.deepEqual(webCrypto.hmac('k'.repeat(32), 'data'), expected);
  assert.equal(webCrypto.timingEqual(expected, expected), true);
});

test('cjs and esm produce byte-identical tokens with the same nonce', () => {
  const opts = { secrets: [SECRET], crypto: deterministic };
  const a = esm.createShield(opts).issueToken({}, { sessionId: 'z', now: 12345 });
  const b = cjs.createShield(opts).issueToken({}, { sessionId: 'z', now: 12345 });
  assert.equal(a, b);
});

test('key rotation verifies tokens signed by any configured secret', () => {
  const signer = makeShield({ secrets: [SECRET2], crypto: deterministic });
  const verifier = makeShield({ secrets: [SECRET, SECRET2], crypto: deterministic });
  const token = signer.issueToken({}, { sessionId: 'alice', now: 1000000 });
  assert.equal(verifier.verifyToken(token, { sessionId: 'alice', now: 1000001 }).ok, true);
});

test('key rotation rejects tokens from retired secrets', () => {
  const old = makeShield({ secrets: [SECRET2], crypto: deterministic });
  const current = makeShield({ secrets: [SECRET], crypto: deterministic });
  const token = old.issueToken({}, { sessionId: 'alice', now: 1000000 });
  expectCode(test, () => current.verifyToken(token, { sessionId: 'alice', now: 1000001 }), CODE.INVALID_TOKEN, 'retired secret');
});

test('rotation uses the first secret when issuing and accepts both afterward', () => {
  const shield = makeShield({ secrets: [SECRET, SECRET2], crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const explicit = esm.hmacSha256(SECRET, parseToken(token).data);
  assert.equal(esm.timingSafeEqual(explicit, parseToken(token).signature), true);
  assert.equal(shield.verifyToken(token, { sessionId: 'alice', now: 1000001 }).ok, true);
});
