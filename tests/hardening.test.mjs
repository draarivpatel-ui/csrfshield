import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { esm, cjs, nodeEsm, cjsNode, fixedCrypto, SECRET, SECRET2, ORIGIN, expectCode, expectCodeAsync } from './helpers.mjs';

const require = createRequire(import.meta.url);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const deterministic = fixedCrypto();
const { CODE } = esm;

function shield(overrides = {}) {
  return esm.createShield(Object.assign({
    secrets: [SECRET],
    crypto: deterministic,
    origin: ORIGIN,
    getSessionId: (request) => request.sessionId || ''
  }, overrides));
}

function request(token, overrides = {}) {
  const headers = Object.assign({
    cookie: overrides.cookie === undefined ? '__Host-csrf=' + token : overrides.cookie,
    origin: overrides.origin === undefined ? ORIGIN : overrides.origin
  }, overrides.headers || {});
  if (token && !overrides.noHeaderToken && headers['x-csrf-token'] === undefined) headers['x-csrf-token'] = token;
  return {
    method: overrides.method || 'POST',
    url: ORIGIN + '/transfer',
    headers,
    body: overrides.body === undefined ? {} : overrides.body,
    sessionId: overrides.sessionId === undefined ? '' : overrides.sessionId
  };
}

test('SHA-256 matches RFC 6234 vectors for multi-block inputs', () => {
  const vectors = new Map([
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1']
  ]);
  for (const [input, expected] of vectors) {
    assert.equal(Buffer.from(esm.sha256(input)).toString('hex'), expected);
  }
});

test('sha256 accepts Uint8Array and ArrayBuffer inputs', () => {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const copy = bytes.slice().buffer;
  assert.deepEqual(esm.sha256(bytes), esm.sha256(copy));
  assert.deepEqual(esm.sha256('1234'), esm.sha256(new TextEncoder().encode('1234')));
  assert.equal(typeof esm.sha256(new DataView(bytes.buffer)).length, 'number');
});

test('hmacSha256 matches RFC 4231 test case 1', () => {
  const key = Buffer.from('0b'.repeat(20), 'hex');
  const data = 'Hi There';
  const actual = Buffer.from(esm.hmacSha256(key, data)).toString('hex');
  assert.equal(actual, 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
});

test('timingSafeEqual never compares by length alone', () => {
  assert.equal(esm.timingSafeEqual('', ''), true);
  assert.equal(esm.timingSafeEqual('', 'x'), false);
  assert.equal(esm.timingSafeEqual(new Uint8Array([0, 128, 255]), new Uint8Array([0, 128, 255])), true);
});

test('base64urlEncode accepts every binary length residue', () => {
  for (let length = 0; length < 12; length++) {
    const bytes = new Uint8Array(length).map((_, index) => (index * 37 + 11) & 255);
    const encoded = esm.base64urlEncode(bytes);
    if (length > 0) {
      assert.equal(encoded.length, Math.ceil(length * 4 / 3));
      assert.deepEqual(esm.base64urlDecodeStrict(encoded), bytes);
    }
  }
});

test('base64urlDecodeStrict rejects non-ASCII and whitespace', () => {
  for (const value of ['\tAA', 'AA ', 'AA\u0000', 'éAA']) {
    expectCode(test, () => esm.base64urlDecodeStrict(value), CODE.INVALID_TOKEN, JSON.stringify(value));
  }
});

test('all error codes carry the correct HTTP status', () => {
  const clientCodes = ['INVALID_TOKEN', 'EXPIRED_TOKEN', 'SESSION_MISMATCH', 'CROSS_SITE_REQUEST', 'ORIGIN_MISMATCH', 'MISSING_COOKIE', 'INVALID_SESSION', 'RNG_UNAVAILABLE'];
  for (const code of clientCodes) assert.equal(new esm.CsrfShieldError(CODE[code], 'x').status, 403);
  for (const code of ['WEAK_SECRET', 'INVALID_CONFIG']) assert.equal(new esm.CsrfShieldError(CODE[code], 'x').status, 500);
});

test('CsrfShieldError preserves metadata', () => {
  const error = new esm.CsrfShieldError(CODE.INVALID_TOKEN, 'detail', { field: 'x-csrf-token' });
  assert.deepEqual(error.meta, { field: 'x-csrf-token' });
});

test('a single legacy secret option is accepted', () => {
  assert.equal(esm.createShield({ secret: SECRET }).secrets.length, 1);
});

test('secrets must be strings of at least 32 bytes each', () => {
  expectCode(test, () => esm.createShield({ secrets: [SECRET, 'b'.repeat(31)] }), CODE.WEAK_SECRET, 'short rotation secret');
  expectCode(test, () => esm.createShield({ secrets: [null] }), CODE.WEAK_SECRET, 'null secret');
  expectCode(test, () => esm.createShield({ secrets: [] }), CODE.WEAK_SECRET, 'empty secrets');
  expectCode(test, () => esm.createShield({}), CODE.WEAK_SECRET, 'no secrets');
});

test('cookie name validation covers prefixes and character sets', () => {
  expectCode(test, () => esm.createShield({ secrets: [SECRET], cookie: { name: 'bad name' } }), CODE.INVALID_CONFIG, 'space in name');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], cookie: { name: '__Secure-csrf', secure: false } }), CODE.INVALID_CONFIG, '__Secure- without Secure');
  assert.match(esm.createShield({ secrets: [SECRET], cookie: { name: '__Secure-csrf' } }).serializeCookie('x'), /__Secure-csrf=x; Path=\/; Secure; HttpOnly; SameSite=Lax/);
});

test('cookie maxAge must be a non-negative integer', () => {
  expectCode(test, () => esm.createShield({ secrets: [SECRET], cookie: { maxAge: -1 } }), CODE.INVALID_CONFIG, 'negative');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], cookie: { maxAge: 1.5 } }), CODE.INVALID_CONFIG, 'fractional');
  assert.match(esm.createShield({ secrets: [SECRET], cookie: { maxAge: 120 } }).serializeCookie('x'), /Max-Age=120$/);
});

test('token TTL and clock skew configuration boundaries', () => {
  expectCode(test, () => esm.createShield({ secrets: [SECRET], tokenTtlMs: -1 }), CODE.INVALID_CONFIG, 'negative ttl');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], tokenTtlMs: 1.5 }), CODE.INVALID_CONFIG, 'fractional ttl');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], clockSkewMs: 1.5 }), CODE.INVALID_CONFIG, 'fractional skew');
  assert.equal(shield({ tokenTtlMs: 1000, clockSkewMs: 999 }).clockSkewMs, 999);
});

test('extractToken and origin configuration types are validated', () => {
  expectCode(test, () => esm.createShield({ secrets: [SECRET], extractToken: 7 }), CODE.INVALID_CONFIG, 'extractToken');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], origin: { bad: true } }), CODE.ORIGIN_MISMATCH, 'origin object');
  expectCode(test, () => esm.createShield({ secrets: [SECRET], cookie: { sameSite: 'lax' } }), CODE.INVALID_CONFIG, 'lowercase sameSite');
});

test('crypto adapter validation rejects partial implementations', () => {
  for (const crypto of [{ randomBytes: () => new Uint8Array(1) }, { hmac: () => new Uint8Array(1), timingEqual: () => true }, null]) {
    expectCode(test, () => esm.createShield({ secrets: [SECRET], crypto }), CODE.INVALID_CONFIG, 'partial adapter');
  }
});

test('issueToken rejects invalid session identifiers', () => {
  const plain = shield({ getSessionId: undefined });
  expectCode(test, () => plain.issueToken({}, { sessionId: 'bad\nheader' }), CODE.INVALID_SESSION, 'control character');
  expectCode(test, () => plain.issueToken({}, { sessionId: 'x'.repeat(257) }), CODE.INVALID_SESSION, 'too long');
  expectCode(test, () => plain.issueToken({}, { sessionId: 42 }), CODE.INVALID_SESSION, 'non-string');
});

test('issueToken rejects invalid nonce sizes and clock values', () => {
  const plain = shield({ getSessionId: undefined });
  expectCode(test, () => plain.issueToken({}, { nonce: new Uint8Array(8) }), CODE.INVALID_CONFIG, 'short nonce');
  expectCode(test, () => plain.issueToken({}, { nonce: new Uint8Array(80) }), CODE.INVALID_CONFIG, 'long nonce');
  expectCode(test, () => plain.issueToken({}, { now: 1.5 }), CODE.INVALID_CONFIG, 'fractional now');
});

test('getSessionId is called with the raw request and normalized context', () => {
  let seenRaw;
  let seenContext;
  const guarded = shield({ getSessionId: (raw, context) => { seenRaw = raw; seenContext = context; return 'bob'; } });
  const raw = { method: 'GET', headers: {} };
  assert.match(guarded.issueToken(raw), /^v1\.[A-Za-z0-9_-]*\./);
  assert.equal(seenRaw, raw);
  assert.equal(seenContext, raw);
});

test('a failing getSessionId is surfaced with INVALID_SESSION', () => {
  const guarded = shield({ getSessionId: () => { throw new esm.CsrfShieldError(CODE.INVALID_SESSION, 'no session'); } });
  expectCode(test, () => guarded.issueToken({}), CODE.INVALID_SESSION, 'getSessionId failure');
});

test('empty session tokens round-trip through parse and verify', () => {
  const plain = shield({ getSessionId: undefined });
  const token = plain.issueToken({}, { now: 1000000 });
  assert.equal(token.split('.')[1], '');
  assert.equal(esm.parseToken(token).session, '');
  assert.equal(plain.verifyToken(token, { now: 1000001 }).ok, true);
});

test('non-ASCII session identifiers are rejected consistently', () => {
  const plain = shield({ getSessionId: undefined });
  expectCode(test, () => plain.issueToken({}, { sessionId: 'café-☃', now: 1000000 }), CODE.INVALID_SESSION, 'unicode session');
  expectCode(test, () => plain.issueToken({}, { sessionId: 'tab\tseparated', now: 1000000 }), CODE.INVALID_SESSION, 'control session');
});

test('token expiry uses base36 and survives long timestamps', () => {
  const plain = shield({ getSessionId: undefined });
  const token = plain.issueToken({}, { sessionId: 'a', now: 4102444800000 });
  assert.equal(esm.parseToken(token).expiresAt, 4102444800000 + 3600000);
});

test('verifyToken rejects a signature with a non-zero diff at every position', () => {
  const plain = shield({ getSessionId: undefined });
  const token = plain.issueToken({}, { sessionId: 'a', now: 1000000 });
  const parts = token.split('.');
  for (const index of [0, 10, 42]) {
    const mutated = parts.slice();
    mutated[4] = mutated[4].slice(0, index) + (mutated[4][index] === 'A' ? 'B' : 'A') + mutated[4].slice(index + 1);
    expectCode(test, () => plain.verifyToken(mutated.join('.'), { sessionId: 'a', now: 1000001 }), CODE.INVALID_TOKEN, 'tamper at ' + index);
  }
});

test('verifyToken rejects an expiry outside the allowed skew window', () => {
  const plain = shield({ getSessionId: undefined });
  const token = plain.issueToken({}, { sessionId: 'a', now: 1000000 });
  expectCode(test, () => plain.verifyToken(token, { sessionId: 'a', now: 1000000 - 3600000 - 30001 }), CODE.INVALID_TOKEN, 'future expiry');
});

test('verifyToken requires an integer clock', () => {
  const plain = shield({ getSessionId: undefined });
  const token = plain.issueToken({}, { sessionId: 'a', now: 1000000 });
  expectCode(test, () => plain.verifyToken(token, { sessionId: 'a', now: '1000001' }), CODE.INVALID_CONFIG, 'string clock');
});

test('parseToken rejects invalid UTF-8 session bytes', () => {
  const token = 'v1.' + esm.base64urlEncode(new Uint8Array([255])) + '.' + esm.base64urlEncode(new Uint8Array(24).fill(7)) + '.1.' + esm.base64urlEncode(new Uint8Array(32).fill(1));
  expectCode(test, () => esm.parseToken(token), CODE.INVALID_TOKEN, 'invalid utf8');
});

test('parseToken enforces nonce size bounds', () => {
  const build = (size) => 'v1.YQ.' + esm.base64urlEncode(new Uint8Array(size).fill(7)) + '.1.' + esm.base64urlEncode(new Uint8Array(32).fill(1));
  expectCode(test, () => esm.parseToken(build(15)), CODE.INVALID_TOKEN, 'short nonce');
  expectCode(test, () => esm.parseToken(build(65)), CODE.INVALID_TOKEN, 'long nonce');
  assert.equal(esm.parseToken(build(64)).nonce.length, 64);
});

test('maskToken uses a fresh mask for the same token', () => {
  const token = shield().issueToken({}, { sessionId: 'alice', now: 1000000 });
  const lengthCrypto = { name: 'variable', randomBytes: (length) => new Uint8Array(length).fill(13), hmac: nativeHmac, timingEqual: nativeTiming };
  const first = esm.maskToken(token, lengthCrypto);
  const second = esm.maskToken(token, lengthCrypto);
  assert.equal(first, second);
  assert.equal(esm.unmaskToken(first), token);
  const a = esm.maskToken(token, { name: 'native', randomBytes, hmac: nativeHmac, timingEqual: nativeTiming });
  const b = esm.maskToken(token, { name: 'native', randomBytes, hmac: nativeHmac, timingEqual: nativeTiming });
  assert.notEqual(a, b);
});

function nativeHmac(key, data) {
  return new Uint8Array(createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest());
}

function nativeTiming(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function variableCrypto() {
  return { name: 'variable-test-crypto', randomBytes: (length) => new Uint8Array(length).fill(23), hmac: nativeHmac, timingEqual: nativeTiming };
}

test('unmaskToken rejects a mask that decodes to an invalid token', () => {
  const mask = esm.base64urlEncode(new Uint8Array(5).fill(0));
  const garbage = esm.base64urlEncode(esm.sha256('garbage'));
  expectCode(test, () => esm.unmaskToken('m1.' + mask + '.' + garbage), CODE.INVALID_TOKEN, 'bad payload');
});

test('isMaskedToken only recognizes the m1 prefix', () => {
  assert.equal(esm.isMaskedToken('m1.'), true);
  assert.equal(esm.isMaskedToken('m2.abc.def'), false);
  assert.equal(esm.isMaskedToken(undefined), false);
});

test('masked tokens verify through the standard header path', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const masked = esm.maskToken(token, variableCrypto());
  const result = await plain.verifyRequest(request(token, { headers: { 'x-csrf-token': masked } }), { now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(result.token, token);
});

test('mask policy rejects a plaintext token but accepts a masked one', async () => {
  const guarded = shield({ mask: true });
  const token = guarded.issueToken({}, { now: 1000000 });
  await expectCodeAsync(test, () => guarded.verifyRequest(request(token), { now: 1000001 }), CODE.INVALID_TOKEN, 'plain token under mask policy');
  const masked = esm.maskToken(token, variableCrypto());
  assert.equal((await guarded.verifyRequest(request(token, { headers: { 'x-csrf-token': masked } }), { now: 1000001 })).ok, true);
});

test('cookie parser accepts whitespace around names and values', () => {
  assert.equal(esm.parseCookieHeader('other=1;  __Host-csrf = v1.a.b.c.d  ; z=3', '__Host-csrf', { strictValues: false }), 'v1.a.b.c.d');
});

test('cookie parser rejects malformed values under strict mode', () => {
  expectCode(test, () => esm.parseCookieHeader('__Host-csrf=v1,a', '__Host-csrf'), CODE.INVALID_TOKEN, 'comma');
  expectCode(test, () => esm.parseCookieHeader('__Host-csrf=v1%20a', '__Host-csrf'), CODE.INVALID_TOKEN, 'percent');
});

test('cookie parser handles null and undefined inputs', () => {
  assert.equal(esm.parseCookieHeader(null, '__Host-csrf'), null);
  assert.equal(esm.parseCookieHeader(undefined, '__Host-csrf'), null);
});

test('cookie parser rejects a non-string header value', () => {
  expectCode(test, () => esm.parseCookieHeader(42, '__Host-csrf'), CODE.INVALID_TOKEN, 'number header');
});

test('cookie parser requires a non-empty name', () => {
  expectCode(test, () => esm.parseCookieHeader('a=1', ''), CODE.INVALID_CONFIG, 'empty name');
});

test('request settings override the raw request values', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const result = await plain.verifyRequest(request(token), {
    method: 'GET',
    url: 'https://override.example.com/',
    body: {},
    sessionId: 'alice',
    now: 1000001
  });
  assert.equal(result.skipped, true);
  assert.equal(result.method, 'GET');
  assert.equal(result.url, 'https://override.example.com/');
});

test('verifyRequest honors settings.token over header and body', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { headers: { 'x-csrf-token': 'garbage' } });
  assert.equal((await plain.verifyRequest(raw, { token, now: 1000001 })).ok, true);
});

test('verifyRequest accepts a URLSearchParams body', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true, body: new URLSearchParams({ _csrf: token }) });
  assert.equal((await plain.verifyRequest(raw, { now: 1000001 })).ok, true);
});

test('verifyRequest accepts a JSON string body', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true, body: JSON.stringify({ _csrf: token }) });
  assert.equal((await plain.verifyRequest(raw, { now: 1000001 })).ok, true);
});

test('verifyRequest accepts a FormData body', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const form = new FormData();
  form.set('_csrf', token);
  const raw = request(token, { noHeaderToken: true, body: form });
  assert.equal((await plain.verifyRequest(raw, { now: 1000001 })).ok, true);
});

test('verifyRequest rejects a body field that is not a string', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true, body: { _csrf: 42 } });
  await expectCodeAsync(test, () => plain.verifyRequest(raw, { now: 1000001 }), CODE.INVALID_TOKEN, 'numeric body token');
});

test('custom extractor can read from a nested location', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true, body: { nested: { token } } });
  const result = await plain.verifyRequest(raw, {
    now: 1000001,
    extractToken: (req, context) => {
      assert.equal(context.raw, raw);
      return req.body.nested.token;
    }
  });
  assert.equal(result.ok, true);
});

test('async custom extractors are awaited', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true, body: {} });
  assert.equal((await plain.verifyRequest(raw, { now: 1000001, extractToken: async () => token })).ok, true);
});

test('custom extractors that return nothing fail with INVALID_TOKEN', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token, { noHeaderToken: true });
  await expectCodeAsync(test, () => plain.verifyRequest(raw, { now: 1000001, extractToken: () => null }), CODE.INVALID_TOKEN, 'null token');
});

test('cookie verification runs before token extraction', async () => {
  const plain = shield();
  const raw = request(null, { noHeaderToken: true, cookie: 'unrelated=1' });
  await expectCodeAsync(test, () => plain.verifyRequest(raw, { now: 1000001 }), CODE.MISSING_COOKIE, 'cookie precedence');
});

test('expired cookie tokens are rejected before the submitted token is inspected', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(token, { noHeaderToken: true }), { now: 10000000 }), CODE.EXPIRED_TOKEN, 'expired cookie');
});

test('session mismatch on the cookie is reported with SESSION_MISMATCH', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { sessionId: 'alice', now: 1000000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(token), { sessionId: 'bob', now: 1000001 }), CODE.SESSION_MISMATCH, 'cookie session');
});

test('cross-session submitted tokens are rejected even with a valid cookie', async () => {
  const plain = shield();
  const cookie = plain.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const other = plain.issueToken({}, { sessionId: 'bob', now: 1000000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(other, { cookie: '__Host-csrf=' + cookie }), { now: 1000001 }), CODE.SESSION_MISMATCH, 'submitted session');
});

test('safe methods bypass all security checks', async () => {
  const plain = shield();
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    const raw = request(null, { method, noHeaderToken: true, cookie: 'malformed\r\nvalue' });
    const result = await plain.verifyRequest(raw, { now: 1000001 });
    assert.equal(result.ok, true);
    assert.equal(result.skipped, true);
  }
});

test('origin allowlist compares canonicalized values', async () => {
  const plain = shield({ origin: [ORIGIN + '/', 'https://other.example.org:443'] });
  assert.deepEqual(plain.allowedOrigins, [ORIGIN, 'https://other.example.org']);
  assert.equal((await plain.verifyRequest(request(plain.issueToken({}, { now: 1000000 }), { origin: 'https://other.example.org' }), { now: 1000001 })).ok, true);
});

test('origin validator receives the raw request and context', async () => {
  let seenRaw;
  let seenContext;
  const plain = shield({ origin: (origin, raw, context) => { seenRaw = raw; seenContext = context; return origin === ORIGIN; } });
  const token = plain.issueToken({}, { now: 1000000 });
  const raw = request(token);
  assert.equal((await plain.verifyRequest(raw, { now: 1000001 })).ok, true);
  assert.equal(seenRaw, raw);
  assert.equal(seenContext.method, 'POST');
});

test('originCheck can be disabled entirely', async () => {
  const plain = shield({ originCheck: { enabled: false } });
  const token = plain.issueToken({}, { now: 1000000 });
  assert.equal((await plain.verifyRequest(request(token, { origin: 'https://evil.example.org' }), { now: 1000001 })).ok, true);
});

test('null referer is rejected unless allowNull is set', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(token, { origin: null, headers: { referer: 'null' } }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'null referer');
  const permissive = shield({ originCheck: { allowNull: true } });
  const permissiveToken = permissive.issueToken({}, { now: 1000000 });
  assert.equal((await permissive.verifyRequest(request(permissiveToken, { origin: null, headers: { referer: 'null' } }), { now: 1000001 })).ok, true);
});

test('duplicate Origin values are rejected even when one is allowed', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(token, { origin: [ORIGIN, ORIGIN] }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'duplicate allowed origin');
});

test('Sec-Fetch-Site comparison is case-insensitive', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  assert.equal((await plain.verifyRequest(request(token, { headers: { 'sec-fetch-site': 'SAME-ORIGIN' } }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => plain.verifyRequest(request(token, { headers: { 'sec-fetch-site': 'CROSS-SITE' } }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'case-insensitive cross-site');
});

test('Sec-Fetch-Site rejection precedes Origin validation', async () => {
  const plain = shield();
  const token = plain.issueToken({}, { now: 1000000 });
  await expectCodeAsync(test, () => plain.verifyRequest(request(token, { origin: 'https://evil.example.org', headers: { 'sec-fetch-site': 'cross-site' } }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'defense order');
});

test('middleware rejects unsafe requests through next(error)', async () => {
  const plain = shield();
  let forwarded;
  await plain.middleware({ method: 'POST', headers: { origin: ORIGIN }, body: {} }, { locals: {} }, (error) => { forwarded = error; });
  assert.equal(forwarded.code, CODE.MISSING_COOKIE);
});

test('middleware requires a next callback', async () => {
  const plain = shield();
  await expectCodeAsync(test, () => plain.middleware({ method: 'GET', headers: {} }, {}, undefined), CODE.INVALID_CONFIG, 'missing next');
  await expectCodeAsync(test, () => plain.middleware({ method: 'GET', headers: {} }, {}, null), CODE.INVALID_CONFIG, 'bad next');
});

test('middleware reuses an existing cookie instead of setting another one', async () => {
  const plain = shield();
  // The middleware now verifies the cookie before reusing it, so the token has
  // to be inside its TTL relative to the middleware's real clock.
  const token = plain.issueToken({});
  const appended = [];
  const response = { locals: {}, appendHeader: (name, value) => appended.push([name, value]) };
  await plain.middleware({ method: 'GET', headers: { cookie: '__Host-csrf=' + token } }, response, () => {});
  assert.equal(appended.length, 0);
  assert.equal(response.locals.csrfToken, token);
});

test('middleware tolerates a malformed existing cookie and issues a new one', async () => {
  const plain = shield();
  const appended = [];
  const response = { locals: {}, appendHeader: (name, value) => appended.push([name, value]) };
  await plain.middleware({ method: 'GET', headers: { cookie: '__Host-csrf=a; __Host-csrf=b' } }, response, () => {});
  assert.equal(appended.length, 1);
  assert.match(response.locals.csrfToken, /^v1\./);
});

test('issueCookie and issueTokenPair expose the documented shapes', () => {
  const plain = shield({ crypto: variableCrypto() });
  assert.match(plain.issueCookie({}, { now: 1000 }), /^__Host-csrf=v1\./);
  const pair = plain.issueTokenPair({}, { sessionId: 'alice', now: 1000 });
  assert.equal(pair.token, pair.cookie.split('=')[1].split(';')[0]);
  assert.equal(esm.unmaskToken(pair.maskedToken), pair.token);
  assert.equal(pair.expiresAt, 1000 + 3600000);
});

test('clearCookie removes the cookie with a zero Max-Age', () => {
  const plain = shield({ cookie: { maxAge: 3600 } });
  assert.equal(plain.clearCookie(), '__Host-csrf=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax');
});

test('serializeCookie rejects empty tokens', () => {
  const plain = shield();
  expectCode(test, () => plain.serializeCookie(''), CODE.INVALID_TOKEN, 'empty token');
});

test('parseCookie uses the configured cookie name', () => {
  const plain = shield({ cookie: { name: '__Secure-csrf' } });
  assert.equal(plain.parseCookie('__Host-csrf=x; __Secure-csrf=y'), 'y');
});

test('errorResponse maps a missing cookie to a structured 403 response', () => {
  const plain = shield();
  const response = plain.errorResponse(new esm.CsrfShieldError(CODE.MISSING_COOKIE, 'missing'));
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('errorResponse supports a custom onError hook', () => {
  const plain = shield();
  const response = plain.errorResponse(new esm.CsrfShieldError(CODE.INVALID_TOKEN, 'bad'), { onError: (error) => error.code });
  assert.equal(response, CODE.INVALID_TOKEN);
});

test('createFetchTokenResponse supports a custom body', async () => {
  const plain = shield();
  const response = plain.createFetchTokenResponse('v1.a.b.c.d', { body: { custom: true } });
  assert.deepEqual(await response.json(), { custom: true });
});

test('withFetch rejects a non-function handler', () => {
  const plain = shield();
  expectCode(test, () => plain.withFetch(null), CODE.INVALID_CONFIG, 'handler');
});

test('withFetch forwards extra arguments to the handler', async () => {
  const plain = shield();
  const handler = plain.withFetch(async (request, verified, extra) => new Response(extra), { now: 1000001 });
  const response = await handler(new Request('https://app.example.com/data', { method: 'GET' }), 'extra-value');
  assert.equal(await response.text(), 'extra-value');
});

test('nodeCrypto adapter hashes unequal-length inputs in constant time', () => {
  assert.equal(nodeEsm.nodeCrypto.timingEqual('a', 'a'.repeat(100)), false);
  assert.equal(cjsNode.nodeCrypto.timingEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
});

test('nodeCrypto adapter validates randomBytes input', () => {
  for (const length of [0, -1, 1.5]) {
    expectCode(test, () => nodeEsm.nodeCrypto.randomBytes(length), CODE.INVALID_CONFIG, 'length ' + length);
  }
});

test('createNodeCrypto rejects an unsupported value', () => {
  expectCode(test, () => nodeEsm.nodeCrypto.hmac(new Uint8Array([1]), 42), CODE.INVALID_CONFIG, 'number payload');
});

test('ESM and CJS expose the same error classes and helper implementations', () => {
  assert.equal(typeof cjs.CsrfShieldError, 'function');
  assert.equal(cjs.CODE.MISSING_COOKIE, esm.CODE.MISSING_COOKIE);
  assert.deepEqual(cjs.sha256('abc'), esm.sha256('abc'));
  assert.deepEqual(cjs.base64urlDecodeStrict('YWJj'), esm.base64urlDecodeStrict('YWJj'));
  assert.equal(cjs.canonicalOrigin('https://app.example.com/'), ORIGIN);
});

test('ESM and CJS agree on verification failures', async () => {
  const options = { secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' };
  const a = esm.createShield(options);
  const b = cjs.createShield(options);
  const token = a.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const raw = request(token, { headers: { 'sec-fetch-site': 'cross-site' } });
  for (const current of [a, b]) {
    await expectCodeAsync(test, () => current.verifyRequest(raw, { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'esm/cjs parity');
  }
});

test('ESM and CJS agree on masked token verification', async () => {
  const options = { secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' };
  const a = esm.createShield(options);
  const b = cjs.createShield(options);
  const token = a.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const masked = esm.maskToken(token, variableCrypto());
  const raw = () => request(token, { headers: { 'x-csrf-token': masked } });
  assert.equal((await a.verifyRequest(raw(), { now: 1000001 })).ok, true);
  assert.equal((await b.verifyRequest(raw(), { now: 1000001 })).ok, true);
});

test('all entry points load through package exports', async () => {
  const rootImport = await import(pathToFileURL(path.join(repoRoot, 'src', 'index.mjs')).href);
  const rootRequire = require(path.join(repoRoot, 'cjs', 'index.cjs'));
  const nodeRequire = require(path.join(repoRoot, 'cjs', 'node.cjs'));
  assert.equal(typeof rootImport.createShield, 'function');
  assert.equal(typeof rootRequire.createShield, 'function');
  assert.equal(typeof nodeRequire.nodeCrypto.hmac, 'function');
});

test('default exports expose a stable public surface', () => {
  for (const entry of [esm.default, cjs.default]) {
    assert.equal(typeof entry.createShield, 'function');
    assert.equal(typeof entry.CsrfShieldError, 'function');
    assert.equal(entry.nodeCrypto, undefined);
  }
  for (const entry of [nodeEsm.default, cjsNode.default]) {
    assert.equal(typeof entry.createShield, 'function');
    assert.equal(typeof entry.CsrfShieldError, 'function');
    assert.equal(typeof entry.nodeCrypto.hmac, 'function');
  }
});

test('rotation secrets are immutable after shield creation', () => {
  const secrets = [SECRET];
  const guarded = esm.createShield({ secrets });
  secrets.push(SECRET2);
  assert.deepEqual(guarded.secrets, [SECRET]);
  assert.equal(Object.isFrozen(guarded.secrets), true);
});

test('cookie configuration is exposed as a frozen snapshot', () => {
  const guarded = esm.createShield({ secrets: [SECRET] });
  assert.equal(Object.isFrozen(guarded.cookie), true);
  assert.equal(guarded.cookie.name, '__Host-csrf');
  assert.equal(guarded.cookie.path, '/');
  assert.equal(guarded.cookie.secure, true);
  assert.equal(guarded.cookie.httpOnly, true);
  assert.equal(guarded.cookie.sameSite, 'Lax');
});

test('tokenTtlMs and clockSkewMs are exposed on the shield', () => {
  const guarded = esm.createShield({ secrets: [SECRET], tokenTtlMs: 5000, clockSkewMs: 1000 });
  assert.equal(guarded.tokenTtlMs, 5000);
  assert.equal(guarded.clockSkewMs, 1000);
});

test('originCheck and fetchMetadata defaults are documented by the shield', () => {
  const guarded = esm.createShield({ secrets: [SECRET], origin: ORIGIN });
  assert.deepEqual(guarded.originCheck, { enabled: true, strict: true, allowNull: false, refererFallback: true });
  assert.deepEqual(guarded.fetchMetadata, { enabled: true, strictness: 'same-site', allowNone: true });
});

test('issueCookie accepts a custom maxAge override', () => {
  const guarded = esm.createShield({ secrets: [SECRET] });
  const issued = guarded.issueCookie({}, { maxAge: 45 });
  assert.match(issued, /Max-Age=45$/);
});

test('verify alias delegates to verifyRequest', async () => {
  const guarded = shield();
  const token = guarded.issueToken({}, { now: 1000000 });
  assert.equal((await guarded.verify(request(token), { now: 1000001 })).ok, true);
});

test('fetchHandler alias delegates to withFetch', async () => {
  const guarded = shield();
  const handler = guarded.fetchHandler(async () => new Response('ok'), { now: 1000001 });
  const response = await handler(new Request(ORIGIN + '/data', { method: 'GET' }));
  assert.equal(await response.text(), 'ok');
});

test('nodeMiddleware alias delegates to middleware', async () => {
  const guarded = shield();
  let called = false;
  await guarded.nodeMiddleware({ method: 'GET', headers: {} }, { locals: {} }, () => { called = true; });
  assert.equal(called, true);
});
