import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esm, cjs, makeShield, fixedCrypto, nativeCrypto, SECRET, ORIGIN, expectCodeAsync } from './helpers.mjs';

const { CODE, parseCookieHeader, canonicalOrigin, isSafeMethod } = esm;
const deterministic = fixedCrypto();

function request(shield, overrides = {}) {
  const token = overrides.token || shield.issueToken({}, { sessionId: overrides.sessionId || 'alice', now: 1000000 });
  const cookie = overrides.cookie !== undefined ? overrides.cookie : shield.serializeCookie(token);
  const headers = Object.assign({
    cookie,
    origin: overrides.origin === undefined ? ORIGIN : overrides.origin,
    'x-csrf-token': overrides.headerToken === undefined ? token : overrides.headerToken
  }, overrides.extraHeaders || {});
  if (overrides.removeHeader) delete headers[overrides.removeHeader];
  return {
    method: overrides.method || 'POST',
    url: overrides.url || ORIGIN + '/transfer',
    headers,
    sessionId: overrides.sessionId || 'alice',
    body: overrides.body === undefined ? {} : overrides.body
  };
}

test('verifyRequest accepts a valid header token', async () => {
  const shield = makeShield({ crypto: deterministic });
  const result = await shield.verifyRequest(request(shield), { now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, false);
  assert.equal(result.sessionId, 'alice');
});

test('verifyRequest accepts a valid form-body token', async () => {
  const shield = makeShield({ crypto: deterministic });
  const req = request(shield, { removeHeader: 'x-csrf-token', body: { _csrf: shield.issueToken({}, { sessionId: 'alice', now: 1000000 }) } });
  const result = await shield.verifyRequest(req, { now: 1000001 });
  assert.equal(result.ok, true);
});

test('verifyRequest accepts a URL encoded body', async () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const req = request(shield, { removeHeader: 'x-csrf-token', body: '_csrf=' + encodeURIComponent(token) + '&amount=10' });
  assert.equal((await shield.verifyRequest(req, { now: 1000001 })).ok, true);
});

test('verifyRequest accepts a JSON body', async () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const req = request(shield, { removeHeader: 'x-csrf-token', body: JSON.stringify({ _csrf: token }) });
  assert.equal((await shield.verifyRequest(req, { now: 1000001 })).ok, true);
});

test('verifyRequest uses custom header and body field names', async () => {
  const shield = makeShield({ crypto: deterministic, header: 'x-my-csrf', bodyField: 'csrf' });
  const req = request(shield, { extraHeaders: { 'x-my-csrf': shield.issueToken({}, { sessionId: 'alice', now: 1000000 }) }, removeHeader: 'x-csrf-token', body: {} });
  assert.equal((await shield.verifyRequest(req, { now: 1000001 })).ok, true);
  const req2 = request(shield, { removeHeader: 'x-my-csrf', body: { csrf: shield.issueToken({}, { sessionId: 'alice', now: 1000000 }) } });
  delete req2.headers['x-csrf-token'];
  assert.equal((await shield.verifyRequest(req2, { now: 1000001 })).ok, true);
});

test('verifyRequest supports a custom extractor', async () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const req = request(shield, { removeHeader: 'x-csrf-token', body: { csrf: token } });
  const result = await shield.verifyRequest(req, {
    now: 1000001,
    extractToken: (raw) => raw.body.csrf
  });
  assert.equal(result.ok, true);
});

test('verifyRequest rejects a missing csrf cookie', async () => {
  const shield = makeShield({ crypto: deterministic });
  const withoutCookie = request(shield, { removeHeader: 'x-csrf-token' });
  delete withoutCookie.headers.cookie;
  await expectCodeAsync(test, () => shield.verifyRequest(withoutCookie, { now: 1000001 }), CODE.MISSING_COOKIE, 'missing cookie');
  const req = request(shield);
  delete req.headers.cookie;
  await expectCodeAsync(test, () => shield.verifyRequest(req, { now: 1000001 }), CODE.MISSING_COOKIE, 'no cookie header');
});

test('verifyRequest rejects a token that does not match the cookie', async () => {
  const shield = makeShield({ crypto: deterministic });
  const other = shield.issueToken({}, { sessionId: 'alice', now: 1000000, nonce: new Uint8Array(24).fill(9) });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { headerToken: other }), { now: 1000001 }), CODE.INVALID_TOKEN, 'cookie mismatch');
});

test('verifyRequest rejects missing tokens and duplicate token headers', async () => {
  const shield = makeShield({ crypto: deterministic });
  const req = request(shield, { removeHeader: 'x-csrf-token' });
  await expectCodeAsync(test, () => shield.verifyRequest(req, { now: 1000001 }), CODE.INVALID_TOKEN, 'no token');
  const dup = request(shield);
  dup.headers['x-csrf-token'] = [dup.headers['x-csrf-token'], dup.headers['x-csrf-token']];
  await expectCodeAsync(test, () => shield.verifyRequest(dup, { now: 1000001 }), CODE.INVALID_TOKEN, 'duplicate header value');
});

test('verifyRequest rejects comma-joined token injection', async () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { headerToken: token + ', ' + token }), { now: 1000001 }), CODE.INVALID_TOKEN, 'comma injection');
});

test('verifyRequest rejects malformed and expired tokens', async () => {
  const shield = makeShield({ crypto: deterministic, tokenTtlMs: 1000, clockSkewMs: 0 });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { headerToken: 'garbage' }), { now: 1000001 }), CODE.INVALID_TOKEN, 'malformed');
  const expired = shield.issueToken({}, { sessionId: 'alice', now: 1000 });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { token: expired }), { now: 5000 }), CODE.EXPIRED_TOKEN, 'expired');
});

test('verifyRequest rejects session-mismatched tokens', async () => {
  const shield = makeShield({ crypto: deterministic });
  const attackerToken = shield.issueToken({}, { sessionId: 'attacker', now: 1000000 });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { token: attackerToken, sessionId: 'victim' }), { now: 1000001 }), CODE.SESSION_MISMATCH, 'session mismatch');
});

test('verifyRequest accepts masked tokens and enforces mask policy', async () => {
  const shield = makeShield({ crypto: deterministic });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const masked = esm.maskToken(token, nativeCrypto);
  assert.equal((await shield.verifyRequest(request(shield, { headerToken: masked }), { now: 1000001 })).ok, true);
  const strict = makeShield({ crypto: deterministic, mask: true });
  await expectCodeAsync(test, () => strict.verifyRequest(request(strict, { headerToken: token, sessionId: 'alice' }), { now: 1000001 }), CODE.INVALID_TOKEN, 'mask policy');
});

test('parseCookieHeader handles duplicates, control chars and empty names', () => {
  assert.equal(parseCookieHeader('a=1; __Host-csrf=token; b=2', '__Host-csrf'), 'token');
  assert.equal(parseCookieHeader('__Host-csrf=token', '__Host-csrf'), 'token');
  assert.equal(parseCookieHeader('other=1', '__Host-csrf'), null);
  assert.throws(() => parseCookieHeader('__Host-csrf=a; __Host-csrf=b', '__Host-csrf'), (error) => error.code === CODE.INVALID_TOKEN);
  assert.throws(() => parseCookieHeader(['__Host-csrf=a', '__Host-csrf=b'], '__Host-csrf', { rejectDuplicateHeaders: true }), (error) => error.code === CODE.INVALID_TOKEN);
  assert.throws(() => parseCookieHeader('__Host-csrf=a\r\n', '__Host-csrf'), (error) => error.code === CODE.INVALID_TOKEN);
  assert.throws(() => parseCookieHeader('__Host-csrf=', '__Host-csrf'), (error) => error.code === CODE.INVALID_TOKEN);
});

test('subdomain cookie tossing: attacker cookie first is rejected, not preferred', async () => {
  const shield = makeShield({ crypto: deterministic });
  const valid = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const tossed = shield.issueToken({}, { sessionId: 'attacker', now: 1000000 });
  const evilFirst = '__Host-csrf=' + tossed + '; __Host-csrf=' + valid;
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { cookie: evilFirst, token: valid }), { now: 1000001 }), CODE.INVALID_TOKEN, 'attacker first');
  const goodFirst = '__Host-csrf=' + valid + '; __Host-csrf=' + tossed;
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { cookie: goodFirst, token: tossed }), { now: 1000001 }), CODE.INVALID_TOKEN, 'attacker second');
});

test('subdomain cookie tossing: signed session binding defeats swapped tokens', async () => {
  const shield = makeShield({ crypto: deterministic });
  const victim = shield.issueToken({}, { sessionId: 'victim', now: 1000000 });
  const attacker = shield.issueToken({}, { sessionId: 'attacker', now: 1000000 });
  await expectCodeAsync(test, () => shield.verifyRequest(request(shield, { token: attacker, sessionId: 'victim' }), { now: 1000001 }), CODE.SESSION_MISMATCH, 'cross-session');
  const victimCookie = request(shield, { token: victim, sessionId: 'victim' });
  victimCookie.headers['x-csrf-token'] = attacker;
  await expectCodeAsync(test, () => shield.verifyRequest(victimCookie, { now: 1000001 }), CODE.SESSION_MISMATCH, 'cross-session submitted token');
  assert.equal(victim.startsWith('v1.'), true);
});

test('safe methods skip all checks', async () => {
  const shield = makeShield({ crypto: deterministic });
  for (const method of ['GET', 'HEAD', 'OPTIONS', 'get', 'head', 'options']) {
    const result = await shield.verifyRequest({
      method,
      headers: { origin: 'https://evil.example.org' },
      body: {}
    }, { now: 1000001 });
    assert.equal(result.ok, true);
    assert.equal(result.skipped, true);
    assert.equal(isSafeMethod(method), true);
  }
});

test('canonicalOrigin accepts exact origins and rejects malformed values', () => {
  assert.equal(canonicalOrigin(ORIGIN), ORIGIN);
  assert.equal(canonicalOrigin('https://app.example.com/'), ORIGIN);
  assert.equal(canonicalOrigin('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(canonicalOrigin('https://app.example.com.evil.com'), 'https://app.example.com.evil.com');
  for (const value of ['https://evil.com/?x=https://app.example.com', 'https://app.example.com@evil.com', 'null', 'https://app.example.com/path', 'not a url']) {
    assert.throws(() => canonicalOrigin(value), (error) => error.code === CODE.ORIGIN_MISMATCH, value);
  }
});

test('canonicalOrigin parses a referer with a path', () => {
  assert.equal(canonicalOrigin(ORIGIN + '/account/settings?tab=1', true), ORIGIN);
  assert.throws(() => canonicalOrigin('chrome-extension://abc/foo', true), (error) => error.code === CODE.ORIGIN_MISMATCH);
});
