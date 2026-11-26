import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esm, cjs, nativeCrypto, fixedCrypto, SECRET, ORIGIN, expectCodeAsync } from './helpers.mjs';

const deterministic = fixedCrypto();
const { CODE } = esm;

function shieldFor(overrides = {}) {
  return esm.createShield(Object.assign({
    secrets: [SECRET],
    crypto: deterministic,
    origin: ORIGIN,
    getSessionId: (req) => req.sessionId || ''
  }, overrides));
}

test('Fetch Request: issued token verifies through header', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'sec-fetch-site': 'same-origin', 'x-csrf-token': token }
  });
  const result = await shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(result.sessionId, 'alice');
});

test('Fetch Request: JSON body token is read without consuming the original stream', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ _csrf: token })
  });
  const result = await shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(await request.text(), JSON.stringify({ _csrf: token }));
});

test('Fetch Request: URL encoded body token is read', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: '_csrf=' + encodeURIComponent(token)
  });
  assert.equal((await shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 })).ok, true);
});

test('Fetch Request: FormData body token is read', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const form = new FormData();
  form.set('_csrf', token);
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN },
    body: form
  });
  assert.equal((await shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 })).ok, true);
});

test('Fetch Request: cross-site metadata is rejected', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'sec-fetch-site': 'cross-site', 'x-csrf-token': token }
  });
  await expectCodeAsync(test, () => shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'fetch cross-site');
});

test('Fetch Request: origin mismatch is rejected', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request('https://evil.example.org/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: 'https://evil.example.org', 'x-csrf-token': token }
  });
  await expectCodeAsync(test, () => shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 }), CODE.ORIGIN_MISMATCH, 'fetch origin mismatch');
});

test('Fetch Request: safe methods skip checks without a cookie', async () => {
  const shield = shieldFor();
  const request = new Request(ORIGIN + '/data', { method: 'GET', headers: { origin: 'https://evil.example.org' } });
  const result = await shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, true);
});

test('protectFetch returns the verified result and original request', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'x-csrf-token': token }
  });
  const output = await shield.protectFetch(request, { sessionId: 'alice', now: 1000001 });
  assert.equal(output.verified.ok, true);
  assert.equal(output.request, request);
});

test('withFetch passes verification to the handler', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const handler = shield.withFetch(async (request, verified) => new Response(JSON.stringify({ ok: verified.ok }), { status: 200 }), { sessionId: 'alice', now: 1000001 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'x-csrf-token': token }
  });
  const response = await handler(request);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});

test('withFetch converts CsrfShieldError into a structured 403 JSON Response', async () => {
  const shield = shieldFor();
  const handler = shield.withFetch(async () => new Response('should never run'), { sessionId: 'alice', now: 1000001 });
  const request = new Request(ORIGIN + '/transfer', { method: 'POST', headers: { origin: ORIGIN }, body: 'x=1' });
  const response = await handler(request);
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json();
  assert.equal(body.error, CODE.MISSING_COOKIE);
});

test('withFetch honors a custom onError handler', async () => {
  const shield = shieldFor();
  const handler = shield.withFetch(async () => new Response('ok'), {
    sessionId: 'alice',
    now: 1000001,
    onError: (error) => new Response(error.code, { status: 418 })
  });
  const response = await handler(new Request(ORIGIN + '/transfer', { method: 'POST', headers: { origin: ORIGIN } }));
  assert.equal(response.status, 418);
  assert.equal(await response.text(), CODE.MISSING_COOKIE);
});

test('errorResponse maps strong-secret failures to 500', () => {
  const shield = shieldFor();
  const response = shield.errorResponse(new esm.CsrfShieldError(CODE.WEAK_SECRET, 'weak secret'));
  assert.equal(response.status, 500);
});

test('createFetchTokenResponse returns JSON and the __Host- cookie', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const response = shield.createFetchTokenResponse(token);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('set-cookie'), /^__Host-csrf=v1\./);
  assert.deepEqual(await response.json(), { csrfToken: token });
});

test('CJS entry point also handles Fetch Request objects', async () => {
  const shield = cjs.createShield({ secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' });
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: { cookie: shield.serializeCookie(token), origin: ORIGIN, 'x-csrf-token': token }
  });
  assert.equal((await shield.verifyRequest(request, { now: 1000001 })).ok, true);
});

test('Fetch Request with duplicate Cookie header is rejected', async () => {
  const shield = shieldFor();
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const request = new Request(ORIGIN + '/transfer', {
    method: 'POST',
    headers: [
      ['cookie', shield.serializeCookie(token)],
      ['cookie', shield.serializeCookie(token)],
      ['origin', ORIGIN],
      ['x-csrf-token', token]
    ]
  });
  await expectCodeAsync(test, () => shield.verifyRequest(request, { sessionId: 'alice', now: 1000001 }), CODE.INVALID_TOKEN, 'duplicate cookie header via Fetch Headers');
});

test('Web Crypto randomness produces distinct nonces across many tokens', () => {
  const shield = esm.createShield({ secrets: [SECRET], origin: ORIGIN });
  const tokens = new Set();
  for (let i = 0; i < 50; i++) tokens.add(shield.issueToken({}, { sessionId: 'alice' }));
  assert.equal(tokens.size, 50);
});
