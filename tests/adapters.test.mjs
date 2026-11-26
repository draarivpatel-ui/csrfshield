import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { esm, cjs, nodeEsm, cjsNode, nativeCrypto, fixedCrypto, SECRET, ORIGIN } from './helpers.mjs';

const deterministic = fixedCrypto();

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

test('nodeCrypto adapter matches portable HMAC and timingSafeEqual', () => {
  for (const data of ['', 'abc', 'x'.repeat(200)]) {
    assert.deepEqual(nodeEsm.nodeCrypto.hmac(SECRET, data), esm.hmacSha256(SECRET, data));
    assert.deepEqual(cjsNode.nodeCrypto.hmac(SECRET, data), esm.hmacSha256(SECRET, data));
  }
  assert.equal(nodeEsm.nodeCrypto.timingEqual('same', 'same'), true);
  assert.equal(nodeEsm.nodeCrypto.timingEqual('same', 'diff'), false);
  assert.equal(nodeEsm.nodeCrypto.timingEqual('a', 'longer'), false);
  assert.equal(nodeEsm.nodeCrypto.randomBytes(32).length, 32);
});

test('createNodeCrypto validates its input', () => {
  assert.throws(() => esm.createNodeCrypto({}), (error) => error.code === esm.CODE.INVALID_CONFIG);
});

test('native nodeCrypto adapter issues and verifies end-to-end tokens', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: nodeEsm.nodeCrypto, origin: ORIGIN, getSessionId: () => 'alice' });
  const token = shield.issueToken({}, { sessionId: 'alice' });
  const result = await shield.verifyRequest({ method: 'POST', headers: { cookie: shield.serializeCookie(token), origin: ORIGIN }, body: { _csrf: token }, sessionId: 'alice' });
  assert.equal(result.ok, true);
});

test('ESM and CJS entry points export the same names', () => {
  const esmNames = Object.keys(esm).filter((name) => name !== 'default').sort();
  const cjsNames = Object.keys(cjs).filter((name) => name !== 'default').sort();
  assert.deepEqual(cjsNames, esmNames);
  assert.equal(typeof esm.createShield, 'function');
  assert.equal(typeof cjs.createShield, 'function');
});

test('ESM and CJS produce identical signatures, cookies and verification results', async () => {
  const opts = { secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: (req) => req.sessionId };
  const a = esm.createShield(opts);
  const b = cjs.createShield(opts);
  const token = a.issueToken({}, { sessionId: 'alice', now: 1000000 });
  assert.equal(token, b.issueToken({}, { sessionId: 'alice', now: 1000000 }));
  assert.equal(a.serializeCookie(token), b.serializeCookie(token));
  const req = { method: 'POST', headers: { cookie: a.serializeCookie(token), origin: ORIGIN }, body: { _csrf: token }, sessionId: 'alice' };
  const ra = await a.verifyRequest(req, { now: 1000001 });
  const rb = await b.verifyRequest(req, { now: 1000001 });
  assert.deepEqual(ra, rb);
});

test('ESM and CJS reject the same attacks with identical codes', async () => {
  const opts = { secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' };
  const shields = [esm.createShield(opts), cjs.createShield(opts)];
  const attacks = [
    { headers: { cookie: '__Host-csrf=bad', origin: ORIGIN }, expect: esm.CODE.INVALID_TOKEN },
    { headers: { cookie: '__Host-csrf=a; __Host-csrf=b', origin: 'https://evil.com' }, expect: esm.CODE.ORIGIN_MISMATCH },
    { headers: { cookie: '__Host-csrf=a; __Host-csrf=b', origin: ORIGIN }, expect: esm.CODE.INVALID_TOKEN }
  ];
  for (const shield of shields) {
    for (const attack of attacks) {
      let code;
      try {
        await shield.verifyRequest({ method: 'POST', headers: attack.headers, body: { _csrf: 'v1.a.b.c.d' } });
      } catch (error) {
        code = error.code;
      }
      assert.equal(code, attack.expect);
    }
  }
});

test('Express-style middleware issues a cookie on safe requests', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' });
  const response = { setHeader(name, value) { this.headers[name] = value; }, getHeader(name) { return this.headers[name]; }, headers: {}, locals: {} };
  let called = false;
  await shield.middleware({ method: 'GET', headers: {}, sessionId: 'alice' }, response, (error) => {
    assert.equal(error, undefined);
    called = true;
  });
  assert.equal(called, true);
  assert.match(response.headers['Set-Cookie'], /^__Host-csrf=v1\./);
  assert.match(response.headers['Set-Cookie'], /Secure/);
  assert.match(response.headers['Set-Cookie'], /HttpOnly/);
  assert.match(response.headers['Set-Cookie'], /SameSite=Lax/);
  assert.match(response.locals.csrfToken, /^v1\./);
});

test('Express-style middleware accepts valid unsafe requests and forwards errors', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' });
  const token = shield.issueToken({}, { sessionId: 'alice' });
  const response = { setHeader() {}, getHeader() {}, locals: {} };
  let forwarded;
  await shield.middleware({ method: 'POST', headers: { cookie: shield.serializeCookie(token), origin: ORIGIN }, body: { _csrf: token }, sessionId: 'alice' }, response, (error) => { forwarded = error; });
  assert.equal(forwarded, undefined);
  assert.equal(response.locals.csrfVerified.ok, true);
  await shield.middleware({ method: 'POST', headers: { origin: ORIGIN }, body: {}, sessionId: 'alice' }, response, (error) => { forwarded = error; });
  assert.equal(forwarded.code, esm.CODE.MISSING_COOKIE);
});

test('middleware appends rather than overwrites existing Set-Cookie headers', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: deterministic, origin: ORIGIN, getSessionId: () => 'alice' });
  const response = { headers: { 'Set-Cookie': 'session=abc' }, setHeader(name, value) { this.headers[name] = value; }, getHeader(name) { return this.headers[name]; }, locals: {} };
  await shield.middleware({ method: 'GET', headers: {} }, response, () => {});
  assert.equal(response.headers['Set-Cookie'].length, 2);
  assert.equal(response.headers['Set-Cookie'][0], 'session=abc');
  assert.match(response.headers['Set-Cookie'][1], /^__Host-csrf=v1\./);
});

test('appendHeader is used when available (Express 5 / newer frameworks)', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: deterministic, origin: ORIGIN });
  const appended = [];
  const response = { appendHeader(name, value) { appended.push([name, value]); }, locals: {} };
  await shield.middleware({ method: 'GET', headers: {} }, response, () => {});
  assert.equal(appended.length, 1);
  assert.equal(appended[0][0], 'Set-Cookie');
});

test('cookie options produce correct attributes and clearCookie', () => {
  const strict = esm.createShield({ secrets: [SECRET], cookie: { name: '__Host-csrf', sameSite: 'Strict', maxAge: 60 } });
  const token = strict.issueToken({}, { sessionId: '' });
  assert.equal(strict.serializeCookie(token), strict.serializeCookie(token, { maxAge: 60 }));
  assert.match(strict.serializeCookie(token), /SameSite=Strict/);
  assert.match(strict.clearCookie(), /Max-Age=0/);
  assert.match(strict.clearCookie(), /__Host-csrf=/);
});

test('insecure __Host- or __Secure- cookie configurations are rejected', () => {
  assert.throws(() => esm.createShield({ secrets: [SECRET], cookie: { secure: false } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], cookie: { name: '__Host-csrf', path: '/api' } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], cookie: { name: '__Host-csrf', domain: 'example.com' } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], cookie: { sameSite: 'None', secure: false } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], cookie: { sameSite: 'Bogus' } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
});

test('shield configuration validation', () => {
  assert.throws(() => esm.createShield({ secrets: [SECRET], tokenTtlMs: 0 }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], clockSkewMs: -1 }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], tokenTtlMs: 100, clockSkewMs: 100 }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], getSessionId: 'x' }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], fetchMetadata: { strictness: 'always' } }), (error) => error.code === esm.CODE.INVALID_CONFIG);
  assert.throws(() => esm.createShield({ secrets: [SECRET], crypto: {} }), (error) => error.code === esm.CODE.INVALID_CONFIG);
});

test('real Node http.Server integrates with middleware end to end', async () => {
  const shield = esm.createShield({ secrets: [SECRET], crypto: deterministic, origin: (origin) => origin.startsWith('http://127.0.0.1:') });
  const server = createServer((req, res) => {
    shield.middleware(req, res, (error) => {
      if (error) {
                res.statusCode = error.status || 403;
        res.end(error.code);
        return;
      }
      res.statusCode = 200;
      res.end(req.method === 'GET' ? res.getHeader('Set-Cookie') : 'ok');
    });
  });
  const port = await listen(server);
  try {
    const base = 'http://127.0.0.1:' + port;
    const get = await fetch(base + '/', { method: 'GET' });
    const setCookie = await get.text();
    assert.match(setCookie, /^__Host-csrf=/);
    const token = setCookie.split(';')[0].split('=')[1];
    const ok = await fetch(base + '/transfer', { method: 'POST', headers: { cookie: setCookie.split(';')[0], origin: base, 'x-csrf-token': token, 'sec-fetch-site': 'same-origin' } });
    assert.equal(ok.status, 200);
    assert.equal(await ok.text(), 'ok');
    const bad = await fetch(base + '/transfer', { method: 'POST', headers: { cookie: setCookie.split(';')[0], origin: base, 'x-csrf-token': token, 'sec-fetch-site': 'cross-site' } });
    assert.equal(bad.status, 403);
    assert.equal(await bad.text(), esm.CODE.CROSS_SITE_REQUEST);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
