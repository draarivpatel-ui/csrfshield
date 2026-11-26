import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeShield, fixedCrypto, ORIGIN, expectCodeAsync } from './helpers.mjs';

const { CODE } = (await import('../src/index.mjs'));
const deterministic = fixedCrypto();

function req(shield, overrides = {}) {
  const token = shield.issueToken({}, { sessionId: 'alice', now: 1000000 });
  const headers = { cookie: shield.serializeCookie(token), 'x-csrf-token': token };
  if (overrides.origin !== undefined) headers.origin = overrides.origin;
  else if (!overrides.noOrigin) headers.origin = ORIGIN;
  if (overrides.referer !== undefined) headers.referer = overrides.referer;
  if (overrides.fetchSite !== undefined) headers['sec-fetch-site'] = overrides.fetchSite;
  if (overrides.noFetchSite) delete headers['sec-fetch-site'];
  return { method: overrides.method || 'POST', url: ORIGIN + '/x', headers, sessionId: 'alice', body: {} };
}

test('exact origin matches', async () => {
  const shield = makeShield({ crypto: deterministic });
  assert.equal((await shield.verifyRequest(req(shield), { now: 1000001 })).ok, true);
  assert.equal((await shield.verifyRequest(req(shield, { origin: ORIGIN + '/' }), { now: 1000001 })).ok, true);
});

test('origin prefix and substring bypasses are rejected', async () => {
  const shield = makeShield({ crypto: deterministic });
  for (const origin of [
    'https://app.example.com.evil.com',
    'https://evilapp.example.com',
    'https://app.example.com@evil.com',
    'http://app.example.com',
    'https://app.example.com:444',
    'https://sub.app.example.com',
    'https://evil.com/?next=' + encodeURIComponent(ORIGIN)
  ]) {
    await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { origin }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, origin);
  }
});

test('null origin is rejected unless explicitly allowed', async () => {
  const shield = makeShield({ crypto: deterministic });
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { origin: 'null' }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'null origin');
  const permissive = makeShield({ crypto: deterministic, originCheck: { allowNull: true } });
  assert.equal((await permissive.verifyRequest(req(permissive, { origin: 'null' }), { now: 1000001 })).ok, true);
});

test('missing Origin and missing Referer is rejected in strict mode', async () => {
  const shield = makeShield({ crypto: deterministic });
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { noOrigin: true }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'missing origin');
});

test('referer fallback validates the referer origin', async () => {
  const shield = makeShield({ crypto: deterministic });
  assert.equal((await shield.verifyRequest(req(shield, { noOrigin: true, referer: ORIGIN + '/account' }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { noOrigin: true, referer: 'https://evil.com/page' }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'evil referer');
});

test('referer fallback can be disabled', async () => {
  const shield = makeShield({ crypto: deterministic, originCheck: { refererFallback: false } });
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { noOrigin: true, referer: ORIGIN + '/account' }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'disabled referer fallback');
});

test('non-strict origin check tolerates missing headers', async () => {
  const shield = makeShield({ crypto: deterministic, originCheck: { strict: false } });
  assert.equal((await shield.verifyRequest(req(shield, { noOrigin: true }), { now: 1000001 })).ok, true);
});

test('duplicate Origin and Referer headers are rejected', async () => {
  const shield = makeShield({ crypto: deterministic });
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { origin: [ORIGIN, 'https://evil.com'] }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'duplicate origin');
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { referer: [ORIGIN, ORIGIN] }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'duplicate referer');
});

test('multiple allowed origins are matched exactly', async () => {
  const shield = makeShield({ crypto: deterministic, origin: [ORIGIN, 'https://admin.example.org'] });
  assert.equal((await shield.verifyRequest(req(shield, { origin: 'https://admin.example.org' }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { origin: 'https://evil.com' }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'not in allowlist');
});

test('custom origin validator function is honored', async () => {
  const shield = makeShield({ crypto: deterministic, origin: (origin) => origin === 'https://partner.example.net' });
  assert.equal((await shield.verifyRequest(req(shield, { origin: 'https://partner.example.net' }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { origin: ORIGIN }), { now: 1000001 }), CODE.ORIGIN_MISMATCH, 'custom rejects');
});

test('async custom origin validator is awaited', async () => {
  const shield = makeShield({ crypto: deterministic, origin: async (origin) => origin === ORIGIN });
  assert.equal((await shield.verifyRequest(req(shield), { now: 1000001 })).ok, true);
});

test('Sec-Fetch-Site cross-site is rejected', async () => {
  const shield = makeShield({ crypto: deterministic });
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { fetchSite: 'cross-site' }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'cross-site');
});

test('Sec-Fetch-Site same-site and same-origin are allowed by default', async () => {
  const shield = makeShield({ crypto: deterministic });
  assert.equal((await shield.verifyRequest(req(shield, { fetchSite: 'same-site' }), { now: 1000001 })).ok, true);
  assert.equal((await shield.verifyRequest(req(shield, { fetchSite: 'same-origin' }), { now: 1000001 })).ok, true);
});

test('same-origin strictness rejects same-site requests', async () => {
  const shield = makeShield({ crypto: deterministic, fetchMetadata: { strictness: 'same-origin' } });
  assert.equal((await shield.verifyRequest(req(shield, { fetchSite: 'same-origin' }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { fetchSite: 'same-site' }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'same-site blocked');
});

test('Sec-Fetch-Site none is policy controlled', async () => {
  const shield = makeShield({ crypto: deterministic });
  assert.equal((await shield.verifyRequest(req(shield, { fetchSite: 'none' }), { now: 1000001 })).ok, true);
  const strict = makeShield({ crypto: deterministic, fetchMetadata: { allowNone: false } });
  await expectCodeAsync(test, () => strict.verifyRequest(req(strict, { fetchSite: 'none' }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'none blocked');
});

test('missing Sec-Fetch-Site is tolerated and duplicate values are rejected', async () => {
  const shield = makeShield({ crypto: deterministic });
  assert.equal((await shield.verifyRequest(req(shield, { noFetchSite: true }), { now: 1000001 })).ok, true);
  await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { fetchSite: ['same-origin', 'cross-site'] }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'duplicate site');
});

test('unknown Sec-Fetch-Site values are rejected', async () => {
  const shield = makeShield({ crypto: deterministic });
  for (const value of ['unknown', '', 'SAME-SITE-EVIL', 'sameorigin']) {
    await expectCodeAsync(test, () => shield.verifyRequest(req(shield, { fetchSite: value }), { now: 1000001 }), CODE.CROSS_SITE_REQUEST, value);
  }
});

test('fetch metadata defense can be disabled independently', async () => {
  const shield = makeShield({ crypto: deterministic, fetchMetadata: { enabled: false } });
  assert.equal((await shield.verifyRequest(req(shield, { fetchSite: 'cross-site' }), { now: 1000001 })).ok, true);
});

test('cross-site check runs before token checks', async () => {
  const shield = makeShield({ crypto: deterministic });
  const bad = req(shield, { fetchSite: 'cross-site' });
  delete bad.headers.cookie;
  await expectCodeAsync(test, () => shield.verifyRequest(bad, { now: 1000001 }), CODE.CROSS_SITE_REQUEST, 'defense in depth order');
});
