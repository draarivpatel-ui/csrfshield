// Red-team regressions: adapter error handling and token fixation.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createShield } from '../src/index.mjs';

const SECRET = 's'.repeat(32);
const ORIGIN = 'https://example.com';

function shield() {
  return createShield({ secrets: [SECRET], origin: ORIGIN });
}

function validHeaders(instance) {
  const pair = instance.issueTokenPair({});
  return {
    origin: ORIGIN,
    cookie: '__Host-csrf=' + pair.token,
    'x-csrf-token': pair.token
  };
}

// A token that is syntactically perfect but signed by nobody. 22 base64url
// characters decode to the minimum 16 byte nonce, 43 characters to a 32 byte
// signature, so only the HMAC can reject it.
const FORGED_COOKIE = 'v1..' + 'A'.repeat(22) + '.1.' + 'A'.repeat(43);

test('withFetch propagates application handler errors instead of leaking them as 403', async () => {
  const instance = shield();
  const handler = instance.withFetch(async () => {
    throw new Error('database password is hunter2');
  });
  const request = new Request(ORIGIN + '/pay', {
    method: 'POST',
    headers: validHeaders(instance)
  });
  await assert.rejects(() => handler(request), /database password is hunter2/);
});

test('withFetch still converts real CSRF failures into structured responses', async () => {
  const instance = shield();
  const handler = instance.withFetch(async () => {
    throw new Error('handler must not run');
  });
  const response = await handler(new Request(ORIGIN + '/pay', {
    method: 'POST',
    headers: { origin: ORIGIN }
  }));
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error, 'MISSING_COOKIE');
});

test('withFetch propagates custom extractor application errors', async () => {
  const instance = shield();
  const handler = instance.withFetch(async () => 'ok', {
    extractToken() {
      throw new Error('extractor secret leaked');
    }
  });
  const request = new Request(ORIGIN + '/pay', {
    method: 'POST',
    headers: validHeaders(instance)
  });
  await assert.rejects(() => handler(request), /extractor secret leaked/);
});

test('middleware replaces a well formed but unsigned cookie instead of echoing it', async () => {
  const instance = shield();
  const response = {
    locals: {},
    headers: {},
    setHeader(key, value) {
      this.headers[key] = value;
    },
    getHeader() {
      return undefined;
    }
  };
  let nextError;
  await instance.middleware(
    { method: 'GET', url: '/', headers: { cookie: '__Host-csrf=' + FORGED_COOKIE } },
    response,
    (error) => {
      nextError = error;
    }
  );
  assert.equal(nextError, undefined);
  assert.notEqual(response.locals.csrfToken, FORGED_COOKIE);
  assert.ok(response.headers['Set-Cookie'], 'a replacement cookie must be sent');
  assert.notEqual(response.headers['Set-Cookie'], '__Host-csrf=' + FORGED_COOKIE);
});
