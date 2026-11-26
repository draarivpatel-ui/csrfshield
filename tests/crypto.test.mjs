import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { esm, SECRET } from './helpers.mjs';

const { sha256, hmacSha256, base64urlEncode, base64urlDecodeStrict, constantTimeDiff, timingSafeEqual, CODE, CsrfShieldError } = esm;

test('SHA-256 matches node:crypto for empty and known vectors', () => {
  assert.equal(Buffer.from(sha256('')).toString('hex'), createHash('sha256').update('').digest('hex'));
  assert.equal(Buffer.from(sha256('abc')).toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(Buffer.from(sha256('csrfshield')).toString('hex'), createHash('sha256').update('csrfshield').digest('hex'));
});

test('SHA-256 matches node:crypto across block boundaries and Unicode', () => {
  for (const length of [1, 55, 56, 63, 64, 65, 119, 120, 128, 129, 1000]) {
    const input = 'x'.repeat(length);
    assert.equal(Buffer.from(sha256(input)).toString('hex'), createHash('sha256').update(input).digest('hex'), 'length ' + length);
  }
  for (const value of ['café', 'key ☃ snowman', '\u{1f600} emoji']) {
    assert.equal(Buffer.from(sha256(value)).toString('hex'), createHash('sha256').update(value, 'utf8').digest('hex'));
  }
});

test('HMAC-SHA256 matches node:crypto for varied key and payload lengths', () => {
  for (const keyLength of [1, 32, 63, 64, 65, 100]) {
    for (const dataLength of [0, 1, 55, 64, 200]) {
      const key = 'k'.repeat(keyLength);
      const data = 'd'.repeat(dataLength);
      const expected = createHmac('sha256', key).update(data).digest('hex');
      assert.equal(Buffer.from(hmacSha256(key, data)).toString('hex'), expected, 'key ' + keyLength + ' data ' + dataLength);
    }
  }
});

test('HMAC handles binary keys and binary payloads', () => {
  const key = new Uint8Array(80).map((_, i) => (i * 7) & 255);
  const data = new Uint8Array(150).map((_, i) => (i * 3) & 255);
  assert.equal(Buffer.from(hmacSha256(key, data)).toString('hex'), createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest('hex'));
});

test('base64url round-trips binary data without padding', () => {
  for (const length of [1, 2, 3, 4, 16, 32, 64]) {
    const bytes = new Uint8Array(length).map((_, i) => (i * 11) & 255);
    const encoded = base64urlEncode(bytes);
    assert.equal(encoded.includes('='), false);
    assert.equal(encoded.includes('+'), false);
    assert.equal(encoded.includes('/'), false);
    assert.deepEqual(base64urlDecodeStrict(encoded), bytes);
  }
});

test('base64urlDecodeStrict rejects padding and malformed inputs', () => {
  const invalid = ['', 'a=', 'a===', 'ab=', '!!!!', 'a b', 'abc\n', 'a+', 'a/', 'A'.repeat(5)];
  for (const value of invalid) {
    assert.throws(() => base64urlDecodeStrict(value), (error) => error.code === CODE.INVALID_TOKEN, value);
  }
});

test('base64urlDecodeStrict rejects non-canonical trailing bits', () => {
  for (const value of ['AB', 'AZ', 'ABB', 'ABZ']) {
    let rejected = false;
    try {
      base64urlDecodeStrict(value);
    } catch (_) {
      rejected = true;
    }
    assert.equal(rejected, true, value + ' should be rejected');
  }
});

test('constantTimeDiff and timingSafeEqual compare bytes', () => {
  assert.equal(constantTimeDiff('abc', 'abc'), 0);
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.notEqual(constantTimeDiff('abc', 'abd'), 0);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(constantTimeDiff('abc', 'abcd'), -1);
  assert.equal(timingSafeEqual('abc', 'abcd'), false);
  assert.equal(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
});

test('CsrfShieldError has typed codes and JSON output', () => {
  const error = new CsrfShieldError(CODE.MISSING_COOKIE, 'cookie missing');
  assert.equal(error.name, 'CsrfShieldError');
  assert.equal(error.code, 'MISSING_COOKIE');
  assert.equal(error.status, 403);
  assert.deepEqual(error.toJSON(), { name: 'CsrfShieldError', code: 'MISSING_COOKIE', message: 'MISSING_COOKIE: cookie missing', status: 403 });
  assert.equal(new CsrfShieldError(CODE.WEAK_SECRET, 'weak').status, 500);
  assert.equal(new CsrfShieldError(CODE.INVALID_CONFIG, 'bad').status, 500);
});

test('all documented error codes are exported', () => {
  for (const code of ['INVALID_TOKEN', 'EXPIRED_TOKEN', 'SESSION_MISMATCH', 'CROSS_SITE_REQUEST', 'ORIGIN_MISMATCH', 'MISSING_COOKIE', 'WEAK_SECRET']) {
    assert.equal(CODE[code], code);
  }
});

test('createShield rejects secrets that are too short', () => {
  for (const secrets of ['x'.repeat(31), ['x'.repeat(32), 'short'], [], [1, 2]]) {
    assert.throws(() => esm.createShield({ secrets }), (error) => error.code === CODE.WEAK_SECRET);
  }
});
