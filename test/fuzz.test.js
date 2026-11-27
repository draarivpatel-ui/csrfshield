import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, timingSafeEqual } from 'node:crypto';
import fc from 'fast-check';
import { createShield, CsrfShieldError } from '../src/index.mjs';

const SECRET = 'csrfshield-fuzz-secret-32-bytes!';
const NOW = 1_000_000;
const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

function asBuffer(value) {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  return Buffer.from(String(value), 'utf8');
}

const deterministicCrypto = Object.freeze({
  name: 'fast-check-deterministic-crypto',
  randomBytes(length) {
    return new Uint8Array(length).fill(7);
  },
  hmac(key, data) {
    return new Uint8Array(createHmac('sha256', asBuffer(key)).update(asBuffer(data)).digest());
  },
  timingEqual(left, right) {
    const a = asBuffer(left);
    const b = asBuffer(right);
    return a.length === b.length && timingSafeEqual(a, b);
  },
});

function makeShield() {
  return createShield({ secrets: [SECRET], crypto: deterministicCrypto });
}

const sessionArbitrary = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'),
  maxLength: 48,
});
const mutationCharacter = fc.constantFrom(...(TOKEN_ALPHABET + '.=!'));

function assertTokenRejected(shield, token, sessionId) {
  assert.throws(
    () => shield.verifyToken(token, { sessionId, now: NOW + 1 }),
    (error) => error instanceof CsrfShieldError,
  );
}

test('mutated CSRF tokens never verify', () => {
  fc.assert(
    fc.property(sessionArbitrary, fc.integer({ min: 0, max: 4096 }), mutationCharacter, (sessionId, position, replacement) => {
      const shield = makeShield();
      const token = shield.issueToken({}, { sessionId, now: NOW });
      const index = position % token.length;
      fc.pre(token[index] !== replacement);
      const mutated = token.slice(0, index) + replacement + token.slice(index + 1);
      assertTokenRejected(shield, mutated, sessionId);
    }),
    { seed: 20261127, numRuns: 150, endOnFailure: true },
  );
});

test('a signature transplanted from another session never verifies', () => {
  fc.assert(
    fc.property(sessionArbitrary, sessionArbitrary, (victimSession, attackerSession) => {
      fc.pre(victimSession !== attackerSession);
      const shield = makeShield();
      const victimToken = shield.issueToken({}, { sessionId: victimSession, now: NOW });
      const attackerToken = shield.issueToken({}, { sessionId: attackerSession, now: NOW });
      const victimParts = victimToken.split('.');
      const attackerParts = attackerToken.split('.');
      victimParts[4] = attackerParts[4];
      assertTokenRejected(shield, victimParts.join('.'), victimSession);
    }),
    { seed: 20261128, numRuns: 100, endOnFailure: true },
  );
});

test('arbitrary token strings fail closed', () => {
  const shield = makeShield();
  const validToken = shield.issueToken({}, { sessionId: 'fixed-session', now: NOW });
  fc.assert(
    fc.property(fc.string({ maxLength: 256 }), (candidate) => {
      fc.pre(candidate !== validToken);
      assertTokenRejected(shield, candidate, 'fixed-session');
    }),
    { seed: 20261129, numRuns: 150, endOnFailure: true },
  );
});
