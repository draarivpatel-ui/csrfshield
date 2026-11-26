# csrfshield

Zero-dependency, stateless CSRF protection for Node.js and Web Fetch runtimes.

`csrfshield` replaces the archived `csurf` package with a signed double-submit
cookie, strict Origin and Referer validation, Fetch Metadata checks, and a
modern dual-module API that works in Express, Next.js Edge, Cloudflare Workers,
Deno, and Bun.

- Zero runtime dependencies, including the cryptographic core.
- Signed `(sessionId, randomNonce, expiresAt)` tokens using HMAC-SHA256.
- Multi-secret key rotation with a minimum 32-byte secret requirement.
- Timing-safe signature and token comparison on every verification.
- `__Host-` cookie prefix by default: `Secure`, `Path=/`, no `Domain`, `HttpOnly`, `SameSite=Lax`.
- Rejects cross-site Fetch Metadata before any cookie or token check.
- Exact Origin and Referer matching, never prefix or substring matching.
- BREACH-safe masked tokens with a fresh random mask per submission.
- Structured errors with stable machine-readable codes.
- 188 deterministic tests, verified with `npm test` on Node 18 or newer.

## Install

```sh
npm install @aarivbuildz/csrfshield
```

## Quick start

The same shield instance works with Node request objects and with Fetch
`Request` objects.

```js
import { createShield } from '@aarivbuildz/csrfshield';

const shield = createShield({
  secrets: [process.env.CSRF_SECRET],
  origin: 'https://app.example.com',
  getSessionId: (request) => request.session.id || ''
});

const token = shield.issueToken({}, { sessionId: 'user-123' });
const cookie = shield.serializeCookie(token);
```

For the fastest native HMAC path in Node, import the optional adapter. The
portable crypto core remains dependency-free.

```js
import { createShield, nodeCrypto } from 'csrfshield/node';

const shield = createShield({
  secrets: ['replace-with-at-least-32-random-bytes'],
  crypto: nodeCrypto,
  origin: 'https://app.example.com'
});
```

CommonJS is supported through the same package name:

```js
const { createShield } = require('@aarivbuildz/csrfshield');
const { nodeCrypto } = require('csrfshield/node');
```

## Express middleware

```js
import express from 'express';
import { createShield, nodeCrypto } from 'csrfshield/node';

const shield = createShield({
  secrets: [process.env.CSRF_SECRET],
  crypto: nodeCrypto,
  origin: 'https://app.example.com',
  getSessionId: (request) => request.session?.id || ''
});

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(shield.middleware);

app.get('/transfer-form', (request, response) => {
  response.json({ token: response.locals.csrfToken });
});

app.post('/transfer', (request, response) => {
  response.json({ ok: true, verified: response.locals.csrfVerified });
});
```

Import the Node adapter with `import { nodeCrypto } from 'csrfshield/node'` and
pass it as `crypto: nodeCrypto` in the configuration above.

On safe methods (`GET`, `HEAD`, and `OPTIONS`) the middleware verifies any
existing cookie, issues a fresh token when the cookie is missing, malformed,
forged, or expired, and exposes the token on `response.locals.csrfToken`. On
state changing methods it verifies the request, exposes the result on
`response.locals.csrfVerified`, and forwards failures to `next(error)`.

## Next.js Edge route handler

```js
import { createShield } from '@aarivbuildz/csrfshield';

const shield = createShield({
  secrets: [process.env.CSRF_SECRET],
  origin: 'https://app.example.com'
});

export async function GET(request) {
  const token = shield.issueToken({}, { sessionId: '' });
  return shield.createFetchTokenResponse(token);
}

export const POST = shield.withFetch(
  async () => new Response('ok', { status: 200 }),
  { sessionId: '' }
);
```

`withFetch` returns a structured JSON 403 response with `Cache-Control:
no-store` when verification fails. Only CSRF failures are converted: an error
thrown by the handler or by a custom extractor propagates to the framework
instead of leaking its message in a 403 body. Pass `onError` in the settings
object to customize the CSRF response.

## Cloudflare Workers

```js
import { createShield } from '@aarivbuildz/csrfshield';

const shield = createShield({
  secrets: [env.CSRF_SECRET],
  origin: 'https://app.example.com'
});

export default {
  async fetch(request) {
    if (request.method === 'GET') {
      const token = shield.issueToken({}, { sessionId: '' });
      return shield.createFetchTokenResponse(token);
    }
    return shield.withFetch(() => new Response('ok'))(request);
  }
};
```

The Fetch adapters accept standard `Request` bodies, including JSON, URL
encoded forms, and `FormData`, without consuming the original request stream.

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `secrets` | required | Array of 32+ byte strings; first secret signs, all verify. |
| `secret` | none | Deprecated single-secret form for simple migrations. |
| `origin` | none | Exact allowlist of origin strings or a validator function. |
| `originCheck` | enabled | `enabled`, `strict`, `allowNull`, `refererFallback`. |
| `fetchMetadata` | enabled | `enabled`, `strictness` (`same-site` or `same-origin`), `allowNone`. |
| `cookie` | `__Host-` defaults | `name`, `path`, `secure`, `httpOnly`, `sameSite`, `maxAge`, `domain`. |
| `header` | `x-csrf-token` | Header used for submitted tokens. |
| `bodyField` | `_csrf` | Form or JSON body field used for submitted tokens. |
| `tokenTtlMs` | `3600000` | Token lifetime in milliseconds. |
| `clockSkewMs` | `30000` | Accepted expiry skew, must be smaller than the TTL. |
| `mask` | `false` | Require BREACH-safe `m1.<mask>.<payload>` tokens. |
| `extractToken` | none | Custom sync or async token extractor. |
| `crypto` | Web Crypto | Crypto adapter; `nodeCrypto` is available from `csrfshield/node`. |

Safe methods skip all checks. Every other method must pass Fetch Metadata,
Origin or Referer validation, cookie verification, and submitted token
verification in that order.

## Migrating from csurf

`csurf` is archived and no longer receives security fixes. It also requires
session middleware to store a secret server side. `csrfshield` is stateless.

1. Replace `import csurf from 'csurf'` with `import { createShield } from 'csrfshield/node'`.
2. Replace `app.use(csurf({ cookie: true }))` with `app.use(shield.middleware)`.
3. Replace `req.csrfToken()` with `res.locals.csrfToken` (or call `shield.issueToken(req)`).
4. Configure `origin` with your exact application origin. Do not rely on the browser to send a predictable Origin header.
5. Set a 32+ byte `CSRF_SECRET` environment variable. If you already have a csurf session secret, generate a fresh independent secret instead.
6. Remove the csurf session dependency if it was only used for CSRF storage.

The default token field name `_csrf` and header name `x-csrf-token` match
common csurf integrations, so most frontend form submissions keep working.

## Threat model

The shield protects state changing requests against cross-site form posts,
cross-site JavaScript, subdomain cookie tossing, token fixation, replay beyond
the token TTL, and BREACH-style compression side channels when masking is
enabled.

It assumes TLS is enforced, the application supplies a trusted session
identifier through `getSessionId`, secrets are kept out of source control,
and browsers implement the `__Host-` cookie prefix correctly. It does not
replace authorization checks, transport security, Content Security Policy,
or input validation.

Origin validation is intentionally exact. A configured origin of
`https://app.example.com` never accepts `https://app.example.com.evil.com` or
userinfo and path tricks. A literal `null` origin is rejected unless
`originCheck.allowNull` is explicitly enabled.

## Error codes

`CsrfShieldError` exposes `code`, `reason`, `status`, and optional `meta`.
Codes are `INVALID_TOKEN`, `EXPIRED_TOKEN`, `SESSION_MISMATCH`,
`CROSS_SITE_REQUEST`, `ORIGIN_MISMATCH`, `MISSING_COOKIE`, `WEAK_SECRET`,
`INVALID_CONFIG`, `INVALID_SESSION`, and `RNG_UNAVAILABLE`. Client-caused
failures map to HTTP 403; configuration failures map to HTTP 500.

## Development

```sh
npm test
npm run build:cjs
```

The test suite covers SHA-256 and HMAC vectors, cookie tossing, duplicate
Cookie headers, key rotation, expiry and clock skew, Fetch Metadata behavior,
Origin bypass attempts, BREACH masking, forged cookie replacement, adapter
error propagation, Express middleware, Fetch adapters, and ESM and CommonJS
parity. See [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md)
for framework integration ideas.

## License

MIT
