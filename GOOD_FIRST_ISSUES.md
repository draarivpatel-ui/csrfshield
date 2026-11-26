# Good first issues

Each item below is a concrete framework integration task. Every adapter should
reuse `createShield` rather than reimplementing CSRF logic, should preserve
the core verification order, and should include deterministic tests.

1. Fastify plugin. Register `shield.middleware` through `onRequest`, expose the token on `reply.locals`, and document cookie parser requirements.
2. Hono middleware. Wrap `shield.withFetch` for Hono's `Context` and pass the underlying `Request` through unchanged.
3. Koa middleware. Adapt `async (ctx, next)` to the Node middleware shape and map failures to Koa's `ctx.throw`.
4. Remix loader and action helpers. Issue tokens in loaders and verify actions with `shield.protectFetch`.
5. SvelteKit hooks. Add a `handle` hook that verifies unsafe methods and exposes tokens through `event.locals`.
6. Astro middleware. Implement an Astro middleware that verifies form actions and forwards tokens to pages.
7. Nuxt server middleware. Add a server middleware that verifies unsafe methods and a composable that reads the token cookie.
8. Oak middleware for Deno. Map Oak's context to the Fetch adapter and preserve the original request stream.
9. Elysia plugin. Add an `onRequest` hook that verifies state changing requests and returns structured 403 responses.
10. NestJS guard and interceptor. Implement a guard backed by `shield.verifyRequest` and expose the token through a decorator.
11. Next.js Pages Router API helper. Provide `withCsrfPages` for API routes alongside the existing Edge handler example.
12. tRPC procedure middleware. Verify mutations only and attach the verified result to the tRPC context.
13. GraphQL mutation guard. Verify requests that contain a mutation operation while allowing queries and introspection.
14. Bun.serve wrapper. Provide a helper that wraps Bun's `fetch` handler with `shield.withFetch`.
15. Express 5 async error propagation. Test `appendHeader` and rejected promises end to end, then document any differences from Express 4.

Suggested acceptance criteria for every adapter:

- Verify safe methods are skipped and state changing methods are checked.
- Assert structured error codes are preserved in framework responses.
- Assert the token cookie and submitted token still round-trip.
- Add the adapter to README.md only after tests are green.
