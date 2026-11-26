# Contributing

## Local setup

No install step is required. The package has no runtime or development
dependencies.

```sh
npm test
```

All 184 tests must pass before submitting a change.

## Guidelines

- Keep the core `src/index.mjs` free of imports. It must run in every JavaScript runtime.
- Add tests for both ESM and CommonJS whenever public behavior changes.
- Regenerate `cjs/index.cjs` with `npm run build:cjs` after core edits.
- Update `types/index.d.ts` when the public API changes.
- Never weaken Origin, Referer, Fetch Metadata, cookie, or signature checks without an explicit security rationale and matching regression tests.
- Use deterministic crypto adapters in tests. Avoid wall-clock assumptions.
- Prefer small focused pull requests. Reference the issue you are fixing.

## Commit hygiene

Do not commit secrets, personal paths, generated profiles, or editor state.
Keep the dependency arrays empty unless a change is explicitly approved as a
runtime feature. Document security-relevant behavior in README.md.
