# Security Policy

## Supported versions

Security fixes apply to the latest published 1.x release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
security advisory form. Include a minimal reproduction, the affected version,
and your assessment of impact. Do not open a public issue for an unpatched
vulnerability.

## What is in scope

- Forgery of state changing requests despite signed double-submit checks.
- Cookie parsing or Origin parsing bypasses.
- Signature comparison flaws or key rotation defects.
- Token expiry, session binding, or masking bypasses.
- Fetch Metadata policy bypasses.

## What is out of scope

- Applications that disable TLS or expose their signing secrets.
- Misconfiguration of trusted session identifiers through `getSessionId`.
- Vulnerabilities in application code that performs authorization after a
  successful CSRF verification.
- Social engineering and attacks requiring arbitrary JavaScript execution on
  the legitimate origin.
