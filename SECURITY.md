# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest published 1.x release | Yes |
| Older releases | No |

Security fixes apply to the latest published 1.x release. Users should upgrade to the fixed release as soon as it is available.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/csrfshield/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- A minimal reproduction, the affected version and the Node.js version.
- The expected security boundary and the observed behavior.
- Your assessment of impact and a suggested fix if you have one.

Do not include real credentials, signing secrets or customer data in a report.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed release and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

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
