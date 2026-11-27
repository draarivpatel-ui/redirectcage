# Security Policy

## Supported versions

Only the latest published `1.x` release receives security fixes. Users should
upgrade promptly when a security release is published.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Older than 1.0.0 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [Report a vulnerability privately through GitHub](https://github.com/draarivpatel-ui/redirectcage/security/advisories/new).

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

## Scope

In scope:

- CWE-601 open redirect bypasses in validated output
- Canonicalization differences that turn a rejected input into a browser-unsafe
  `Location` value
- Host, origin, port, userinfo, scheme, Unicode or percent-decoding confusion
- Prototype pollution through supported option objects
- ESM and CommonJS behavior differences with security impact
- Prototype or object mutation caused by the library

Out of scope:

- Open redirect behavior in an application that ignores the returned normalized
  value and uses the original input
- Nested callback parameters that the application later trusts without separate
  validation
- Compromise, malicious content or phishing pages hosted on an explicitly
  allowlisted domain
- DNS rebinding, SSRF, server-side fetch validation or network reachability
- Denial of service requiring input significantly above the documented
  `maxLength` default when the caller intentionally raises that limit
- Reports requiring a modified Node.js runtime or a nonstandard URL parser

## Response expectations

Reports are triaged as time permits. A confirmed vulnerability receives a fix or
mitigation plan before public disclosure whenever practical. Credit is given in
release notes only when the reporter asks for it.

## Hardening guidance

Use `assertSafeRedirect` where falling back would hide an integration error. Use
`allowedOrigins` rather than broad host patterns, keep `allowSubdomains` off
unless every subdomain is trusted, prefer `allowProtocols: ['https']`, keep
`allowUserinfo` and `allowIpLiterals` disabled, and validate every nested return
URL separately.
