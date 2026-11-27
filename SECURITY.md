# Security Policy

## Supported versions

Only the latest published `1.x` release receives security fixes. Users should
upgrade promptly when a security release is published.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Older than 1.0.0 | No |

## Reporting a vulnerability

Report suspected vulnerabilities privately through the GitHub Security
Advisories workflow for `draarivpatel-ui/redirectcage`. Do not open a public
issue, pull request or discussion with a working exploit.

Include:

- The exact package version and Node.js version
- Whether input came through `sanitizeRedirect`, `assertSafeRedirect`,
  `isSafeRedirect`, `parseRedirectLocation` or `res.safeRedirect`
- The complete options object, with secrets removed
- A minimal input string and the expected safe result
- The actual normalized output or error code
- Whether the behavior differs between ESM and CommonJS or between operating
  systems

A useful report does not need a large application reproduction. A small script
that imports the package and prints the parse result is enough.

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
