# redirectcage

Zero-dependency CWE-601 open redirect and return URL protection for Node.js.

`redirectcage` validates untrusted redirect targets before they reach a
`Location` header. It is strict by default: only canonical root-relative paths
such as `/dashboard?tab=1#top` are accepted unless exact external origins or
hosts are explicitly allowlisted. It ships ESM, CommonJS and strict TypeScript
definitions from one audited source of truth.

- Zero runtime dependencies and zero devDependencies
- 444 deterministic tests verified live with `npm test`
- ESM and CommonJS parity tested through package self-reference
- Typed `RedirectCageError` failures with stable machine-readable codes
- Defense against protocol-relative URLs, backslash confusion, encoded schemes,
  control character smuggling, invalid UTF-8 byte sequences, userinfo spoofing,
  IP literal obfuscation and incomplete `scheme:` forms
- Optional exact origin and host allowlists with strict subdomain boundaries

## Install

```sh
npm install redirectcage
```

Node 18 or newer. No build step and no peer dependencies.

## Quick start

```js
import { sanitizeRedirect, assertSafeRedirect } from 'redirectcage';

app.get('/login', (req, res) => {
  const target = sanitizeRedirect(req.query.next);
  res.redirect(302, target);
});

// Throws RedirectCageError instead of falling back:
const target = assertSafeRedirect(req.query.next);
```

By default these results are returned:

```js
sanitizeRedirect('/dashboard?tab=1#top'); // '/dashboard?tab=1#top'
sanitizeRedirect('//evil.example');       // '/'
sanitizeRedirect('javascript:alert(1)');  // '/'
sanitizeRedirect('https://evil.example'); // '/'
```

`sanitizeRedirect` never throws because user-controlled input is hostile. It
returns the validated and canonicalized `fallback`, which defaults to `/`.
Configuration errors, including an unsafe fallback or an unknown option key,
still throw loudly.

## Strict assertions and predicates

```js
import {
  assertSafeRedirect,
  isSafeRedirect,
  parseRedirectLocation
} from 'redirectcage';

assertSafeRedirect('/account');        // '/account'
assertSafeRedirect('//evil.example');  // throws RedirectCageError

isSafeRedirect('/account');            // true
isSafeRedirect('https://evil.example'); // false

const parsed = parseRedirectLocation('/account?tab=security#keys');
// parsed.safe is true and includes kind, value, pathname, search and hash.
```

Every assertion failure has a stable `code`, a human-readable `reason`, and the
rejected `input`:

```js
try {
  assertSafeRedirect('//evil.example');
} catch (error) {
  error.name;  // 'RedirectCageError'
  error.code;  // 'ERR_REDIRECTCAGE_PROTOCOL_RELATIVE'
}
```

## Allowlisting external targets

Absolute URLs are rejected unless an explicit origin or host allowlist is
configured.

```js
import { createRedirectGuard } from 'redirectcage';

const guard = createRedirectGuard({
  allowedOrigins: [
    'https://app.example.com',
    'https://admin.example.com:8443'
  ],
  fallback: '/login'
});

guard.sanitize('/settings');                            // '/settings'
guard.sanitize('https://app.example.com/settings');     // canonical absolute URL
guard.sanitize('https://evil.example/settings');        // '/login'
```

`allowedOrigins` binds scheme, host and port. `allowedHosts` is intentionally
scheme-independent, so use `allowedOrigins` when the scheme must be pinned.

```js
const hostGuard = createRedirectGuard({
  allowedHosts: ['example.com', 'api.example.com:8443'],
  allowProtocols: ['https']
});
```

A host entry without a port accepts only the default port for the candidate
scheme. A host entry with a port requires that exact effective port. Explicit
default ports are canonicalized away by the WHATWG `URL` parser.

## Subdomains, IDN, IP literals and userinfo

Subdomains are off by default. Enable them only when every subdomain is trusted:

```js
const guard = createRedirectGuard({
  allowedOrigins: ['https://example.com'],
  allowSubdomains: true
});

guard.isSafe('https://app.example.com/x');      // true
guard.isSafe('https://evil-example.com/x');     // false
guard.isSafe('https://example.com.evil/x');     // false
```

The subdomain check requires a literal dot boundary. `eviltrusted.com` never
matches `trusted.com`. Internationalized host names are canonicalized through
the WHATWG `URL` parser to punycode before comparison.

IP literals are rejected even when an unrelated host is allowlisted. To support
a deliberate local or test deployment, enable them and allowlist the canonical
literal explicitly:

```js
createRedirectGuard({
  allowedHosts: ['127.0.0.1', '[::1]'],
  allowIpLiterals: true
});
```

Userinfo is rejected by default because `https://trusted.com@evil.example/` is a
classic visual spoof. It can be enabled with `allowUserinfo: true`, but host
matching still applies to the real authority host. Most applications should keep
it disabled.

## Reusable guard and middleware

```js
import { createRedirectGuard } from 'redirectcage';

const redirectGuard = createRedirectGuard({
  fallback: '/',
  blockedPaths: ['/logout']
});

app.use(redirectGuard.middleware());

app.get('/login', (req, res) => {
  res.safeRedirect(req.query.next, 303);
});
```

`middleware()` is framework-agnostic and does not depend on Express. It expects
the response object to provide `setHeader`, `statusCode` and `end`, which Node
HTTP and Express responses both do. The installed `res.safeRedirect(target,
status)` helper uses a 302 status unless another integer status from 300 through
399 is supplied. Unsafe targets are replaced by the configured fallback before
the `Location` header is written.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `allowedOrigins` | `[]` | Exact `http` or `https` origins allowed for absolute redirects. Entries must not have a path, query, fragment or userinfo. |
| `allowedHosts` | `[]` | Literal hosts, optionally with one explicit port. Scheme-independent. |
| `allowSubdomains` | `false` | Also allow descendants of allowlisted hosts at a strict dot boundary. |
| `allowProtocols` | `['http', 'https']` | Narrow absolute redirects to `https` or `http`. Non-HTTP schemes cannot be enabled. |
| `allowUserinfo` | `false` | Permit userinfo in absolute URL authorities. Not recommended. |
| `allowIpLiterals` | `false` | Permit explicitly allowlisted IPv4 and IPv6 literals. |
| `allowQuery` | `true` | Permit literal or encoded query structure. |
| `allowHash` | `true` | Permit literal or encoded fragment structure. |
| `normalizeDotSegments` | `true` | Canonicalize dot segments using WHATWG URL semantics. When false, direct and encoded dot segments are rejected. |
| `blockedPaths` | `[]` | Canonical paths that must never be targets. Matching is case sensitive because URL paths are case sensitive. An entry also covers its slash-delimited descendants and percent-decoded equivalents. |
| `fallback` | `'/'` | Safe value returned by `sanitize` for rejected input. It is validated under the complete policy and canonicalized at configuration time. |
| `maxLength` | `2048` | Maximum input length in UTF-16 code units, checked before decoding. |
| `maxDecodeLayers` | `8` | Maximum nested percent-decoding layers inspected. Values from 1 through 16 are accepted. |
| `throwOnUnsafe` | `false` | Make `sanitize` throw on unsafe input instead of returning `fallback`. |

Unknown option keys and the reserved keys `__proto__`, `constructor` and
`prototype` are rejected. Configuration objects are copied into null-prototype
internal state, arrays are copied at guard creation time, and guards are frozen.

## Canonical model

A safe relative target must start with exactly one slash. Bare relative strings
such as `dashboard`, `../x`, `?next=/x` and `#top` are rejected because their
meaning depends on the current document path. `/@user` is valid: a single slash
followed by an at sign is only a path segment, not authority confusion.

Dot segments are normalized by default, so `/a/../b` returns `/b`. Unicode path
text is percent encoded canonically and percent hex triplets are uppercase. The
output is always the normalized value returned by the library. Do not use the
original input after validation.

Percent-decoded byte sequences must be valid UTF-8. Overlong encodings, isolated
continuation bytes, encoded surrogate code points and other malformed byte
sequences are rejected instead of being interpreted differently by lenient
decoders.

`blockedPaths` uses the case-sensitive path comparison required by the URL
standard. `/LOGOUT` and `/logout` are different paths. An entry ending in a
slash is also a distinct path, so `/logout/` does not block `/logout`.

Empty query and fragment markers are dropped during canonicalization. Query and
fragment content is allowed by default because it is often required for return
URLs, but both can be disabled independently.

## Attack classes covered

The test suite includes individual vectors for:

- `//evil.example`, `///evil.example` and deeper slash variants
- mixed slash and backslash authority confusion, including encoded backslashes
- raw and encoded tab, CR, LF, NUL, C0, C1, DEL and invisible formatting characters
- CRLF header-splitting payloads
- `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:` and other non-HTTP schemes
- encoded and double-encoded scheme construction
- `https:evil.example` and other incomplete scheme forms
- userinfo and at-sign authority spoofing
- malformed percent encoding, invalid UTF-8 byte sequences and bounded nested decoding
- Unicode compatibility characters that normalize into URL structural characters
- slash lookalike code points that must remain inert percent-encoded path text
- trailing-dot host confusion and strict host boundary bypasses
- IPv4 shorthand, hexadecimal, decimal and octal forms plus IPv6 literals
- port mismatch, empty-port and default-port canonicalization
- maximum-length denial-of-service input
- prototype-polluting option keys and unsafe fallback configuration

## Limitations

`redirectcage` validates the navigation target itself. It does not validate a
nested callback parameter inside that target. For example, `/login?next=//evil.example`
is a same-origin path, but an application that later reads `next` must pass that
value through `redirectcage` separately.

The library does not resolve DNS, inspect reputation, prevent phishing content
on an allowlisted host, or protect against compromise of an allowlisted domain.
It is not an SSRF guard and does not validate server-side fetch destinations.

Only `http` and `https` can be selected in `allowProtocols`. Browser execution
schemes and local resource schemes are never enabled. Bare relative references
are intentionally rejected in favor of canonical root-relative paths. Raw
whitespace is rejected; percent-encoded regular spaces remain encoded in the
returned value. Slash lookalikes such as U+2044 and U+2215 are not path or
authority separators under the WHATWG URL standard or Unicode NFKC. When such a
code point is otherwise valid path text, the canonical output keeps it percent
encoded rather than treating it as a slash.

`blockedPaths` is a URL path policy, not a framework-specific route matcher.
Frameworks that strip matrix parameters, collapse repeated slashes or apply
additional Unicode normalization before routing can have route behavior that no
generic URL library can predict. Keep routing and block policy on the same
canonical path model.

`allowedHosts` is scheme-independent by design. Use `allowedOrigins` or
`allowProtocols: ['https']` when plaintext HTTP must not be accepted. Enabling
`allowSubdomains` trusts every subdomain below the configured host, including
user-controlled subdomains if the platform offers them.

## Development

```sh
node scripts/build-cjs.mjs
npm test
npm pack --dry-run
```

The CommonJS file is generated deterministically from `src/index.mjs`. CI checks
that regeneration produces no diff, then runs the test suite on Node 18, 20, 22
and 24 on Linux and Windows. On Windows `cmd.exe` with Node 18 or 20, use
`npm run test:windows`; cmd does not expand the primary test glob before Node's
older test runner reads it.

## Security

Read `SECURITY.md` before reporting a vulnerability. Do not open a public issue
for a working exploit.
