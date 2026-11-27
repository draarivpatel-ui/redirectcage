import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, throwsCode, throwsInvalidOptions, fakeResponse } from './helpers.mjs';

const C = cjs.CODE;

test('sanitizeRedirect returns the default fallback for unsafe input', () => {
  assert.equal(cjs.sanitizeRedirect('//evil.com'), '/');
});

test('sanitizeRedirect returns a custom fallback for unsafe input', () => {
  assert.equal(cjs.sanitizeRedirect('//evil.com', { fallback: '/home' }), '/home');
});

test('sanitizeRedirect returns the normalized target for valid input', () => {
  assert.equal(cjs.sanitizeRedirect('/a/../b'), '/b');
});

test('sanitizeRedirect does not throw for non-string user input', () => {
  for (const input of [undefined, null, 0, false, {}, []]) {
    assert.equal(cjs.sanitizeRedirect(input), '/');
  }
});

test('sanitizeRedirect honors throwOnUnsafe', () => {
  throwsCode(
    () => cjs.sanitizeRedirect('//evil.com', { throwOnUnsafe: true }),
    C.PROTOCOL_RELATIVE
  );
});

test('assertSafeRedirect returns valid input unchanged when already canonical', () => {
  assert.equal(cjs.assertSafeRedirect('/x?y#z'), '/x?y#z');
});

test('assertSafeRedirect throws a structured error for unsafe input', () => {
  const error = throwsCode(() => cjs.assertSafeRedirect('//evil.com'), C.PROTOCOL_RELATIVE);
  assert.equal(error.input, '//evil.com');
  assert.match(error.message, /^ERR_REDIRECTCAGE_PROTOCOL_RELATIVE: /);
});

test('isSafeRedirect is a strict boolean predicate', () => {
  assert.equal(cjs.isSafeRedirect('/x'), true);
  assert.equal(cjs.isSafeRedirect('//evil.com'), false);
  assert.equal(cjs.isSafeRedirect(null), false);
});

test('parseRedirectLocation returns detailed relative metadata', () => {
  const result = cjs.parseRedirectLocation('/x?y#z');
  assert.deepEqual(result, {
    input: '/x?y#z',
    safe: true,
    value: '/x?y#z',
    kind: 'relative',
    code: null,
    reason: null,
    origin: null,
    protocol: null,
    host: null,
    hostname: null,
    port: null,
    pathname: '/x',
    search: '?y',
    hash: '#z'
  });
});

test('parseRedirectLocation returns detailed absolute metadata', () => {
  const result = cjs.parseRedirectLocation('https://trusted.com:8443/x?y#z', {
    allowedHosts: ['trusted.com:8443']
  });
  assert.deepEqual(result, {
    input: 'https://trusted.com:8443/x?y#z',
    safe: true,
    value: 'https://trusted.com:8443/x?y#z',
    kind: 'absolute',
    code: null,
    reason: null,
    origin: 'https://trusted.com:8443',
    protocol: 'https',
    host: 'trusted.com:8443',
    hostname: 'trusted.com',
    port: '8443',
    pathname: '/x',
    search: '?y',
    hash: '#z'
  });
});

test('parseRedirectLocation returns detailed failure metadata without throwing', () => {
  const result = cjs.parseRedirectLocation('//evil.com');
  assert.equal(result.safe, false);
  assert.equal(result.value, null);
  assert.equal(result.kind, null);
  assert.equal(result.code, C.PROTOCOL_RELATIVE);
  assert.equal(result.pathname, null);
  assert.equal(result.search, null);
  assert.equal(result.hash, null);
});

test('RedirectCageError exposes structured fields and JSON serialization', () => {
  const error = throwsCode(() => cjs.assertSafeRedirect('javascript:alert(1)'), C.DANGEROUS_SCHEME);
  assert.ok(error instanceof Error);
  assert.ok(error instanceof cjs.RedirectCageError);
  assert.equal(error.name, 'RedirectCageError');
  assert.equal(error.code, C.DANGEROUS_SCHEME);
  assert.equal(error.input, 'javascript:alert(1)');
  assert.deepEqual(error.toJSON(), {
    name: 'RedirectCageError',
    code: C.DANGEROUS_SCHEME,
    reason: error.reason,
    input: 'javascript:alert(1)'
  });
});

test('per-call options are not mutated', () => {
  const options = Object.freeze({ fallback: '/safe', maxLength: 32 });
  assert.equal(cjs.sanitizeRedirect('//evil.com', options), '/safe');
  assert.deepEqual(options, { fallback: '/safe', maxLength: 32 });
});

test('unsafe custom fallback fails at configuration time', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ fallback: '//evil.com' }));
});

test('fallback absolute URL must satisfy the configured allowlist', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({
    fallback: 'https://evil.com/',
    allowedHosts: ['trusted.com']
  }));
});

test('safe absolute fallback is accepted when allowlisted', () => {
  const guard = cjs.createRedirectGuard({
    fallback: 'https://trusted.com/fallback',
    allowedHosts: ['trusted.com']
  });
  assert.equal(guard.sanitize('//evil.com'), 'https://trusted.com/fallback');
});

test('fallback longer than maxLength is invalid configuration', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ fallback: '/abcdef', maxLength: 4 }));
});

test('createRedirectGuard returns a frozen reusable guard', () => {
  const guard = cjs.createRedirectGuard();
  assert.equal(Object.isFrozen(guard), true);
  assert.equal(typeof guard.sanitize, 'function');
  assert.equal(typeof guard.assert, 'function');
  assert.equal(typeof guard.isSafe, 'function');
  assert.equal(typeof guard.parseLocation, 'function');
  assert.equal(typeof guard.middleware, 'function');
});

test('guard methods preserve base configuration', () => {
  const guard = cjs.createRedirectGuard({ fallback: '/safe', allowQuery: false });
  assert.equal(guard.sanitize('//evil.com'), '/safe');
  assert.equal(guard.isSafe('/x'), true);
  assert.equal(guard.isSafe('/x?y=1'), false);
});

test('guard overrides apply to one call without replacing the base configuration', () => {
  const guard = cjs.createRedirectGuard({ allowQuery: false, fallback: '/safe' });
  assert.equal(guard.isSafe('/x?y=1', { allowQuery: true }), true);
  assert.equal(guard.isSafe('/x?y=1'), false);
  assert.equal(guard.sanitize('//evil.com', { fallback: '/other' }), '/other');
  assert.equal(guard.sanitize('//evil.com'), '/safe');
});

test('guard invalid overrides throw invalid options errors', () => {
  const guard = cjs.createRedirectGuard();
  throwsInvalidOptions(() => guard.isSafe('/x', { unknown: true }));
});

test('guard assert throws while guard sanitize falls back', () => {
  const guard = cjs.createRedirectGuard();
  assert.equal(guard.sanitize('javascript:alert(1)'), '/');
  throwsCode(() => guard.assert('javascript:alert(1)'), C.DANGEROUS_SCHEME);
});

test('guard parseLocation matches top-level parse behavior', () => {
  const guard = cjs.createRedirectGuard();
  assert.deepEqual(guard.parseLocation('/x'), cjs.parseRedirectLocation('/x'));
  assert.deepEqual(guard.parseLocation('//evil.com'), cjs.parseRedirectLocation('//evil.com'));
});

test('guard throwOnUnsafe configuration affects sanitize only', () => {
  const guard = cjs.createRedirectGuard({ throwOnUnsafe: true });
  throwsCode(() => guard.sanitize('//evil.com'), C.PROTOCOL_RELATIVE);
  assert.equal(guard.isSafe('//evil.com'), false);
});

test('blockedPaths rejects an exact path', () => {
  const result = cjs.parseRedirectLocation('/logout', { blockedPaths: ['/logout'] });
  assert.equal(result.code, C.BLOCKED_PATH);
});

test('blockedPaths rejects descendants on a path boundary', () => {
  const result = cjs.parseRedirectLocation('/logout/confirm', { blockedPaths: ['/logout'] });
  assert.equal(result.code, C.BLOCKED_PATH);
});

test('blockedPaths does not reject a merely similar prefix', () => {
  assert.equal(cjs.assertSafeRedirect('/logoutify', { blockedPaths: ['/logout'] }), '/logoutify');
});

test('blockedPaths ignores query and fragment structure after canonicalization', () => {
  const result = cjs.parseRedirectLocation('/logout?next=/home', { blockedPaths: ['/logout'] });
  assert.equal(result.code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/logout#next=/home', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/a/../logout', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
});

test('blockedPaths inspects percent-decoded path layers', () => {
  const result = cjs.parseRedirectLocation('/l%6fgout', { blockedPaths: ['/logout'] });
  assert.equal(result.code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/l%6Fgout', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/l%256fgout', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/logout%3fnext=x', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
  assert.equal(cjs.parseRedirectLocation('/logout%23x', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
});

test('blockedPaths matches canonical percent encoding case', () => {
  const result = cjs.parseRedirectLocation('/files%2fprivate', { blockedPaths: ['/files%2Fprivate'] });
  assert.equal(result.code, C.BLOCKED_PATH);
});

test('blockedPaths entries are canonicalized at configuration time', () => {
  const result = cjs.parseRedirectLocation('/logout', { blockedPaths: ['/a/../logout'] });
  assert.equal(result.code, C.BLOCKED_PATH);
});

test('a blocked fallback is invalid configuration', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ fallback: '/logout', blockedPaths: ['/logout'] }));
});

test('blockedPaths entries must be canonical root-relative paths', () => {
  for (const entry of ['logout', '//logout', '/logout?x=1', '/logout#x', '/bad path', '/bad\\path']) {
    throwsInvalidOptions(() => cjs.createRedirectGuard({ blockedPaths: [entry] }), JSON.stringify(entry));
  }
});

test('middleware installs safeRedirect and calls next', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  let calls = 0;
  guard.middleware()(null, response, () => { calls += 1; });
  assert.equal(calls, 1);
  assert.equal(typeof response.safeRedirect, 'function');
});

test('safeRedirect writes a safe Location header and ends the response', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  guard.middleware()(null, response, () => {});
  const location = response.safeRedirect('/dashboard');
  assert.equal(location, '/dashboard');
  assert.equal(response.headers.location, '/dashboard');
  assert.equal(response.statusCode, 302);
  assert.equal(response.ended, true);
  assert.equal(response.endCount, 1);
});

test('safeRedirect writes the fallback for an unsafe target', () => {
  const guard = cjs.createRedirectGuard({ fallback: '/safe' });
  const response = fakeResponse();
  guard.middleware()(null, response, () => {});
  const location = response.safeRedirect('//evil.com');
  assert.equal(location, '/safe');
  assert.equal(response.headers.location, '/safe');
});

test('safeRedirect accepts an explicit 3xx status', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  guard.middleware()(null, response, () => {});
  response.safeRedirect('/dashboard', 307);
  assert.equal(response.statusCode, 307);
});

test('safeRedirect rejects a non-3xx status before writing', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  guard.middleware()(null, response, () => {});
  throwsCode(() => response.safeRedirect('/dashboard', 200), C.INVALID_INPUT);
  assert.equal(response.headers.location, undefined);
});

test('middleware override configuration applies to safeRedirect', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  guard.middleware({ fallback: '/overridden' })(null, response, () => {});
  response.safeRedirect('javascript:alert(1)');
  assert.equal(response.headers.location, '/overridden');
});

test('middleware supports allowlisted absolute redirects', () => {
  const guard = cjs.createRedirectGuard({ allowedHosts: ['trusted.com'] });
  const response = fakeResponse();
  guard.middleware()(null, response, () => {});
  response.safeRedirect('https://trusted.com/dashboard', 308);
  assert.equal(response.headers.location, 'https://trusted.com/dashboard');
  assert.equal(response.statusCode, 308);
});

test('middleware refuses to overwrite an existing safeRedirect property', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  response.safeRedirect = function existing() {};
  throwsCode(() => guard.middleware()(null, response, () => {}), C.INVALID_INPUT);
});

test('middleware rejects a missing response object', () => {
  const guard = cjs.createRedirectGuard();
  throwsCode(() => guard.middleware()(null, null, () => {}), C.INVALID_INPUT);
});

test('middleware works when next is omitted', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  assert.doesNotThrow(() => guard.middleware()(null, response));
  assert.equal(typeof response.safeRedirect, 'function');
});

test('relative fallback is returned in canonical form', () => {
  const guard = cjs.createRedirectGuard({ fallback: '/a/../home' });
  assert.equal(guard.sanitize('//evil.com'), '/home');
});

test('absolute fallback is returned in canonical form', () => {
  const guard = cjs.createRedirectGuard({
    fallback: 'https://%74rusted.com/safe',
    allowedHosts: ['trusted.com']
  });
  assert.equal(guard.sanitize('//evil.com'), 'https://trusted.com/safe');
});

test('blockedPaths matching is case sensitive because URL paths are case sensitive', () => {
  assert.equal(cjs.assertSafeRedirect('/LOGOUT', { blockedPaths: ['/logout'] }), '/LOGOUT');
  assert.equal(cjs.parseRedirectLocation('/logout', { blockedPaths: ['/logout'] }).code, C.BLOCKED_PATH);
});

test('blockedPaths trailing slash entries require the trailing slash', () => {
  assert.equal(cjs.assertSafeRedirect('/logout', { blockedPaths: ['/logout/'] }), '/logout');
  assert.equal(cjs.parseRedirectLocation('/logout/', { blockedPaths: ['/logout/'] }).code, C.BLOCKED_PATH);
});

test('safeRedirect rejects noninteger and non-3xx status values before writing', () => {
  const guard = cjs.createRedirectGuard();
  for (const status of [299, 400, 302.5, Number.NaN, '302', null]) {
    const response = fakeResponse();
    guard.middleware()(null, response, () => {});
    throwsCode(() => response.safeRedirect('/dashboard', status), C.INVALID_INPUT, String(status));
    assert.equal(response.headers.location, undefined, String(status));
  }
});

test('safeRedirect does not write Location when statusCode assignment fails', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  Object.defineProperty(response, 'statusCode', {
    value: 200,
    writable: false,
    configurable: true
  });
  guard.middleware()(null, response, () => {});
  throwsCode(() => response.safeRedirect('/dashboard', 302), C.INVALID_INPUT);
  assert.equal(response.headers.location, undefined);
  assert.equal(response.ended, false);
});

test('parse metadata percent triplets match canonical output casing', () => {
  const result = cjs.parseRedirectLocation('/%e2%82%AC?x=%2f#%e2%82%AC');
  assert.equal(result.safe, true);
  assert.equal(result.pathname, '/%E2%82%AC');
  assert.equal(result.search, '?x=%2F');
  assert.equal(result.hash, '#%E2%82%AC');
  assert.equal(result.value, '/%E2%82%AC?x=%2F#%E2%82%AC');
});

test('middleware coexists with response writeHead and redirect methods', () => {
  const guard = cjs.createRedirectGuard();
  const response = fakeResponse();
  response.writeHead = function writeHead() { return this; };
  response.redirect = function redirect() { return this; };
  const originalWriteHead = response.writeHead;
  const originalRedirect = response.redirect;
  guard.middleware()(null, response, () => {});
  response.safeRedirect('/dashboard', 302);
  assert.equal(response.writeHead, originalWriteHead);
  assert.equal(response.redirect, originalRedirect);
  assert.equal(response.headers.location, '/dashboard');
});
