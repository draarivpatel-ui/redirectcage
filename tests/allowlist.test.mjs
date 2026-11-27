import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, parseUnsafe, throwsInvalidOptions } from './helpers.mjs';

const C = cjs.CODE;
const exactOrigin = { allowedOrigins: ['https://trusted.com'] };

const exactOriginCases = [
  ['https://trusted.com', 'https://trusted.com/'],
  ['https://trusted.com/', 'https://trusted.com/'],
  ['https://trusted.com/x?y#z', 'https://trusted.com/x?y#z'],
  ['https://trusted.com?', 'https://trusted.com/'],
  ['https://trusted.com#', 'https://trusted.com/'],
  ['HTTPS://TRUSTED.COM/x', 'https://trusted.com/x'],
  ['https://trusted.com:443/x', 'https://trusted.com/x'],
  ['https://%74rusted.com/x', 'https://trusted.com/x']
];

for (const [input, expected] of exactOriginCases) {
  test('exact allowlisted origin canonicalizes: ' + JSON.stringify(input), () => {
    assert.equal(cjs.assertSafeRedirect(input, exactOrigin), expected);
  });
}

test('absolute target is rejected when no allowlist is configured', () => {
  const result = parseUnsafe(cjs, 'https://trusted.com/');
  assert.equal(result.code, C.ABSOLUTE_URL);
});

test('relative target remains safe when an allowlist is configured', () => {
  assert.equal(cjs.assertSafeRedirect('/local', exactOrigin), '/local');
});

test('wrong scheme does not match an https origin', () => {
  const result = parseUnsafe(cjs, 'http://trusted.com/x', exactOrigin);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('wrong host does not match an exact origin', () => {
  const result = parseUnsafe(cjs, 'https://evil.com/x', exactOrigin);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('origin with a nondefault port requires that port', () => {
  const options = { allowedOrigins: ['https://trusted.com:8443'] };
  assert.equal(
    cjs.assertSafeRedirect('https://trusted.com:8443/x', options),
    'https://trusted.com:8443/x'
  );
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), false);
  assert.equal(cjs.isSafeRedirect('https://trusted.com:4443/x', options), false);
});

test('explicit default port in an allowlisted origin is canonicalized', () => {
  const options = { allowedOrigins: ['https://trusted.com:443'] };
  assert.equal(cjs.assertSafeRedirect('https://trusted.com/x', options), 'https://trusted.com/x');
});

test('subdomains are rejected by default', () => {
  const result = parseUnsafe(cjs, 'https://sub.trusted.com/x', exactOrigin);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('allowSubdomains accepts a direct subdomain', () => {
  const options = { allowedOrigins: ['https://trusted.com'], allowSubdomains: true };
  assert.equal(cjs.assertSafeRedirect('https://sub.trusted.com/x', options), 'https://sub.trusted.com/x');
});

test('allowSubdomains accepts a deep subdomain', () => {
  const options = { allowedOrigins: ['https://trusted.com'], allowSubdomains: true };
  assert.equal(cjs.isSafeRedirect('https://a.b.trusted.com/x', options), true);
});

test('allowSubdomains still accepts the bare allowlisted host', () => {
  const options = { allowedOrigins: ['https://trusted.com'], allowSubdomains: true };
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
});

const subdomainLookalikes = [
  'https://eviltrusted.com/x',
  'https://trusted.com.evil.com/x',
  'https://nottrusted.com/x',
  'https://trusted-com.evil.com/x',
  'https://evil.com/trusted.com',
  'https://trusted.com./x',
  'https://sub.trusted.com./x'
];

for (const input of subdomainLookalikes) {
  test('subdomain boundary lookalike is rejected: ' + JSON.stringify(input), () => {
    const options = { allowedOrigins: ['https://trusted.com'], allowSubdomains: true };
    const result = parseUnsafe(cjs, input, options);
    assert.equal(result.code, C.HOST_NOT_ALLOWED);
  });
}

test('allowedHosts accepts both default http and default https unless narrowed', () => {
  const options = { allowedHosts: ['trusted.com'] };
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
  assert.equal(cjs.isSafeRedirect('http://trusted.com/x', options), true);
});

test('allowedHosts without a port rejects a nondefault https port', () => {
  const result = parseUnsafe(cjs, 'https://trusted.com:444/x', { allowedHosts: ['trusted.com'] });
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('allowedHosts without a port rejects a nondefault http port', () => {
  const result = parseUnsafe(cjs, 'http://trusted.com:8080/x', { allowedHosts: ['trusted.com'] });
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('allowedHosts explicit port accepts that exact port', () => {
  const options = { allowedHosts: ['trusted.com:8443'] };
  assert.equal(cjs.assertSafeRedirect('https://trusted.com:8443/x', options), 'https://trusted.com:8443/x');
});

test('allowedHosts explicit port rejects a different port', () => {
  const options = { allowedHosts: ['trusted.com:8443'] };
  const result = parseUnsafe(cjs, 'https://trusted.com:8444/x', options);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('allowedHosts entries are scheme independent by design', () => {
  const options = { allowedHosts: ['trusted.com:443'] };
  assert.equal(cjs.isSafeRedirect('http://trusted.com:443/x', options), true);
});

test('allowedHosts host names are case insensitive', () => {
  const options = { allowedHosts: ['TrUsTeD.cOm'] };
  assert.equal(cjs.assertSafeRedirect('https://TRUSTED.COM/x', options), 'https://trusted.com/x');
});

test('allowSubdomains applies to allowedHosts with a strict boundary', () => {
  const options = { allowedHosts: ['trusted.com'], allowSubdomains: true };
  assert.equal(cjs.isSafeRedirect('https://api.trusted.com/x', options), true);
  assert.equal(cjs.isSafeRedirect('https://eviltrusted.com/x', options), false);
});

test('allowSubdomains does not cross a configured explicit port', () => {
  const options = { allowedHosts: ['trusted.com:8443'], allowSubdomains: true };
  assert.equal(cjs.isSafeRedirect('https://api.trusted.com:8443/x', options), true);
  assert.equal(cjs.isSafeRedirect('https://api.trusted.com/x', options), false);
});

test('Unicode origin allowlist canonicalizes IDN input to punycode', () => {
  const options = { allowedOrigins: ['https://täst.de'] };
  assert.equal(cjs.assertSafeRedirect('https://täst.de/x', options), 'https://xn--tst-qla.de/x');
});

test('punycode input matches a Unicode allowlist entry', () => {
  const options = { allowedOrigins: ['https://täst.de'] };
  assert.equal(cjs.assertSafeRedirect('https://xn--tst-qla.de/x', options), 'https://xn--tst-qla.de/x');
});

test('punycode allowlist matches Unicode input', () => {
  const options = { allowedHosts: ['xn--tst-qla.de'] };
  assert.equal(cjs.assertSafeRedirect('https://täst.de/x', options), 'https://xn--tst-qla.de/x');
});

test('trailing dot host does not match the bare allowlisted host', () => {
  const result = parseUnsafe(cjs, 'https://trusted.com./x', exactOrigin);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('encoded trailing dot host does not match the bare allowlisted host', () => {
  const result = parseUnsafe(cjs, 'https://trusted.com%2e/x', exactOrigin);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('encoded host letters canonicalize before allowlist matching', () => {
  assert.equal(cjs.assertSafeRedirect('https://%74rusted.com/x', exactOrigin), 'https://trusted.com/x');
});

const ipVectors = [
  'https://127.1/x',
  'https://127.0.0.1/x',
  'https://0x7f000001/x',
  'https://2130706433/x',
  'https://0177.0.0.1/x',
  'https://[::1]/x',
  'https://[0:0:0:0:0:0:0:1]/x'
];

for (const input of ipVectors) {
  test('IP literal is rejected unless explicitly enabled: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['trusted.com'] });
    assert.equal(result.code, C.IP_LITERAL);
  });
}

test('allowlisted IPv4 literal is accepted when allowIpLiterals is true', () => {
  const options = { allowedHosts: ['127.0.0.1'], allowIpLiterals: true };
  assert.equal(cjs.assertSafeRedirect('https://127.0.0.1/x', options), 'https://127.0.0.1/x');
});

test('obfuscated IPv4 forms canonicalize before allowlist matching', () => {
  const options = { allowedHosts: ['127.0.0.1'], allowIpLiterals: true };
  for (const input of ['https://127.1/x', 'https://0x7f000001/x', 'https://2130706433/x', 'https://0177.0.0.1/x']) {
    assert.equal(cjs.assertSafeRedirect(input, options), 'https://127.0.0.1/x', input);
  }
});

test('allowlisted IPv6 literal is accepted when allowIpLiterals is true', () => {
  const options = { allowedHosts: ['[::1]'], allowIpLiterals: true };
  assert.equal(cjs.assertSafeRedirect('https://[::1]/x', options), 'https://[::1]/x');
});

test('nonallowlisted IP literal still reports the IP defense first', () => {
  const result = parseUnsafe(cjs, 'https://192.168.0.1/x', { allowedHosts: ['trusted.com'] });
  assert.equal(result.code, C.IP_LITERAL);
});

test('allowProtocols can narrow absolute redirects to https', () => {
  const options = { allowedHosts: ['trusted.com'], allowProtocols: ['https'] };
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
  const result = parseUnsafe(cjs, 'http://trusted.com/x', options);
  assert.equal(result.code, C.PROTOCOL_NOT_ALLOWED);
});

test('allowProtocols accepts a string and a trailing colon form', () => {
  const options = { allowedHosts: ['trusted.com'], allowProtocols: 'https:' };
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
});

test('http can be selected explicitly', () => {
  const options = { allowedHosts: ['trusted.com'], allowProtocols: ['http'] };
  assert.equal(cjs.isSafeRedirect('http://trusted.com/x', options), true);
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), false);
});

test('ftp cannot be enabled through allowProtocols', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowProtocols: ['ftp'] }));
});

test('empty allowProtocols is invalid', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowProtocols: [] }));
});

test('userinfo can be enabled explicitly for an allowlisted host', () => {
  const options = { allowedHosts: ['trusted.com'], allowUserinfo: true };
  assert.equal(cjs.assertSafeRedirect('https://user@trusted.com/x', options), 'https://user@trusted.com/x');
});

test('userinfo password is preserved only when explicitly enabled', () => {
  const options = { allowedHosts: ['trusted.com'], allowUserinfo: true };
  assert.equal(cjs.assertSafeRedirect('https://user:pass@trusted.com/x', options), 'https://user:pass@trusted.com/x');
});

test('enabled userinfo does not weaken host matching', () => {
  const options = { allowedHosts: ['trusted.com'], allowUserinfo: true };
  const result = parseUnsafe(cjs, 'https://trusted.com@evil.com/x', options);
  assert.equal(result.code, C.HOST_NOT_ALLOWED);
});

test('absolute query and fragment controls apply to allowlisted targets', () => {
  const options = { allowedHosts: ['trusted.com'], allowQuery: false, allowHash: false };
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x?y=1', options), false);
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x#y', options), false);
});

test('blockedPaths applies to absolute allowlisted targets', () => {
  const options = { allowedHosts: ['trusted.com'], blockedPaths: ['/logout'] };
  const result = parseUnsafe(cjs, 'https://trusted.com/logout?next=/x', options);
  assert.equal(result.code, C.BLOCKED_PATH);
});

test('unknown option keys fail loudly', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedOrigin: ['https://trusted.com'] }));
});

test('null options are invalid', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard(null));
});

test('array options are invalid', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard([]));
});

test('string options are invalid', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard('https://trusted.com'));
});

const reservedKeys = ['__proto__', 'constructor', 'prototype'];
for (const key of reservedKeys) {
  test('reserved option key is rejected: ' + key, () => {
    const options = Object.create(null);
    options[key] = 'x';
    throwsInvalidOptions(() => cjs.createRedirectGuard(options));
  });
}

test('JSON parsed proto pollution key is rejected without polluting Object.prototype', () => {
  const options = JSON.parse('{"__proto__":{"fallback":"//evil.com"}}');
  throwsInvalidOptions(() => cjs.createRedirectGuard(options));
  assert.equal({}.fallback, undefined);
});

test('null prototype option objects are accepted', () => {
  const options = Object.create(null);
  options.allowedHosts = 'trusted.com';
  assert.equal(cjs.isSafeRedirect('https://trusted.com/x', options), true);
});

test('boolean options reject nonboolean values', () => {
  for (const key of ['allowSubdomains', 'allowUserinfo', 'allowIpLiterals', 'allowQuery', 'allowHash', 'normalizeDotSegments', 'throwOnUnsafe']) {
    const options = {};
    options[key] = 1;
    throwsInvalidOptions(() => cjs.createRedirectGuard(options), key);
  }
});

test('invalid maxLength values are rejected', () => {
  for (const value of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '2048']) {
    throwsInvalidOptions(() => cjs.createRedirectGuard({ maxLength: value }), String(value));
  }
});

test('invalid maxDecodeLayers values are rejected', () => {
  for (const value of [0, 17, 1.5, Number.NaN, '8']) {
    throwsInvalidOptions(() => cjs.createRedirectGuard({ maxDecodeLayers: value }), String(value));
  }
});

test('allowlist entries must be strings', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedHosts: ['trusted.com', 42] }));
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedOrigins: [null] }));
});

const invalidHostEntries = [
  '*.trusted.com',
  'trusted.com/path',
  'trusted.com?x',
  'trusted.com#x',
  'user@trusted.com',
  'trusted.com.',
  'trusted..com',
  '.trusted.com',
  'trusted.com:0',
  'trusted.com:65536',
  'trusted.com:abc',
  '::1',
  '[::1',
  'bad host.com',
  'bad\\host.com'
];

for (const entry of invalidHostEntries) {
  test('invalid allowedHosts entry fails at configuration time: ' + JSON.stringify(entry), () => {
    throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedHosts: [entry] }));
  });
}

const invalidOriginEntries = [
  'trusted.com',
  'https:trusted.com',
  'https:/trusted.com',
  'https:///trusted.com',
  'ftp://trusted.com',
  'https://user@trusted.com',
  'https://trusted.com/path',
  'https://trusted.com/./',
  'https://trusted.com/%2e',
  'https://trusted.com/?x=1',
  'https://trusted.com/#x',
  'https://trusted.com?',
  'https://trusted.com#',
  'https://trusted.com.',
  'https://127.0.0.1'
];

for (const entry of invalidOriginEntries) {
  test('invalid allowedOrigins entry fails at configuration time: ' + JSON.stringify(entry), () => {
    throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedOrigins: [entry] }));
  });
}

test('IP allowlist entry requires allowIpLiterals true', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({ allowedHosts: ['127.0.0.1'] }));
  assert.doesNotThrow(() => cjs.createRedirectGuard({ allowedHosts: ['127.0.0.1'], allowIpLiterals: true }));
});

test('origin protocol disabled by allowProtocols is invalid configuration', () => {
  throwsInvalidOptions(() => cjs.createRedirectGuard({
    allowedOrigins: ['http://trusted.com'],
    allowProtocols: ['https']
  }));
});

test('duplicate allowlist entries are accepted and deduplicated', () => {
  const guard = cjs.createRedirectGuard({
    allowedHosts: ['trusted.com', 'TRUSTED.com', 'trusted.com']
  });
  assert.equal(guard.isSafe('https://trusted.com/x'), true);
});

test('configuration arrays are copied at guard creation time', () => {
  const hosts = ['trusted.com'];
  const guard = cjs.createRedirectGuard({ allowedHosts: hosts });
  hosts[0] = 'evil.com';
  assert.equal(guard.isSafe('https://trusted.com/x'), true);
  assert.equal(guard.isSafe('https://evil.com/x'), false);
});

test('empty explicit port canonicalizes to the default port', () => {
  assert.equal(
    cjs.assertSafeRedirect('https://trusted.com:/path', exactOrigin),
    'https://trusted.com/path'
  );
});

test('IPv6 mapped IPv4 literal is rejected without explicit opt-in', () => {
  const result = parseUnsafe(cjs, 'https://[::ffff:127.0.0.1]/x', exactOrigin);
  assert.equal(result.code, C.IP_LITERAL);
});

test('IPv6 mapped IPv4 literal canonicalizes before allowlist matching', () => {
  const options = { allowedHosts: ['[::ffff:127.0.0.1]'], allowIpLiterals: true };
  assert.equal(
    cjs.assertSafeRedirect('https://[::ffff:127.0.0.1]/x', options),
    'https://[::ffff:7f00:1]/x'
  );
});

test('ideographic full stop canonicalizes as a host separator', () => {
  assert.equal(
    cjs.assertSafeRedirect('https://trusted。com/x', exactOrigin),
    'https://trusted.com/x'
  );
});
