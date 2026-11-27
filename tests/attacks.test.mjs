import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, parseUnsafe } from './helpers.mjs';

const C = cjs.CODE;

const protocolRelative = [
  '//evil.com',
  '///evil.com',
  '////evil.com',
  '//trusted.com',
  '//evil.com/path?x=1#y',
  '/%2fevil.com',
  '/%2Fevil.com',
  '/%2f%2fevil.com',
  '%2f%2fevil.com',
  '%252f%252fevil.com',
  '/%252fevil.com',
  '/%25252fevil.com',
  '//%65vil.com',
  '/%2f%65vil.com',
  '/.//evil.com',
  '/..//evil.com',
  '/a/../../..//evil.com',
  '/%2f/evil.com',
  '/%2e//evil.com',
  '/./%2f/evil.com',
  '/.%2f/evil.com',
  '/a/../%2f/evil.com'
];

for (const input of protocolRelative) {
  test('protocol-relative vector is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['trusted.com', 'evil.com'] });
    assert.equal(result.code, C.PROTOCOL_RELATIVE);
  });
}

const backslashes = [
  '/\\evil.com',
  '\\/evil.com',
  '\\\\evil.com',
  '\\\\\\evil.com',
  '/\\\\evil.com',
  '\\//evil.com',
  'https:\\evil.com',
  'https:\\\\evil.com',
  'https://trusted.com\\@evil.com',
  '/%5cevil.com',
  '/%5Cevil.com',
  '%5cevil.com',
  '/%2f%5cevil.com',
  '/%5c%2fevil.com',
  '%2f%5cevil.com',
  '/%255cevil.com',
  '/%5c%5cevil.com'
];

for (const input of backslashes) {
  test('backslash confusion vector is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['trusted.com', 'evil.com'] });
    assert.equal(result.code, C.BACKSLASH);
  });
}

const hardSchemes = [
  'javascript:alert(1)',
  'JavaScript:alert(1)',
  'JAVASCRIPT:alert(document.domain)',
  'data:text/html,<script>alert(1)</script>',
  'data:text/html;base64,PHNjcmlwdD4=',
  'vbscript:msgbox(1)',
  'file:///etc/passwd',
  'file://localhost/etc/passwd',
  'blob:https://evil.com/550e8400-e29b-41d4-a716-446655440000',
  'about:blank',
  'filesystem:https://evil.com/temporary/x',
  'chrome://settings',
  'chrome-extension://abcdef/content.html',
  'moz-extension://abcdef/content.html',
  'ms-browser-extension://abcdef/content.html',
  'intent://evil.com/#Intent;scheme=https;end'
];

for (const input of hardSchemes) {
  test('dangerous scheme is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['evil.com', 'localhost'] });
    assert.equal(result.code, C.DANGEROUS_SCHEME);
  });
}

const nonHttpSchemes = [
  'ftp://evil.com/file',
  'ftp:evil.com',
  'mailto:user@example.com',
  'tel:+12025550123',
  'view-source:https://evil.com/',
  'ws://evil.com/socket',
  'wss://evil.com/socket'
];

for (const input of nonHttpSchemes) {
  test('non-HTTP scheme is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['evil.com'] });
    assert.equal(result.code, C.PROTOCOL_NOT_ALLOWED);
  });
}

const encodedSchemes = [
  '%6aavascript:alert(1)',
  'j%61vascript:alert(1)',
  'javascript%3aalert(1)',
  'javascript%3Aalert(1)',
  '%68ttps://evil.com',
  'h%74tps://evil.com',
  'https%3a//evil.com',
  'https%3A//evil.com',
  '%256a%2561%2576%2561script%253aalert(1)',
  '%2568%2574%2574%2570%2573%253a%252f%252fevil.com'
];

for (const input of encodedSchemes) {
  test('encoded scheme vector is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['evil.com'] });
    assert.equal(result.code, C.ENCODED_ATTACK);
  });
}

const invalidAbsoluteSyntax = [
  'https:evil.com',
  'HTTPS:evil.com',
  'https:/evil.com',
  'https://evil.com'.replace('://', ':'),
  'https:////evil.com',
  'https:///evil.com',
  'https://',
  'https://?x=1',
  'https://#x',
  'http:evil.com',
  'http:/evil.com',
  'http:///evil.com'
];

for (const input of invalidAbsoluteSyntax) {
  test('noncanonical absolute syntax is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['evil.com'] });
    assert.equal(result.code, C.INVALID_URL);
  });
}

test('scheme text without a colon is only a bare relative input and is rejected', () => {
  const result = parseUnsafe(cjs, 'https//evil.com');
  assert.equal(result.code, C.RELATIVE_PATH);
});

const userinfoVectors = [
  'https://trusted.com@evil.com/',
  'https://evil.com@trusted.com/',
  'https://user@trusted.com/',
  'https://user:pass@trusted.com/',
  'https://@trusted.com/',
  'https://user%40name@trusted.com/',
  'http://trusted.com@evil.com/',
  'https://trusted.com@evil.com/%2f%2fexample.com'
];

const userinfoOptions = { allowedHosts: ['trusted.com', 'evil.com'] };
for (const input of userinfoVectors) {
  test('userinfo spoofing vector is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, userinfoOptions);
    assert.equal(result.code, C.USERINFO);
  });
}

test('encoded at sign in host cannot become authority userinfo', () => {
  const result = parseUnsafe(cjs, 'https://trusted.com%40evil.com/', userinfoOptions);
  assert.equal(result.safe, false);
});

test('trusted text in query or fragment does not allow an evil host', () => {
  for (const input of ['https://evil.com#trusted.com', 'https://evil.com?https://trusted.com']) {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['trusted.com'] });
    assert.equal(result.code, C.HOST_NOT_ALLOWED, JSON.stringify(input));
  }
});

test('single slash at-sign paths remain valid relative paths', () => {
  assert.equal(cjs.assertSafeRedirect('/@evil.com'), '/@evil.com');
  assert.equal(cjs.assertSafeRedirect('/@user'), '/@user');
  assert.equal(cjs.assertSafeRedirect('/users/@user'), '/users/@user');
  assert.equal(cjs.assertSafeRedirect('/;/@evil.com'), '/;/@evil.com');
});

const crlfVectors = [
  '/%0d%0aSet-Cookie:x=1',
  '/%0D%0ASet-Cookie:x=1',
  '%0d%0a//evil.com',
  'https://trusted.com/\r\nSet-Cookie:x=1',
  'https://trusted.com/%0d%0aSet-Cookie:x=1',
  'https://trusted.com/%0aLocation:%20https://evil.com',
  '/x\r\nSet-Cookie:x=1',
  '/x\nSet-Cookie:x=1',
  '/x\rSet-Cookie:x=1',
  '/%00%0d%0a'
];

for (const input of crlfVectors) {
  test('CRLF or header splitting vector is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input, { allowedHosts: ['trusted.com'] });
    assert.equal(result.code, C.CONTROL_CHARACTER);
  });
}

test('embedded NUL is rejected in raw input', () => {
  const result = parseUnsafe(cjs, '/x\0https://evil.com');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('encoded NUL is rejected', () => {
  const result = parseUnsafe(cjs, '/x%00//evil.com');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('tab split javascript scheme is rejected as a control character', () => {
  const result = parseUnsafe(cjs, 'java\tscript:alert(1)');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('newline split javascript scheme is rejected as a control character', () => {
  const result = parseUnsafe(cjs, 'java\nscript:alert(1)');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('encoded tab inside javascript scheme is rejected as a control character', () => {
  const result = parseUnsafe(cjs, 'java%09script:alert(1)');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('zero width character inside javascript scheme is rejected', () => {
  const result = parseUnsafe(cjs, 'java\u200bscript:alert(1)');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('fullwidth letters that normalize into a scheme are rejected', () => {
  const result = parseUnsafe(cjs, 'ｊavascript:alert(1)');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('encoded fullwidth slashes that normalize into authority syntax are rejected', () => {
  const result = parseUnsafe(cjs, '/%ef%bc%8f%ef%bc%8fevil.com');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});


test('fullwidth dot compatibility input is rejected even in a path', () => {
  const result = parseUnsafe(cjs, '/a．b');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('fullwidth dot cannot create a dot segment before authority confusion', () => {
  const result = parseUnsafe(cjs, '/．//evil.com');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

const invalidUtf8Vectors = [
  '/%c0%af/evil.com',
  '/%e0%80%af/evil.com',
  '/%ed%a0%80/x',
  '/%ff%fe'
];

for (const input of invalidUtf8Vectors) {
  test('invalid UTF-8 byte sequence is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input);
    assert.equal(result.code, C.INVALID_UTF8);
  });
}

const inertSlashLookalikes = ['/%E2%81%84%EF%B8%8F?x', '/\u2215\u2215evil.com'];
for (const input of inertSlashLookalikes) {
  test('slash lookalike remains percent-encoded path text: ' + JSON.stringify(input), () => {
    const result = cjs.parseRedirectLocation(input);
    assert.equal(result.safe, true);
    assert.equal(result.kind, 'relative');
    assert.equal(result.value.startsWith('/'), true);
    assert.equal(result.value.startsWith('//'), false);
    assert.equal(result.value.includes('\\'), false);
    assert.match(result.value, /^[\x20-\x7e]*$/);
  });
}
