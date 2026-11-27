import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, throwsCode, parseUnsafe } from './helpers.mjs';

const C = cjs.CODE;

const safeCases = [
  ['/', '/'],
  ['/?', '/'],
  ['/#', '/'],
  ['/?#', '/'],
  ['/dashboard', '/dashboard'],
  ['/dashboard?tab=1#top', '/dashboard?tab=1#top'],
  ['/a%20b', '/a%20b'],
  ['/café', '/caf%C3%A9'],
  ['/@user', '/@user'],
  ['/a@b', '/a@b'],
  ['/a;b=1', '/a;b=1'],
  ['/a:b', '/a:b'],
  ['/a+b', '/a+b'],
  ['/~user', '/~user'],
  ['/x?q=a%20b', '/x?q=a%20b'],
  ['/x#frag', '/x#frag'],
  ['/ａｂｃ', '/%EF%BD%81%EF%BD%82%EF%BD%83']
];

for (const [input, expected] of safeCases) {
  test('safe relative target canonicalizes: ' + JSON.stringify(input), () => {
    assert.equal(cjs.assertSafeRedirect(input), expected);
    assert.equal(cjs.sanitizeRedirect(input), expected);
    assert.equal(cjs.isSafeRedirect(input), true);
  });
}

const invalidInputs = [
  ['undefined', undefined],
  ['null', null],
  ['false', false],
  ['zero', 0],
  ['number', 42],
  ['plain object', {}],
  ['array', ['/x']],
  ['String object', new String('/x')],
  ['URL object', new URL('https://example.com/')],
  ['symbol', Symbol('/x')]
];

for (const [label, input] of invalidInputs) {
  test('non-string input is rejected without throwing in sanitize: ' + label, () => {
    assert.equal(cjs.sanitizeRedirect(input), '/');
    assert.equal(cjs.isSafeRedirect(input), false);
    throwsCode(() => cjs.assertSafeRedirect(input), C.INVALID_INPUT);
  });
}

test('empty string is rejected', () => {
  assert.equal(cjs.sanitizeRedirect(''), '/');
  throwsCode(() => cjs.assertSafeRedirect(''), C.INVALID_INPUT);
});

test('bare relative paths are rejected in canonical mode', () => {
  for (const input of ['dashboard', 'dashboard?x=1', './x', '../x', '?x=1', '#top', 'a/b']) {
    const result = parseUnsafe(cjs, input);
    assert.equal(result.code, C.RELATIVE_PATH, JSON.stringify(input));
  }
});

const rawForbidden = [
  ' /x', '/x ', '\t/x', '/x\t', '\n/x', '/x\r\ny', '/x y',
  '/x\u00a0y', '/x\u200by', '/x\u2028y', '/x\u2029y', '/x\0y',
  '/x\x7fy', '/x\x85y', '\t//evil.com'
];

for (const input of rawForbidden) {
  test('raw whitespace or control is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input);
    assert.equal(result.code, C.CONTROL_CHARACTER);
  });
}

const encodedForbidden = [
  '/%00x', '/%0ax', '/%0dx', '/%09x', '/%1fx', '/%7fx',
  '/%c2%80x', '/%c2%85x', '/%e2%80%8ex', '/%e2%80%aex',
  '%09//evil.com', 'java%09script:alert(1)', '/%e3%80%80x'
];

for (const input of encodedForbidden) {
  test('encoded control is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input);
    assert.equal(result.code, C.CONTROL_CHARACTER);
  });
}

test('encoded regular spaces remain encoded and are accepted', () => {
  assert.equal(cjs.assertSafeRedirect('/a%20b'), '/a%20b');
  assert.equal(cjs.assertSafeRedirect('/a%2520b'), '/a%2520b');
});

const malformed = [
  '%', '/%', '/%2', '/%zz', '/%1x', '/100%', '/%%41', '/%u202e', '/a%2G'
];

for (const input of malformed) {
  test('malformed percent encoding is rejected: ' + JSON.stringify(input), () => {
    const result = parseUnsafe(cjs, input);
    assert.equal(result.code, C.MALFORMED_ENCODING);
  });
}

test('input exactly at default maxLength is accepted', () => {
  const input = '/' + 'a'.repeat(2047);
  assert.equal(cjs.assertSafeRedirect(input), input);
});

test('input one unit over default maxLength is rejected', () => {
  const input = '/' + 'a'.repeat(2048);
  const result = parseUnsafe(cjs, input);
  assert.equal(result.code, C.LIMIT_EXCEEDED);
});

test('custom maxLength accepts the exact boundary', () => {
  const input = '/' + 'a'.repeat(9);
  assert.equal(cjs.assertSafeRedirect(input, { maxLength: 10 }), input);
});

test('custom maxLength rejects one unit over the boundary', () => {
  const input = '/' + 'a'.repeat(10);
  const result = parseUnsafe(cjs, input, { maxLength: 10 });
  assert.equal(result.code, C.LIMIT_EXCEEDED);
});

test('maxLength counts UTF-16 units rather than bytes', () => {
  assert.equal(cjs.isSafeRedirect('/é', { maxLength: 2 }), true);
  assert.equal(cjs.isSafeRedirect('/éx', { maxLength: 2 }), false);
});

test('maxLength is measured before decoding so long encoded input is bounded', () => {
  const input = '/' + '%41'.repeat(700);
  assert.equal(input.length > 2048, true);
  assert.equal(cjs.isSafeRedirect(input), false);
});

test('decode depth bound rejects nested encoding that remains encoded', () => {
  const input = '/%25252f';
  const result = parseUnsafe(cjs, input, { maxDecodeLayers: 2 });
  assert.equal(result.code, C.ENCODED_ATTACK);
});

const dotCases = [
  ['/a/./b', '/a/b'],
  ['/a/../b', '/b'],
  ['/../x', '/x'],
  ['/.', '/'],
  ['/a/..', '/'],
  ['/%2e%2e/b', '/b'],
  ['/%2e/b', '/b'],
  ['/a/%2e%2e/b', '/b']
];

for (const [input, expected] of dotCases) {
  test('dot segments normalize: ' + JSON.stringify(input), () => {
    assert.equal(cjs.assertSafeRedirect(input), expected);
  });
}

test('normalizeDotSegments false rejects a plain dot segment', () => {
  const result = parseUnsafe(cjs, '/a/./b', { normalizeDotSegments: false });
  assert.equal(result.code, C.DOT_SEGMENT);
});

test('normalizeDotSegments false rejects a parent segment', () => {
  const result = parseUnsafe(cjs, '/a/../b', { normalizeDotSegments: false });
  assert.equal(result.code, C.DOT_SEGMENT);
});

test('normalizeDotSegments false rejects encoded dot segments', () => {
  const result = parseUnsafe(cjs, '/%2e%2e/b', { normalizeDotSegments: false });
  assert.equal(result.code, C.DOT_SEGMENT);
});

test('normalizeDotSegments false rejects double encoded dot segments', () => {
  const result = parseUnsafe(cjs, '/%252e%252e/b', { normalizeDotSegments: false });
  assert.equal(result.code, C.DOT_SEGMENT);
});

test('normalizeDotSegments false accepts a canonical path', () => {
  assert.equal(cjs.assertSafeRedirect('/a/b', { normalizeDotSegments: false }), '/a/b');
});

test('query and fragment are allowed by default', () => {
  assert.equal(cjs.assertSafeRedirect('/x?y=1#z'), '/x?y=1#z');
});

test('allowQuery false rejects a query string', () => {
  const result = parseUnsafe(cjs, '/x?y=1', { allowQuery: false });
  assert.equal(result.code, C.QUERY_NOT_ALLOWED);
});

test('allowQuery false rejects an empty query marker', () => {
  const result = parseUnsafe(cjs, '/x?', { allowQuery: false });
  assert.equal(result.code, C.QUERY_NOT_ALLOWED);
});

test('allowQuery false rejects an encoded question mark', () => {
  const result = parseUnsafe(cjs, '/x%3fy=1', { allowQuery: false });
  assert.equal(result.code, C.QUERY_NOT_ALLOWED);
});

test('allowQuery false still allows a fragment', () => {
  assert.equal(cjs.assertSafeRedirect('/x#y', { allowQuery: false }), '/x#y');
});

test('allowHash false rejects a fragment', () => {
  const result = parseUnsafe(cjs, '/x#y', { allowHash: false });
  assert.equal(result.code, C.HASH_NOT_ALLOWED);
});

test('allowHash false rejects an empty fragment marker', () => {
  const result = parseUnsafe(cjs, '/x#', { allowHash: false });
  assert.equal(result.code, C.HASH_NOT_ALLOWED);
});

test('allowHash false rejects an encoded fragment sign', () => {
  const result = parseUnsafe(cjs, '/x%23y', { allowHash: false });
  assert.equal(result.code, C.HASH_NOT_ALLOWED);
});

test('allowHash false still allows a query string', () => {
  assert.equal(cjs.assertSafeRedirect('/x?y=1', { allowHash: false }), '/x?y=1');
});

test('allowQuery and allowHash false accepts a plain path', () => {
  assert.equal(cjs.assertSafeRedirect('/x', { allowQuery: false, allowHash: false }), '/x');
});

test('fullwidth slash compatibility input is rejected', () => {
  const result = parseUnsafe(cjs, '/a／b');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('fullwidth backslash compatibility input is rejected', () => {
  const result = parseUnsafe(cjs, '/a＼b');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('fullwidth colon compatibility input is rejected', () => {
  const result = parseUnsafe(cjs, '/a：b');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('fullwidth percent compatibility input is rejected', () => {
  const result = parseUnsafe(cjs, '/a％41b');
  assert.equal(result.code, C.UNICODE_NORMALIZATION);
});

test('ordinary Unicode path text is accepted and percent encoded canonically', () => {
  const output = cjs.assertSafeRedirect('/café/日本');
  assert.equal(output, '/caf%C3%A9/%E6%97%A5%E6%9C%AC');
  assert.match(output, /^[\x20-\x7e]*$/);
});

test('encoded Unicode path text is preserved in uppercase percent triplets', () => {
  assert.equal(cjs.assertSafeRedirect('/%e2%82%AC'), '/%E2%82%AC');
});

test('unpaired surrogate input is rejected', () => {
  const result = parseUnsafe(cjs, '/x\ud800y');
  assert.equal(result.code, C.CONTROL_CHARACTER);
});

test('encoded invalid UTF-8 bytes are rejected', () => {
  const result = parseUnsafe(cjs, '/%ff%fe');
  assert.equal(result.code, C.INVALID_UTF8);
});

test('nested encoded invalid UTF-8 bytes are rejected', () => {
  const result = parseUnsafe(cjs, '/%25ff%25fe');
  assert.equal(result.code, C.INVALID_UTF8);
});
