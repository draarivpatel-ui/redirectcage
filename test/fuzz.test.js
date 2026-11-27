import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  assertSafeRedirect,
  isSafeRedirect,
  parseRedirectLocation,
  sanitizeRedirect
} from '../src/index.mjs';

const ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function stringFrom(chars, minLength, maxLength) {
  return fc.array(fc.constantFrom(...chars.split('')), { minLength, maxLength }).map((items) => items.join(''));
}

const segment = stringFrom(ALPHA_NUM, 1, 12);
const benignPath = fc.array(segment, { minLength: 1, maxLength: 4 }).map((parts) => '/' + parts.join('/'));
const hostLabel = stringFrom('abcdefghijklmnopqrstuvwxyz0123456789', 1, 12);

test('positive: canonical root-relative paths are accepted unchanged', () => {
  fc.assert(fc.property(benignPath, (input) => {
    const parsed = parseRedirectLocation(input);
    assert.equal(parsed.safe, true);
    assert.equal(parsed.kind, 'relative');
    assert.equal(parsed.value, input);
    assert.equal(isSafeRedirect(input), true);
    assert.equal(assertSafeRedirect(input), input);
    assert.equal(sanitizeRedirect(input), input);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: external and dangerous targets fall back instead of becoming redirects', () => {
  const scheme = fc.constantFrom('https', 'http', 'javascript', 'data', 'file');
  fc.assert(fc.property(scheme, hostLabel, segment, (schemeName, host, pathPart) => {
    const input = schemeName + '://evil' + host + '.example/' + pathPart;
    const parsed = parseRedirectLocation(input);
    assert.equal(parsed.safe, false);
    assert.equal(isSafeRedirect(input), false);
    assert.equal(sanitizeRedirect(input), '/');
    assert.throws(() => assertSafeRedirect(input), (error) => error && error.code === parsed.code);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: encoded protocol-relative and backslash forms are always rejected', () => {
  const prefix = fc.constantFrom('//', '%2f%2f', '%252f%252f', '/%2f/', '/%5c', '%5c%5c');
  fc.assert(fc.property(prefix, hostLabel, segment, (hostilePrefix, host, pathPart) => {
    const input = hostilePrefix + 'evil' + host + '.example/' + pathPart;
    const parsed = parseRedirectLocation(input);
    assert.equal(parsed.safe, false);
    assert.equal(isSafeRedirect(input), false);
    assert.equal(sanitizeRedirect(input), '/');
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: arbitrary hostile strings never throw and all APIs agree', () => {
  fc.assert(fc.property(fc.string({ maxLength: 140 }), (input) => {
    const parsed = parseRedirectLocation(input);
    assert.equal(typeof parsed.safe, 'boolean');
    assert.equal(isSafeRedirect(input), parsed.safe);
    if (parsed.safe) {
      assert.equal(assertSafeRedirect(input), parsed.value);
      assert.equal(sanitizeRedirect(input), parsed.value);
      assert.equal(parsed.value.startsWith('//'), false);
    } else {
      assert.equal(sanitizeRedirect(input), '/');
      assert.throws(() => assertSafeRedirect(input), (error) => error && error.code === parsed.code);
    }
  }), { seed: 20261127, numRuns: 120 });
});
