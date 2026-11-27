import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs } from './helpers.mjs';

const C = cjs.CODE;

function makeRng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function assertOutputInvariant(input, result, options) {
  if (!result.safe) return;
  assert.match(result.value, /^[\x20-\x7e]*$/, JSON.stringify(input));
  assert.equal(result.value.includes('\\'), false, JSON.stringify(input));
  if (result.kind === 'relative') {
    assert.equal(result.value.startsWith('/'), true, JSON.stringify(input));
    assert.equal(result.value.startsWith('//'), false, JSON.stringify(input));
    return;
  }
  const url = new URL(result.value);
  const allowSubdomains = Boolean(options && options.allowSubdomains);
  const hostAllowed = url.hostname === 'trusted.com' ||
    (allowSubdomains && url.hostname.endsWith('.trusted.com'));
  assert.equal(hostAllowed, true, JSON.stringify(input) + ' -> ' + result.value);
  if (!options || !options.allowUserinfo) {
    assert.equal(url.username, '');
    assert.equal(url.password, '');
  }
}

const alphabet = '/\\%.?#@:abcdefghijklmnopqrstuvwxyz0123456789';

function randomAlphabetInput(rng, maximumLength) {
  const length = Math.floor(rng() * (maximumLength + 1));
  let input = '';
  for (let index = 0; index < length; index += 1) {
    input += alphabet[Math.floor(rng() * alphabet.length)];
  }
  return input;
}

test('fuzz: mutated hostile strings never throw and preserve output invariants', () => {
  const rng = makeRng(0xc0ffee);
  const options = { allowedHosts: ['trusted.com'] };
  for (let index = 0; index < 1500; index += 1) {
    const input = randomAlphabetInput(rng, 40);
    const result = cjs.parseRedirectLocation(input, options);
    assert.equal(typeof result.safe, 'boolean');
    assertOutputInvariant(input, result, options);
  }
});

test('fuzz: hostile control mutations never throw', () => {
  const rng = makeRng(9999);
  const controls = ['\u0000', '\t', '\n', '\r', '\u007f', '\u0085', '\u200e', ' '];
  for (let index = 0; index < 500; index += 1) {
    const base = randomAlphabetInput(rng, 24);
    const position = Math.floor(rng() * (base.length + 1));
    const input = base.slice(0, position) + controls[Math.floor(rng() * controls.length)] + base.slice(position);
    const result = cjs.parseRedirectLocation(input);
    assert.equal(result.safe, false, JSON.stringify(input));
    assert.ok([C.CONTROL_CHARACTER, C.MALFORMED_ENCODING, C.INVALID_UTF8].includes(result.code), JSON.stringify(input));
  }
});

test('fuzz: parse results are deterministic across repeated evaluation', () => {
  const rng = makeRng(42);
  const options = { allowedHosts: ['trusted.com'], allowSubdomains: true };
  for (let index = 0; index < 300; index += 1) {
    const input = randomAlphabetInput(rng, 32);
    assert.deepEqual(
      cjs.parseRedirectLocation(input, options),
      cjs.parseRedirectLocation(input, options),
      JSON.stringify(input)
    );
  }
});

test('fuzz: sanitize, assert and isSafe agree', () => {
  const rng = makeRng(1337);
  const options = { fallback: '/fallback', allowedHosts: ['trusted.com'] };
  for (let index = 0; index < 300; index += 1) {
    const input = randomAlphabetInput(rng, 28);
    const result = cjs.parseRedirectLocation(input, options);
    assert.equal(cjs.isSafeRedirect(input, options), result.safe, JSON.stringify(input));
    if (result.safe) {
      assert.equal(cjs.assertSafeRedirect(input, options), result.value, JSON.stringify(input));
      assert.equal(cjs.sanitizeRedirect(input, options), result.value, JSON.stringify(input));
    } else {
      assert.equal(cjs.sanitizeRedirect(input, options), '/fallback', JSON.stringify(input));
      assert.throws(() => cjs.assertSafeRedirect(input, options), (error) => error.code === result.code);
    }
  }
});

test('fuzz: dot and encoded slash combinations never canonicalize to protocol-relative output', () => {
  const tokens = ['/', '.', '..', '%2f', '%252f', 'a'];
  let tested = 0;
  function visit(prefix, depth) {
    if (depth === 0) {
      tested += 1;
      const result = cjs.parseRedirectLocation(prefix);
      if (result.safe) {
        assert.equal(result.value.startsWith('/'), true, JSON.stringify(prefix));
        assert.equal(result.value.startsWith('//'), false, JSON.stringify(prefix) + ' -> ' + result.value);
      }
      return;
    }
    for (const token of tokens) visit(prefix + token, depth - 1);
  }
  for (let depth = 1; depth <= 4; depth += 1) visit('/', depth);
  assert.equal(tested > 1000, true);
});

test('fuzz: absolute output never escapes the configured host boundary', () => {
  const rng = makeRng(2026);
  const options = { allowedHosts: ['trusted.com'], allowSubdomains: true };
  const hosts = [
    'trusted.com', 'sub.trusted.com', 'eviltrusted.com', 'trusted.com.evil',
    'trusted.com.', 'xtrusted.com', 'a.b.trusted.com', 'evil.com'
  ];
  const mutations = ['', '%65', '%2e', '%252e', '%00', '%5c', '@evil.com', ':443', ':444'];
  for (let index = 0; index < 500; index += 1) {
    const host = hosts[Math.floor(rng() * hosts.length)];
    const mutation = mutations[Math.floor(rng() * mutations.length)];
    const input = 'https://' + host + mutation + '/x';
    const result = cjs.parseRedirectLocation(input, options);
    assertOutputInvariant(input, result, options);
  }
});

test('fuzz: deeply nested encoded protocol-relative input is always unsafe', () => {
  function encodeAllAscii(value) {
    let output = '';
    for (const char of value) output += '%' + char.charCodeAt(0).toString(16).padStart(2, '0');
    return output;
  }
  let input = '//evil.com';
  for (let layer = 0; layer < 12; layer += 1) {
    input = encodeAllAscii(input);
    assert.equal(cjs.isSafeRedirect(input), false, 'layer ' + layer);
  }
});

test('fuzz: malformed percent mutations never throw', () => {
  const rng = makeRng(5150);
  const insertions = ['%', '%2', '%zz', '%u202e'];
  for (let index = 0; index < 300; index += 1) {
    const base = randomAlphabetInput(rng, 24);
    const position = Math.floor(rng() * (base.length + 1));
    const input = base.slice(0, position) + insertions[Math.floor(rng() * insertions.length)] + base.slice(position);
    const result = cjs.parseRedirectLocation(input);
    assert.equal(typeof result.safe, 'boolean');
    if (!result.safe) assert.match(result.code, /^ERR_REDIRECTCAGE_/);
  }
});
