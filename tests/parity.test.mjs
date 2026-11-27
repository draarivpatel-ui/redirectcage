import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { APIs, cjs, esm } from './helpers.mjs';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('all public exports exist in both module formats', () => {
  const names = [
    'CODE', 'RedirectCageError', 'sanitizeRedirect', 'assertSafeRedirect',
    'isSafeRedirect', 'parseRedirectLocation', 'createRedirectGuard'
  ];
  for (const name of names) {
    assert.ok(esm[name], 'missing ESM export ' + name);
    assert.ok(cjs[name], 'missing CJS export ' + name);
    assert.equal(typeof esm[name], typeof cjs[name], name);
  }
});

test('ESM default export mirrors every named export', () => {
  for (const name of ['CODE', 'RedirectCageError', 'sanitizeRedirect', 'assertSafeRedirect', 'isSafeRedirect', 'parseRedirectLocation', 'createRedirectGuard']) {
    assert.equal(esm.default[name], esm[name], name);
  }
});

test('CJS default export is the module object', () => {
  assert.equal(cjs.default, cjs);
});

test('package self-reference works through require', () => {
  const loaded = require('redirectcage');
  assert.equal(typeof loaded.sanitizeRedirect, 'function');
  assert.equal(loaded.sanitizeRedirect('/x'), '/x');
});

test('package self-reference works through import', async () => {
  const loaded = await import('redirectcage');
  assert.equal(typeof loaded.sanitizeRedirect, 'function');
  assert.equal(loaded.sanitizeRedirect('/x'), '/x');
});

const parityCases = [
  ['/x', undefined],
  ['/a/../b', undefined],
  ['/@user', undefined],
  ['//evil.com', undefined],
  ['/%2fevil.com', undefined],
  ['javascript:alert(1)', undefined],
  ['https:evil.com', undefined],
  ['/x?y#z', { allowQuery: false }],
  ['/logout', { blockedPaths: ['/logout'] }],
  ['https://trusted.com/x', { allowedHosts: ['trusted.com'] }],
  ['https://sub.trusted.com/x', { allowedHosts: ['trusted.com'], allowSubdomains: true }],
  ['https://eviltrusted.com/x', { allowedHosts: ['trusted.com'], allowSubdomains: true }],
  ['https://127.1/x', { allowedHosts: ['trusted.com'] }],
  ['https://user@trusted.com/x', { allowedHosts: ['trusted.com'], allowUserinfo: true }],
  ['/l%6fgout', { blockedPaths: ['/logout'] }]
];

for (const [input, options] of parityCases) {
  test('ESM and CJS parse results agree: ' + JSON.stringify(input), () => {
    const a = esm.parseRedirectLocation(input, options);
    const b = cjs.parseRedirectLocation(input, options);
    assert.deepEqual(a, b);
  });
}

test('ESM and CJS output values agree for representative valid inputs', () => {
  const cases = [
    ['/x', undefined],
    ['/a/../b', undefined],
    ['/café', undefined],
    ['https://trusted.com/x', { allowedHosts: ['trusted.com'] }],
    ['https://täst.de/x', { allowedHosts: ['täst.de'] }]
  ];
  for (const [input, options] of cases) {
    assert.equal(esm.sanitizeRedirect(input, options), cjs.sanitizeRedirect(input, options));
    assert.equal(esm.assertSafeRedirect(input, options), cjs.assertSafeRedirect(input, options));
    assert.equal(esm.isSafeRedirect(input, options), cjs.isSafeRedirect(input, options));
  }
});

test('ESM and CJS throw identical error codes and messages', () => {
  const cases = [
    '//evil.com',
    '/\\evil.com',
    'javascript:alert(1)',
    'https:evil.com',
    '/%zz'
  ];
  for (const input of cases) {
    let esmError;
    let cjsError;
    try { esm.assertSafeRedirect(input); } catch (error) { esmError = error; }
    try { cjs.assertSafeRedirect(input); } catch (error) { cjsError = error; }
    assert.ok(esmError && cjsError, input);
    assert.equal(cjsError.code, esmError.code, input);
    assert.equal(cjsError.message, esmError.message, input);
  }
});

test('guard behavior is identical across module formats', () => {
  for (const [label, api] of APIs) {
    const guard = api.createRedirectGuard({ fallback: '/safe', blockedPaths: ['/logout'] });
    assert.equal(guard.sanitize('//evil.com'), '/safe', label);
    assert.equal(guard.isSafe('/x'), true, label);
    assert.equal(guard.isSafe('/logout'), false, label);
  }
});

test('generated CommonJS build is byte deterministic', async () => {
  const cjsPath = path.join(root, 'cjs', 'index.cjs');
  const before = await readFile(cjsPath);
  const result = spawnSync(process.execPath, [path.join(root, 'scripts', 'build-cjs.mjs')], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr);
  const after = await readFile(cjsPath);
  assert.deepEqual(after, before);
});

test('package manifest declares clean dual-module packaging', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'redirectcage');
  assert.equal(pkg.version, '1.0.0');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
  assert.equal(pkg.sideEffects, false);
  assert.equal(pkg.engines.node, '>=18');
});

test('gitattributes enforces LF line endings for generated CommonJS', async () => {
  const text = await readFile(path.join(root, '.gitattributes'), 'utf8');
  assert.match(text, /^\* text=auto eol=lf$/m);
  assert.match(text, /^\*\.cjs text eol=lf$/m);
});

test('TypeScript declarations expose the complete public API', async () => {
  const text = await readFile(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const fragment of [
    'export const CODE',
    'export declare class RedirectCageError',
    'export declare function sanitizeRedirect',
    'export declare function assertSafeRedirect',
    'export declare function isSafeRedirect',
    'export declare function parseRedirectLocation',
    'export declare function createRedirectGuard',
    'export default redirectcage'
  ]) {
    assert.ok(text.includes(fragment), 'missing declaration: ' + fragment);
  }
});

test('TypeScript declarations contain every runtime error code', async () => {
  const text = await readFile(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const value of Object.values(cjs.CODE)) {
    assert.ok(text.includes(value), 'missing error code ' + value);
  }
});

test('source of truth has no static or dynamic node imports', async () => {
  const text = await readFile(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(/from\s+['"]node:/.test(text), false);
  assert.equal(/require\s*\(\s*['"]node:/.test(text), false);
  assert.equal(/import\s*\(\s*['"]node:/.test(text), false);
});
