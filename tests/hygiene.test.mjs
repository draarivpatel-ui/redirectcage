import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { cjs } from './helpers.mjs';

const EXPECTED_TEST_COUNT = 416;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_ENTRIES = new Set(['.git', 'node_modules', '.DS_Store']);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (SKIP_ENTRIES.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      output.push(...await walk(full));
    } else if (entry.isFile() && !entry.name.endsWith('.tgz')) {
      output.push(full);
    }
  }
  return output.sort();
}

async function trackedTextFiles() {
  const files = await walk(root);
  return files.filter((file) => !file.endsWith('.png') && !file.endsWith('.jpg'));
}

test('repository text files contain no em or en dash characters', async () => {
  const emDash = String.fromCharCode(0x2014);
  const enDash = String.fromCharCode(0x2013);
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes(emDash), false, file + ' contains an em dash');
    assert.equal(text.includes(enDash), false, file + ' contains an en dash');
  }
});

test('repository text files contain no local paths or private account data', async () => {
  const banned = [
    new RegExp('/' + 'Users' + '/'),
    new RegExp('Hub' + '/' + 'personal'),
    new RegExp('Contest' + ' ' + 'Submissions'),
    new RegExp('@' + 'gmail'),
    new RegExp('t3' + '-code', 'i'),
    new RegExp('pro' + 'ro' + 'blox', 'i')
  ];
  for (const file of await trackedTextFiles()) {
    const raw = await readFile(file, 'utf8');
    const text = raw
      .replaceAll('287273626+draarivpatel-ui@users.noreply.github.com', '')
      .replaceAll('draarivpatel-ui', '');
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, file + ' contains ' + pattern);
    }
    assert.equal(new RegExp('aa' + 'riv' + 'patel', 'i').test(text), false, file + ' contains a private account string');
  }
});

test('repository text files use LF line endings', async () => {
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes('\r'), false, file + ' contains CR');
  }
});

test('repository text files contain no secret-shaped placeholders with vendor prefixes', async () => {
  const patterns = [new RegExp('ts' + 'key-'), new RegExp('s' + 'k-[A-Za-z0-9]'), new RegExp('gh' + 'p_[A-Za-z0-9]'), new RegExp('github' + '_pat_[A-Za-z0-9]'), new RegExp('AK' + 'IA[0-9A-Z]'), new RegExp('x' + 'ox[baprs]-'), new RegExp('nv' + 'api-'), new RegExp('AI' + 'za[0-9A-Za-z_-]')];
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    for (const pattern of patterns) {
      assert.equal(pattern.test(text), false, file + ' contains ' + pattern);
    }
  }
});

test('package metadata points at the public repository', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.repository.url, 'git+https://github.com/draarivpatel-ui/redirectcage.git');
  assert.equal(pkg.homepage, 'https://github.com/draarivpatel-ui/redirectcage#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/draarivpatel-ui/redirectcage/issues');
});

test('published file list is intentionally minimal', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.files, [
    'src',
    'cjs',
    'types',
    'README.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'GOOD_FIRST_ISSUES.md',
    'LICENSE'
  ]);
});

test('README deterministic test count matches the verified live count', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  const match = readme.match(/\b(\d+) deterministic tests\b/i);
  assert.ok(match, 'README does not state the deterministic test count');
  assert.equal(Number(match[1]), EXPECTED_TEST_COUNT);
});

test('README states limitations and supported Node versions', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /Node 18 or newer/i);
  assert.match(readme, /Limitations/i);
  assert.match(readme, /root-relative/i);
  assert.match(readme, /fallback/i);
});

test('security documentation includes a reporting channel and scope', async () => {
  const security = await readFile(path.join(root, 'SECURITY.md'), 'utf8');
  assert.match(security, /report/i);
  assert.match(security, /supported versions/i);
  assert.match(security, /CWE-601/);
});

test('good first issues file contains ten starter ideas', async () => {
  const text = await readFile(path.join(root, 'GOOD_FIRST_ISSUES.md'), 'utf8');
  const count = (text.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('CI covers Node 18, 20, 22 and 24 on Linux and Windows', async () => {
  const ci = await readFile(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  for (const fragment of ['ubuntu-latest', 'windows-latest', 'node: [18, 20, 22, 24]']) {
    assert.ok(ci.includes(fragment), 'missing CI fragment ' + fragment);
  }
});

test('license is MIT without personal data', async () => {
  const license = await readFile(path.join(root, 'LICENSE'), 'utf8');
  assert.match(license, /MIT License/);
  assert.match(license, /Permission is hereby granted/);
});

test('generated CommonJS file carries the generator marker', async () => {
  const text = await readFile(path.join(root, 'cjs', 'index.cjs'), 'utf8');
  assert.match(text, /Generated by scripts\/build-cjs\.mjs/);
  assert.match(text, /module\.exports\.default = module\.exports/);
});

test('public runtime does not use eval or the Function constructor', async () => {
  for (const file of ['src/index.mjs', 'cjs/index.cjs']) {
    const text = await readFile(path.join(root, file), 'utf8');
    assert.equal(/\beval\s*\(/.test(text), false, file);
    assert.equal(/\bnew\s+Function\s*\(/.test(text), false, file);
  }
});

test('runtime error codes are frozen and unique', () => {
  assert.equal(Object.isFrozen(cjs.CODE), true);
  const values = Object.values(cjs.CODE);
  assert.equal(new Set(values).size, values.length);
  for (const value of values) assert.match(value, /^ERR_REDIRECTCAGE_[A-Z_]+$/);
});
