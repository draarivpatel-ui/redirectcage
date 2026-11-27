import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export const cjs = require('../cjs/index.cjs');
export const esm = await import('../src/index.mjs');
export const APIs = [
  ['esm', esm],
  ['cjs', cjs]
];

export function throwsCode(fn, code, message) {
  let error;
  const label = message || 'expected RedirectCageError ' + code;
  assert.throws(fn, (caught) => {
    error = caught;
    return true;
  }, label);
  assert.equal(error.name, 'RedirectCageError', label);
  assert.equal(error.code, code, label);
  assert.ok(typeof error.reason === 'string' && error.reason.length > 0, label);
  assert.ok('input' in error, label);
  return error;
}

export function throwsInvalidOptions(fn, message) {
  return throwsCode(fn, cjs.CODE.INVALID_OPTIONS, message);
}

export function fakeResponse() {
  return {
    headers: Object.create(null),
    statusCode: 200,
    ended: false,
    endCount: 0,
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = String(value);
    },
    end() {
      this.ended = true;
      this.endCount += 1;
    }
  };
}

export function parseUnsafe(api, input, options) {
  const result = api.parseRedirectLocation(input, options);
  assert.equal(result.safe, false, JSON.stringify(String(input)));
  assert.equal(result.value, null);
  assert.equal(result.kind, null);
  assert.equal(typeof result.code, 'string');
  assert.ok(result.code.length > 0);
  return result;
}
