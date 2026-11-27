/*
 * redirectcage core.
 *
 * Pure Web Standards JavaScript with no static imports and no runtime
 * dependencies. The CommonJS build in cjs/index.cjs is generated from this
 * file by scripts/build-cjs.mjs so both module formats have identical
 * behavior.
 */

export const CODE = Object.freeze({
  INVALID_INPUT: 'ERR_REDIRECTCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'ERR_REDIRECTCAGE_INVALID_OPTIONS',
  LIMIT_EXCEEDED: 'ERR_REDIRECTCAGE_LIMIT_EXCEEDED',
  CONTROL_CHARACTER: 'ERR_REDIRECTCAGE_CONTROL_CHARACTER',
  UNICODE_NORMALIZATION: 'ERR_REDIRECTCAGE_UNICODE_NORMALIZATION',
  MALFORMED_ENCODING: 'ERR_REDIRECTCAGE_MALFORMED_ENCODING',
  INVALID_UTF8: 'ERR_REDIRECTCAGE_INVALID_UTF8',
  ENCODED_ATTACK: 'ERR_REDIRECTCAGE_ENCODED_ATTACK',
  PROTOCOL_RELATIVE: 'ERR_REDIRECTCAGE_PROTOCOL_RELATIVE',
  BACKSLASH: 'ERR_REDIRECTCAGE_BACKSLASH',
  DANGEROUS_SCHEME: 'ERR_REDIRECTCAGE_DANGEROUS_SCHEME',
  PROTOCOL_NOT_ALLOWED: 'ERR_REDIRECTCAGE_PROTOCOL_NOT_ALLOWED',
  INVALID_URL: 'ERR_REDIRECTCAGE_INVALID_URL',
  ABSOLUTE_URL: 'ERR_REDIRECTCAGE_ABSOLUTE_URL',
  RELATIVE_PATH: 'ERR_REDIRECTCAGE_RELATIVE_PATH',
  USERINFO: 'ERR_REDIRECTCAGE_USERINFO',
  IP_LITERAL: 'ERR_REDIRECTCAGE_IP_LITERAL',
  HOST_NOT_ALLOWED: 'ERR_REDIRECTCAGE_HOST_NOT_ALLOWED',
  QUERY_NOT_ALLOWED: 'ERR_REDIRECTCAGE_QUERY_NOT_ALLOWED',
  HASH_NOT_ALLOWED: 'ERR_REDIRECTCAGE_HASH_NOT_ALLOWED',
  DOT_SEGMENT: 'ERR_REDIRECTCAGE_DOT_SEGMENT',
  BLOCKED_PATH: 'ERR_REDIRECTCAGE_BLOCKED_PATH'
});

export class RedirectCageError extends Error {
  constructor(code, reason, input, cause) {
    super(code + ': ' + reason);
    this.name = 'RedirectCageError';
    this.code = code;
    this.reason = reason;
    this.input = input;
    if (cause !== undefined) this.cause = cause;
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      reason: this.reason,
      input: this.input
    };
  }
}

function throwError(code, reason, input, cause) {
  throw new RedirectCageError(code, reason, input, cause);
}

function configError(reason, input) {
  throwError(CODE.INVALID_OPTIONS, reason, input);
}

const DEFAULT_MAX_LENGTH = 2048;
const DEFAULT_MAX_DECODE_LAYERS = 8;
const MAX_DECODE_LAYER_LIMIT = 16;
const BASE_URL = 'https://redirectcage.invalid/';
const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):/;
const RAW_FORBIDDEN_RE = /[\u0000-\u001f\u007f-\u009f\s\p{Cf}\p{Cs}]/u;
const DECODED_FORBIDDEN_RE = /[\u0000-\u001f\u007f-\u009f\p{Cf}\p{Cs}\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u;
const VALID_PERCENT_RE = /%[0-9a-fA-F]{2}/;
const PERCENT_TRIPLET_RE = /%[0-9a-fA-F]{2}/g;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const PRINTABLE_ASCII_URL_RE = /^[\x20-\x7e]*$/;
const PORT_RE = /^\d+$/;
const STRUCTURAL_CHARS = ['/', '\\', '%', ':', '@', '?', '#', '.'];
const HARD_BLOCKED_SCHEMES = new Set([
  'javascript', 'data', 'vbscript', 'file', 'blob', 'about',
  'filesystem', 'chrome', 'chrome-extension', 'moz-extension',
  'ms-browser-extension', 'intent'
]);
const DOT_SEGMENT_ENCODINGS = new Set([
  '.', '..', '%2e', '%2e%2e', '.%2e', '%2e.'
]);
const KNOWN_OPTION_KEYS = new Set([
  'allowedOrigins', 'allowedHosts', 'allowSubdomains', 'allowProtocols',
  'allowUserinfo', 'allowIpLiterals', 'allowQuery', 'allowHash',
  'normalizeDotSegments', 'blockedPaths', 'fallback', 'maxLength',
  'maxDecodeLayers', 'throwOnUnsafe'
]);
const RESERVED_OPTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function defaultConfig() {
  const config = Object.create(null);
  config.allowedOrigins = Object.freeze([]);
  config.allowedHosts = Object.freeze([]);
  config.allowSubdomains = false;
  config.allowProtocols = Object.freeze(['http', 'https']);
  config.allowUserinfo = false;
  config.allowIpLiterals = false;
  config.allowQuery = true;
  config.allowHash = true;
  config.normalizeDotSegments = true;
  config.blockedPaths = Object.freeze([]);
  config.fallback = '/';
  config.maxLength = DEFAULT_MAX_LENGTH;
  config.maxDecodeLayers = DEFAULT_MAX_DECODE_LAYERS;
  config.throwOnUnsafe = false;
  return config;
}

function copyConfig(base) {
  const config = Object.create(null);
  for (const key of Object.keys(base)) config[key] = base[key];
  return config;
}

function assertBoolean(value, key) {
  if (typeof value !== 'boolean') configError(key + ' must be a boolean', value);
  return value;
}

function assertPositiveInteger(value, key, maximum) {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    (maximum !== undefined && value > maximum)
  ) {
    configError(key + ' must be a positive safe integer within its supported range', value);
  }
  return value;
}

function assertConfigText(value, label, maximumLength) {
  if (typeof value !== 'string' || value.length === 0) {
    configError(label + ' must be a non-empty string', value);
  }
  if (maximumLength !== undefined && value.length > maximumLength) {
    configError(label + ' exceeds the configured length limit', value);
  }
  if (RAW_FORBIDDEN_RE.test(value)) {
    configError(label + ' contains whitespace, control or invisible characters', value);
  }
  if (value.indexOf('\\') !== -1) {
    configError(label + ' must not contain a backslash', value);
  }
  return value;
}

function asArray(value, label) {
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) {
    configError(label + ' must be a string or an array of strings', value);
  }
  for (const item of value) {
    if (typeof item !== 'string') {
      configError(label + ' entries must be strings', item);
    }
  }
  return value.slice();
}

function parseScheme(value) {
  const match = SCHEME_RE.exec(value);
  if (!match) return null;
  return { raw: match[1], lower: match[1].toLowerCase(), length: match[0].length };
}

function countChar(value, needle) {
  let count = 0;
  for (const char of value) if (char === needle) count += 1;
  return count;
}

function hexValue(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function percentByteAt(value, index) {
  if (value.charCodeAt(index) !== 37) return -1;
  const high = hexValue(value.charCodeAt(index + 1));
  const low = hexValue(value.charCodeAt(index + 2));
  if (high === -1 || low === -1) return -1;
  return high * 16 + low;
}

function validatePercentEncoding(value) {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== 37) continue;
    if (percentByteAt(value, index) === -1) return false;
    index += 2;
  }
  return true;
}

function appendUtf8(bytes, char) {
  const encoded = textEncoder.encode(char);
  for (const byte of encoded) bytes.push(byte);
}

function decodePercentLayer(value) {
  if (value.indexOf('%') === -1) return { value, changed: false, invalidUtf8: false };
  const bytes = [];
  let changed = false;
  for (let index = 0; index < value.length; index += 1) {
    const encodedByte = percentByteAt(value, index);
    if (encodedByte !== -1) {
      bytes.push(encodedByte);
      changed = true;
      index += 2;
      continue;
    }
    const first = value.charCodeAt(index);
    if (first <= 0x7f) {
      bytes.push(first);
      continue;
    }
    let char = value[index];
    if (
      first >= 0xd800 && first <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      char += value[index + 1];
      index += 1;
    }
    appendUtf8(bytes, char);
  }
  try {
    return { value: textDecoder.decode(Uint8Array.from(bytes)), changed, invalidUtf8: false };
  } catch (error) {
    return { value: null, changed, invalidUtf8: true };
  }
}

function leadingSlashCount(value) {
  let count = 0;
  while (count < value.length && (value[count] === '/' || value[count] === '\\')) count += 1;
  return count;
}

function uppercasePercentTriplets(value) {
  return value.replace(PERCENT_TRIPLET_RE, (match) => match.toUpperCase());
}

function failureResult(input, code, reason) {
  return Object.freeze({
    input,
    safe: false,
    value: null,
    kind: null,
    code,
    reason,
    origin: null,
    protocol: null,
    host: null,
    hostname: null,
    port: null,
    pathname: null,
    search: null,
    hash: null
  });
}

function successResult(input, value, kind, url) {
  if (!PRINTABLE_ASCII_URL_RE.test(value)) {
    return failureResult(input, CODE.CONTROL_CHARACTER, 'canonical redirect output is not printable ASCII');
  }
  const absolute = kind === 'absolute';
  return Object.freeze({
    input,
    safe: true,
    value,
    kind,
    code: null,
    reason: null,
    origin: absolute ? url.origin : null,
    protocol: absolute ? url.protocol.slice(0, -1) : null,
    host: absolute ? url.host : null,
    hostname: absolute ? url.hostname : null,
    port: absolute && url.port !== '' ? url.port : null,
    pathname: uppercasePercentTriplets(url.pathname),
    search: uppercasePercentTriplets(url.search),
    hash: uppercasePercentTriplets(url.hash)
  });
}

function failureFrom(result) {
  return new RedirectCageError(result.code, result.reason, result.input);
}

function validateHostnameShape(hostname, label) {
  if (hostname.length === 0) configError(label + ' must include a host', hostname);
  if (hostname[0] === '[' && hostname[hostname.length - 1] === ']') return hostname;
  if (
    hostname[0] === '.' ||
    hostname[hostname.length - 1] === '.' ||
    hostname.indexOf('..') !== -1
  ) {
    configError(label + ' must not contain empty or trailing host labels', hostname);
  }
  return hostname;
}

function isIpLiteralHostname(hostname) {
  if (hostname[0] === '[' && hostname[hostname.length - 1] === ']') return true;
  return IPV4_RE.test(hostname);
}

function parsePort(value, label) {
  if (!PORT_RE.test(value)) configError(label + ' has an invalid port', value);
  const port = Number.parseInt(value, 10);
  if (port < 1 || port > 65535) configError(label + ' port must be between 1 and 65535', value);
  return port;
}

function extractRawAuthority(value) {
  const scheme = parseScheme(value);
  if (!scheme) return null;
  if (value.slice(scheme.length, scheme.length + 2) !== '//') return null;
  const rest = value.slice(scheme.length + 2);
  let end = rest.length;
  for (const delimiter of ['/', '?', '#']) {
    const index = rest.indexOf(delimiter);
    if (index !== -1 && index < end) end = index;
  }
  return rest.slice(0, end);
}

function parseAllowedOriginEntry(value) {
  assertConfigText(value, 'allowedOrigins entry');
  const scheme = parseScheme(value);
  if (!scheme || (scheme.lower !== 'http' && scheme.lower !== 'https')) {
    configError('allowedOrigins entries must use the http or https scheme', value);
  }
  const authority = extractRawAuthority(value);
  if (!authority) {
    configError('allowedOrigins entries must use exact scheme://authority syntax', value);
  }
  if (authority.indexOf('@') !== -1) {
    configError('allowedOrigins entries must not contain userinfo', value);
  }
  const suffix = value.slice(scheme.length + 2 + authority.length);
  if (suffix !== '' && suffix !== '/') {
    configError('allowedOrigins entries must not contain a path', value);
  }
  if (value.indexOf('?') !== -1 || value.indexOf('#') !== -1) {
    configError('allowedOrigins entries must not contain a query or fragment', value);
  }
  let url;
  try {
    url = new URL(value);
  } catch (error) {
    configError('allowedOrigins entry is not a valid absolute URL', value);
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    configError('allowedOrigins entries must be origins without a path, query or fragment', value);
  }
  const hostname = validateHostnameShape(url.hostname, 'allowedOrigins entry');
  const port = effectivePort(url);
  return Object.freeze({
    origin: url.origin,
    protocol: url.protocol.slice(0, -1),
    hostname,
    port
  });
}

function parseAllowedHostEntry(value) {
  assertConfigText(value, 'allowedHosts entry');
  if (
    value.indexOf('*') !== -1 || value.indexOf('@') !== -1 ||
    value.indexOf('/') !== -1 || value.indexOf('?') !== -1 ||
    value.indexOf('#') !== -1 || value.indexOf('%') !== -1
  ) {
    configError('allowedHosts entries must be literal hosts without wildcards or URL syntax', value);
  }
  let hostPart = value;
  let port = null;
  if (value[0] === '[') {
    const close = value.indexOf(']');
    if (close === -1) configError('allowedHosts entry has an unterminated IPv6 literal', value);
    hostPart = value.slice(0, close + 1);
    const rest = value.slice(close + 1);
    if (rest !== '') {
      if (!rest.startsWith(':')) configError('allowedHosts entry has invalid IPv6 port syntax', value);
      port = parsePort(rest.slice(1), 'allowedHosts entry');
    }
  } else {
    const colonCount = countChar(value, ':');
    if (colonCount > 1) {
      configError('allowedHosts IPv6 entries must use brackets', value);
    }
    if (colonCount === 1) {
      const split = value.lastIndexOf(':');
      hostPart = value.slice(0, split);
      port = parsePort(value.slice(split + 1), 'allowedHosts entry');
    }
  }
  if (hostPart.length === 0) configError('allowedHosts entry must include a host', value);
  let url;
  try {
    url = new URL('https://' + hostPart + (port === null ? '' : ':' + port) + '/');
  } catch (error) {
    configError('allowedHosts entry is not a valid host', value);
  }
  const hostname = validateHostnameShape(url.hostname, 'allowedHosts entry');
  return Object.freeze({ hostname, port });
}

function parseListOption(value, label, parser) {
  const entries = asArray(value, label);
  const seen = new Set();
  const parsed = [];
  for (const entry of entries) {
    const item = parser(entry);
    const key = JSON.stringify(item);
    if (seen.has(key)) continue;
    seen.add(key);
    parsed.push(item);
  }
  return Object.freeze(parsed);
}

function parseAllowProtocols(value) {
  const entries = asArray(value, 'allowProtocols');
  const present = new Set();
  for (let entry of entries) {
    entry = entry.toLowerCase();
    if (entry.endsWith(':')) entry = entry.slice(0, -1);
    if (entry !== 'http' && entry !== 'https') {
      configError('allowProtocols supports only http and https redirect targets', entry);
    }
    present.add(entry);
  }
  const canonical = [];
  if (present.has('http')) canonical.push('http');
  if (present.has('https')) canonical.push('https');
  if (canonical.length === 0) configError('allowProtocols must not be empty', value);
  return Object.freeze(canonical);
}

function extractRawPath(value) {
  let start = 0;
  const scheme = parseScheme(value);
  if (scheme) {
    const authority = extractRawAuthority(value);
    if (authority === null) return '';
    start = scheme.length + 2 + authority.length;
    if (value[start] !== '/') return '';
  }
  let end = value.length;
  for (const delimiter of ['?', '#']) {
    const index = value.indexOf(delimiter, start);
    if (index !== -1 && index < end) end = index;
  }
  return value.slice(start, end);
}

function isDotLikeSegment(segment) {
  return DOT_SEGMENT_ENCODINGS.has(segment.toLowerCase());
}

function hasDotSegments(value) {
  const rawPath = extractRawPath(value);
  if (rawPath === '') return false;
  return rawPath.split('/').some(isDotLikeSegment);
}

function canonicalizeBlockedPath(value) {
  assertConfigText(value, 'blockedPaths entry');
  if (value.indexOf('?') !== -1 || value.indexOf('#') !== -1) {
    configError('blockedPaths entries are paths only, without query or fragment', value);
  }
  if (!validatePercentEncoding(value)) {
    configError('blockedPaths entry contains malformed percent encoding', value);
  }
  if (!value.startsWith('/') || value.startsWith('//')) {
    configError('blockedPaths entries must start with exactly one slash', value);
  }
  let url;
  try {
    url = new URL(value, BASE_URL);
  } catch (error) {
    configError('blockedPaths entry is not a valid path', value);
  }
  return uppercasePercentTriplets(url.pathname);
}

function effectivePort(url) {
  if (url.port !== '') return Number.parseInt(url.port, 10);
  return url.protocol === 'https:' ? 443 : 80;
}

function defaultPort(protocol) {
  return protocol === 'https' ? 443 : 80;
}

function validateDependentConfig(config) {
  for (const origin of config.allowedOrigins) {
    if (!config.allowProtocols.includes(origin.protocol)) {
      configError('allowedOrigins contains a protocol disabled by allowProtocols', origin.origin);
    }
    if (isIpLiteralHostname(origin.hostname) && !config.allowIpLiterals) {
      configError('allowedOrigins contains an IP literal but allowIpLiterals is false', origin.origin);
    }
  }
  for (const host of config.allowedHosts) {
    if (isIpLiteralHostname(host.hostname) && !config.allowIpLiterals) {
      configError('allowedHosts contains an IP literal but allowIpLiterals is false', host.hostname);
    }
  }
}

let cachedDefaultConfig = null;

function buildConfig(options, base) {
  if (options === undefined && base) return base;
  if (options === undefined && !base && cachedDefaultConfig) return cachedDefaultConfig;
  const config = base ? copyConfig(base) : defaultConfig();
  if (options !== undefined) {
    if (!isPlainObject(options)) configError('options must be an object', options);
    for (const key of Object.keys(options)) {
      if (RESERVED_OPTION_KEYS.has(key)) {
        configError('reserved option key is not allowed', key);
      }
      if (!KNOWN_OPTION_KEYS.has(key)) {
        configError('unknown option key: ' + key, key);
      }
      const value = options[key];
      if (value === undefined) continue;
      if (key === 'allowedOrigins') {
        config.allowedOrigins = parseListOption(value, 'allowedOrigins', parseAllowedOriginEntry);
      } else if (key === 'allowedHosts') {
        config.allowedHosts = parseListOption(value, 'allowedHosts', parseAllowedHostEntry);
      } else if (key === 'allowProtocols') {
        config.allowProtocols = parseAllowProtocols(value);
      } else if (key === 'blockedPaths') {
        config.blockedPaths = parseListOption(value, 'blockedPaths', canonicalizeBlockedPath);
      } else if (key === 'fallback') {
        if (typeof value !== 'string' || value.length === 0) {
          configError('fallback must be a non-empty string', value);
        }
        config.fallback = value;
      } else if (key === 'maxLength') {
        config.maxLength = assertPositiveInteger(value, 'maxLength');
      } else if (key === 'maxDecodeLayers') {
        config.maxDecodeLayers = assertPositiveInteger(value, 'maxDecodeLayers', MAX_DECODE_LAYER_LIMIT);
      } else {
        config[key] = assertBoolean(value, key);
      }
    }
  }
  validateDependentConfig(config);
  const probe = evaluateRedirectValue(config.fallback, config);
  if (!probe.safe) {
    configError('fallback is not safe under the configured policy (' + probe.code + ')', config.fallback);
  }
  config.fallback = probe.value;
  const frozen = Object.freeze(config);
  if (options === undefined && !base) cachedDefaultConfig = frozen;
  return frozen;
}

function scanUnicodeHazards(value) {
  const compat = value.normalize('NFKC');
  if (compat === value) return null;
  if (DECODED_FORBIDDEN_RE.test(compat)) {
    return {
      code: CODE.UNICODE_NORMALIZATION,
      reason: 'Unicode normalization introduces whitespace, control or invisible characters'
    };
  }
  if (compat.indexOf('\\') !== -1) {
    return {
      code: CODE.UNICODE_NORMALIZATION,
      reason: 'Unicode normalization introduces a backslash'
    };
  }
  for (const char of STRUCTURAL_CHARS) {
    if (countChar(compat, char) !== countChar(value, char)) {
      return {
        code: CODE.UNICODE_NORMALIZATION,
        reason: 'Unicode normalization changes URL structural characters'
      };
    }
  }
  if (leadingSlashCount(compat) >= 2) {
    return {
      code: CODE.UNICODE_NORMALIZATION,
      reason: 'Unicode normalization creates a protocol-relative prefix'
    };
  }
  if (parseScheme(compat) && !parseScheme(value)) {
    return {
      code: CODE.UNICODE_NORMALIZATION,
      reason: 'Unicode normalization creates a URL scheme'
    };
  }
  return null;
}

function scanVariant(value, original) {
  const forbidden = original ? RAW_FORBIDDEN_RE : DECODED_FORBIDDEN_RE;
  if (forbidden.test(value)) {
    return {
      code: CODE.CONTROL_CHARACTER,
      reason: original
        ? 'raw whitespace, control or invisible characters are not allowed'
        : 'percent-decoding reveals control or invisible characters'
    };
  }
  if (value.indexOf('\\') !== -1) {
    return {
      code: CODE.BACKSLASH,
      reason: 'backslashes are not allowed in redirect targets'
    };
  }
  if (leadingSlashCount(value) >= 2) {
    return {
      code: CODE.PROTOCOL_RELATIVE,
      reason: 'protocol-relative and authority-relative prefixes are not allowed'
    };
  }
  return scanUnicodeHazards(value);
}

function prepareInput(input, config) {
  if (typeof input !== 'string') {
    return failureResult(input, CODE.INVALID_INPUT, 'redirect target must be a string');
  }
  if (input.length === 0) {
    return failureResult(input, CODE.INVALID_INPUT, 'redirect target must not be empty');
  }
  if (input.length > config.maxLength) {
    return failureResult(input, CODE.LIMIT_EXCEEDED, 'redirect target exceeds maxLength');
  }
  if (!validatePercentEncoding(input)) {
    return failureResult(input, CODE.MALFORMED_ENCODING, 'malformed percent encoding');
  }

  const variants = [input];
  let current = input;
  let layers = 0;
  while (layers < config.maxDecodeLayers) {
    const decoded = decodePercentLayer(current);
    if (decoded.invalidUtf8) {
      return failureResult(input, CODE.INVALID_UTF8, 'percent-decoding produces bytes that are not valid UTF-8');
    }
    if (!decoded.changed) break;
    current = decoded.value;
    layers += 1;
    variants.push(current);
  }
  if (layers === config.maxDecodeLayers && VALID_PERCENT_RE.test(current)) {
    return failureResult(input, CODE.ENCODED_ATTACK, 'percent-decoding depth exceeds the configured bound');
  }

  for (let index = 0; index < variants.length; index += 1) {
    const scan = scanVariant(variants[index], index === 0);
    if (scan) return failureResult(input, scan.code, scan.reason);
  }

  for (const variant of variants) {
    if (!variant.startsWith('/') || leadingSlashCount(variant) !== 1) continue;
    let canonical;
    try {
      canonical = new URL(variant, BASE_URL).pathname;
    } catch (error) {
      continue;
    }
    if (leadingSlashCount(canonical) >= 2) {
      return failureResult(input, CODE.PROTOCOL_RELATIVE, 'dot-segment normalization creates a protocol-relative path');
    }
  }

  const originalScheme = parseScheme(input);
  if (!originalScheme) {
    for (let index = 1; index < variants.length; index += 1) {
      if (parseScheme(variants[index])) {
        return failureResult(input, CODE.ENCODED_ATTACK, 'percent-decoding creates a URL scheme');
      }
    }
  }
  return { input, variants, scheme: originalScheme };
}

function pathsMatch(blocked, candidate) {
  if (blocked === '/') return true;
  if (candidate === blocked) return true;
  const prefix = blocked.endsWith('/') ? blocked : blocked + '/';
  return candidate.startsWith(prefix);
}

function decodedPathVariants(pathname, config) {
  const variants = [pathname];
  let current = pathname;
  let layers = 0;
  while (layers < config.maxDecodeLayers) {
    const decoded = decodePercentLayer(current);
    if (!decoded.changed) break;
    current = decoded.value;
    layers += 1;
    variants.push(uppercasePercentTriplets(current));
  }
  return variants;
}

function blockedPathFailure(input, pathname, config) {
  if (config.blockedPaths.length === 0) return null;
  for (const variant of decodedPathVariants(pathname, config)) {
    let structuralPath = variant;
    const queryIndex = structuralPath.indexOf('?');
    const hashIndex = structuralPath.indexOf('#');
    let end = structuralPath.length;
    if (queryIndex !== -1 && queryIndex < end) end = queryIndex;
    if (hashIndex !== -1 && hashIndex < end) end = hashIndex;
    structuralPath = structuralPath.slice(0, end);
    for (const blocked of config.blockedPaths) {
      if (pathsMatch(blocked, structuralPath)) {
        return failureResult(input, CODE.BLOCKED_PATH, 'redirect path is blocked by policy');
      }
    }
  }
  return null;
}

function queryHashFailure(input, prepared, config) {
  if (!config.allowQuery) {
    for (const variant of prepared.variants) {
      if (variant.indexOf('?') !== -1) {
        return failureResult(input, CODE.QUERY_NOT_ALLOWED, 'query strings are not allowed by policy');
      }
    }
  }
  if (!config.allowHash) {
    for (const variant of prepared.variants) {
      if (variant.indexOf('#') !== -1) {
        return failureResult(input, CODE.HASH_NOT_ALLOWED, 'fragments are not allowed by policy');
      }
    }
  }
  return null;
}

function dotSegmentFailure(input, prepared, config) {
  if (config.normalizeDotSegments) return null;
  for (const variant of prepared.variants) {
    if (hasDotSegments(variant)) {
      return failureResult(input, CODE.DOT_SEGMENT, 'dot segments are not allowed when normalization is disabled');
    }
  }
  return null;
}

function hostMatches(hostname, allowedHostname, allowSubdomains) {
  if (hostname === allowedHostname) return true;
  if (!allowSubdomains) return false;
  if (isIpLiteralHostname(allowedHostname)) return false;
  return hostname.length > allowedHostname.length && hostname.endsWith('.' + allowedHostname);
}

function matchesAllowedOrigin(url, origin, allowSubdomains) {
  if (url.protocol.slice(0, -1) !== origin.protocol) return false;
  if (effectivePort(url) !== origin.port) return false;
  return hostMatches(url.hostname, origin.hostname, allowSubdomains);
}

function matchesAllowedHost(url, host, allowSubdomains) {
  const candidatePort = effectivePort(url);
  if (host.port !== null) {
    if (candidatePort !== host.port) return false;
  } else if (candidatePort !== defaultPort(url.protocol.slice(0, -1))) {
    return false;
  }
  return hostMatches(url.hostname, host.hostname, allowSubdomains);
}

function isAllowedAbsolute(url, config) {
  for (const origin of config.allowedOrigins) {
    if (matchesAllowedOrigin(url, origin, config.allowSubdomains)) return true;
  }
  for (const host of config.allowedHosts) {
    if (matchesAllowedHost(url, host, config.allowSubdomains)) return true;
  }
  return false;
}

function canonicalAbsoluteValue(url) {
  let userinfo = '';
  if (url.username !== '' || url.password !== '') {
    userinfo = url.username;
    if (url.password !== '') userinfo += ':' + url.password;
    userinfo += '@';
  }
  return uppercasePercentTriplets(
    url.protocol + '//' + userinfo + url.host + url.pathname + url.search + url.hash
  );
}

function canonicalRelativeValue(url) {
  return uppercasePercentTriplets(url.pathname + url.search + url.hash);
}

function evaluateAbsolute(input, prepared, config) {
  const scheme = prepared.scheme.lower;
  if (HARD_BLOCKED_SCHEMES.has(scheme)) {
    return failureResult(input, CODE.DANGEROUS_SCHEME, 'this URL scheme can execute or expose local content and is never allowed');
  }
  if (!config.allowProtocols.includes(scheme)) {
    return failureResult(input, CODE.PROTOCOL_NOT_ALLOWED, 'URL scheme is not allowed by policy');
  }
  const authority = extractRawAuthority(input);
  if (!authority) {
    return failureResult(input, CODE.INVALID_URL, 'absolute redirect targets require exact scheme://authority syntax');
  }
  let url;
  try {
    url = new URL(input);
  } catch (error) {
    return failureResult(input, CODE.INVALID_URL, 'absolute redirect target is not a valid URL');
  }
  if (!url.hostname || url.origin === 'null') {
    return failureResult(input, CODE.INVALID_URL, 'absolute redirect target must include a valid host');
  }
  if (authority.indexOf('@') !== -1 || url.username !== '' || url.password !== '') {
    if (!config.allowUserinfo) {
      return failureResult(input, CODE.USERINFO, 'userinfo in redirect authority is not allowed');
    }
  }
  if (isIpLiteralHostname(url.hostname) && !config.allowIpLiterals) {
    return failureResult(input, CODE.IP_LITERAL, 'IP literal redirect hosts are not allowed');
  }
  const hasAllowlist = config.allowedOrigins.length > 0 || config.allowedHosts.length > 0;
  if (!hasAllowlist) {
    return failureResult(input, CODE.ABSOLUTE_URL, 'absolute redirect targets are not allowed without an explicit allowlist');
  }
  if (!isAllowedAbsolute(url, config)) {
    return failureResult(input, CODE.HOST_NOT_ALLOWED, 'redirect host or origin is not allowed by policy');
  }
  const queryHash = queryHashFailure(input, prepared, config);
  if (queryHash) return queryHash;
  const dotSegments = dotSegmentFailure(input, prepared, config);
  if (dotSegments) return dotSegments;
  const blocked = blockedPathFailure(input, uppercasePercentTriplets(url.pathname), config);
  if (blocked) return blocked;
  return successResult(input, canonicalAbsoluteValue(url), 'absolute', url);
}

function evaluateRelative(input, prepared, config) {
  if (!input.startsWith('/')) {
    return failureResult(input, CODE.RELATIVE_PATH, 'relative redirect targets must start with exactly one slash');
  }
  const queryHash = queryHashFailure(input, prepared, config);
  if (queryHash) return queryHash;
  const dotSegments = dotSegmentFailure(input, prepared, config);
  if (dotSegments) return dotSegments;
  let url;
  try {
    url = new URL(input, BASE_URL);
  } catch (error) {
    return failureResult(input, CODE.INVALID_URL, 'relative redirect target is not a valid URL path');
  }
  if (leadingSlashCount(url.pathname) >= 2) {
    return failureResult(input, CODE.PROTOCOL_RELATIVE, 'dot-segment normalization creates a protocol-relative path');
  }
  const blocked = blockedPathFailure(input, uppercasePercentTriplets(url.pathname), config);
  if (blocked) return blocked;
  return successResult(input, canonicalRelativeValue(url), 'relative', url);
}

function evaluateRedirectValue(input, config) {
  const prepared = prepareInput(input, config);
  if (Object.prototype.hasOwnProperty.call(prepared, 'safe')) return prepared;
  if (prepared.scheme) return evaluateAbsolute(input, prepared, config);
  return evaluateRelative(input, prepared, config);
}

function resolveConfig(base, overrides) {
  if (overrides === undefined) return base;
  return buildConfig(overrides, base);
}

function sanitizeWithConfig(input, config) {
  const result = evaluateRedirectValue(input, config);
  if (result.safe) return result.value;
  if (config.throwOnUnsafe) throw failureFrom(result);
  return config.fallback;
}

function assertWithConfig(input, config) {
  const result = evaluateRedirectValue(input, config);
  if (!result.safe) throw failureFrom(result);
  return result.value;
}

function validateRedirectStatus(status) {
  if (!Number.isSafeInteger(status) || status < 300 || status > 399) {
    throwError(CODE.INVALID_INPUT, 'redirect status must be an integer between 300 and 399', status);
  }
  return status;
}

function writeSafeRedirect(response, target, status, config) {
  if (!response || typeof response !== 'object' || typeof response.setHeader !== 'function') {
    throwError(CODE.INVALID_INPUT, 'response must provide setHeader(name, value)', response);
  }
  const finalStatus = validateRedirectStatus(status === undefined ? 302 : status);
  const location = sanitizeWithConfig(target, config);
  try {
    response.statusCode = finalStatus;
  } catch (error) {
    throwError(CODE.INVALID_INPUT, 'response statusCode could not be assigned', response, error);
  }
  response.setHeader('Location', location);
  if (typeof response.end === 'function') response.end();
  return location;
}

export function sanitizeRedirect(input, options) {
  const config = buildConfig(options);
  return sanitizeWithConfig(input, config);
}

export function assertSafeRedirect(input, options) {
  const config = buildConfig(options);
  return assertWithConfig(input, config);
}

export function isSafeRedirect(input, options) {
  const config = buildConfig(options);
  return evaluateRedirectValue(input, config).safe;
}

export function parseRedirectLocation(input, options) {
  const config = buildConfig(options);
  return evaluateRedirectValue(input, config);
}

export function createRedirectGuard(options) {
  const baseConfig = buildConfig(options);
  const guard = {
    sanitize(input, overrides) {
      return sanitizeWithConfig(input, resolveConfig(baseConfig, overrides));
    },
    assert(input, overrides) {
      return assertWithConfig(input, resolveConfig(baseConfig, overrides));
    },
    isSafe(input, overrides) {
      return evaluateRedirectValue(input, resolveConfig(baseConfig, overrides)).safe;
    },
    parseLocation(input, overrides) {
      return evaluateRedirectValue(input, resolveConfig(baseConfig, overrides));
    },
    middleware(overrides) {
      const middlewareConfig = resolveConfig(baseConfig, overrides);
      return function redirectCageMiddleware(request, response, next) {
        if (!response || typeof response !== 'object') {
          throwError(CODE.INVALID_INPUT, 'middleware response must be an object', response);
        }
        if (response.safeRedirect !== undefined) {
          throwError(CODE.INVALID_INPUT, 'response already has a safeRedirect property', response);
        }
        response.safeRedirect = function safeRedirect(target, status) {
          return writeSafeRedirect(response, target, status, middlewareConfig);
        };
        if (typeof next === 'function') next();
      };
    }
  };
  return Object.freeze(guard);
}

const redirectcage = {
  CODE,
  RedirectCageError,
  sanitizeRedirect,
  assertSafeRedirect,
  isSafeRedirect,
  parseRedirectLocation,
  createRedirectGuard
};

export default redirectcage;
