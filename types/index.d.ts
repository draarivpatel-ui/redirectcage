/** Error codes emitted by redirectcage. */
export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_REDIRECTCAGE_INVALID_INPUT';
  INVALID_OPTIONS: 'ERR_REDIRECTCAGE_INVALID_OPTIONS';
  LIMIT_EXCEEDED: 'ERR_REDIRECTCAGE_LIMIT_EXCEEDED';
  CONTROL_CHARACTER: 'ERR_REDIRECTCAGE_CONTROL_CHARACTER';
  UNICODE_NORMALIZATION: 'ERR_REDIRECTCAGE_UNICODE_NORMALIZATION';
  MALFORMED_ENCODING: 'ERR_REDIRECTCAGE_MALFORMED_ENCODING';
  ENCODED_ATTACK: 'ERR_REDIRECTCAGE_ENCODED_ATTACK';
  PROTOCOL_RELATIVE: 'ERR_REDIRECTCAGE_PROTOCOL_RELATIVE';
  BACKSLASH: 'ERR_REDIRECTCAGE_BACKSLASH';
  DANGEROUS_SCHEME: 'ERR_REDIRECTCAGE_DANGEROUS_SCHEME';
  PROTOCOL_NOT_ALLOWED: 'ERR_REDIRECTCAGE_PROTOCOL_NOT_ALLOWED';
  INVALID_URL: 'ERR_REDIRECTCAGE_INVALID_URL';
  ABSOLUTE_URL: 'ERR_REDIRECTCAGE_ABSOLUTE_URL';
  RELATIVE_PATH: 'ERR_REDIRECTCAGE_RELATIVE_PATH';
  USERINFO: 'ERR_REDIRECTCAGE_USERINFO';
  IP_LITERAL: 'ERR_REDIRECTCAGE_IP_LITERAL';
  HOST_NOT_ALLOWED: 'ERR_REDIRECTCAGE_HOST_NOT_ALLOWED';
  QUERY_NOT_ALLOWED: 'ERR_REDIRECTCAGE_QUERY_NOT_ALLOWED';
  HASH_NOT_ALLOWED: 'ERR_REDIRECTCAGE_HASH_NOT_ALLOWED';
  DOT_SEGMENT: 'ERR_REDIRECTCAGE_DOT_SEGMENT';
  BLOCKED_PATH: 'ERR_REDIRECTCAGE_BLOCKED_PATH';
}>;

export type RedirectCageErrorCode =
  'ERR_REDIRECTCAGE_INVALID_INPUT' | 'ERR_REDIRECTCAGE_INVALID_OPTIONS' |
  'ERR_REDIRECTCAGE_LIMIT_EXCEEDED' | 'ERR_REDIRECTCAGE_CONTROL_CHARACTER' |
  'ERR_REDIRECTCAGE_UNICODE_NORMALIZATION' | 'ERR_REDIRECTCAGE_MALFORMED_ENCODING' |
  'ERR_REDIRECTCAGE_ENCODED_ATTACK' | 'ERR_REDIRECTCAGE_PROTOCOL_RELATIVE' |
  'ERR_REDIRECTCAGE_BACKSLASH' | 'ERR_REDIRECTCAGE_DANGEROUS_SCHEME' |
  'ERR_REDIRECTCAGE_PROTOCOL_NOT_ALLOWED' | 'ERR_REDIRECTCAGE_INVALID_URL' |
  'ERR_REDIRECTCAGE_ABSOLUTE_URL' | 'ERR_REDIRECTCAGE_RELATIVE_PATH' |
  'ERR_REDIRECTCAGE_USERINFO' | 'ERR_REDIRECTCAGE_IP_LITERAL' |
  'ERR_REDIRECTCAGE_HOST_NOT_ALLOWED' | 'ERR_REDIRECTCAGE_QUERY_NOT_ALLOWED' |
  'ERR_REDIRECTCAGE_HASH_NOT_ALLOWED' | 'ERR_REDIRECTCAGE_DOT_SEGMENT' |
  'ERR_REDIRECTCAGE_BLOCKED_PATH';

/** Structured error thrown by assertion APIs and invalid configuration. */
export declare class RedirectCageError extends Error {
  constructor(code: RedirectCageErrorCode | string, reason: string, input: unknown, cause?: unknown);
  readonly name: 'RedirectCageError';
  readonly code: RedirectCageErrorCode | string;
  readonly reason: string;
  readonly input: unknown;
  readonly cause?: unknown;
  toJSON(): { name: string; code: string; reason: string; input: unknown };
}

export type RedirectProtocol = 'http' | 'https';

export interface RedirectOptions {
  /** Exact origins such as https://app.example.com that may receive absolute redirects. */
  allowedOrigins?: string | readonly string[];
  /** Literal host names, optionally with one explicit port, that may receive absolute redirects. */
  allowedHosts?: string | readonly string[];
  /** Permit subdomains below allowlisted hosts using a strict dot boundary. Default false. */
  allowSubdomains?: boolean;
  /** HTTP schemes accepted for absolute targets. Default ['http', 'https']. */
  allowProtocols?: RedirectProtocol | `${RedirectProtocol}:` | readonly (RedirectProtocol | `${RedirectProtocol}:`)[];
  /** Permit userinfo in an absolute URL authority. Default false. */
  allowUserinfo?: boolean;
  /** Permit IPv4 and IPv6 literal hosts when they are explicitly allowlisted. Default false. */
  allowIpLiterals?: boolean;
  /** Permit query strings. Default true. */
  allowQuery?: boolean;
  /** Permit URL fragments. Default true. */
  allowHash?: boolean;
  /** Normalize dot segments with WHATWG URL semantics. Default true. False rejects dot segments. */
  normalizeDotSegments?: boolean;
  /** Canonical paths that must never be redirect targets. A path also covers its descendants. */
  blockedPaths?: string | readonly string[];
  /** Safe target returned by sanitize when input is rejected. Default '/'. Validated at configuration time. */
  fallback?: string;
  /** Maximum input length in UTF-16 code units. Default 2048. */
  maxLength?: number;
  /** Maximum nested percent-decoding layers inspected. Default 8, maximum 16. */
  maxDecodeLayers?: number;
  /** Make sanitizeRedirect throw on unsafe input instead of returning fallback. Default false. */
  throwOnUnsafe?: boolean;
}

export interface SafeRedirectLocation {
  input: unknown;
  safe: true;
  value: string;
  kind: 'relative' | 'absolute';
  code: null;
  reason: null;
  origin: string | null;
  protocol: RedirectProtocol | null;
  host: string | null;
  hostname: string | null;
  port: string | null;
  pathname: string;
  search: string;
  hash: string;
}

export interface UnsafeRedirectLocation {
  input: unknown;
  safe: false;
  value: null;
  kind: null;
  code: RedirectCageErrorCode | string;
  reason: string;
  origin: null;
  protocol: null;
  host: null;
  hostname: null;
  port: null;
  pathname: null;
  search: null;
  hash: null;
}

export type RedirectLocationParse = SafeRedirectLocation | UnsafeRedirectLocation;

export interface RedirectGuard {
  /** Return a normalized safe target or the configured fallback. Invalid options still throw. */
  sanitize(input: unknown, overrides?: RedirectOptions): string;
  /** Return a normalized safe target or throw RedirectCageError. */
  assert(input: unknown, overrides?: RedirectOptions): string;
  /** Strict boolean predicate. Invalid options still throw. */
  isSafe(input: unknown, overrides?: RedirectOptions): boolean;
  /** Return a structured, non-throwing parse result for user-controlled input. */
  parseLocation(input: unknown, overrides?: RedirectOptions): RedirectLocationParse;
  /** Return framework-agnostic middleware that installs response.safeRedirect(target, status). */
  middleware(overrides?: RedirectOptions): RedirectMiddleware;
}

export type RedirectMiddleware = (
  request: unknown,
  response: unknown,
  next?: () => void
) => void;

/** Return a normalized safe redirect target or the configured fallback. */
export declare function sanitizeRedirect(input: unknown, options?: RedirectOptions): string;
/** Return a normalized safe redirect target or throw RedirectCageError. */
export declare function assertSafeRedirect(input: unknown, options?: RedirectOptions): string;
/** Strict boolean predicate for redirect targets. */
export declare function isSafeRedirect(input: unknown, options?: RedirectOptions): boolean;
/** Return a structured, non-throwing parse result for user-controlled input. */
export declare function parseRedirectLocation(input: unknown, options?: RedirectOptions): RedirectLocationParse;
/** Create a reusable guard with validated configuration. */
export declare function createRedirectGuard(options?: RedirectOptions): RedirectGuard;

declare const redirectcage: {
  CODE: typeof CODE;
  RedirectCageError: typeof RedirectCageError;
  sanitizeRedirect: typeof sanitizeRedirect;
  assertSafeRedirect: typeof assertSafeRedirect;
  isSafeRedirect: typeof isSafeRedirect;
  parseRedirectLocation: typeof parseRedirectLocation;
  createRedirectGuard: typeof createRedirectGuard;
};

export default redirectcage;
