/** Error codes emitted by CsrfShieldError. */
export declare const CODE: Readonly<{
  INVALID_TOKEN: 'INVALID_TOKEN';
  EXPIRED_TOKEN: 'EXPIRED_TOKEN';
  SESSION_MISMATCH: 'SESSION_MISMATCH';
  CROSS_SITE_REQUEST: 'CROSS_SITE_REQUEST';
  ORIGIN_MISMATCH: 'ORIGIN_MISMATCH';
  MISSING_COOKIE: 'MISSING_COOKIE';
  WEAK_SECRET: 'WEAK_SECRET';
  INVALID_CONFIG: 'INVALID_CONFIG';
  INVALID_SESSION: 'INVALID_SESSION';
  RNG_UNAVAILABLE: 'RNG_UNAVAILABLE';
}>;

export type CsrfErrorCode = typeof CODE[keyof typeof CODE];

/** Structured CSRF failure with a stable, typed machine-readable code. */
export declare class CsrfShieldError extends Error {
  readonly name: 'CsrfShieldError';
  readonly code: CsrfErrorCode;
  readonly reason: string;
  readonly meta?: unknown;
  readonly status: number;
  constructor(code: CsrfErrorCode, reason: string, meta?: unknown);
  toJSON(): { name: string; code: CsrfErrorCode; message: string; status: number };
}

/** A crypto adapter. Use nodeCrypto from csrfshield/node for native HMAC. */
export interface CryptoAdapter {
  readonly name?: string;
  randomBytes(length: number): Uint8Array;
  hmac(key: string | Uint8Array, data: string | Uint8Array): Uint8Array;
  timingEqual(a: string | Uint8Array, b: string | Uint8Array): boolean;
}

export declare const webCrypto: CryptoAdapter;
export declare function createNodeCrypto(nodeCryptoModule: unknown): CryptoAdapter;

export declare function base64urlEncode(input: string | Uint8Array | ArrayBuffer): string;
export declare function base64urlDecodeStrict(text: string): Uint8Array;
export declare function sha256(input: string | Uint8Array | ArrayBuffer): Uint8Array;
export declare function hmacSha256(key: string | Uint8Array, data: string | Uint8Array): Uint8Array;
export declare function constantTimeDiff(a: string | Uint8Array, b: string | Uint8Array): number;
export declare function timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean;

export interface MaskedTokenMarker {
  readonly masked: true;
}
export declare function maskToken(token: string, crypto?: CryptoAdapter): string;
export declare function unmaskToken(value: string): string;
export declare function isMaskedToken(value: string): boolean;

export interface ParsedToken {
  readonly version: 'v1';
  readonly session: string;
  readonly nonce: Uint8Array;
  readonly expiresAt: number;
  readonly signature: Uint8Array;
  readonly raw: string;
  readonly data: string;
}
export declare function parseToken(token: string): ParsedToken;

export declare function parseCookieHeader(
  headerValue: string | string[] | undefined | null,
  name: string,
  options?: { rejectDuplicateHeaders?: boolean; strictValues?: boolean }
): string | null;

export declare function canonicalOrigin(value: string, fromReferer?: boolean): string;
export declare function isSafeMethod(method: string): boolean;

export interface CookieOptions {
  name?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
  domain?: string;
  maxAge?: number;
}

export interface OriginCheckOptions {
  enabled?: boolean;
  strict?: boolean;
  allowNull?: boolean;
  refererFallback?: boolean;
}

export interface FetchMetadataOptions {
  enabled?: boolean;
  strictness?: 'same-origin' | 'same-site';
  allowNone?: boolean;
}

/** Minimal shape accepted by verifyRequest. Node IncomingMessage and Fetch Request both satisfy it. */
export interface ShieldRequest {
  method?: string;
  url?: string;
  headers?: Record<string, string | string[] | undefined> | { get(name: string): string | null; getAll?(name: string): string[]; has?(name: string): boolean; forEach(callback: (value: string, key: string) => void): void };
  body?: unknown;
  cookie?: string | string[];
  [key: string]: unknown;
}

/** Minimal shape accepted by appendSetCookie. */
export interface ShieldResponse {
  setHeader?(name: string, value: string | string[]): unknown;
  getHeader?(name: string): string | string[] | undefined;
  appendHeader?(name: string, value: string): unknown;
  locals?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface IssueSettings {
  sessionId?: string;
  nonce?: string | Uint8Array;
  now?: number;
  maxAge?: number;
}

export interface VerifySettings {
  sessionId?: string;
  now?: number;
  cookie?: string | string[];
  headers?: ShieldRequest['headers'];
  method?: string;
  url?: string;
  body?: unknown;
  token?: string;
  extractToken?: (request: ShieldRequest, context: VerifyContext) => string | null | undefined | Promise<string | null | undefined>;
}

export interface VerifyContext {
  readonly raw: ShieldRequest;
  readonly method: string;
  readonly url: string;
  readonly headers: { get(name: string): string | null; getAll(name: string): string[]; has(name: string): boolean };
  readonly cookieHeader: string | string[] | undefined | null;
}

export interface VerifyResult {
  readonly ok: true;
  readonly skipped: boolean;
  readonly method: string;
  readonly url: string;
  readonly token?: string;
  readonly sessionId?: string;
  readonly expiresAt?: number;
}

export interface TokenPair {
  readonly token: string;
  readonly maskedToken: string;
  readonly cookie: string;
  readonly setCookie: string;
  readonly expiresAt: number;
}

export interface ShieldOptions {
  secrets?: string[];
  /** @deprecated Use secrets. Retained for single-secret migrations. */
  secret?: string;
  getSessionId?: (request: ShieldRequest, context?: VerifyContext) => string;
  origin?: string | string[] | ((origin: string, request: ShieldRequest, context: VerifyContext) => boolean | Promise<boolean>);
  originCheck?: OriginCheckOptions;
  fetchMetadata?: FetchMetadataOptions;
  cookie?: CookieOptions;
  header?: string;
  bodyField?: string;
  tokenTtlMs?: number;
  clockSkewMs?: number;
  mask?: boolean;
  extractToken?: (request: ShieldRequest, context: VerifyContext) => string | null | undefined | Promise<string | null | undefined>;
  crypto?: CryptoAdapter;
}

export interface Shield {
  readonly secrets: readonly string[];
  readonly cookie: Readonly<Required<Pick<CookieOptions, 'name' | 'path' | 'secure' | 'httpOnly' | 'sameSite'>>> & { readonly domain: string | null; readonly maxAge: number | null };
  readonly header: string;
  readonly bodyField: string;
  readonly tokenTtlMs: number;
  readonly clockSkewMs: number;
  readonly originCheck: Readonly<Required<OriginCheckOptions>>;
  readonly fetchMetadata: Readonly<Required<FetchMetadataOptions>>;
  readonly allowedOrigins: readonly string[] | null;
  issueToken(context?: ShieldRequest, settings?: IssueSettings): string;
  verifyToken(token: string, settings?: { sessionId?: string; now?: number }): { readonly ok: true; readonly token: string; readonly sessionId: string; readonly expiresAt: number; readonly ttlMs: number };
  serializeCookie(token: string, settings?: { maxAge?: number }): string;
  clearCookie(): string;
  issueCookie(context?: ShieldRequest, settings?: IssueSettings): string;
  issueTokenPair(context?: ShieldRequest, settings?: IssueSettings): TokenPair;
  verifyRequest(request: ShieldRequest, settings?: VerifySettings): Promise<VerifyResult>;
  verify(request: ShieldRequest, settings?: VerifySettings): Promise<VerifyResult>;
  middleware(request: ShieldRequest, response: ShieldResponse, next: (error?: unknown) => void): Promise<unknown>;
  nodeMiddleware(request: ShieldRequest, response: ShieldResponse, next: (error?: unknown) => void): Promise<unknown>;
  protectFetch(request: unknown, settings?: VerifySettings): Promise<{ readonly verified: VerifyResult; readonly request: unknown }>;
  withFetch(handler: (request: unknown, verified: VerifyResult, ...rest: unknown[]) => unknown, settings?: VerifySettings): (request: unknown, ...rest: unknown[]) => Promise<unknown>;
  fetchHandler(handler: (request: unknown, verified: VerifyResult, ...rest: unknown[]) => unknown, settings?: VerifySettings): (request: unknown, ...rest: unknown[]) => Promise<unknown>;
  errorResponse(error: CsrfShieldError, settings?: { onError?: (error: CsrfShieldError) => unknown }): unknown;
  createFetchTokenResponse(token: string, settings?: { body?: unknown; maxAge?: number }): unknown;
  parseCookie(headerValue: string | string[] | undefined | null): string | null;
}

export declare function createShield(options?: ShieldOptions): Shield;

declare const csrfshield: {
  readonly CODE: typeof CODE;
  readonly CsrfShieldError: typeof CsrfShieldError;
  readonly createShield: typeof createShield;
  readonly webCrypto: CryptoAdapter;
  readonly nodeCrypto: undefined;
};
export default csrfshield;
