/**
 * Classified provider errors (design note D2). An error never carries a header, token, URL with a
 * query string or response body: only a code (≤ 64 characters from PROVIDER_ERROR_CODES), the
 * HTTP status, whether it is retryable, the wait hint and a sanitized provider error code.
 */
import { ProviderAdapterError } from '../port/ato-port';
import { ConnectionAccessError } from '../port/connection-port';

export const PROVIDER_ERROR_CODES = [
  // HTTP classification (D2)
  'unauthorized',
  'missing_permission',
  'missing_license',
  'missing_privileged_role',
  'forbidden',
  'not_found',
  'conflict',
  'bad_request',
  'throttled',
  'quota_exhausted',
  'provider_unavailable',
  'unexpected_response',
  'response_too_large',
  'blocked_host',
  'redirect_refused',
  'aborted',
  // rate budget (D7.5)
  'rate_budget',
  // token acquisition through the connection port (§0.3)
  'connection_not_found',
  'connection_inactive',
  'grant_missing',
  'consent_missing',
  'credentials_invalid',
] as const;
export type ProviderErrorCode = (typeof PROVIDER_ERROR_CODES)[number];

const RETRYABLE: ReadonlySet<ProviderErrorCode> = new Set([
  'throttled',
  'quota_exhausted',
  'provider_unavailable',
  'rate_budget',
]);

/** Throttle-like codes: ingestion ends the page early with `retryAfterMs` instead of failing. */
export const THROTTLE_CODES: ReadonlySet<ProviderErrorCode> = new Set([
  'throttled',
  'quota_exhausted',
  'rate_budget',
]);

/** Provider error codes are kept only when they match this shape (never free text). */
const PROVIDER_CODE_SHAPE = /^[A-Za-z0-9_.-]{1,64}$/;

export function sanitizeProviderCode(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isInteger(value)) return String(value);
  return typeof value === 'string' && PROVIDER_CODE_SHAPE.test(value) ? value : undefined;
}

/**
 * A classified provider call failure. It extends 8.4's `ProviderAdapterError` (merge note M1), so
 * the 8.4 runner and contract kit classify it (`code`, `retryable`, `retryAfterMs`) without
 * knowing 8.5's vocabulary.
 */
export class ProviderCallError extends ProviderAdapterError {
  declare readonly code: ProviderErrorCode;
  readonly status: number | undefined;
  /** Provider error code (`Authorization_RequestDenied`, `AF20022`, `rateLimitExceeded`, …). */
  readonly providerCode: string | undefined;
  constructor(
    code: ProviderErrorCode,
    options: {
      status?: number;
      retryAfterMs?: number;
      retryable?: boolean;
      providerCode?: string;
    } = {},
  ) {
    super(code, options.retryable ?? RETRYABLE.has(code), options.retryAfterMs);
    this.name = 'ProviderCallError';
    this.message = code;
    this.status = options.status;
    this.providerCode = sanitizeProviderCode(options.providerCode);
  }
}

export function isProviderCallError(error: unknown): error is ProviderCallError {
  return error instanceof ProviderCallError;
}

/** Maps a connection-port failure (token acquisition) onto the provider error vocabulary. */
export function fromConnectionAccessError(error: ConnectionAccessError): ProviderCallError {
  switch (error.code) {
    case 'scope_not_granted':
      return new ProviderCallError('missing_permission');
    case 'throttled':
      return new ProviderCallError('throttled', { retryAfterMs: error.retryAfterMs });
    case 'provider_unavailable':
      return new ProviderCallError('provider_unavailable');
    default:
      return new ProviderCallError(error.code);
  }
}

/** Normalizes anything thrown during a provider call into a ProviderCallError. */
export function toProviderCallError(error: unknown): ProviderCallError {
  if (error instanceof ProviderCallError) return error;
  if (error instanceof ConnectionAccessError) return fromConnectionAccessError(error);
  return new ProviderCallError('provider_unavailable');
}
