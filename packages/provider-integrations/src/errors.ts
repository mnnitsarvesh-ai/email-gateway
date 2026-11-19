/**
 * Classified provider errors (D2, §4.3). Messages name the code only: never a response body,
 * a token, a secret, a tenant's error text or a request URL with a query string.
 */
export const PROVIDER_ERROR_CODES = [
  'invalid_client',
  'consent_missing',
  'unauthorized_client',
  'tenant_not_found',
  'forbidden',
  'throttled',
  'unavailable',
  'timeout',
  'bad_response',
  'credential_unavailable',
] as const;
export type ProviderErrorCode = (typeof PROVIDER_ERROR_CODES)[number];

export interface ProviderError {
  code: ProviderErrorCode;
  retryable: boolean;
  retryAfterMs?: number;
}

const RETRYABLE: ReadonlySet<ProviderErrorCode> = new Set(['throttled', 'unavailable', 'timeout']);

export class ProviderRequestError extends Error implements ProviderError {
  override readonly name = 'ProviderRequestError';
  readonly code: ProviderErrorCode;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  /** HTTP status of the provider response, when there was one. */
  readonly status?: number;

  constructor(code: ProviderErrorCode, options: { retryAfterMs?: number; status?: number } = {}) {
    super(`Provider request failed: ${code}`);
    this.code = code;
    this.retryable = RETRYABLE.has(code);
    if (options.retryAfterMs !== undefined) this.retryAfterMs = options.retryAfterMs;
    if (options.status !== undefined) this.status = options.status;
  }

  toJSON(): ProviderError & { status?: number } {
    return {
      code: this.code,
      retryable: this.retryable,
      ...(this.retryAfterMs !== undefined ? { retryAfterMs: this.retryAfterMs } : {}),
      ...(this.status !== undefined ? { status: this.status } : {}),
    };
  }
}

export const isProviderRequestError = (error: unknown): error is ProviderRequestError =>
  error instanceof ProviderRequestError;

/** The classified view of any error (unknown errors are `bad_response`, not retryable). */
export function toProviderError(error: unknown): ProviderError {
  if (error instanceof ProviderRequestError) {
    return {
      code: error.code,
      retryable: error.retryable,
      ...(error.retryAfterMs !== undefined ? { retryAfterMs: error.retryAfterMs } : {}),
    };
  }
  return { code: 'bad_response', retryable: false };
}
