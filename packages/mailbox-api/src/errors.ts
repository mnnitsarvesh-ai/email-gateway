/**
 * The one error type of the mailbox clients (design D9): the 8.5 provider vocabulary
 * (`ProviderCallError` codes) plus `cursor_expired` (Graph `410 syncStateNotFound`, Gmail `404`
 * on history) and `throttle_paused` (the connection-family is paused by an earlier `Retry-After`).
 *
 * Like `ProviderCallError`, an error carries only a code, the HTTP status, whether it is
 * retryable, the wait hint and a sanitized provider error code: never a header, token, URL, delta
 * link, query string, address, subject or body.
 */
import {
  ConnectionAccessError,
  PROVIDER_ERROR_CODES,
  ProviderCallError,
  toProviderCallError,
  type ProviderErrorCode,
} from '@email-gateway/idp-adapters';

export const MAILBOX_API_ERROR_CODES = [
  ...PROVIDER_ERROR_CODES,
  'cursor_expired',
  'throttle_paused',
] as const;
export type MailboxApiErrorCode = (typeof MAILBOX_API_ERROR_CODES)[number];

/** Graph's codes for an expired or invalid delta state. */
const GRAPH_SYNC_STATE_CODE = /^(syncStateNotFound|syncStateInvalid|resyncRequired)$/i;
/** Graph's mailbox access-denied code (403), meaning a missing Mail permission. */
const GRAPH_ACCESS_DENIED = /^ErrorAccessDenied$/i;

export class MailboxApiError extends Error {
  override readonly name = 'MailboxApiError';
  readonly code: MailboxApiErrorCode;
  readonly retryable: boolean;
  readonly retryAfterMs: number | undefined;
  readonly status: number | undefined;
  /** Sanitized provider code (`syncStateNotFound`, `rateLimitExceeded`, …). */
  readonly providerCode: string | undefined;

  constructor(
    code: MailboxApiErrorCode,
    options: {
      retryable?: boolean;
      retryAfterMs?: number;
      status?: number;
      providerCode?: string;
    } = {},
  ) {
    super(code);
    this.code = code;
    this.retryable = options.retryable ?? (code === 'throttle_paused' || code === 'rate_budget');
    this.retryAfterMs = options.retryAfterMs;
    this.status = options.status;
    this.providerCode = options.providerCode;
  }

  /** JSON shape for logs: classified fields only. */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      retryable: this.retryable,
      retryAfterMs: this.retryAfterMs,
      status: this.status,
      providerCode: this.providerCode,
    };
  }
}

export function isMailboxApiError(error: unknown): error is MailboxApiError {
  return error instanceof MailboxApiError;
}

function fromProviderCallError(error: ProviderCallError): MailboxApiError {
  let code: MailboxApiErrorCode = error.code;
  if (code === 'forbidden' && error.providerCode && GRAPH_ACCESS_DENIED.test(error.providerCode)) {
    code = 'missing_permission';
  }
  return new MailboxApiError(code, {
    retryable: error.retryable,
    ...(error.retryAfterMs !== undefined ? { retryAfterMs: error.retryAfterMs } : {}),
    ...(error.status !== undefined ? { status: error.status } : {}),
    ...(error.providerCode !== undefined ? { providerCode: error.providerCode } : {}),
  });
}

/**
 * Normalizes anything thrown by a provider call (HTTP client, token source, extractor) into a
 * `MailboxApiError`. Unknown errors become `provider_unavailable` (retryable) without their text.
 */
export function toMailboxApiError(error: unknown): MailboxApiError {
  if (error instanceof MailboxApiError) return error;
  if (error instanceof ProviderCallError || error instanceof ConnectionAccessError) {
    return fromProviderCallError(toProviderCallError(error));
  }
  return fromProviderCallError(new ProviderCallError('provider_unavailable'));
}

/** Graph delta: `410`, or a sync-state code, means the stored delta link is gone. */
export function isGraphCursorExpired(error: MailboxApiError): boolean {
  return (
    error.status === 410 ||
    (error.providerCode !== undefined && GRAPH_SYNC_STATE_CODE.test(error.providerCode))
  );
}

export const cursorExpired = (status: number | undefined, providerCode?: string): MailboxApiError =>
  new MailboxApiError('cursor_expired', {
    retryable: false,
    ...(status !== undefined ? { status } : {}),
    ...(providerCode !== undefined ? { providerCode } : {}),
  });

/** Codes that are 8.5 provider codes (useful for metrics labels). */
export const isProviderErrorCode = (code: MailboxApiErrorCode): code is ProviderErrorCode =>
  (PROVIDER_ERROR_CODES as readonly string[]).includes(code);
