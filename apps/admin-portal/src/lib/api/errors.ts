import type { OperationId } from './operations.gen';

/**
 * Normalized API error (design P8): the api envelope `{ statusCode, error, code, message,
 * requestId, correlationId, ... }`, portal-coded BFF errors (same shape) and network failures.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** A string, or `"<path>: <issue>"` strings for `validation_failed`. */
  readonly apiMessage: string | string[];
  readonly requestId: string | null;
  readonly correlationId: string | null;
  readonly retryAfterSeconds: number | null;
  /** Additional coded fields of the envelope (ids, states, versions; never content). */
  readonly details: Readonly<Record<string, unknown>>;
  readonly operationId: OperationId | null;

  constructor(init: {
    status: number;
    code: string;
    message: string | string[];
    requestId?: string | null;
    correlationId?: string | null;
    retryAfterSeconds?: number | null;
    details?: Record<string, unknown>;
    operationId?: OperationId | null;
  }) {
    super(Array.isArray(init.message) ? init.message.join('; ') : init.message);
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.apiMessage = init.message;
    this.requestId = init.requestId ?? null;
    this.correlationId = init.correlationId ?? null;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.details = init.details ?? {};
    this.operationId = init.operationId ?? null;
  }

  /** Message lines for display. */
  get messages(): string[] {
    return Array.isArray(this.apiMessage) ? this.apiMessage : [this.apiMessage];
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

const DEFAULT_CODES: Record<number, string> = {
  400: 'validation_failed',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  413: 'payload_too_large',
  415: 'unsupported_media_type',
  422: 'unprocessable',
  429: 'rate_limited',
  500: 'internal_error',
  502: 'upstream_unavailable',
  503: 'service_unavailable',
  504: 'upstream_timeout',
};

export function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, Math.ceil((date - Date.now()) / 1000));
  return null;
}

const ENVELOPE_KEYS = new Set([
  'statusCode',
  'error',
  'code',
  'message',
  'requestId',
  'correlationId',
]);

/** Builds an ApiError from a non-2xx response and its parsed body (any shape). */
export function toApiError(
  response: Pick<Response, 'status' | 'headers'>,
  body: unknown,
  operationId: OperationId | null = null,
): ApiError {
  const envelope = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const rawMessage = envelope.message;
  const message =
    typeof rawMessage === 'string'
      ? rawMessage
      : Array.isArray(rawMessage) && rawMessage.every((m) => typeof m === 'string')
        ? rawMessage
        : `Request failed with status ${response.status}`;
  const details: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (!ENVELOPE_KEYS.has(key)) details[key] = value;
  }
  return new ApiError({
    status: response.status,
    code:
      typeof envelope.code === 'string'
        ? envelope.code
        : (DEFAULT_CODES[response.status] ?? 'error'),
    message,
    requestId:
      (typeof envelope.requestId === 'string' ? envelope.requestId : null) ??
      response.headers.get('x-request-id'),
    correlationId:
      (typeof envelope.correlationId === 'string' ? envelope.correlationId : null) ??
      response.headers.get('x-correlation-id'),
    retryAfterSeconds: parseRetryAfter(response.headers.get('retry-after')),
    details,
    operationId,
  });
}

export function networkError(error: unknown, operationId: OperationId | null = null): ApiError {
  return new ApiError({
    status: 0,
    code: 'network_error',
    message:
      error instanceof Error && error.name === 'AbortError'
        ? 'The request was cancelled'
        : 'The portal could not be reached; check your connection',
    operationId,
  });
}

/**
 * Splits `validation_failed` messages (`"<path>: <issue>"`) into field errors (for the given
 * form field names) and form-level messages (P8).
 */
export function mapValidationErrors(
  error: ApiError,
  fields: readonly string[],
): { fieldErrors: Record<string, string>; formErrors: string[] } {
  const fieldErrors: Record<string, string> = {};
  const formErrors: string[] = [];
  if (error.status !== 400) return { fieldErrors, formErrors: error.messages };
  for (const line of error.messages) {
    const index = line.indexOf(': ');
    const path = index > 0 ? line.slice(0, index) : '';
    const issue = index > 0 ? line.slice(index + 2) : line;
    const field = fields.find((name) => path === name || path.startsWith(`${name}.`));
    if (field && !fieldErrors[field]) fieldErrors[field] = issue;
    else formErrors.push(line);
  }
  return { fieldErrors, formErrors };
}
