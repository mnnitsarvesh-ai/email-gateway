/**
 * A failed OpenSearch call (step 8.1 A16, §7). It exposes only the HTTP status and the
 * OpenSearch error type (`index_not_found_exception`, …) — never a request or response body,
 * a query, an index document or credentials, so it is safe to log and to map to
 * `503 archive_search_unavailable`.
 *
 * `kind`: `http` (a non-2xx status), `timeout` (the per-request deadline), `unavailable`
 * (connection refused, DNS, TLS), `invalid_response` (a 2xx body that is not JSON).
 */
export type OpenSearchErrorKind = 'http' | 'timeout' | 'unavailable' | 'invalid_response';

const ERROR_TYPE = /^[a-z][a-z0-9_]{0,63}$/;

export class OpenSearchError extends Error {
  override readonly name = 'OpenSearchError';
  /** The OpenSearch `error.type`, when the response carried a well-formed one. */
  readonly errorType: string | null;

  constructor(
    readonly kind: OpenSearchErrorKind,
    readonly status: number | null = null,
    errorType: string | null = null,
  ) {
    const type = errorType !== null && ERROR_TYPE.test(errorType) ? errorType : null;
    super(
      `OpenSearch request failed (${kind}${status !== null ? `, status ${status}` : ''}${
        type ? `, ${type}` : ''
      })`,
    );
    this.errorType = type;
  }
}

/** Extracts `error.type` from an OpenSearch error body without keeping anything else. */
export function openSearchErrorType(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const error = (body as { error?: unknown }).error;
  if (typeof error === 'string') return ERROR_TYPE.test(error) ? error : null;
  if (typeof error !== 'object' || error === null) return null;
  const type = (error as { type?: unknown }).type;
  return typeof type === 'string' && ERROR_TYPE.test(type) ? type : null;
}
