import { refreshSession } from '@/lib/session/refresh';
import { emitSessionEvent } from '@/lib/session/events';
import { readCsrfToken } from './csrf';
import { ApiError, networkError, toApiError } from './errors';
import { buildPath } from './operations';
import { operations } from './operations.gen';
import type { OperationId, PathParams, RequestBody } from './types';

/**
 * A raw streaming call of one operation through the BFF proxy (step AI-1 D14): the typed client
 * (openapi-fetch) parses the whole body, so an event stream (`text/event-stream`) is opened here
 * with the same rules as `bffMiddleware`: same-origin `/bff` + the operation's template path, CSRF
 * double submit, `Idempotency-Key` never needed (the assistant turn is idempotent by its
 * `clientTurnId`), and the refresh-once-then-retry rule for `401 access_token_expired` /
 * `unauthorized` before the first byte. The caller reads `response.body` incrementally.
 */
export interface StreamCallInput<Id extends OperationId> {
  readonly path?: PathParams<Id>;
  readonly body?: RequestBody<Id>;
}

export interface StreamCallOptions {
  readonly signal?: AbortSignal;
  /** The `accept` header (default `text/event-stream`). */
  readonly accept?: string;
}

const REFRESHABLE_401 = new Set(['access_token_expired', 'unauthorized']);

function urlFor<Id extends OperationId>(operationId: Id, input: StreamCallInput<Id>): string {
  const op = operations[operationId];
  const origin = typeof window === 'undefined' ? 'http://localhost' : window.location.origin;
  const params = (input.path ?? {}) as Record<string, string>;
  return `${origin}/bff${buildPath(op.path, params)}`;
}

async function errorCodeOf(response: Response): Promise<string | null> {
  try {
    const body = (await response.clone().json()) as { code?: unknown };
    return typeof body.code === 'string' ? body.code : null;
  } catch {
    return null;
  }
}

async function send<Id extends OperationId>(
  operationId: Id,
  input: StreamCallInput<Id>,
  options: StreamCallOptions,
): Promise<Response> {
  const op = operations[operationId];
  const headers = new Headers({ accept: options.accept ?? 'text/event-stream' });
  if (op.method !== 'GET') {
    const csrf = readCsrfToken();
    if (csrf) headers.set('X-CSRF-Token', csrf);
  }
  let body: string | undefined;
  if (input.body !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(input.body);
  }
  return globalThis.fetch(urlFor(operationId, input), {
    method: op.method,
    headers,
    body,
    credentials: 'same-origin',
    cache: 'no-store',
    signal: options.signal,
  });
}

/**
 * Opens the response of a streaming operation. Resolves with an ok `Response` (its body not yet
 * read); a non-2xx answer becomes an `ApiError` (coded envelope), a network failure
 * `network_error`. An abort rejects with the original `AbortError`.
 */
export async function openOperationStream<Id extends OperationId>(
  operationId: Id,
  input: StreamCallInput<Id> = {},
  options: StreamCallOptions = {},
): Promise<Response> {
  const attempt = async (): Promise<Response> => {
    try {
      return await send(operationId, input, options);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      if (options.signal?.aborted) throw error;
      throw networkError(error, operationId);
    }
  };
  let response = await attempt();
  if (response.status === 401) {
    const code = await errorCodeOf(response);
    if (code === 'override_expired') {
      emitSessionEvent({ type: 'override-expired' });
    } else if (code && REFRESHABLE_401.has(code)) {
      let refreshed = false;
      try {
        await refreshSession({ force: code === 'unauthorized' });
        refreshed = true;
      } catch {
        // The refresh coordinator emits `session-expired`; the 401 below is the answer.
      }
      if (refreshed) response = await attempt();
    }
  }
  if (!response.ok) {
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    throw toApiError(response, parsed, operationId);
  }
  return response;
}

/** Whether an error is the abort of a stream the caller cancelled. */
export function isAbortError(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === 'AbortError') ||
    (error instanceof Error && error.name === 'AbortError') ||
    (error instanceof ApiError &&
      error.code === 'network_error' &&
      error.message.includes('cancel'))
  );
}
