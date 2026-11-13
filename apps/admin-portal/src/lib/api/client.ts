import createClient, { type Middleware } from 'openapi-fetch';
import { emitSessionEvent } from '@/lib/session/events';
import { refreshSession } from '@/lib/session/refresh';
import { readCsrfToken } from './csrf';
import { ApiError, networkError, toApiError } from './errors';
import type { OperationMeta } from './operation-types';
import { operations, type OperationId } from './operations.gen';
import type { paths } from './schema.gen';

/**
 * The only way feature code reaches the api (design P7): `api.GET('/api/v1/domains', …)` is
 * fully typed from the OpenAPI snapshot and goes to the BFF proxy `/bff/api/v1/domains`.
 * The OpenAPI paths already start with `/api/v1`, so the base URL is `<origin>/bff`.
 */

const byMethodAndPath = new Map<string, OperationMeta & { operationId: OperationId }>();
for (const op of Object.values(operations)) {
  byMethodAndPath.set(`${op.method} ${op.path}`, op);
}

export function operationFor(
  method: string,
  schemaPath: string,
): (OperationMeta & { operationId: OperationId }) | null {
  return byMethodAndPath.get(`${method.toUpperCase()} ${schemaPath}`) ?? null;
}

const IDEMPOTENCY_HEADER = 'Idempotency-Key';
/** 401 codes after which the request is retried once following a successful refresh (P4). */
const REFRESHABLE_401 = new Set(['access_token_expired', 'unauthorized']);
const RETRIED = 'x-eg-portal-retried';

const pending = new Map<string, Request>();

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

async function errorCode(response: Response): Promise<string | null> {
  try {
    const body = (await response.clone().json()) as { code?: unknown };
    return typeof body.code === 'string' ? body.code : null;
  } catch {
    return null;
  }
}

/**
 * CSRF double submit on mutations, an `Idempotency-Key` for `required`/`legacy` operations
 * (the mutation hook supplies one per intent; a key is generated only when none was given),
 * and the refresh-once-then-retry rule.
 */
export const bffMiddleware: Middleware = {
  onRequest({ request, schemaPath, id }) {
    const method = request.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      const csrf = readCsrfToken();
      if (csrf) request.headers.set('X-CSRF-Token', csrf);
      const op = operationFor(method, schemaPath);
      if (op?.idempotency && !request.headers.has(IDEMPOTENCY_HEADER)) {
        request.headers.set(IDEMPOTENCY_HEADER, newIdempotencyKey());
      }
    }
    pending.set(id, request.clone());
    return request;
  },
  async onResponse({ response, id }) {
    const original = pending.get(id);
    pending.delete(id);
    if (response.status !== 401 || !original || original.headers.has(RETRIED)) return response;
    const code = await errorCode(response);
    if (code === 'override_expired') {
      emitSessionEvent({ type: 'override-expired' });
      return response;
    }
    if (!code || !REFRESHABLE_401.has(code)) return response;
    try {
      // The BFF answers `access_token_expired` itself (its cookie says the token expired); an
      // api `unauthorized` with a token the BFF still thinks fresh means the session may have
      // been revoked (logout-all elsewhere, disabled user): force the refresh past the BFF's
      // "fresh enough" short-circuit so a revoked session ends here (session-expired event).
      await refreshSession({ force: code === 'unauthorized' });
    } catch {
      return response;
    }
    const headers = new Headers(original.headers);
    headers.set(RETRIED, '1');
    const csrf = readCsrfToken();
    if (csrf && original.method !== 'GET') headers.set('X-CSRF-Token', csrf);
    const retry = new Request(original, { headers });
    return globalThis.fetch(retry);
  },
  onError({ id }) {
    pending.delete(id);
  },
};

function baseUrl(): string {
  return `${typeof window === 'undefined' ? 'http://localhost' : window.location.origin}/bff`;
}

export const api = createClient<paths>({
  baseUrl: baseUrl(),
  // Late-bound so test interceptors installed after import are honoured.
  fetch: (request: Request) => globalThis.fetch(request),
  credentials: 'same-origin',
  cache: 'no-store',
  // The api's list filters take `field=a,b,c` (docs/api/README.md "Filtering and sorting").
  querySerializer: { array: { style: 'form', explode: false } },
});
api.use(bffMiddleware);

export type ApiClient = typeof api;

/**
 * Unwraps an openapi-fetch result: returns `data` or throws an ApiError (network failures
 * become `network_error`, status 0).
 */
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
  operationId: OperationId | null = null,
): Promise<T> {
  let result: { data?: T; error?: unknown; response: Response };
  try {
    result = await call;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw networkError(error, operationId);
  }
  if (!result.response.ok) throw toApiError(result.response, result.error, operationId);
  return result.data as T;
}
