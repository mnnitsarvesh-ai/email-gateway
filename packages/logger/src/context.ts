import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

/** Request/message-scoped context propagated through async calls. */
export interface RequestContext {
  correlationId: string;
  /**
   * The organization id (`organizations.id`, a decimal string). The field keeps the name
   * `tenantId` for log schema stability. Set only after authentication resolves the tenant.
   * Never taken from client headers.
   */
  tenantId?: string;
  /**
   * Server-minted id of one HTTP request (step 6.1 D1, the api's `X-Request-Id`). Never taken from
   * client headers (clients use the correlation id for their own ids).
   */
  requestId?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

export const CORRELATION_ID_HEADER = 'x-correlation-id';

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

/** Accepts a caller-supplied correlation id only if it is well formed; otherwise mints a new one. */
export function normalizeCorrelationId(candidate: unknown): string {
  return typeof candidate === 'string' && CORRELATION_ID_PATTERN.test(candidate)
    ? candidate
    : randomUUID();
}

export function runWithContext<T>(context: RequestContext, fn: () => T): T {
  return storage.run(context, fn);
}

export function getContext(): RequestContext | undefined {
  return storage.getStore();
}

export function getCorrelationId(): string | undefined {
  return storage.getStore()?.correlationId;
}

/**
 * Records the authenticated tenant (decimal `organizations.id`) on the current request context so
 * every later log line carries it. Called by the API's authentication guard only, after the
 * principal is resolved; a no-op outside a context.
 */
export function setContextTenant(organizationId: string): void {
  const store = storage.getStore();
  if (store) store.tenantId = organizationId;
}

/**
 * Records the server-minted request id (step 6.1 D1) on the current request context so every
 * later log line carries it. Called by the API's request-id middleware; a no-op outside a context.
 */
export function setContextRequestId(requestId: string): void {
  const store = storage.getStore();
  if (store) store.requestId = requestId;
}

export function getRequestId(): string | undefined {
  return storage.getStore()?.requestId;
}
