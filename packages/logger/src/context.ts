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
