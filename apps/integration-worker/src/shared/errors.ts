import { isProviderRequestError } from '@email-gateway/provider-integrations';

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * A bounded code for `last_error_code` columns and check evidence: the classified provider code,
 * the error's own code or name — never its message (messages may carry provider text).
 */
export function errorCode(error: unknown, fallback = 'error'): string {
  if (isProviderRequestError(error)) return error.code;
  const e = error as { code?: unknown; name?: unknown } | null;
  for (const candidate of [e?.code, e?.name]) {
    if (typeof candidate === 'string' && TOKEN.test(candidate)) return candidate.slice(0, 64);
  }
  return fallback;
}

/** Log fields of an error: class name, code and HTTP status only (never the message). */
export function errorFields(error: unknown): Record<string, unknown> {
  const e = error as { name?: unknown; code?: unknown; status?: unknown } | null;
  const out: Record<string, unknown> = {};
  if (typeof e?.name === 'string') out.errName = e.name;
  if (typeof e?.code === 'string' && TOKEN.test(e.code)) out.errCode = e.code;
  if (typeof e?.status === 'number') out.status = e.status;
  return out;
}

/** Provider codes that mean "the provider is unavailable right now" (D15: `error`, not `fail`). */
const TRANSIENT: ReadonlySet<string> = new Set(['throttled', 'unavailable', 'timeout']);

export const isTransientProviderError = (error: unknown): boolean =>
  isProviderRequestError(error) && TRANSIENT.has(error.code);

/** Prisma unique-constraint violation (P2002) or the raw MySQL duplicate-key error (1062). */
export function isUniqueViolation(error: unknown): boolean {
  const e = error as { code?: unknown; meta?: { code?: unknown } } | null;
  return e?.code === 'P2002' || (e?.code === 'P2010' && e.meta?.code === '1062');
}
