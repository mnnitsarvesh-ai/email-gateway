/**
 * Error helpers of the ato-worker. Logs carry class names and codes only: never a message (which
 * could quote an address, an IP or provider text), never a stack.
 */

/** A row read on the writer did not echo its organization or key (retryable, D3). */
export class InconsistentReadError extends Error {
  readonly code = 'inconsistent_read';
  constructor(readonly what: string) {
    super(`inconsistent read: ${what}`);
    this.name = 'InconsistentReadError';
  }
}

/** A transient dependency failure (Redis down for the detect role): the event is retried. */
export class DependencyUnavailableError extends Error {
  constructor(readonly code: string) {
    super(`dependency unavailable: ${code}`);
    this.name = 'DependencyUnavailableError';
  }
}

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/** A bounded code: the error's code (or name), never its message. */
export function errorCode(error: unknown, fallback = 'error'): string {
  const e = error as { code?: unknown; name?: unknown } | null;
  for (const candidate of [e?.code, e?.name]) {
    if (typeof candidate === 'string' && TOKEN.test(candidate)) return candidate.slice(0, 64);
  }
  return fallback;
}

/** Log fields of an error: class name and code only. */
export function errorFields(error: unknown): Record<string, unknown> {
  const e = error as { name?: unknown; code?: unknown } | null;
  const out: Record<string, unknown> = {};
  if (typeof e?.name === 'string' && TOKEN.test(e.name)) out.errName = e.name;
  if (typeof e?.code === 'string' && TOKEN.test(e.code)) out.errCode = e.code;
  return out;
}
