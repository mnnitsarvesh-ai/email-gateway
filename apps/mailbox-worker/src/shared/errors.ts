/**
 * Error helpers of the mailbox-worker. Logs carry class names and codes only: never a message
 * (which could quote an address, a delta link or provider text), never a stack.
 */

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/** A row read on the writer did not echo its organization or key (retryable). */
export class InconsistentReadError extends Error {
  readonly code = 'inconsistent_read';
  constructor(readonly what: string) {
    super(`inconsistent read: ${what}`);
    this.name = 'InconsistentReadError';
  }
}

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

/** The lower-case domain of an address (logs carry the domain at most, never the local part). */
export function domainOf(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return address
    .slice(at + 1)
    .trim()
    .toLowerCase();
}
