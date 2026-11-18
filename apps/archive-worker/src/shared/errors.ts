/**
 * Error codes of the archive-worker (stored in `last_error_code`, `error_code` and logs). Codes
 * are tokens: never a message, an address, a subject, an object key or an OpenSearch reason.
 */

/** A failure whose cause will not change on retry (A5.7): the intent fails at once. */
export class DeterministicCaptureError extends Error {
  constructor(readonly code: 'integrity_mismatch' | 'object_lock_unavailable' | 'facts_invalid') {
    super(`capture failed: ${code}`);
    this.name = 'DeterministicCaptureError';
  }
}

/** The original object is gone (mail-bucket lifecycle): the intent ends `lost`. */
export class OriginalMissingError extends Error {
  readonly code = 'original_missing';
  constructor() {
    super('original object missing');
    this.name = 'OriginalMissingError';
  }
}

/** The archive bucket's Object Lock availability is not known yet (probe pending): retried. */
export class ObjectLockUnknownError extends Error {
  readonly code = 'object_lock_unprobed';
  constructor() {
    super('object lock availability not probed yet');
    this.name = 'ObjectLockUnknownError';
  }
}

/** A row read on the writer did not echo its organization or partition key. */
export class InconsistentReadError extends Error {
  constructor(readonly code: string) {
    super(`inconsistent read: ${code}`);
    this.name = 'InconsistentReadError';
  }
}

/** The claimed lease was lost (another replica took over after expiry): nothing is written. */
export class LeaseLostError extends Error {
  readonly code = 'lease_lost';
  constructor() {
    super('lease lost');
    this.name = 'LeaseLostError';
  }
}

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/** A bounded code for `last_error_code` columns: the error's code (or name), never its message. */
export function errorCode(error: unknown, fallback = 'error'): string {
  const e = error as { code?: unknown; name?: unknown; Code?: unknown } | null;
  for (const candidate of [e?.code, e?.Code, e?.name]) {
    if (typeof candidate === 'string' && TOKEN.test(candidate)) return candidate.slice(0, 64);
  }
  return fallback;
}

/** Log fields of an error: class name, code and HTTP status only (never the message). */
export function errorFields(error: unknown): Record<string, unknown> {
  const e = error as {
    name?: unknown;
    code?: unknown;
    kind?: unknown;
    status?: unknown;
    errorType?: unknown;
    $metadata?: { httpStatusCode?: unknown };
  } | null;
  const out: Record<string, unknown> = {};
  if (typeof e?.name === 'string') out.errName = e.name;
  if (typeof e?.code === 'string' && TOKEN.test(e.code)) out.errCode = e.code;
  if (typeof e?.kind === 'string') out.errKind = e.kind;
  if (typeof e?.status === 'number') out.status = e.status;
  if (typeof e?.errorType === 'string' && TOKEN.test(e.errorType)) out.errorType = e.errorType;
  if (typeof e?.$metadata?.httpStatusCode === 'number') out.status = e.$metadata.httpStatusCode;
  return out;
}

/** Prisma unique-constraint violation (P2002) or the raw MySQL duplicate-key error (1062). */
export function isUniqueViolation(error: unknown): boolean {
  const e = error as { code?: unknown; meta?: { code?: unknown } } | null;
  return e?.code === 'P2002' || (e?.code === 'P2010' && e.meta?.code === '1062');
}
