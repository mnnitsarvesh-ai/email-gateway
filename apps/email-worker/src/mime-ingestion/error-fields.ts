import { Prisma } from '@email-gateway/database';
import type { RetryClass } from './mime-metrics';

/** A class name or code that is a bare token (never free text that could quote content). */
const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * The only error fields this worker logs (design M15): the error's class name and code, when
 * they are bare tokens. Never `err.message`, `err.stack` or the error object, because parser,
 * decoder and S3 errors can quote message content or object keys.
 */
export function errorFields(error: unknown): { errName?: string; errCode?: string } {
  if (typeof error !== 'object' || error === null) return { errName: typeof error };
  const { name, code } = error as { name?: unknown; code?: unknown };
  const fields: { errName?: string; errCode?: string } = {};
  if (typeof name === 'string' && TOKEN.test(name)) fields.errName = name;
  if ((typeof code === 'string' || typeof code === 'number') && TOKEN.test(String(code))) {
    fields.errCode = String(code);
  }
  return fields;
}

const PRISMA_ERRORS = [
  Prisma.PrismaClientKnownRequestError,
  Prisma.PrismaClientUnknownRequestError,
  Prisma.PrismaClientInitializationError,
  Prisma.PrismaClientRustPanicError,
];

/** Which dependency an infrastructure failure came from (`mime_retries_total{class}`). */
export function retryClassOf(error: unknown, phase: 's3' | 'db'): RetryClass {
  if (PRISMA_ERRORS.some((type) => error instanceof type)) return 'db';
  if (typeof error === 'object' && error !== null && '$metadata' in error) return 's3';
  if (phase === 's3') return 's3';
  return phase === 'db' && error instanceof Error && error.name.startsWith('Prisma')
    ? 'db'
    : 'other';
}

/**
 * Prisma error codes of a dependency that may succeed on retry: connection, pool, timeout,
 * transaction API, write conflict / deadlock. Everything else a query can fail with (P2000 value
 * too long, P2002 unique violation, P2003, P2011, P2020, ...) is a property of the data being
 * written and fails the same way again.
 */
const TRANSIENT_PRISMA_CODES = new Set([
  'P1000',
  'P1001',
  'P1002',
  'P1008',
  'P1011',
  'P1017',
  'P2024',
  'P2028',
  'P2034',
]);
/** MySQL errors of a raw query (P2010 `meta.code`) worth retrying: lock wait, deadlock, lost connection. */
const TRANSIENT_MYSQL_CODES = new Set(['1205', '1213', '2006', '2013']);
/** Node, undici and AWS SDK network or timeout errors (by code or class name). */
const TRANSIENT_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'ETIMEDOUT',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'ESOCKETTIMEDOUT',
]);
const TRANSIENT_NAMES = new Set([
  'AbortError',
  'TimeoutError',
  'NetworkingError',
  'RequestTimeout',
  'RequestTimeoutException',
  'S3Stalled',
  'UploadTimedOut',
]);

/**
 * True when a failed attempt may succeed unchanged on retry (an outage of MySQL, S3 or the
 * network), so the attempt is given back (design M3.10). False for a deterministic failure (a
 * data or contract error, an unexpected exception): that attempt counts toward
 * MIME_MAX_ATTEMPTS, so the poison-message guard ends the message as
 * `parse_failed / max_attempts_exceeded` instead of retrying it forever.
 */
export function isTransientFailure(error: unknown, depth = 0): boolean {
  if (typeof error !== 'object' || error === null || depth > 4) return false;
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (TRANSIENT_PRISMA_CODES.has(error.code)) return true;
    const mysqlCode = (error.meta as { code?: unknown } | undefined)?.code;
    return error.code === 'P2010' && TRANSIENT_MYSQL_CODES.has(String(mysqlCode));
  }
  if (
    error instanceof Prisma.PrismaClientUnknownRequestError ||
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return true;
  }
  // Every S3 service error (5xx, throttling, and also 4xx such as AccessDenied, which is a
  // deployment problem shared by every message, never a property of this one).
  if ('$metadata' in error) return true;
  const { name, code, cause } = error as { name?: unknown; code?: unknown; cause?: unknown };
  if (typeof code === 'string' && (TRANSIENT_CODES.has(code) || code.startsWith('UND_ERR_'))) {
    return true;
  }
  if (typeof name === 'string' && TRANSIENT_NAMES.has(name)) return true;
  return cause !== undefined && cause !== error && isTransientFailure(cause, depth + 1);
}
