import { Prisma } from '@email-gateway/database';

/** A class name or code that is a bare token (never free text that could quote content). */
const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;

/** How a consumer treats a handler failure (step 3.2 Q8). */
export type FailureClass = 'transient' | 'retryable' | 'fatal';

/** A handler code that is safe as a dead-letter reason (`x-eg-failure-reason`, metric label). */
export const FAILURE_CODE = /^[a-z0-9_]{1,48}$/;

/**
 * A deterministic failure the handler knows retrying cannot fix (Q8 fatal): the consumer
 * dead-letters the delivery at once with `code` as the reason (`handler_rejected` when the code
 * is not a bare `[a-z0-9_]{1,48}` token).
 */
export class NonRetryableError extends Error {
  override readonly name = 'NonRetryableError';
  constructor(readonly code: string) {
    super(`non-retryable: ${FAILURE_CODE.test(code) ? code : 'handler_rejected'}`);
  }
}

/**
 * The broker cannot take the operation now: disconnected, the channel died, or the connection
 * closed while confirms were pending. Always transient. `reason` is a token (an AMQP reply name
 * such as `ACCESS_REFUSED`, `NOT_FOUND`, or `disconnected`), never broker text.
 */
export class BrokerUnavailableError extends Error {
  override readonly name = 'BrokerUnavailableError';
  readonly code: string;
  constructor(reason = 'disconnected', options?: { cause?: unknown }) {
    super(`broker unavailable: ${TOKEN.test(reason) ? reason : 'disconnected'}`, options);
    this.code = TOKEN.test(reason) ? reason : 'disconnected';
  }
}

/**
 * The only error fields the messaging library logs (step 3.1 M15, step 3.2 Q6): the error's
 * class name and code, when they are bare tokens. Never `err.message`, `err.stack` or the error
 * object, which can quote message content, object keys or broker text.
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

/**
 * Prisma codes of a dependency that may succeed on retry: cannot reach / timed out / closed
 * connection (P1001, P1002, P1008, P1017), pool timeout (P2024), interactive transaction expired
 * (P2028), write conflict or deadlock (P2034). Data errors (P2002, P2003, ...) are not here.
 */
const TRANSIENT_PRISMA_CODES = new Set([
  'P1001',
  'P1002',
  'P1008',
  'P1017',
  'P2024',
  'P2028',
  'P2034',
]);
/** MySQL codes of a raw query (P2010 `meta.code`): lock wait timeout, deadlock, gone away, lost. */
const TRANSIENT_MYSQL_CODES = new Set(['1205', '1213', '2006', '2013']);
/** Node / undici socket and DNS errors. */
const TRANSIENT_SOCKET_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'ESOCKETTIMEDOUT',
]);
const TRANSIENT_NAMES = new Set(['AbortError', 'TimeoutError', 'BrokerUnavailableError']);
/** AWS SDK throttling error names (with `$metadata`). */
const AWS_THROTTLING_NAMES = new Set([
  'Throttling',
  'ThrottlingException',
  'ThrottledException',
  'TooManyRequestsException',
  'RequestLimitExceeded',
  'RequestThrottled',
  'RequestThrottledException',
  'ProvisionedThroughputExceededException',
  'SlowDown',
  'BandwidthLimitExceeded',
  'TransactionInProgressException',
  'RequestTimeout',
  'RequestTimeoutException',
  'InternalError',
  'ServiceUnavailable',
]);

function isAwsTransient(error: object): boolean {
  const { $metadata, $retryable, name } = error as {
    $metadata?: { httpStatusCode?: unknown };
    $retryable?: { throttling?: unknown };
    name?: unknown;
  };
  const status = $metadata?.httpStatusCode;
  if (typeof status === 'number' && (status >= 500 || status === 429)) return true;
  if ($retryable !== undefined && $retryable !== null) return true;
  return typeof name === 'string' && AWS_THROTTLING_NAMES.has(name);
}

/**
 * True when a failure is an outage of a dependency (MySQL, S3, the network, the broker) that
 * may pass unchanged on retry, so the consumer gives the attempt back (Q8 transient): Prisma
 * connection/pool/timeout/transaction/write-conflict codes and initialization or unknown-request
 * errors, MySQL lock wait/deadlock, AWS SDK 5xx/429/throttling, socket errors, `AbortError` /
 * `TimeoutError`, `BrokerUnavailableError`; follows `cause` (bounded).
 */
export function isTransientInfrastructureError(error: unknown, depth = 0): boolean {
  if (typeof error !== 'object' || error === null || depth > 4) return false;
  if (error instanceof BrokerUnavailableError) return true;
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (TRANSIENT_PRISMA_CODES.has(error.code)) return true;
    const mysqlCode = (error.meta as { code?: unknown } | undefined)?.code;
    return error.code === 'P2010' && TRANSIENT_MYSQL_CODES.has(String(mysqlCode));
  }
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientUnknownRequestError
  ) {
    return true;
  }
  if ('$metadata' in error && isAwsTransient(error)) return true;
  const { name, code, errno, cause } = error as {
    name?: unknown;
    code?: unknown;
    errno?: unknown;
    cause?: unknown;
  };
  // A Prisma-shaped error from another copy of the client (or a plain object in tests).
  if (typeof code === 'string' && TRANSIENT_PRISMA_CODES.has(code)) return true;
  if (
    typeof code === 'string' &&
    (TRANSIENT_SOCKET_CODES.has(code) || code.startsWith('UND_ERR_'))
  ) {
    return true;
  }
  if (
    (typeof errno === 'number' || typeof errno === 'string') &&
    TRANSIENT_MYSQL_CODES.has(String(errno))
  ) {
    return true;
  }
  if (typeof name === 'string' && TRANSIENT_NAMES.has(name)) return true;
  return cause !== undefined && cause !== error && isTransientInfrastructureError(cause, depth + 1);
}

/** `NonRetryableError` → fatal; an infrastructure outage → transient; anything else → retryable. */
export function defaultClassify(error: unknown): FailureClass {
  if (error instanceof NonRetryableError) return 'fatal';
  return isTransientInfrastructureError(error) ? 'transient' : 'retryable';
}

/** AMQP 0-9-1 reply codes (channel/connection close, basic.return) as tokens for logs. */
const AMQP_REPLY_NAMES: Readonly<Record<number, string>> = {
  311: 'CONTENT_TOO_LARGE',
  312: 'NO_ROUTE',
  313: 'NO_CONSUMERS',
  320: 'CONNECTION_FORCED',
  402: 'INVALID_PATH',
  403: 'ACCESS_REFUSED',
  404: 'NOT_FOUND',
  405: 'RESOURCE_LOCKED',
  406: 'PRECONDITION_FAILED',
  501: 'FRAME_ERROR',
  502: 'SYNTAX_ERROR',
  503: 'COMMAND_INVALID',
  504: 'CHANNEL_ERROR',
  505: 'UNEXPECTED_FRAME',
  506: 'RESOURCE_ERROR',
  530: 'NOT_ALLOWED',
  540: 'NOT_IMPLEMENTED',
  541: 'INTERNAL_ERROR',
};

/**
 * The AMQP reply name of an amqplib error or reply code (`ACCESS_REFUSED`, `NOT_FOUND`, ...),
 * `fallback` when there is none. Never the broker's reply text (it quotes object names and
 * user names).
 */
export function amqpReplyName(errorOrCode: unknown, fallback = 'channel_closed'): string {
  const code =
    typeof errorOrCode === 'number'
      ? errorOrCode
      : typeof errorOrCode === 'object' && errorOrCode !== null
        ? (errorOrCode as { code?: unknown }).code
        : undefined;
  if (typeof code === 'number') return AMQP_REPLY_NAMES[code] ?? `amqp_${code}`;
  if (typeof code === 'string' && TOKEN.test(code)) return code;
  return fallback;
}
