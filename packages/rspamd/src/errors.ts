/**
 * Typed transport errors of the Rspamd client (docs/plan/steps/09-rspamd.md S9, S7 R0). Every
 * message is built here from fixed text, ids and numbers only: no error ever carries a message
 * body, a request or reply header value, a symbol option or a password (§2.0 invariant 2).
 * Underlying errors are reduced to a short code (`causeCode`) and never attached as `cause`.
 */
export type RspamdErrorKind =
  'timeout' | 'unavailable' | 'http_error' | 'protocol_error' | 'soft_reject' | 'invalid_request';

export abstract class RspamdError extends Error {
  abstract readonly kind: RspamdErrorKind;
  /** Whether repeating the same call later can succeed (R0 failures are attempt failures). */
  abstract readonly retryable: boolean;
  /** Which endpoint failed (`checkv2`, `learnspam`, `fuzzyadd`, `stat`, …). */
  readonly operation: string;

  protected constructor(operation: string, message: string) {
    super(message);
    this.name = new.target.name;
    this.operation = operation;
  }
}

/** The per-call timeout (or the caller's timeout signal) expired before the reply was read. */
export class RspamdTimeoutError extends RspamdError {
  readonly kind = 'timeout' as const;
  readonly retryable = true;
  readonly timeoutMs: number | null;

  constructor(operation: string, timeoutMs: number | null) {
    super(
      operation,
      timeoutMs === null
        ? `rspamd ${operation} timed out`
        : `rspamd ${operation} timed out after ${timeoutMs} ms`,
    );
    this.timeoutMs = timeoutMs;
  }
}

/** Connection refused/reset, DNS failure of the Rspamd host, socket closed mid-reply. */
export class RspamdUnavailableError extends RspamdError {
  readonly kind = 'unavailable' as const;
  readonly retryable = true;
  /** System or undici error code (`ECONNREFUSED`, `UND_ERR_SOCKET`, …), never a message. */
  readonly causeCode: string;

  constructor(operation: string, causeCode: string) {
    super(operation, `rspamd ${operation} unavailable (${causeCode})`);
    this.causeCode = causeCode;
  }
}

/** Rspamd answered with an HTTP status >= 400 (401 wrong password, 404 nothing to hash, …). */
export class RspamdHttpError extends RspamdError {
  readonly kind = 'http_error' as const;
  readonly status: number;
  readonly retryable: boolean;

  constructor(operation: string, status: number) {
    super(operation, `rspamd ${operation} answered HTTP ${status}`);
    this.status = status;
    // Server-side and throttling errors can pass; client errors repeat identically.
    this.retryable = status >= 500 || status === 408 || status === 429;
  }
}

/** The reply was not JSON, did not match the expected schema or exceeded the size limit. */
export class RspamdProtocolError extends RspamdError {
  readonly kind = 'protocol_error' as const;
  readonly retryable = true;
  /** `invalid_json`, `schema_mismatch`, `reply_too_large`, `unexpected_reply`. */
  readonly reason: string;
  /** Paths of the schema issues (field names only, never values). */
  readonly issuePaths: readonly string[];

  constructor(operation: string, reason: string, issuePaths: readonly string[] = []) {
    const where = issuePaths.length > 0 ? ` at ${issuePaths.slice(0, 5).join(', ')}` : '';
    super(operation, `rspamd ${operation} protocol error: ${reason}${where}`);
    this.reason = reason;
    this.issuePaths = issuePaths;
  }
}

/** The scan ended with the `soft reject` action (Rspamd could not finish it, e.g. a timeout). */
export class RspamdSoftRejectError extends RspamdError {
  readonly kind = 'soft_reject' as const;
  readonly retryable = true;

  constructor(operation: string) {
    super(operation, `rspamd ${operation} returned soft reject`);
  }
}

/**
 * The request cannot be built safely (a header value with CR/LF, an envelope sender that is
 * not a mailbox, a missing controller password). Repeating it never helps.
 */
export class RspamdRequestError extends RspamdError {
  readonly kind = 'invalid_request' as const;
  readonly retryable = false;
  /** The offending field name (`From`, `Log-Tag`, `controllerPassword`, …), never its value. */
  readonly field: string;

  constructor(operation: string, field: string, problem: string) {
    super(operation, `rspamd ${operation}: invalid ${field} (${problem})`);
    this.field = field;
  }
}

export function isRspamdError(error: unknown): error is RspamdError {
  return error instanceof RspamdError;
}
