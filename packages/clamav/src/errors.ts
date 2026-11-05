import type { ClamdVersion } from './reply';

/**
 * Typed transport errors of the clamd client (docs/plan/steps/10-attachment-scanning.md A7).
 * Every message is built here from fixed text, codes and numbers only: no error ever carries
 * attachment bytes, a reply text or a host name (§2.0 invariant 2). Underlying errors are
 * reduced to a short code (`causeCode`) and never attached as `cause`.
 */
export type ClamdErrorKind = 'unavailable' | 'timeout' | 'protocol_error' | 'size_limit';

/** `ping`, `version` or `scan`. */
export type ClamdOperation = 'ping' | 'version' | 'scan';

export abstract class ClamdError extends Error {
  abstract readonly kind: ClamdErrorKind;
  /** Whether repeating the same call later can succeed (attempt failure vs definite answer). */
  abstract readonly retryable: boolean;
  readonly operation: ClamdOperation;

  protected constructor(operation: ClamdOperation, message: string) {
    super(message);
    this.name = new.target.name;
    this.operation = operation;
  }
}

/** Connection refused/reset, DNS failure, socket closed before a complete reply. */
export class ClamdUnavailableError extends ClamdError {
  readonly kind = 'unavailable' as const;
  readonly retryable = true;
  /** System error code (`ECONNREFUSED`, `ECONNRESET`, `ENOTFOUND`, `CLOSED`, …), never a message. */
  readonly causeCode: string;

  constructor(operation: ClamdOperation, causeCode: string) {
    super(operation, `clamd ${operation} unavailable (${causeCode})`);
    this.causeCode = causeCode;
  }
}

/** The per-call timeout (or the caller's timeout signal) expired before the reply was read. */
export class ClamdTimeoutError extends ClamdError {
  readonly kind = 'timeout' as const;
  readonly retryable = true;
  readonly timeoutMs: number | null;

  constructor(operation: ClamdOperation, timeoutMs: number | null) {
    super(
      operation,
      timeoutMs === null
        ? `clamd ${operation} timed out`
        : `clamd ${operation} timed out after ${timeoutMs} ms`,
    );
    this.timeoutMs = timeoutMs;
  }
}

/**
 * The reply could not be parsed or reported a clamd-side error. `reason`: `unexpected_reply`
 * (unparseable text, wrong session id), `reply_too_large`, `invalid_signature` (a FOUND name
 * outside `^[\x21-\x7e]{1,128}$`), `invalid_version`, `server_error` (`… ERROR` other than the
 * size limit, e.g. a clamd allocation failure or a command read timeout).
 */
export class ClamdProtocolError extends ClamdError {
  readonly kind = 'protocol_error' as const;
  readonly retryable = true;
  readonly reason: string;

  constructor(operation: ClamdOperation, reason: string) {
    super(operation, `clamd ${operation} protocol error: ${reason}`);
    this.reason = reason;
  }
}

/**
 * clamd refused the stream: `INSTREAM size limit exceeded` (the stream is longer than its
 * `StreamMaxLength`). A definite answer about this input, not retryable: the attachment engine
 * maps it to `limit.clamav` (suspicious) and logs it at warn, because configuration keeps
 * `StreamMaxLength` above `ATTACHMENT_MAX_BYTES`.
 */
export class ClamdSizeLimitError extends ClamdError {
  readonly kind = 'size_limit' as const;
  readonly retryable = false;
  /** Version of the clamd that refused the stream (from the same IDSESSION); null if not read. */
  readonly version: ClamdVersion | null;
  /** Bytes of the input written before clamd refused it. */
  readonly bytesSent: number;

  constructor(version: ClamdVersion | null, bytesSent: number) {
    super('scan', `clamd scan refused the stream: size limit exceeded after ${bytesSent} bytes`);
    this.version = version;
    this.bytesSent = bytesSent;
  }
}

export function isClamdError(error: unknown): error is ClamdError {
  return error instanceof ClamdError;
}
