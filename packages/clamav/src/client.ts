import { connect, type Socket } from 'node:net';
import { Readable } from 'node:stream';
import {
  ClamdProtocolError,
  ClamdSizeLimitError,
  ClamdTimeoutError,
  ClamdUnavailableError,
  type ClamdOperation,
} from './errors';
import { ConnectionLimiter } from './limiter';
import {
  parseScanReply,
  parseVersion,
  ReplyReader,
  splitSessionReply,
  type ClamdVerdict,
  type ClamdVersion,
} from './reply';

/** Attachment bytes: sent as is when a buffer, streamed (with back-pressure) when a Readable. */
export type ClamdScanInput = Uint8Array | Readable;

export interface ClamdClientOptions {
  /** clamd host (TCP only; no local socket), e.g. `clamav` or `127.0.0.1`. */
  host: string;
  port: number;
  /**
   * Upper bound of one call (`CLAMAV_TIMEOUT_MS`), including the wait for a connection slot;
   * it covers a non-concurrent database reload, during which clamd holds new commands.
   */
  timeoutMs: number;
  /** Most concurrent connections of this client (`CLAMAV_MAX_CONNECTIONS`, 1-64); default 4. */
  maxConnections?: number;
  /** INSTREAM chunk size (`CLAMAV_CHUNK_BYTES`, 1 KiB-8 MiB, <= clamd StreamMaxLength); default 64 KiB. */
  chunkBytes?: number;
}

/** A definite answer plus the engine and database of the clamd that produced it (same IDSESSION). */
export type ClamdScanResult = ClamdVerdict &
  ClamdVersion & {
    /** Input bytes streamed to clamd. */
    bytes: number;
    durationMs: number;
  };

export const CLAMD_MAX_CONNECTIONS_LIMIT = 64;
const DEFAULT_MAX_CONNECTIONS = 4;
const DEFAULT_CHUNK_BYTES = 65_536;
const MIN_CHUNK_BYTES = 1024;
const MAX_CHUNK_BYTES = 8 * 1024 * 1024;
/** Request numbers inside the IDSESSION: clamd numbers commands from 1 in the order received. */
const VERSION_ID = 1;
const INSTREAM_ID = 2;
const SESSION_HEADER = Buffer.from('zIDSESSION\0zVERSION\0zINSTREAM\0', 'latin1');
const SESSION_TRAILER = Buffer.concat([Buffer.alloc(4), Buffer.from('zEND\0', 'latin1')]);
const TIMEOUT = Symbol('clamd-timeout');

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,48}$/.test(code) ? code : 'UNKNOWN';
}

function chunkHeader(length: number): Buffer {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(length, 0);
  return header;
}

/**
 * One TCP connection to clamd: collects null-terminated replies until `expected` arrived and
 * settles `done`. A failure (socket error, early close, timeout, abort) settles it with a typed
 * error; writes after that are dropped (`write` resolves false) so a writer loop stops at once.
 */
class Connection {
  readonly done: Promise<string[]>;
  private readonly socket: Socket;
  private readonly reader = new ReplyReader();
  private readonly replies: string[] = [];
  private settled = false;
  private resolveDone!: (replies: string[]) => void;
  private rejectDone!: (error: unknown) => void;
  private drainWaiters: Array<(open: boolean) => void> = [];

  constructor(
    host: string,
    port: number,
    private readonly operation: ClamdOperation,
    private readonly expected: number,
  ) {
    this.done = new Promise<string[]>((resolve, reject) => {
      this.resolveDone = resolve;
      this.rejectDone = reject;
    });
    // A failure that nobody awaits any more (the writer failed first) is not unhandled.
    this.done.catch(() => undefined);
    this.socket = connect({ host, port });
    this.socket.setNoDelay(true);
    this.socket.on('data', (chunk: Buffer) => this.onData(chunk));
    this.socket.on('drain', () => this.flushDrain(true));
    this.socket.on('error', (error) => {
      this.fail(new ClamdUnavailableError(this.operation, errorCode(error)));
    });
    this.socket.on('close', () => {
      this.flushDrain(false);
      if (this.settled) return;
      // clamd answered fewer replies than commands and hung up: an unexpected (unnumbered)
      // reply such as `UNKNOWN COMMAND`, or nothing at all.
      if (this.replies.length > 0 || this.reader.trailingBytes > 0) {
        this.fail(new ClamdProtocolError(this.operation, 'unexpected_reply'));
      } else {
        this.fail(new ClamdUnavailableError(this.operation, 'CLOSED'));
      }
    });
  }

  get finished(): boolean {
    return this.settled;
  }

  /** Writes with back-pressure; resolves false (nothing written) once the connection settled. */
  write(bytes: Uint8Array): Promise<boolean> {
    if (this.settled) return Promise.resolve(false);
    if (this.socket.write(bytes)) return Promise.resolve(true);
    return new Promise((resolve) => this.drainWaiters.push(resolve));
  }

  fail(error: unknown): void {
    if (this.settled) return;
    this.settled = true;
    this.socket.destroy();
    this.flushDrain(false);
    this.rejectDone(error);
  }

  close(): void {
    this.socket.destroy();
    this.flushDrain(false);
  }

  private onData(chunk: Buffer): void {
    if (this.settled) return;
    let complete: string[];
    try {
      complete = this.reader.push(chunk);
    } catch {
      this.fail(new ClamdProtocolError(this.operation, 'reply_too_large'));
      return;
    }
    this.replies.push(...complete);
    if (this.replies.length >= this.expected) {
      this.settled = true;
      this.socket.destroy();
      this.flushDrain(false);
      this.resolveDone(this.replies.slice());
    }
  }

  private flushDrain(open: boolean): void {
    const waiters = this.drainWaiters;
    this.drainWaiters = [];
    for (const wake of waiters) wake(open && !this.settled);
  }
}

/**
 * clamd client over TCP (step 4.2 A7, docs/plan/steps/10-attachment-scanning.md): `PING`,
 * `VERSION` and `INSTREAM` with the null-terminated (`z`) commands. A scan runs inside one
 * `IDSESSION` together with `VERSION`, so the engine and database recorded for a result are
 * those of the clamd instance that scanned it. Bounded: per-call timeout, at most
 * `maxConnections` sockets, back-pressured writes, bounded reply buffering; the caller's
 * AbortSignal destroys the socket. Every failure is a typed ClamdError; the client decides no
 * platform verdict and never logs.
 */
export class ClamdClient {
  readonly host: string;
  readonly port: number;
  private readonly timeoutMs: number;
  private readonly chunkBytes: number;
  private readonly limiter: ConnectionLimiter;

  constructor(options: ClamdClientOptions) {
    if (typeof options.host !== 'string' || options.host.length === 0) {
      throw new RangeError('ClamdClient host must be a non-empty string');
    }
    if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65_535) {
      throw new RangeError('ClamdClient port must be an integer in 1..65535');
    }
    if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1) {
      throw new RangeError('ClamdClient timeoutMs must be a positive integer');
    }
    const maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    if (
      !Number.isInteger(maxConnections) ||
      maxConnections < 1 ||
      maxConnections > CLAMD_MAX_CONNECTIONS_LIMIT
    ) {
      throw new RangeError(
        `ClamdClient maxConnections must be an integer in 1..${CLAMD_MAX_CONNECTIONS_LIMIT}`,
      );
    }
    const chunkBytes = options.chunkBytes ?? DEFAULT_CHUNK_BYTES;
    if (
      !Number.isInteger(chunkBytes) ||
      chunkBytes < MIN_CHUNK_BYTES ||
      chunkBytes > MAX_CHUNK_BYTES
    ) {
      throw new RangeError(
        `ClamdClient chunkBytes must be an integer in ${MIN_CHUNK_BYTES}..${MAX_CHUNK_BYTES}`,
      );
    }
    this.host = options.host;
    this.port = options.port;
    this.timeoutMs = options.timeoutMs;
    this.chunkBytes = chunkBytes;
    this.limiter = new ConnectionLimiter(maxConnections);
  }

  /** Connections in use / waiting for a slot (metrics and tests). */
  get connections(): { active: number; waiting: number } {
    return { active: this.limiter.inFlight, waiting: this.limiter.waiting };
  }

  /** `zPING` → `PONG` (readiness). */
  async ping(signal?: AbortSignal): Promise<void> {
    const [reply] = await this.call('ping', 1, signal, async (connection) => {
      await connection.write(Buffer.from('zPING\0', 'latin1'));
    });
    if (reply !== 'PONG') throw new ClamdProtocolError('ping', 'unexpected_reply');
  }

  /** `zVERSION` → engine, database version and database time (signature watcher, A13). */
  async version(signal?: AbortSignal): Promise<ClamdVersion> {
    const [reply] = await this.call('version', 1, signal, async (connection) => {
      await connection.write(Buffer.from('zVERSION\0', 'latin1'));
    });
    const version = parseVersion(reply ?? '');
    if (!version) throw new ClamdProtocolError('version', 'invalid_version');
    return version;
  }

  /**
   * Scans one attachment: `zIDSESSION`, `zVERSION`, `zINSTREAM` + `[uint32 BE length][bytes]`
   * chunks + a zero-length chunk, `zEND`. Resolves `clean` or `found` with the version of the
   * scanning clamd; throws ClamdSizeLimitError when clamd refuses the stream size. An error of
   * a Readable input (e.g. an S3 body) is rethrown unchanged.
   */
  async scan(input: ClamdScanInput, signal?: AbortSignal): Promise<ClamdScanResult> {
    const started = performance.now();
    let bytes = 0;
    const replies = await this.call('scan', 2, signal, async (connection) => {
      if (!(await connection.write(SESSION_HEADER))) return;
      for await (const piece of this.pieces(input)) {
        // Header and payload are separate writes (no copy of the payload); only a full
        // socket buffer waits for `drain`.
        if (!(await connection.write(chunkHeader(piece.length)))) return;
        if (!(await connection.write(piece))) return;
        bytes += piece.length;
      }
      await connection.write(SESSION_TRAILER);
    });

    let versionText: string | null = null;
    let scanText: string | null = null;
    for (const reply of replies) {
      const { id, text } = splitSessionReply(reply);
      if (id === VERSION_ID && versionText === null) versionText = text;
      else if (id === INSTREAM_ID && scanText === null) scanText = text;
      else throw new ClamdProtocolError('scan', 'unexpected_reply');
    }
    const version = versionText === null ? null : parseVersion(versionText);
    const outcome = scanText === null ? null : parseScanReply(scanText);
    if (outcome?.status === 'size_limit') throw new ClamdSizeLimitError(version, bytes);
    if (!outcome) throw new ClamdProtocolError('scan', 'unexpected_reply');
    if (outcome.status === 'server_error') throw new ClamdProtocolError('scan', 'server_error');
    if (outcome.status === 'invalid_signature') {
      throw new ClamdProtocolError('scan', 'invalid_signature');
    }
    if (!version) throw new ClamdProtocolError('scan', 'invalid_version');
    const verdict: ClamdVerdict =
      outcome.status === 'found'
        ? { status: 'found', signature: outcome.signature }
        : { status: 'clean' };
    return {
      ...verdict,
      ...version,
      bytes,
      durationMs: Math.round(performance.now() - started),
    };
  }

  /** Splits the input into chunks of at most `chunkBytes` (views, no copies of buffers). */
  private async *pieces(input: ClamdScanInput): AsyncGenerator<Uint8Array> {
    if (input instanceof Readable) {
      for await (const chunk of input as AsyncIterable<unknown>) {
        if (!(chunk instanceof Uint8Array)) {
          throw new TypeError('ClamdClient.scan: the Readable must yield bytes, not strings');
        }
        for (let offset = 0; offset < chunk.length; offset += this.chunkBytes) {
          yield chunk.subarray(offset, offset + this.chunkBytes);
        }
      }
      return;
    }
    if (!(input instanceof Uint8Array)) {
      throw new TypeError('ClamdClient.scan: input must be a Buffer, Uint8Array or Readable');
    }
    for (let offset = 0; offset < input.length; offset += this.chunkBytes) {
      yield input.subarray(offset, offset + this.chunkBytes);
    }
  }

  /**
   * Runs one exchange inside a connection slot and the per-call timeout: opens the socket, runs
   * `writer`, waits for `expected` replies. The writer's own errors win (input stream errors are
   * the caller's); then the connection's typed error; a caller abort rethrows its reason
   * (a TimeoutError reason becomes ClamdTimeoutError).
   */
  private async call(
    operation: ClamdOperation,
    expected: number,
    signal: AbortSignal | undefined,
    writer: (connection: Connection) => Promise<void>,
  ): Promise<string[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(TIMEOUT), this.timeoutMs);
    const onAbort = () => controller.abort(signal?.reason);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
    const abortError = (): unknown => {
      const reason: unknown = controller.signal.reason;
      if (reason === TIMEOUT) return new ClamdTimeoutError(operation, this.timeoutMs);
      if (reason instanceof Error && reason.name === 'TimeoutError') {
        return new ClamdTimeoutError(operation, null);
      }
      return reason;
    };

    let release: (() => void) | null = null;
    let connection: Connection | null = null;
    const onInternalAbort = () => connection?.fail(abortError());
    try {
      try {
        release = await this.limiter.acquire(controller.signal);
      } catch {
        throw abortError();
      }
      if (controller.signal.aborted) throw abortError();
      connection = new Connection(this.host, this.port, operation, expected);
      controller.signal.addEventListener('abort', onInternalAbort, { once: true });
      const active = connection;
      const writing = writer(active).catch((error: unknown) => {
        active.fail(error);
        throw error;
      });
      writing.catch(() => undefined);
      const [, replies] = await Promise.all([writing, active.done]);
      return replies;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      controller.signal.removeEventListener('abort', onInternalAbort);
      connection?.close();
      release?.();
    }
  }
}
