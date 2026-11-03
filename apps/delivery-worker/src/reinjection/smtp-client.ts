import { createConnection, type Socket } from 'node:net';

/**
 * A small purpose-built SMTP client for the worker's own hop into postfix-outbound (step 2.3
 * R8): plaintext on the internal network, XFORWARD, DSN parameters, strict reply parsing,
 * streaming DATA with dot-stuffing. Not a general-purpose client (no TLS, no AUTH, no
 * PIPELINING: commands are sent one at a time).
 */

/** RFC 5321 §4.5.3.1.5: 512 octets including CRLF; tolerated up to this length. */
export const MAX_REPLY_LINE_BYTES = 2048;
/** A whole (multi-line) reply above this is a protocol error. */
export const MAX_REPLY_BYTES = 64 * 1024;

export interface SmtpReply {
  code: number;
  /** RFC 3463 enhanced status of the first line (`2.0.0`), when present. */
  enhancedStatus: string | null;
  /** Text of every line (without code and separator). */
  lines: string[];
  /** Lines joined with a space (the reply as Postfix logs it). */
  text: string;
}

export type SmtpErrorKind = 'connection' | 'timeout' | 'protocol';

/**
 * Every failure of a session. `afterDot` = the final `.` of DATA was (being) written: the
 * server may have queued the message, so the outcome is **ambiguous** (R8: leave the
 * reinjection to the reconciler, never retry blindly).
 */
export class SmtpClientError extends Error {
  constructor(
    readonly kind: SmtpErrorKind,
    message: string,
    readonly afterDot: boolean,
  ) {
    super(message);
    this.name = 'SmtpClientError';
  }

  get ambiguous(): boolean {
    return this.afterDot;
  }
}

export class SmtpConnectionError extends SmtpClientError {
  constructor(message: string, afterDot: boolean) {
    super('connection', message, afterDot);
    this.name = 'SmtpConnectionError';
  }
}

export class SmtpTimeoutError extends SmtpClientError {
  constructor(message: string, afterDot: boolean) {
    super('timeout', message, afterDot);
    this.name = 'SmtpTimeoutError';
  }
}

export class SmtpProtocolError extends SmtpClientError {
  constructor(message: string, afterDot: boolean) {
    super('protocol', message, afterDot);
    this.name = 'SmtpProtocolError';
  }
}

/** True for a failure after the final dot (outcome unknown). */
export const isAmbiguousSmtpError = (error: unknown): boolean =>
  error instanceof SmtpClientError && error.afterDot;

/**
 * RFC 3461 §4 xtext over the UTF-8 bytes: `!`..`~` except `+` and `=` as is, everything else
 * `+HH` (upper-case hex). Used for XFORWARD values, ENVID and ORCPT.
 */
export function xtext(value: string): string {
  let out = '';
  for (const byte of Buffer.from(value, 'utf8')) {
    if (byte >= 0x21 && byte <= 0x7e && byte !== 0x2b && byte !== 0x3d) {
      out += String.fromCharCode(byte);
    } else {
      out += `+${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return out;
}

/**
 * DATA transparency for a byte stream (RFC 5321 §4.5.2): LF → CRLF (a bare LF only; CRLF is
 * kept), a `.` at the start of a line is doubled, the state survives chunk boundaries, and
 * `end()` guarantees a final CRLF followed by the terminator `.` CRLF. Bare CRs are passed
 * through unchanged (the stored message is otherwise not modified).
 */
export class DotStuffer {
  private atLineStart = true;
  private lastWasCr = false;

  transform(chunk: Uint8Array): Buffer {
    const out = Buffer.allocUnsafe(chunk.length * 2);
    let n = 0;
    for (const byte of chunk) {
      if (byte === 0x0a) {
        if (!this.lastWasCr) out[n++] = 0x0d;
        out[n++] = 0x0a;
        this.atLineStart = true;
        this.lastWasCr = false;
        continue;
      }
      if (this.atLineStart && byte === 0x2e) out[n++] = 0x2e;
      out[n++] = byte;
      this.lastWasCr = byte === 0x0d;
      this.atLineStart = false;
    }
    return out.subarray(0, n);
  }

  /** The final CRLF (unless the data ended with one) and `.` CRLF. */
  end(): Buffer {
    if (this.atLineStart) return Buffer.from('.\r\n', 'latin1');
    return Buffer.from(this.lastWasCr ? '\n.\r\n' : '\r\n.\r\n', 'latin1');
  }
}

export interface SmtpClientOptions {
  host: string;
  port: number;
  /** Per command (connect, greeting, each reply, each stalled write). */
  commandTimeoutMs: number;
  /** After the final dot. */
  dataTimeoutMs: number;
  /** Aborting destroys the connection (an abort after the dot is still ambiguous). */
  signal?: AbortSignal;
}

export interface MailParams {
  size?: number;
  ret?: 'HDRS' | 'FULL';
  envid?: string;
  smtputf8?: boolean;
}

export interface RcptParams {
  notify?: 'NEVER' | 'FAILURE,DELAY' | 'SUCCESS,FAILURE,DELAY' | 'FAILURE';
  /** The original recipient address (sent as `ORCPT=rfc822;<xtext>`). */
  orcpt?: string;
}

export interface DataResult {
  /** The reply to `DATA` (354 to proceed). */
  start: SmtpReply;
  /** The reply after the final dot; absent when DATA was refused. */
  final?: SmtpReply;
}

const REPLY_LINE = /^([2-5]\d\d)(?:([ -])(.*))?$/;
const ENHANCED = /^([245]\.\d{1,3}\.\d{1,3})(?:\s|$)/;
const PATH_FORBIDDEN = /[\s<>\0]/;

type Waiter = {
  resolve: (reply: SmtpReply) => void;
  reject: (error: SmtpClientError) => void;
};

/** One SMTP session over one TCP connection. */
export class SmtpClient {
  /** EHLO keywords (upper case) → parameters. */
  readonly capabilities = new Map<string, string[]>();
  private buffer: Buffer = Buffer.alloc(0);
  private partial: { code: number; lines: string[]; bytes: number } | null = null;
  private readonly replies: SmtpReply[] = [];
  private waiter: Waiter | null = null;
  private failure: SmtpClientError | null = null;
  private afterDot = false;
  private closed = false;

  private constructor(
    private readonly socket: Socket,
    private readonly options: SmtpClientOptions,
  ) {
    socket.on('data', (chunk: Buffer) => this.onData(chunk));
    socket.on('error', (err) => this.fail(new SmtpConnectionError(err.message, this.afterDot)));
    socket.on('close', () => {
      this.closed = true;
      this.fail(new SmtpConnectionError('connection closed by the server', this.afterDot));
    });
    options.signal?.addEventListener('abort', this.onAbort, { once: true });
  }

  /** Connects and reads the greeting (any code; the caller checks for 220). */
  static async connect(
    options: SmtpClientOptions,
  ): Promise<{ client: SmtpClient; greeting: SmtpReply }> {
    if (options.signal?.aborted) throw new SmtpConnectionError('aborted', false);
    const socket = createConnection({ host: options.host, port: options.port });
    socket.setNoDelay(true);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        socket.destroy();
        reject(new SmtpTimeoutError(`connect to ${options.host}:${options.port} timed out`, false));
      }, options.commandTimeoutMs);
      const onConnect = (): void => {
        cleanup();
        resolve();
      };
      const onError = (err: Error): void => {
        cleanup();
        socket.destroy();
        reject(
          new SmtpConnectionError(
            `connect to ${options.host}:${options.port}: ${err.message}`,
            false,
          ),
        );
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        socket.off('connect', onConnect);
        socket.off('error', onError);
      };
      socket.once('connect', onConnect);
      socket.once('error', onError);
    });
    const client = new SmtpClient(socket, options);
    try {
      const greeting = await client.read(options.commandTimeoutMs);
      return { client, greeting };
    } catch (err) {
      client.destroy();
      throw err;
    }
  }

  has(capability: string): boolean {
    return this.capabilities.has(capability.toUpperCase());
  }

  /** EHLO; on 250 the capabilities are (re)parsed from the reply lines. */
  async ehlo(name: string): Promise<SmtpReply> {
    const reply = await this.command(`EHLO ${name}`);
    if (reply.code === 250) {
      this.capabilities.clear();
      for (const line of reply.lines.slice(1)) {
        const [keyword, ...params] = line.trim().split(/\s+/);
        if (keyword) this.capabilities.set(keyword.toUpperCase(), params);
      }
    }
    return reply;
  }

  /** `XFORWARD NAME=… ADDR=…` with xtext values (Postfix attribute names, upper case). */
  async xforward(attributes: readonly (readonly [string, string])[]): Promise<SmtpReply> {
    if (attributes.length === 0) throw new SmtpProtocolError('XFORWARD needs attributes', false);
    const parts = attributes.map(([name, value]) => {
      if (!/^[A-Z]+$/.test(name)) throw new SmtpProtocolError('invalid XFORWARD attribute', false);
      return `${name}=${xtext(value)}`;
    });
    return await this.command(`XFORWARD ${parts.join(' ')}`);
  }

  async mail(from: string, params: MailParams = {}): Promise<SmtpReply> {
    assertPath(from, true);
    let line = `MAIL FROM:<${from}>`;
    if (params.size !== undefined) line += ` SIZE=${Math.max(0, Math.floor(params.size))}`;
    if (params.ret) line += ` RET=${params.ret}`;
    if (params.envid) line += ` ENVID=${xtext(params.envid)}`;
    if (params.smtputf8) line += ' SMTPUTF8';
    return await this.command(line);
  }

  async rcpt(to: string, params: RcptParams = {}): Promise<SmtpReply> {
    assertPath(to, false);
    let line = `RCPT TO:<${to}>`;
    if (params.notify) line += ` NOTIFY=${params.notify}`;
    if (params.orcpt) line += ` ORCPT=rfc822;${xtext(params.orcpt)}`;
    return await this.command(line);
  }

  /**
   * DATA: on 354 writes `prefix` (the prepended header, already CRLF-terminated) and the body
   * through the DotStuffer with backpressure, then the terminator, and reads the final reply
   * with the data-done timeout. A body stream error destroys the connection before the dot
   * (the server discards the transaction) and is rethrown unchanged.
   */
  async data(prefix: string, body: AsyncIterable<Uint8Array>): Promise<DataResult> {
    if (/[\r\n]/.test(prefix.replace(/\r\n$/, '')) || !prefix.endsWith('\r\n')) {
      throw new SmtpProtocolError('DATA prefix must be one CRLF-terminated header line', false);
    }
    const start = await this.command('DATA');
    if (start.code !== 354) return { start };
    const stuffer = new DotStuffer();
    await this.write(stuffer.transform(Buffer.from(prefix, 'utf8')));
    try {
      for await (const chunk of body) {
        if (chunk.length > 0) await this.write(stuffer.transform(chunk));
      }
    } catch (err) {
      if (err instanceof SmtpClientError) throw err;
      this.destroy();
      throw err;
    }
    this.afterDot = true;
    await this.write(stuffer.end());
    const final = await this.read(this.options.dataTimeoutMs);
    return { start, final };
  }

  /** QUIT (best effort, short timeout) and close. Never throws. */
  async quit(): Promise<void> {
    if (!this.closed && !this.failure) {
      try {
        this.send('QUIT');
        await this.read(Math.min(this.options.commandTimeoutMs, 5000));
      } catch {
        // The transaction outcome is already known; a lost QUIT reply changes nothing.
      }
    }
    this.destroy();
  }

  destroy(): void {
    this.options.signal?.removeEventListener('abort', this.onAbort);
    this.socket.destroy();
  }

  private readonly onAbort = (): void => {
    this.fail(new SmtpConnectionError('aborted', this.afterDot));
    this.socket.destroy();
  };

  private async command(line: string): Promise<SmtpReply> {
    this.send(line);
    return this.read(this.options.commandTimeoutMs);
  }

  private send(line: string): void {
    if (/[\r\n\0]/.test(line))
      throw new SmtpProtocolError('command contains CR, LF or NUL', this.afterDot);
    if (this.failure) throw this.failure;
    this.socket.write(`${line}\r\n`, 'utf8');
  }

  private write(chunk: Buffer): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    if (chunk.length === 0 || this.socket.write(chunk)) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        const error = new SmtpTimeoutError('write to the server stalled', this.afterDot);
        this.fail(error);
        this.socket.destroy();
        reject(error);
      }, this.options.commandTimeoutMs);
      const onDrain = (): void => {
        cleanup();
        resolve();
      };
      const onClose = (): void => {
        cleanup();
        reject(this.failure ?? new SmtpConnectionError('connection closed', this.afterDot));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.socket.off('drain', onDrain);
        this.socket.off('close', onClose);
      };
      this.socket.once('drain', onDrain);
      this.socket.once('close', onClose);
    });
  }

  /** The next complete reply. */
  private read(timeoutMs: number): Promise<SmtpReply> {
    const queued = this.replies.shift();
    if (queued) return Promise.resolve(queued);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        const error = new SmtpTimeoutError(
          this.afterDot
            ? 'timed out waiting for the reply to the final dot'
            : 'timed out waiting for a reply',
          this.afterDot,
        );
        this.fail(error);
        this.socket.destroy();
        reject(error);
      }, timeoutMs);
      this.waiter = {
        resolve: (reply) => {
          clearTimeout(timer);
          resolve(reply);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
    });
  }

  private onData(chunk: Buffer): void {
    if (this.failure) return;
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const lf = this.buffer.indexOf(0x0a);
      if (lf === -1) {
        if (this.buffer.length > MAX_REPLY_LINE_BYTES) {
          this.protocolError('reply line too long');
        }
        return;
      }
      if (lf + 1 > MAX_REPLY_LINE_BYTES) return this.protocolError('reply line too long');
      const end = lf > 0 && this.buffer[lf - 1] === 0x0d ? lf - 1 : lf;
      const line = this.buffer.subarray(0, end).toString('utf8');
      const bytes = lf + 1;
      this.buffer = this.buffer.subarray(lf + 1);
      if (!this.onLine(line, bytes)) return;
    }
  }

  /** False when the session failed. */
  private onLine(line: string, bytes: number): boolean {
    const match = REPLY_LINE.exec(line);
    if (!match) {
      this.protocolError('malformed reply line');
      return false;
    }
    const code = Number(match[1]);
    const final = match[2] !== '-';
    const text = match[3] ?? '';
    if (this.partial && this.partial.code !== code) {
      this.protocolError('inconsistent codes in a multi-line reply');
      return false;
    }
    const partial = this.partial ?? { code, lines: [], bytes: 0 };
    partial.lines.push(text);
    partial.bytes += bytes;
    if (partial.bytes > MAX_REPLY_BYTES) {
      this.protocolError('reply too large');
      return false;
    }
    if (!final) {
      this.partial = partial;
      return true;
    }
    this.partial = null;
    const first = partial.lines[0] ?? '';
    const reply: SmtpReply = {
      code,
      enhancedStatus: ENHANCED.exec(first)?.[1] ?? null,
      lines: partial.lines,
      text: `${code} ${partial.lines.join(' ')}`.trim(),
    };
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter.resolve(reply);
    } else {
      this.replies.push(reply);
    }
    return true;
  }

  private protocolError(message: string): void {
    this.fail(new SmtpProtocolError(message, this.afterDot));
    this.socket.destroy();
  }

  private fail(error: SmtpClientError): void {
    if (this.failure) return;
    this.failure = error;
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter.reject(error);
    }
  }
}

function assertPath(address: string, allowEmpty: boolean): void {
  if (address === '' && allowEmpty) return;
  if (
    address.length === 0 ||
    address.length > 320 ||
    PATH_FORBIDDEN.test(address) ||
    /[\r\n]/.test(address)
  ) {
    throw new SmtpProtocolError('invalid envelope address', false);
  }
}
