import { connect, type Socket } from 'node:net';

/** One (possibly multi-line) SMTP/LMTP reply. */
export interface LmtpReply {
  code: number;
  /** Every line without the code and separator. */
  lines: string[];
  /** The last line as sent, e.g. `250 2.0.0 Ok`. */
  text: string;
}

const REPLY_LINE = /^(\d{3})([ -])(.*)$/;

/**
 * Raw-socket LMTP client for tests (it plays the Postfix LMTP client): LHLO, XFORWARD, MAIL,
 * RCPT, DATA with dot-stuffing, one reply per accepted recipient after DATA.
 */
export class LmtpTestClient {
  private buffer = '';
  private readonly replies: LmtpReply[] = [];
  private readonly waiters: {
    resolve: (reply: LmtpReply) => void;
    reject: (err: Error) => void;
  }[] = [];
  private partial: string[] = [];
  private closedError: Error | null = null;

  private constructor(private readonly socket: Socket) {
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => this.onData(chunk));
    socket.on('close', () => this.fail(new Error('connection closed')));
    socket.on('error', (err) => this.fail(err));
  }

  static async connect(port: number, host = '127.0.0.1'): Promise<LmtpTestClient> {
    const socket = connect({ port, host });
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve());
      socket.once('error', reject);
    });
    return new LmtpTestClient(socket);
  }

  /** The next reply from the server (greeting, command reply, or one DATA reply). */
  read(timeoutMs = 30_000): Promise<LmtpReply> {
    const queued = this.replies.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closedError) return Promise.reject(this.closedError);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out waiting for a reply')), timeoutMs);
      this.waiters.push({
        resolve: (reply) => {
          clearTimeout(timer);
          resolve(reply);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
    });
  }

  async command(line: string): Promise<LmtpReply> {
    this.socket.write(`${line}\r\n`);
    return this.read();
  }

  /** Sends DATA, the dot-stuffed message and the terminator; returns `expected` replies. */
  async data(message: string | Buffer, expected: number): Promise<LmtpReply[]> {
    const go = await this.command('DATA');
    if (go.code !== 354) throw new Error(`DATA refused: ${go.text}`);
    // Byte-transparent: latin1 maps every byte to one code unit and back.
    const text = (Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8')).toString(
      'latin1',
    );
    const normalized = text.replace(/\r?\n/g, '\r\n');
    const stuffed = normalized.replace(/(^|\r\n)\./g, '$1..');
    const terminated = stuffed.endsWith('\r\n') ? stuffed : `${stuffed}\r\n`;
    this.socket.write(Buffer.from(`${terminated}.\r\n`, 'latin1'));
    const replies: LmtpReply[] = [];
    for (let i = 0; i < expected; i += 1) replies.push(await this.read(60_000));
    return replies;
  }

  async quit(): Promise<void> {
    if (!this.closedError) {
      try {
        await this.command('QUIT');
      } catch {
        // already closed
      }
    }
    this.socket.destroy();
  }

  destroy(): void {
    this.socket.destroy();
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let index = this.buffer.indexOf('\r\n');
    while (index !== -1) {
      const line = this.buffer.slice(0, index);
      this.buffer = this.buffer.slice(index + 2);
      const match = REPLY_LINE.exec(line);
      if (match) {
        this.partial.push(match[3]!);
        if (match[2] === ' ') {
          this.push({ code: Number(match[1]), lines: this.partial, text: line });
          this.partial = [];
        }
      }
      index = this.buffer.indexOf('\r\n');
    }
  }

  private push(reply: LmtpReply): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve(reply);
    else this.replies.push(reply);
  }

  private fail(err: Error): void {
    this.closedError ??= err;
    while (this.waiters.length > 0) this.waiters.shift()!.reject(err);
  }
}

export interface DeliveryRequest {
  port: number;
  /** LHLO name (the MTA id); default `mx.gateway.test`. */
  lhlo?: string;
  /** XFORWARD attributes, e.g. `{ IDENT: '4ZbK3B2xyz', ADDR: '203.0.113.7', HELO: 'mail.example' }`. */
  xforward?: Record<string, string>;
  from: string;
  to: readonly string[];
  message: string | Buffer;
}

export interface DeliveryResult {
  greeting: LmtpReply;
  mail: LmtpReply;
  rcpt: LmtpReply[];
  /** One reply per accepted recipient (empty when no RCPT was accepted). */
  data: LmtpReply[];
}

/** One full LMTP transaction on a new connection, the way Postfix's LMTP client sends it. */
export async function deliver(request: DeliveryRequest): Promise<DeliveryResult> {
  const client = await LmtpTestClient.connect(request.port);
  try {
    const greeting = await client.read();
    const lhlo = await client.command(`LHLO ${request.lhlo ?? 'mx.gateway.test'}`);
    if (lhlo.code !== 250) throw new Error(`LHLO refused: ${lhlo.text}`);
    if (request.xforward) {
      // Postfix splits XFORWARD attributes over several commands.
      const entries = Object.entries(request.xforward);
      const first = entries.filter(([key]) => key !== 'IDENT' && key !== 'SOURCE');
      const second = entries.filter(([key]) => key === 'IDENT' || key === 'SOURCE');
      for (const batch of [first, second]) {
        if (batch.length === 0) continue;
        const reply = await client.command(
          `XFORWARD ${batch.map(([key, value]) => `${key}=${value}`).join(' ')}`,
        );
        if (reply.code !== 250) throw new Error(`XFORWARD refused: ${reply.text}`);
      }
    }
    const mail = await client.command(`MAIL FROM:<${request.from}>`);
    const rcpt: LmtpReply[] = [];
    if (mail.code === 250) {
      for (const address of request.to) rcpt.push(await client.command(`RCPT TO:<${address}>`));
    }
    const accepted = rcpt.filter((reply) => reply.code === 250).length;
    let data: LmtpReply[] = [];
    if (accepted > 0) data = await client.data(request.message, accepted);
    else if (mail.code === 250) await client.command('RSET');
    await client.quit();
    return { greeting, mail, rcpt, data };
  } finally {
    client.destroy();
  }
}
