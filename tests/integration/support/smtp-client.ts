import { createConnection, type Socket } from 'node:net';

/** Minimal line-oriented SMTP client: enough to assert server replies, nothing more. */
export class SmtpClient {
  private buffer = '';
  private waiters: ((reply: string) => void)[] = [];

  private constructor(private readonly socket: Socket) {
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.flush();
    });
  }

  static async connect(
    host: string,
    port: number,
  ): Promise<{ client: SmtpClient; banner: string }> {
    const socket = createConnection({ host, port });
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    const client = new SmtpClient(socket);
    return { client, banner: await client.read() };
  }

  async command(line: string): Promise<string> {
    this.socket.write(`${line}\r\n`);
    return this.read();
  }

  close(): void {
    this.socket.end('QUIT\r\n');
  }

  private read(): Promise<string> {
    return new Promise((resolve) => {
      this.waiters.push(resolve);
      this.flush();
    });
  }

  /** A reply is complete when a line has a space (not '-') after the 3-digit code. */
  private flush(): void {
    while (this.waiters.length > 0) {
      const match = /(^|\r\n)(\d{3}) [^\r\n]*\r\n/.exec(this.buffer);
      if (!match) return;
      const end = match.index + match[0].length;
      const reply = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end);
      this.waiters.shift()!(reply);
    }
  }
}
