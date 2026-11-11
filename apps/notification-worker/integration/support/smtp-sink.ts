import { createServer, type Server, type Socket } from 'node:net';

export interface SunkMessage {
  from: string;
  recipients: string[];
  data: string;
}

/**
 * A minimal in-process SMTP listener (plaintext, no TLS; `NOTIFY_SMTP_SECURE=none` as the local
 * relay): EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT. `smtp-server` is not a dependency of
 * this package (dependencies are not changed in this step), so the test carries its own. When
 * `failData` is set, DATA is answered `451` (a temporary failure the worker must retry).
 */
export class SmtpSink {
  readonly messages: SunkMessage[] = [];
  failData = false;
  private readonly sockets = new Set<Socket>();
  private server: Server | null = null;
  port = 0;

  async start(): Promise<void> {
    this.server = createServer((socket) => this.session(socket));
    await new Promise<void>((done) => this.server!.listen(0, '127.0.0.1', done));
    const address = this.server.address();
    this.port = typeof address === 'object' && address ? address.port : 0;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((done) => (this.server ? this.server.close(() => done()) : done()));
  }

  private session(socket: Socket): void {
    this.sockets.add(socket);
    socket.on('close', () => this.sockets.delete(socket));
    socket.setEncoding('utf8');
    const reply = (line: string) => socket.write(`${line}\r\n`);
    let buffer = '';
    let inData = false;
    let current: SunkMessage = { from: '', recipients: [], data: '' };
    reply('220 sink.test ESMTP');
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end === -1) return;
          current.data = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          if (this.failData) {
            reply('451 4.3.0 temporary failure');
          } else {
            this.messages.push(current);
            reply('250 2.0.0 queued');
          }
          current = { from: '', recipients: [], data: '' };
          continue;
        }
        const nl = buffer.indexOf('\r\n');
        if (nl === -1) return;
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 2);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === 'EHLO') socket.write('250-sink.test\r\n250 8BITMIME\r\n');
        else if (verb === 'HELO') reply('250 sink.test');
        else if (verb === 'MAIL') {
          current.from = /<([^>]*)>/.exec(line)?.[1] ?? '';
          reply('250 2.1.0 ok');
        } else if (verb === 'RCPT') {
          current.recipients.push((/<([^>]*)>/.exec(line)?.[1] ?? '').toLowerCase());
          reply('250 2.1.5 ok');
        } else if (verb === 'DATA') {
          inData = true;
          reply('354 end with <CRLF>.<CRLF>');
        } else if (verb === 'RSET') {
          current = { from: '', recipients: [], data: '' };
          reply('250 ok');
        } else if (verb === 'NOOP') reply('250 ok');
        else if (verb === 'QUIT') {
          reply('221 bye');
          socket.end();
        } else reply('502 5.5.2 unknown command');
      }
    });
  }
}
