import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { SMTPServer, type SMTPServerAddress, type SMTPServerSession } from 'smtp-server';

/** One transaction the fake reinjection listener accepted (or refused). */
export interface FakeTransaction {
  listener: 'inbound' | 'outbound';
  helo: string;
  xforward: Record<string, string>;
  mailFrom: string;
  envid: string | null;
  ret: string | null;
  rcpts: { address: string; notify: string[] | null; orcpt: string | null }[];
  data: Buffer;
  queueId: string | null;
}

export type ReplySpec = { code: number; message: string } | null;
export type DataSpec = ReplySpec | 'hang';

class ReplyError extends Error {
  constructor(
    message: string,
    readonly responseCode: number,
  ) {
    super(message);
  }
}

/**
 * An in-process stand-in for postfix-outbound's reinjection listeners 10026/10027 (smtp-server
 * on two free ports of 127.0.0.1): advertises XFORWARD, DSN, SIZE and SMTPUTF8 like Postfix
 * 3.7, records every transaction, and answers `250 2.0.0 Ok: queued as <QID>` after the final
 * dot unless a test scripts another reply (RCPT 4xx/5xx, DATA 4xx/5xx, or a hang to provoke the
 * ambiguous timeout after the dot).
 */
export class FakePostfix {
  readonly transactions: FakeTransaction[] = [];
  /** Per-recipient RCPT reply; null = accept. */
  rcptReply: (address: string) => ReplySpec = () => null;
  /** Reply after the final dot; null = 250 queued as <random QID>. */
  dataReply: (tx: FakeTransaction) => DataSpec = () => null;
  inboundPort = 0;
  outboundPort = 0;
  private readonly servers: SMTPServer[] = [];

  async start(): Promise<void> {
    this.inboundPort = await this.listen('inbound');
    this.outboundPort = await this.listen('outbound');
  }

  async stop(): Promise<void> {
    await Promise.all(
      this.servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
    );
  }

  /** Overrides for workerConfig(): the worker reinjects into this fake. */
  get configOverrides(): Record<string, string> {
    return {
      DELIVERY_REINJECT_HOST: '127.0.0.1',
      DELIVERY_REINJECT_INBOUND_PORT: String(this.inboundPort),
      DELIVERY_REINJECT_OUTBOUND_PORT: String(this.outboundPort),
    };
  }

  reset(): void {
    this.transactions.length = 0;
    this.rcptReply = () => null;
    this.dataReply = () => null;
  }

  private async listen(listener: 'inbound' | 'outbound'): Promise<number> {
    const current = new WeakMap<SMTPServerSession, FakeTransaction>();
    const transaction = (session: SMTPServerSession): FakeTransaction => {
      let tx = current.get(session);
      if (!tx) {
        tx = {
          listener,
          helo: session.hostNameAppearsAs,
          xforward: Object.fromEntries(
            (session as unknown as { xForward?: Map<string, string> }).xForward ?? new Map(),
          ),
          mailFrom: '',
          envid: null,
          ret: null,
          rcpts: [],
          data: Buffer.alloc(0),
          queueId: null,
        };
        current.set(session, tx);
      }
      return tx;
    };
    const server = new SMTPServer({
      name: 'out.gateway.local',
      banner: 'ESMTP',
      authOptional: true,
      disabledCommands: ['AUTH', 'STARTTLS'],
      useXForward: true,
      hideDSN: false,
      size: 52_428_800,
      logger: false,
      onMailFrom: (address: SMTPServerAddress, session, callback) => {
        current.delete(session);
        const tx = transaction(session);
        tx.mailFrom = address.address;
        const dsn = (
          session.envelope as unknown as { dsn?: { envid?: string | null; ret?: string | null } }
        ).dsn;
        tx.envid = dsn?.envid ?? null;
        tx.ret = dsn?.ret ?? null;
        this.transactions.push(tx);
        callback();
      },
      onRcptTo: (address: SMTPServerAddress, session, callback) => {
        const tx = transaction(session);
        const dsn = (address as unknown as { dsn?: { notify?: string[]; orcpt?: string } }).dsn;
        tx.rcpts.push({
          address: address.address,
          notify: dsn?.notify ?? null,
          orcpt: dsn?.orcpt ?? null,
        });
        const reply = this.rcptReply(address.address);
        if (reply) return callback(new ReplyError(reply.message, reply.code));
        callback();
      },
      onData: (stream, session, callback) => {
        const tx = transaction(session);
        const chunks: Buffer[] = [];
        stream.on('data', (chunk: Buffer) => chunks.push(chunk));
        stream.on('end', () => {
          tx.data = Buffer.concat(chunks);
          current.delete(session);
          const reply = this.dataReply(tx);
          if (reply === 'hang') return; // never answer: the client times out after the dot
          if (reply) return callback(new ReplyError(reply.message, reply.code));
          tx.queueId = `4jJ${randomBytes(6).toString('hex')}`;
          callback(null, `2.0.0 Ok: queued as ${tx.queueId}`);
        });
      },
    });
    server.on('error', () => undefined);
    this.servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return (server.server.address() as AddressInfo).port;
  }
}
