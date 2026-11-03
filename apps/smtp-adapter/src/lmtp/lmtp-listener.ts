import type { Logger } from '@email-gateway/logger';
import type { BlockList } from 'node:net';
import {
  SMTPServer,
  type SMTPServerAddress,
  type SMTPServerDataStream,
  type SMTPServerSession,
} from 'smtp-server';
import { isAllowedClient } from '../shared/internal-networks';
import { LMTP_ACCESS_DENIED, LMTP_TEMPFAIL, replyError, type SmtpReply } from '../shared/replies';
import { LmtpReplyException, replyForError } from './lmtp-reply';

/** What the LMTP client told us about itself and the original SMTP client (XFORWARD). */
export interface LmtpClientInfo {
  /** smtp-server's connection id (logs only). */
  connectionId: string;
  /** The peer that connected (before any XFORWARD), i.e. the Postfix instance. */
  peerAddress: string;
  /** The LHLO argument (lower-cased): the MTA id of the Postfix instance (D7). */
  lhloName: string | null;
  /** XFORWARD IDENT: the Postfix queue id. */
  queueId: string | null;
  /** XFORWARD ADDR: the original SMTP client address. */
  clientAddress: string | null;
  /** XFORWARD HELO: the original SMTP client's HELO name. */
  clientHelo: string | null;
}

/**
 * Per-transaction behaviour of an LMTP listener. Throw `LmtpReplyException` to answer MAIL or
 * RCPT with a specific reply; any other error answers `451 4.3.0`.
 */
export interface LmtpHandler<TTransaction, TRecipient> {
  /** MAIL FROM (`mailFrom` is '' for the null sender). Returns the transaction state. */
  beginTransaction(client: LmtpClientInfo, mailFrom: string): Promise<TTransaction>;
  /** RCPT TO, resolved immediately (D7 step 1). Returns the accepted recipient. */
  acceptRecipient(transaction: TTransaction, address: string): Promise<TRecipient>;
  /**
   * DATA: consume the stream and return exactly one reply per recipient, in RCPT order. The
   * recipients are distinct (case-insensitive); the listener repeats a recipient's reply for
   * every RCPT of it that was accepted. The listener drains whatever the handler leaves unread;
   * a throw answers 451 for everyone.
   */
  handleData(
    transaction: TTransaction,
    recipients: readonly TRecipient[],
    stream: SMTPServerDataStream,
  ): Promise<SmtpReply[]>;
}

export interface LmtpListenerOptions {
  /** Log and health name, e.g. `lmtp-inbound`. */
  name: string;
  host: string;
  /** 0 picks a free port (tests). */
  port: number;
  maxClients: number;
  /** Advertised SIZE and smtp-server's `sizeExceeded` flag. */
  maxMessageBytes: number;
  /** SMTP_INTERNAL_CLIENT_NETWORKS: every other peer is refused at connect (554 5.7.1). */
  internalNetworks: BlockList;
  /** How long `close()` waits for transactions in DATA before dropping connections. */
  drainTimeoutMs?: number;
}

/** Postfix's LMTP client may keep a connection cached for a while; transactions are short. */
const DEFAULT_DRAIN_TIMEOUT_MS = 30_000;
/** Idle LMTP connections (Postfix connection cache) are closed after this long. */
const SOCKET_TIMEOUT_MS = 10 * 60_000;
/** Minimum interval between two "peer refused" warnings. */
const REFUSED_WARN_INTERVAL_MS = 60_000;
/** Generic greeting name: the banner never reveals host names or software versions. */
const GREETING_NAME = 'lmtp';
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;

type SmtpConnection = SMTPServer['connections'] extends Set<infer C> ? C : never;

interface SessionState<TTransaction, TRecipient> {
  lhloName: string | null;
  transaction: TTransaction | null;
  /** Distinct accepted recipients in order of their first accepted RCPT. */
  recipients: TRecipient[];
  /** Lower-cased address → position in `recipients`. */
  positions: Map<string, number>;
  /**
   * One entry per RCPT that was answered 250, in RCPT order: the position of its recipient.
   * smtp-server merges repeated RCPTs case-insensitively in `envelope.rcptTo` but answers 250
   * to each of them, and Postfix (which compares addresses exactly) then expects one DATA reply
   * per accepted RCPT. Replying per `rcptTo` entry left Postfix waiting for the missing replies.
   */
  accepted: number[];
}

const emptyRecipients = () => ({
  recipients: [],
  positions: new Map<string, number>(),
  accepted: [],
});

const xForwardText = (session: SMTPServerSession, key: string): string | null => {
  const value = session.xForward.get(key);
  return typeof value === 'string' && value.length > 0 ? value : null;
};

/**
 * An LMTP server (step 2.2 D7, D13) built on `smtp-server` in LMTP mode: XFORWARD on, AUTH and
 * STARTTLS disabled (internal plaintext hop, invariant 1), peers outside
 * SMTP_INTERNAL_CLIENT_NETWORKS refused, per-recipient replies after DATA, and a graceful close
 * that stops accepting, waits for transactions in DATA, then drops idle connections.
 *
 * smtp-server overwrites the LHLO name with XFORWARD HELO (both feed `hostNameAppearsAs`), so the
 * listener records the LHLO argument when the LHLO handler runs (the MTA id of the ingest key).
 */
export class LmtpListener<TTransaction, TRecipient> {
  private readonly server: SMTPServer;
  private readonly sessions = new WeakMap<
    SMTPServerSession,
    SessionState<TTransaction, TRecipient>
  >();
  private readonly inFlight = new Set<Promise<unknown>>();
  private closing = false;
  private closed = false;
  private lastRefusedWarnAt = 0;

  constructor(
    private readonly options: LmtpListenerOptions,
    private readonly handler: LmtpHandler<TTransaction, TRecipient>,
    private readonly logger: Logger,
  ) {
    const recordLhlo = (connection: SmtpConnection) => this.instrument(connection);
    class LmtpServer extends SMTPServer {
      override connect(...args: Parameters<SMTPServer['connect']>): void {
        super.connect(...args);
        let latest: SmtpConnection | undefined;
        for (const connection of this.connections) latest = connection;
        if (latest) recordLhlo(latest);
      }
    }

    this.server = new LmtpServer({
      lmtp: true,
      name: GREETING_NAME,
      banner: 'ready',
      heloResponse: '%s',
      useXForward: true,
      disabledCommands: ['AUTH', 'STARTTLS'],
      hideSTARTTLS: true,
      authOptional: true,
      disableReverseLookup: true,
      maxClients: options.maxClients,
      size: options.maxMessageBytes,
      socketTimeout: SOCKET_TIMEOUT_MS,
      logger: false,
      onConnect: (session, callback) => this.onConnect(session, callback),
      onMailFrom: (address, session, callback) => this.onMailFrom(address, session, callback),
      onRcptTo: (address, session, callback) => this.onRcptTo(address, session, callback),
      onData: (stream, session, callback) => this.onData(stream, session, callback),
    });
    this.server.on('error', (err: Error) =>
      this.logger.warn({ err, listener: options.name }, 'lmtp connection error'),
    );
  }

  get name(): string {
    return this.options.name;
  }

  /** True while the listener accepts connections and is not draining. */
  get accepting(): boolean {
    return this.server.server.listening && !this.closing;
  }

  /** Bound port (differs from the configured one when it is 0). */
  port(): number {
    const address = this.server.server.address();
    return typeof address === 'object' && address ? address.port : this.options.port;
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      this.server.server.once('error', onError);
      this.server.listen(this.options.port, this.options.host, () => {
        this.server.server.off('error', onError);
        resolve();
      });
    });
    this.logger.info(
      { listener: this.options.name, host: this.options.host, port: this.port() },
      'lmtp listener started',
    );
  }

  /**
   * Graceful close: stop accepting connections and new transactions, wait up to the drain
   * timeout for transactions in DATA to answer, then close every remaining connection (Postfix
   * retries anything that did not get its replies; ingestion is idempotent).
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.closing = true;
    const serverClosed = new Promise<void>((resolve) => {
      if (!this.server.server.listening) return resolve();
      this.server.server.close(() => resolve());
    });
    const drainMs = this.options.drainTimeoutMs ?? DEFAULT_DRAIN_TIMEOUT_MS;
    if (this.inFlight.size > 0) {
      this.logger.info(
        { listener: this.options.name, transactions: this.inFlight.size },
        'waiting for lmtp transactions to finish',
      );
      let timer: NodeJS.Timeout | undefined;
      await Promise.race([
        Promise.allSettled([...this.inFlight]),
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, drainMs);
          timer.unref();
        }),
      ]);
      clearTimeout(timer);
    }
    for (const connection of this.server.connections) connection.close();
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      serverClosed,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 5_000);
        timer.unref();
      }),
    ]);
    clearTimeout(timer);
    this.logger.info({ listener: this.options.name }, 'lmtp listener closed');
  }

  private instrument(connection: SmtpConnection): void {
    const handleLhlo = connection.handler_EHLO.bind(connection);
    // Own property shadows the prototype method that smtp-server's dispatcher looks up.
    connection.handler_EHLO = (command: Buffer, callback: () => void) => {
      handleLhlo(command, callback);
      const name = connection.hostNameAppearsAs;
      this.state(connection.session).lhloName = typeof name === 'string' && name ? name : null;
    };
  }

  private state(session: SMTPServerSession): SessionState<TTransaction, TRecipient> {
    let state = this.sessions.get(session);
    if (!state) {
      state = { lhloName: null, transaction: null, ...emptyRecipients() };
      this.sessions.set(session, state);
    }
    return state;
  }

  private clientInfo(session: SMTPServerSession): LmtpClientInfo {
    const ident = xForwardText(session, 'IDENT');
    const peer = session.xForward.get('ADDR:DEFAULT');
    return {
      connectionId: session.id,
      peerAddress: typeof peer === 'string' ? peer : session.remoteAddress,
      lhloName: this.state(session).lhloName,
      queueId: ident !== null && QUEUE_ID.test(ident) ? ident : null,
      clientAddress: xForwardText(session, 'ADDR'),
      clientHelo: xForwardText(session, 'HELO'),
    };
  }

  private onConnect(session: SMTPServerSession, callback: (err?: Error | null) => void): void {
    if (this.closing) return callback(replyError(LMTP_TEMPFAIL));
    if (!isAllowedClient(this.options.internalNetworks, session.remoteAddress)) {
      const now = Date.now();
      if (now - this.lastRefusedWarnAt >= REFUSED_WARN_INTERVAL_MS) {
        this.lastRefusedWarnAt = now;
        this.logger.warn(
          { listener: this.options.name, peer: session.remoteAddress },
          'refused lmtp connection from a peer outside SMTP_INTERNAL_CLIENT_NETWORKS',
        );
      }
      return callback(replyError(LMTP_ACCESS_DENIED));
    }
    this.state(session);
    callback();
  }

  private onMailFrom(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error | null) => void,
  ): void {
    const state = this.state(session);
    state.transaction = null;
    Object.assign(state, emptyRecipients());
    if (this.closing) return callback(replyError(LMTP_TEMPFAIL));
    // Invoked inside the chain so a synchronous throw becomes a reply too.
    const client = this.clientInfo(session);
    Promise.resolve()
      .then(() => this.handler.beginTransaction(client, address.address))
      .then(
        (transaction) => {
          state.transaction = transaction;
          callback();
        },
        (err: unknown) => {
          this.logUnexpected(err, 'MAIL');
          callback(replyError(replyForError(err)));
        },
      );
  }

  private onRcptTo(
    address: SMTPServerAddress,
    session: SMTPServerSession,
    callback: (err?: Error | null) => void,
  ): void {
    const state = this.state(session);
    const transaction = state.transaction;
    if (transaction === null) return callback(replyError(LMTP_TEMPFAIL));
    Promise.resolve()
      .then(() => this.handler.acceptRecipient(transaction, address.address))
      .then(
        (recipient) => {
          // A late answer for a transaction that was reset (RSET, new MAIL) is dropped.
          if (state.transaction === transaction) {
            const key = address.address.toLowerCase();
            let position = state.positions.get(key);
            if (position === undefined) {
              position = state.recipients.length;
              state.recipients.push(recipient);
              state.positions.set(key, position);
            }
            state.accepted.push(position);
          }
          callback();
        },
        (err: unknown) => {
          this.logUnexpected(err, 'RCPT');
          callback(replyError(replyForError(err)));
        },
      );
  }

  private onData(
    stream: SMTPServerDataStream,
    session: SMTPServerSession,
    callback: (err?: Error | null, message?: (string | Error)[]) => void,
  ): void {
    const state = this.state(session);
    const transaction = state.transaction;
    const distinct = session.envelope.rcptTo.length;
    const { recipients, accepted } = state;
    state.transaction = null;
    Object.assign(state, emptyRecipients());

    const work = (async (): Promise<SmtpReply[]> => {
      if (transaction === null || recipients.length !== distinct || accepted.length === 0) {
        throw new Error('lmtp transaction state missing at DATA');
      }
      const replies = await this.handler.handleData(transaction, recipients, stream);
      if (replies.length !== recipients.length) {
        throw new Error(`handler returned ${replies.length} replies for ${recipients.length}`);
      }
      // One reply per accepted RCPT (a case variant repeats its recipient's reply).
      return accepted.map((position) => replies[position]!);
    })();
    this.inFlight.add(work);
    work
      .catch((err: unknown) => {
        this.logger.error(
          { err, listener: this.options.name },
          'lmtp DATA handling failed; tempfailing every recipient',
        );
        // One reply per RCPT answered 250 (the envelope's count only if tracking was lost).
        const count = accepted.length > 0 ? accepted.length : distinct;
        return Array.from({ length: count }, () => LMTP_TEMPFAIL);
      })
      .then((replies) => {
        this.inFlight.delete(work);
        // Never leave the rest of the message unread: smtp-server answers on 'end'.
        if (stream.readable && !stream.destroyed) stream.resume();
        callback(
          null,
          replies.map((reply) => (reply.code === 250 ? reply.text : replyError(reply))),
        );
      })
      .catch((err: unknown) => this.logger.error({ err }, 'lmtp reply failed'));
  }

  private logUnexpected(err: unknown, command: string): void {
    if (err instanceof LmtpReplyException) return;
    this.logger.error(
      { err, listener: this.options.name, command },
      'lmtp handler failed; tempfailing',
    );
  }
}
