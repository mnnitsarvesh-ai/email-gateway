import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { type Counter, type HealthIndicator, MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { randomBytes } from 'node:crypto';
import type { BlockList, Socket } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { type AuthResult, ConnectorAuthService } from '../connectors/connector-auth.service';
import { TcpListener } from '../listener/tcp-listener';
import { normalizeClientAddress } from '../shared/internal-networks';
import {
  AuthProtocolError,
  type AuthRequest,
  decodeBase64,
  decodePlain,
  encodeBase64,
  handshake,
  isRequestId,
  isSafeUsername,
  LineSplitter,
  type Mechanism,
  MECHANISMS,
  parseAuthRequest,
} from './dovecot-auth-protocol';

export const SASL_SERVER_OPTIONS = Symbol('SASL_SERVER_OPTIONS');

export interface SaslServerOptions {
  host: string;
  port: number;
  internalNetworks: BlockList;
}

/** Postfix keeps one auth connection per smtpd process; close it only after a long idle. */
export const SASL_IDLE_TIMEOUT_MS = 330_000;

export type SaslResult = 'ok' | 'fail' | 'temp' | 'throttled';

interface Pending {
  mechanism: Mechanism;
  /** LOGIN: username received, password next. */
  username?: string;
  clientIp: string;
}

interface Connection {
  socket: Socket;
  versionSeen: boolean;
  pending: Map<string, Pending>;
  closed: boolean;
}

/**
 * Dovecot-auth-protocol server for Postfix's `smtpd_sasl_type = dovecot` (step 2.2 D10) on
 * SASL_AUTH_PORT. PLAIN and LOGIN only, and only on TLS-protected sessions (`secured`).
 *
 * - success → `OK <id> user=<username>`;
 * - wrong/unknown credentials or an inactive connector/organization → `FAIL <id> user=<name>`
 *   after SMTP_AUTH_FAILURE_DELAY_MS;
 * - DB/Redis failure or too many failures from the client IP → the auth connection is CLOSED
 *   without a reply, so Postfix answers `454 4.7.0 Temporary authentication failure` (it
 *   reconnects for the next AUTH). DEVIATION from D10's `FAIL <id> temp`, found by the step 2.2
 *   stack tests (WP6): Postfix 3.7's Dovecot client ignores the `temp` parameter and answers a
 *   permanent `535 5.7.8` for every FAIL, which would turn an infrastructure failure into a
 *   permanent credential error for the tenant's MTA. Only a lost connection maps to
 *   XSASL_AUTH_TEMP;
 * - malformed input or a line over 64 KiB closes the connection.
 *
 * Postfix itself holds no credentials (security boundary Z2). Secrets are never logged.
 */
@Injectable()
export class SaslServerService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'sasl-listener';
  private readonly listener: TcpListener;
  private readonly logger: Logger;
  private readonly attempts: Counter<'mech' | 'result'>;
  private connectionCounter = 0;
  private stopping = false;

  constructor(
    @Inject(SASL_SERVER_OPTIONS) options: SaslServerOptions,
    private readonly auth: ConnectorAuthService,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<SmtpAdapterConfig, 'SMTP_AUTH_FAILURE_DELAY_MS'>,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'sasl-server' });
    this.attempts = metrics.counter(
      'smtp_sasl_auth_total',
      'SASL authentication attempts by mechanism and result',
      ['mech', 'result'],
    );
    this.listener = new TcpListener(
      { name: this.healthName, idleTimeoutMs: SASL_IDLE_TIMEOUT_MS, ...options },
      this.logger,
      (socket) => this.handle(socket),
    );
  }

  async onModuleInit(): Promise<void> {
    await this.listener.start();
  }

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    await this.listener.stop();
  }

  checkHealth(): Promise<void> {
    return this.listener.listening
      ? Promise.resolve()
      : Promise.reject(new Error('SASL listener is not accepting connections'));
  }

  address(): number {
    return this.listener.port();
  }

  private handle(socket: Socket): void {
    this.connectionCounter += 1;
    const connection: Connection = {
      socket,
      versionSeen: false,
      pending: new Map(),
      closed: false,
    };
    socket.once('close', () => {
      connection.closed = true;
    });
    socket.write(handshake(process.pid, this.connectionCounter, randomBytes(16).toString('hex')));

    const splitter = new LineSplitter();
    socket.on('data', (chunk: Buffer) => {
      if (connection.closed) return;
      try {
        for (const line of splitter.push(chunk)) this.onLine(connection, line);
      } catch (err) {
        this.logger.warn(
          { err: err instanceof AuthProtocolError ? err.message : err },
          'malformed auth protocol input; closing the connection',
        );
        connection.closed = true;
        socket.destroy();
      }
    });
  }

  /** Throws AuthProtocolError on malformed input (the caller closes the connection). */
  private onLine(connection: Connection, line: string): void {
    if (line === '') return;
    const [command, ...fields] = line.split('\t');
    switch (command) {
      case 'VERSION':
        if (fields[0] !== '1') throw new AuthProtocolError('unsupported auth protocol version');
        connection.versionSeen = true;
        return;
      case 'CPID':
        return;
      case 'AUTH': {
        if (!connection.versionSeen) throw new AuthProtocolError('AUTH before VERSION');
        const request = parseAuthRequest(fields);
        if (connection.pending.has(request.id)) throw new AuthProtocolError('duplicate AUTH id');
        this.track(connection, this.begin(connection, request));
        return;
      }
      case 'CONT': {
        const [id, response = ''] = fields;
        if (!isRequestId(id)) throw new AuthProtocolError('malformed CONT');
        const pending = connection.pending.get(id);
        if (!pending) throw new AuthProtocolError('CONT for an unknown request');
        this.track(connection, this.continue(connection, id, pending, response));
        return;
      }
      default:
        throw new AuthProtocolError('unknown auth protocol command');
    }
  }

  private track(connection: Connection, work: Promise<void>): void {
    work.catch((err: unknown) => {
      this.logger.error({ err }, 'auth request failed unexpectedly; closing the connection');
      connection.closed = true;
      connection.socket.destroy();
    });
  }

  private async begin(connection: Connection, request: AuthRequest): Promise<void> {
    const mechanism = MECHANISMS.find((m) => m === request.mechanism);
    const mechLabel = mechanism?.toLowerCase() ?? 'unknown';
    if (!mechanism) {
      this.attempts.inc({ mech: mechLabel, result: 'fail' });
      this.send(connection, `FAIL\t${request.id}`);
      return;
    }
    if (!request.flags.has('secured')) {
      // Never accept credentials over an unencrypted session (smtpd_tls_auth_only as well).
      this.attempts.inc({ mech: mechLabel, result: 'fail' });
      this.logger.warn('AUTH without TLS refused');
      this.send(connection, `FAIL\t${request.id}`);
      return;
    }
    const clientIp = normalizeClientAddress(request.params.get('rip'))?.address ?? '';
    const response = request.params.get('resp');
    const pending: Pending = { mechanism, clientIp };
    if (response === undefined) {
      connection.pending.set(request.id, pending);
      // PLAIN without an initial response gets an empty challenge; LOGIN asks for the user.
      this.send(
        connection,
        `CONT\t${request.id}\t${mechanism === 'LOGIN' ? encodeBase64('Username:') : ''}`,
      );
      return;
    }
    await this.continue(connection, request.id, pending, response);
  }

  private async continue(
    connection: Connection,
    id: string,
    pending: Pending,
    response: string,
  ): Promise<void> {
    connection.pending.delete(id);
    if (pending.mechanism === 'PLAIN') {
      const credentials = decodePlain(response);
      if (
        !credentials ||
        (credentials.authzid !== '' && credentials.authzid !== credentials.authcid)
      ) {
        // Malformed, or an attempt to act as another identity: never authorized.
        this.attempts.inc({ mech: 'plain', result: 'fail' });
        await this.delayFailure();
        this.send(connection, `FAIL\t${id}`);
        return;
      }
      await this.verify(connection, id, pending, credentials.authcid, credentials.password);
      return;
    }
    // LOGIN: first the username, then the password.
    const decoded = decodeBase64(response)?.toString('utf8');
    if (decoded === undefined || decoded === '' || decoded.includes('\0')) {
      this.attempts.inc({ mech: 'login', result: 'fail' });
      await this.delayFailure();
      this.send(connection, `FAIL\t${id}`);
      return;
    }
    if (pending.username === undefined) {
      connection.pending.set(id, { ...pending, username: decoded });
      this.send(connection, `CONT\t${id}\t${encodeBase64('Password:')}`);
      return;
    }
    await this.verify(connection, id, pending, pending.username, decoded);
  }

  private async verify(
    connection: Connection,
    id: string,
    pending: Pending,
    username: string,
    secret: string,
  ): Promise<void> {
    const mech = pending.mechanism.toLowerCase();
    if (!isSafeUsername(username)) {
      this.attempts.inc({ mech, result: 'fail' });
      await this.delayFailure();
      this.send(connection, `FAIL\t${id}`);
      return;
    }
    let outcome: AuthResult;
    try {
      outcome = await this.auth.authenticate(username, secret, pending.clientIp);
    } catch (err) {
      this.logger.error({ err }, 'authentication error; temporary failure');
      outcome = { result: 'temp' };
    }
    this.attempts.inc({ mech, result: outcome.result });
    switch (outcome.result) {
      case 'ok':
        this.logger.info(
          {
            connectorId: String(outcome.connectorId),
            organizationId: String(outcome.organizationId),
          },
          'SASL authentication succeeded',
        );
        this.send(connection, `OK\t${id}\tuser=${username}`);
        return;
      case 'fail':
        this.logger.info({ username, clientIp: pending.clientIp }, 'SASL authentication failed');
        await this.delayFailure();
        this.send(connection, `FAIL\t${id}\tuser=${username}`);
        return;
      case 'throttled':
        this.logger.warn({ clientIp: pending.clientIp }, 'SASL authentication throttled');
        await this.delayFailure();
        this.failTemporarily(connection);
        return;
      case 'temp':
        this.failTemporarily(connection);
        return;
    }
  }

  /**
   * Temporary failure: close the connection without a FAIL line. Postfix's Dovecot client maps
   * only a lost auth-server connection to a temporary SMTP error (454 4.7.0); a `FAIL … temp`
   * line would become a permanent 535 (see the class comment).
   */
  private failTemporarily(connection: Connection): void {
    connection.closed = true;
    connection.socket.end();
  }

  private async delayFailure(): Promise<void> {
    if (this.config.SMTP_AUTH_FAILURE_DELAY_MS > 0 && !this.stopping) {
      await sleep(this.config.SMTP_AUTH_FAILURE_DELAY_MS, undefined, { ref: false });
    }
  }

  private send(connection: Connection, line: string): void {
    if (connection.closed || connection.socket.destroyed || !connection.socket.writable) return;
    connection.socket.write(`${line}\n`);
  }
}
