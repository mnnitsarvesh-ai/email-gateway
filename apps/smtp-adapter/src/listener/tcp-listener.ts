import type { Logger } from '@email-gateway/logger';
import { type BlockList, createServer, type Server, type Socket } from 'node:net';
import { isAllowedClient } from '../shared/internal-networks';

export interface TcpListenerOptions {
  /** Health/log name, e.g. `policy-listener`. */
  name: string;
  host: string;
  port: number;
  /** Peers outside this list are disconnected immediately (D20). */
  internalNetworks: BlockList;
  /** Idle connections are closed after this many milliseconds. */
  idleTimeoutMs: number;
  /** Connections still open this long after `stop()` are destroyed. */
  drainTimeoutMs?: number;
}

/** Minimum interval between two "peer refused" warnings (a scan must not flood the logs). */
const REFUSED_WARN_INTERVAL_MS = 60_000;

/**
 * A plain TCP listener for Postfix's extension protocols (policy delegation, socketmap, Dovecot
 * auth). It refuses peers outside SMTP_INTERNAL_CLIENT_NETWORKS, closes idle connections, and on
 * `stop()` closes the server **and** every open connection: Postfix keeps policy, socketmap and
 * auth connections open for minutes, so `server.close()` alone would block shutdown.
 */
export class TcpListener {
  private readonly server: Server;
  private readonly sockets = new Set<Socket>();
  private lastRefusedWarnAt = 0;

  constructor(
    private readonly options: TcpListenerOptions,
    private readonly logger: Logger,
    private readonly onConnection: (socket: Socket) => void,
  ) {
    this.server = createServer((socket) => this.accept(socket));
    // A failed accept must never crash the process.
    this.server.on('error', (err) => this.logger.error({ err }, `${options.name} error`));
  }

  get listening(): boolean {
    return this.server.listening;
  }

  /** Bound port (differs from the configured one when it is 0, as in tests). */
  port(): number {
    const address = this.server.address();
    return typeof address === 'object' && address ? address.port : this.options.port;
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      this.server.once('error', onError);
      this.server.listen(this.options.port, this.options.host, () => {
        this.server.off('error', onError);
        resolve();
      });
    });
    this.logger.info({ port: this.port(), host: this.options.host }, `${this.options.name} up`);
  }

  async stop(): Promise<void> {
    if (!this.server.listening && this.sockets.size === 0) return;
    const closed = new Promise<void>((resolve) => this.server.close(() => resolve()));
    for (const socket of this.sockets) socket.end();
    const drain = setTimeout(() => {
      for (const socket of this.sockets) socket.destroy();
    }, this.options.drainTimeoutMs ?? 1000);
    drain.unref();
    await closed;
    clearTimeout(drain);
  }

  private accept(socket: Socket): void {
    if (!isAllowedClient(this.options.internalNetworks, socket.remoteAddress)) {
      const now = Date.now();
      if (now - this.lastRefusedWarnAt >= REFUSED_WARN_INTERVAL_MS) {
        this.lastRefusedWarnAt = now;
        this.logger.warn(
          { peer: socket.remoteAddress },
          `${this.options.name}: refusing a peer outside SMTP_INTERNAL_CLIENT_NETWORKS`,
        );
      }
      socket.destroy();
      return;
    }
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
    socket.on('error', (err) => this.logger.debug({ err }, `${this.options.name} socket error`));
    socket.setTimeout(this.options.idleTimeoutMs, () => socket.end());
    this.onConnection(socket);
  }
}
