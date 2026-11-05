import { createConnection, createServer, type Server, type Socket } from 'node:net';

/**
 * Test-only TCP proxy between a database client and MySQL (step 4.2 §6.2 item 1). `freeze()`
 * stops forwarding in **both** directions while keeping every socket open, which is what
 * `docker compose pause mysql` does to a client: the TCP connection stays established, nothing
 * is answered, and everything sent in the meantime arrives after `unfreeze()`. Bytes received
 * while frozen are buffered in order and flushed on unfreeze. Used only by integration tests;
 * never part of a service.
 */
export class FreezeProxy {
  private server: Server | undefined;
  private frozen = false;
  private trigger: Buffer | undefined;
  private readonly pairs = new Set<Pair>();
  /** Upstream connections opened over the proxy's lifetime. */
  opened = 0;
  /** Connections closed by either side over the proxy's lifetime. */
  closed = 0;
  /** Connections closed by the client side (the driver gave up on the socket). */
  closedByClient = 0;

  constructor(
    private readonly upstreamHost: string,
    private readonly upstreamPort: number,
  ) {}

  /** Listens on an ephemeral loopback port; returns it. */
  async start(): Promise<number> {
    const server = createServer((client) => this.accept(client));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('proxy has no port');
    return address.port;
  }

  /** Connections currently open through the proxy. */
  get active(): number {
    return this.pairs.size;
  }

  freeze(): void {
    this.frozen = true;
  }

  /**
   * Freezes as soon as the client sends a packet containing `text` (for example the SQL of a
   * statement being prepared); that packet is held too, so the statement is in flight from the
   * client's point of view and unanswered. One-shot.
   */
  freezeOn(text: string): void {
    this.trigger = Buffer.from(text, 'utf8');
  }

  /** True once a `freezeOn` trigger fired (or `freeze()` was called) and before `unfreeze()`. */
  get isFrozen(): boolean {
    return this.frozen;
  }

  unfreeze(): void {
    this.frozen = false;
    for (const pair of this.pairs) pair.flush();
  }

  async stop(): Promise<void> {
    this.frozen = false;
    for (const pair of this.pairs) pair.destroy();
    const server = this.server;
    this.server = undefined;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private check(chunk: Buffer): void {
    if (this.trigger !== undefined && chunk.includes(this.trigger)) {
      this.trigger = undefined;
      this.frozen = true;
    }
  }

  private accept(client: Socket): void {
    const upstream = createConnection({ host: this.upstreamHost, port: this.upstreamPort });
    this.opened += 1;
    const pair = new Pair(
      client,
      upstream,
      () => this.frozen,
      (chunk) => this.check(chunk),
    );
    this.pairs.add(pair);
    let counted = false;
    const done = (byClient: boolean) => {
      if (counted) return;
      counted = true;
      this.closed += 1;
      if (byClient) this.closedByClient += 1;
      this.pairs.delete(pair);
      pair.destroy();
    };
    client.on('close', () => done(true));
    upstream.on('close', () => done(false));
    client.on('error', () => done(true));
    upstream.on('error', () => done(false));
  }
}

/** One proxied connection: forwards chunks unless frozen, then buffers them in order. */
class Pair {
  private readonly toUpstream: Buffer[] = [];
  private readonly toClient: Buffer[] = [];

  constructor(
    private readonly client: Socket,
    private readonly upstream: Socket,
    private readonly isFrozen: () => boolean,
    inspect: (chunk: Buffer) => void,
  ) {
    client.on('data', (chunk: Buffer) => {
      inspect(chunk);
      this.forward(chunk, this.toUpstream, upstream);
    });
    upstream.on('data', (chunk: Buffer) => this.forward(chunk, this.toClient, client));
  }

  private forward(chunk: Buffer, queue: Buffer[], target: Socket): void {
    if (this.isFrozen() || queue.length > 0) {
      queue.push(chunk);
      if (!this.isFrozen()) this.flush();
      return;
    }
    if (!target.destroyed) target.write(chunk);
  }

  flush(): void {
    for (const [queue, target] of [
      [this.toUpstream, this.upstream],
      [this.toClient, this.client],
    ] as const) {
      while (queue.length > 0) {
        const chunk = queue.shift()!;
        if (!target.destroyed) target.write(chunk);
      }
    }
  }

  destroy(): void {
    this.client.destroy();
    this.upstream.destroy();
  }
}

/**
 * The URL with its host and port replaced by the proxy's and the given query parameters set
 * (e.g. `connection_limit`). The original credentials stay in the URL; never log it.
 */
export function proxiedUrl(url: string, port: number, params: Record<string, string>): string {
  const parsed = new URL(url);
  parsed.hostname = '127.0.0.1';
  parsed.port = String(port);
  for (const [key, value] of Object.entries(params)) parsed.searchParams.set(key, value);
  return parsed.toString();
}
