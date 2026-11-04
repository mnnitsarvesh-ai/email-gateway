import type { Logger } from '@email-gateway/logger';
import { type Channel, type ChannelModel, type ConfirmChannel, connect } from 'amqplib';
import type { HealthIndicator } from '../health/health-indicator';
import { type BackoffPolicy, backoffDelay, sleep } from './backoff';
import { amqpReplyName, BrokerUnavailableError, errorFields } from './errors';
import type { MessagingMetrics } from './metrics';

export { BrokerUnavailableError } from './errors';

/** amqplib's `connect` (injected by tests). */
export type AmqpConnectFn = (
  url: string,
  socketOptions: Record<string, unknown>,
) => Promise<ChannelModel>;

export interface AmqpConnectionOptions {
  /** One or more amqp(s):// URLs (cluster nodes); tried in rotation on (re)connect. */
  urls: string[];
  connectionName: string;
  logger: Logger;
  metrics?: MessagingMetrics;
  /** Default 30. */
  heartbeatSeconds?: number;
  /** Default 500 / 30 000 ms, equal jitter. */
  reconnect?: BackoffPolicy;
  /** TCP + AMQP handshake timeout per attempt (default 10 000 ms). */
  connectTimeoutMs?: number;
  /** Tests: replaces amqplib's `connect`. */
  connect?: AmqpConnectFn;
  /** Tests: jitter source in [0, 1). */
  random?: () => number;
  /** Tests: replaces the reconnect backoff sleep (resolves false when aborted). */
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

type Setup = (model: ChannelModel) => Promise<void>;

/** A connection that stayed up shorter than this counts as a failed attempt (backoff grows). */
const FLAPPING_MS = 5_000;
const CLOSE_TIMEOUT_MS = 5_000;

/**
 * One AMQP connection with its own recovery (step 3.2 Q6, ADR-0024): connects in the background,
 * and on an unexpected `error`/`close` drops the connection (amqplib closes every channel, which
 * rejects pending confirms), reconnects with equal-jitter backoff rotating through `urls`, then
 * re-runs every `onConnected` setup in registration order. **It never exits the process.**
 *
 * Readiness (`checkHealth`, indicator `rabbitmq`): connected, not blocked by a resource alarm,
 * and every object named through `requireTopology` verified passively (`checkExchange` /
 * `checkQueue`; services never declare). Logs carry tokens only: the node index, never a URL
 * (URLs carry credentials), never broker reply text.
 */
export class AmqpConnection implements HealthIndicator {
  readonly healthName = 'rabbitmq';
  private readonly logger: Logger;
  private readonly urls: string[];
  private readonly heartbeatSeconds: number;
  private readonly reconnectPolicy: BackoffPolicy;
  private readonly connectTimeoutMs: number;
  private readonly connectFn: AmqpConnectFn;
  private readonly random: () => number;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly abort = new AbortController();
  private readonly setups: { fn: Setup }[] = [];
  private readonly exchanges = new Set<string>();
  private readonly queues = new Set<string>();
  private readonly connectedWaiters = new Set<() => void>();
  private readonly unblockedWaiters = new Set<() => void>();
  private model: ChannelModel | undefined;
  private isConnected = false;
  private isBlocked = false;
  private started = false;
  private closed = false;
  private urlIndex = 0;
  private connections = 0;
  private loop: Promise<void> | undefined;
  /** The model whose topology was verified with the current requirements. */
  private verifiedFor: ChannelModel | undefined;
  private verifying: Promise<void> | undefined;

  constructor(private readonly options: AmqpConnectionOptions) {
    if (options.urls.length === 0) throw new Error('AmqpConnection needs at least one URL');
    for (const url of options.urls) {
      if (!/^amqps?:\/\//.test(url)) throw new Error('AmqpConnection URLs must be amqp(s)://');
    }
    if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(options.connectionName)) {
      throw new Error('AmqpConnection connectionName must be a token of at most 64 characters');
    }
    this.urls = [...options.urls];
    this.heartbeatSeconds = options.heartbeatSeconds ?? 30;
    this.reconnectPolicy = options.reconnect ?? { baseMs: 500, maxMs: 30_000 };
    if (
      this.reconnectPolicy.baseMs <= 0 ||
      this.reconnectPolicy.baseMs > this.reconnectPolicy.maxMs
    ) {
      throw new Error('AmqpConnection reconnect needs 0 < baseMs <= maxMs');
    }
    this.connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
    this.connectFn = options.connect ?? ((url, socketOptions) => connect(url, socketOptions));
    this.random = options.random ?? Math.random;
    this.sleepFn = options.sleep ?? sleep;
    this.logger = options.logger.child({
      component: 'amqp-connection',
      connection: options.connectionName,
    });
    options.metrics?.connectionUp(options.connectionName, false);
    options.metrics?.connectionBlocked(options.connectionName, false);
  }

  /** Connects in the background; reconnects until `close()`. Idempotent. */
  start(): void {
    if (this.started || this.closed) return;
    this.started = true;
    this.loop = this.run();
  }

  get connected(): boolean {
    return this.isConnected;
  }

  /** `connection.blocked` (memory or disk alarm): publishes would stall. */
  get blocked(): boolean {
    return this.isBlocked;
  }

  /** Resolves once connected; rejects with `BrokerUnavailableError` after `timeoutMs` or on close. */
  waitUntilConnected(timeoutMs: number): Promise<void> {
    if (this.isConnected) return Promise.resolve();
    if (this.closed) return Promise.reject(new BrokerUnavailableError('closed'));
    return new Promise((resolve, reject) => {
      const done = (ok: boolean) => {
        clearTimeout(timer);
        this.connectedWaiters.delete(waiter);
        if (ok) resolve();
        else reject(new BrokerUnavailableError(this.closed ? 'closed' : 'connect_timeout'));
      };
      const waiter = () => done(this.isConnected);
      const timer = setTimeout(() => done(false), Math.max(0, timeoutMs));
      this.connectedWaiters.add(waiter);
    });
  }

  /** Resolves `true` once not blocked (immediately when not blocked), `false` after `timeoutMs`. */
  waitUntilUnblocked(timeoutMs: number): Promise<boolean> {
    if (!this.isBlocked) return Promise.resolve(true);
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.unblockedWaiters.delete(done);
        resolve(!this.isBlocked);
      };
      const timer = setTimeout(done, Math.max(0, timeoutMs));
      this.unblockedWaiters.add(done);
    });
  }

  /**
   * Runs `setup` on every (re)connect, in registration order (consumers re-subscribe here), and
   * at once when already connected. A failing setup is logged; its owner retries. Returns an
   * unregister function.
   */
  onConnected(setup: Setup): () => void {
    const entry = { fn: setup };
    this.setups.push(entry);
    const model = this.model;
    if (this.isConnected && model) void this.runSetup(entry, model);
    return () => {
      const index = this.setups.indexOf(entry);
      if (index >= 0) this.setups.splice(index, 1);
    };
  }

  createConfirmChannel(): Promise<ConfirmChannel> {
    return this.openChannel((model) => model.createConfirmChannel());
  }

  createChannel(): Promise<Channel> {
    return this.openChannel((model) => model.createChannel());
  }

  /** Passive checks added by publishers/consumers; part of `checkHealth`. */
  requireTopology(objects: { exchanges?: string[]; queues?: string[] }): void {
    let added = false;
    for (const name of objects.exchanges ?? []) {
      if (!this.exchanges.has(name)) {
        this.exchanges.add(name);
        added = true;
      }
    }
    for (const name of objects.queues ?? []) {
      if (!this.queues.has(name)) {
        this.queues.add(name);
        added = true;
      }
    }
    if (added) this.verifiedFor = undefined;
  }

  /** Connected, not blocked, required topology verified (passively, once per connection). */
  async checkHealth(): Promise<void> {
    const model = this.model;
    if (!this.isConnected || !model) throw new Error('rabbitmq disconnected');
    if (this.isBlocked) throw new Error('rabbitmq connection blocked by a resource alarm');
    await this.verify(model);
  }

  async close(): Promise<void> {
    if (this.closed) {
      await this.loop;
      return;
    }
    this.closed = true;
    this.abort.abort();
    const model = this.model;
    if (model) {
      await Promise.race([model.close().catch(() => undefined), sleep(CLOSE_TIMEOUT_MS)]);
    }
    this.markDisconnected();
    for (const waiter of [...this.connectedWaiters]) waiter();
    for (const waiter of [...this.unblockedWaiters]) waiter();
    await this.loop;
  }

  // -------------------------------------------------------------------------------------------

  private async run(): Promise<void> {
    let failures = 0;
    while (!this.closed) {
      const node = this.urlIndex % this.urls.length;
      this.urlIndex += 1;
      let model: ChannelModel;
      try {
        model = await this.connectFn(this.withHeartbeat(this.urls[node] ?? ''), {
          clientProperties: { connection_name: this.options.connectionName },
          timeout: this.connectTimeoutMs,
        });
      } catch (error) {
        failures += 1;
        const delayMs = backoffDelay(failures, this.reconnectPolicy, this.random);
        this.logger.warn(
          { node, failures, delayMs, ...errorFields(error) },
          'AMQP connect failed; retrying',
        );
        await this.sleepFn(delayMs, this.abort.signal);
        continue;
      }
      if (this.closed) {
        await model.close().catch(() => undefined);
        break;
      }
      const connectedAt = Date.now();
      const lost = new Promise<void>((resolve) => {
        model.on('error', (error: unknown) =>
          this.logger.warn(
            { node, reply: amqpReplyName(error, 'connection_error'), ...errorFields(error) },
            'AMQP connection error',
          ),
        );
        model.on('close', () => {
          if (this.model === model) this.markDisconnected();
          resolve();
        });
        model.on('blocked', () => this.setBlocked(true));
        model.on('unblocked', () => this.setBlocked(false));
      });
      this.model = model;
      this.isConnected = true;
      this.connections += 1;
      this.options.metrics?.connectionUp(this.options.connectionName, true);
      if (this.connections > 1) this.options.metrics?.reconnected(this.options.connectionName);
      this.logger.info(
        { node, reconnect: this.connections > 1 },
        this.connections > 1 ? 'AMQP reconnected' : 'AMQP connected',
      );
      for (const waiter of [...this.connectedWaiters]) waiter();
      await this.runSetups(model);
      // Logs missing objects early; readiness re-checks on demand.
      void this.verify(model).catch(() => undefined);

      await lost;
      if (this.model === model) this.markDisconnected();
      if (this.closed) break;
      failures = Date.now() - connectedAt < FLAPPING_MS ? failures + 1 : 1;
      const delayMs = backoffDelay(failures, this.reconnectPolicy, this.random);
      this.logger.warn({ node, delayMs }, 'AMQP connection lost; reconnecting');
      await this.sleepFn(delayMs, this.abort.signal);
    }
  }

  private markDisconnected(): void {
    this.model = undefined;
    this.verifiedFor = undefined;
    this.isConnected = false;
    this.options.metrics?.connectionUp(this.options.connectionName, false);
    if (this.isBlocked) this.setBlocked(false);
  }

  private setBlocked(blocked: boolean): void {
    this.isBlocked = blocked;
    this.options.metrics?.connectionBlocked(this.options.connectionName, blocked);
    if (blocked) this.logger.warn('AMQP connection blocked by the broker (resource alarm)');
    else {
      this.logger.info('AMQP connection unblocked');
      for (const waiter of [...this.unblockedWaiters]) waiter();
    }
  }

  private async runSetups(model: ChannelModel): Promise<void> {
    for (const entry of [...this.setups]) {
      if (this.model !== model) return;
      if (!this.setups.includes(entry)) continue;
      await this.runSetup(entry, model);
    }
  }

  private async runSetup(entry: { fn: Setup }, model: ChannelModel): Promise<void> {
    try {
      await entry.fn(model);
    } catch (error) {
      this.logger.warn({ ...errorFields(error) }, 'AMQP connection setup failed');
    }
  }

  private async openChannel<C extends Channel>(
    open: (model: ChannelModel) => Promise<C>,
  ): Promise<C> {
    const model = this.model;
    if (!this.isConnected || !model) throw new BrokerUnavailableError('disconnected');
    let channel: C;
    try {
      channel = await open(model);
    } catch (error) {
      throw new BrokerUnavailableError(amqpReplyName(error, 'channel_open_failed'), {
        cause: error,
      });
    }
    // An unhandled 'error' event would throw; owners attach their own close handling.
    channel.on('error', (error: unknown) =>
      this.logger.warn({ reply: amqpReplyName(error) }, 'AMQP channel closed by the broker'),
    );
    return channel;
  }

  private verify(model: ChannelModel): Promise<void> {
    if (this.verifiedFor === model) return Promise.resolve();
    if (this.verifying) return this.verifying;
    const exchanges = [...this.exchanges];
    const queues = [...this.queues];
    const run = async () => {
      if (exchanges.length === 0 && queues.length === 0) {
        if (this.model === model) this.verifiedFor = model;
        return;
      }
      let channel: Channel;
      try {
        channel = await model.createChannel();
      } catch (error) {
        throw new BrokerUnavailableError(amqpReplyName(error, 'channel_open_failed'));
      }
      channel.on('error', () => undefined);
      let current = '';
      try {
        for (const name of exchanges) {
          current = `exchange ${name}`;
          await channel.checkExchange(name);
        }
        for (const name of queues) {
          current = `queue ${name}`;
          await channel.checkQueue(name);
        }
      } catch (error) {
        const reply = amqpReplyName(error, 'check_failed');
        this.logger.warn({ object: current, reply }, 'AMQP topology check failed');
        throw new Error(`rabbitmq topology check failed: ${current} (${reply})`);
      } finally {
        await channel.close().catch(() => undefined);
      }
      // Requirements added while verifying are checked next time.
      if (
        this.model === model &&
        exchanges.length === this.exchanges.size &&
        queues.length === this.queues.size
      ) {
        this.verifiedFor = model;
      }
    };
    this.verifying = run().finally(() => {
      this.verifying = undefined;
    });
    return this.verifying;
  }

  private withHeartbeat(url: string): string {
    try {
      const parsed = new URL(url);
      if (!parsed.searchParams.has('heartbeat')) {
        parsed.searchParams.set('heartbeat', String(this.heartbeatSeconds));
      }
      return parsed.toString();
    } catch {
      return url;
    }
  }
}
