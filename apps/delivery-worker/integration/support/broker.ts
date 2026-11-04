import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer, connect, type Server, type Socket } from 'node:net';
import { resolve } from 'node:path';

/**
 * Broker helpers of the delivery-worker integration suites (step 3.2 §10): a minimal copy of
 * `tests/integration/support/{broker,tcp-proxy}.ts` (this package's tsconfig cannot include
 * files outside it). Credentials come from the repository's .env and are never printed.
 */
const REPO_ROOT = resolve(__dirname, '../../../..');
const INIT_SCRIPT = resolve(REPO_ROOT, 'infrastructure/rabbitmq/init.mjs');
/** Prefix of every throwaway vhost (step 3.2 §10). */
export const TEST_VHOST_PREFIX = 'eg-it-';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/** Runs `infrastructure/rabbitmq/init.mjs` as the administrator (it never prints secrets). */
async function runInit(args: string[]): Promise<void> {
  await new Promise<void>((done, fail) => {
    const child = spawn(process.execPath, [INIT_SCRIPT, ...args], {
      cwd: REPO_ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    child.on('error', fail);
    child.on('close', (code) => {
      if (code === 0) done();
      else fail(new Error(`init.mjs ${args.join(' ')} exited ${String(code)}:\n${output}`));
    });
  });
}

export interface TestVhost {
  vhost: string;
  /** Administrator AMQP URL on the throwaway vhost (never logged). */
  adminUrl: string;
  cleanup(): Promise<void>;
}

/** A throwaway vhost `eg-it-<8 hex>` with the full topology v1 (exchanges, queues, policies). */
export async function createTestVhost(): Promise<TestVhost> {
  const vhost = `${TEST_VHOST_PREFIX}${randomBytes(4).toString('hex')}`;
  await runInit(['--vhost', vhost]);
  const url = new URL(requireEnv('RABBITMQ_URL'));
  url.pathname = `/${encodeURIComponent(vhost)}`;
  return {
    vhost,
    adminUrl: url.toString(),
    cleanup: () => runInit(['--delete-vhost', vhost]),
  };
}

export interface QueueStats {
  messages: number;
  messagesReady: number;
  messagesUnacknowledged: number;
  consumers: number;
}

/** A small reader of the RabbitMQ management API (administrator, credentials in the header). */
export class ManagementApi {
  private readonly base: string;
  private readonly authorization: string;

  constructor() {
    const base = new URL(requireEnv('RABBITMQ_MGMT_URL'));
    base.username = '';
    base.password = '';
    this.base = base.toString().replace(/\/+$/, '');
    const user = requireEnv('RABBITMQ_USER');
    const password = requireEnv('RABBITMQ_PASSWORD');
    this.authorization = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
  }

  async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.base}/api${path}`, {
      headers: { authorization: this.authorization, accept: 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`management GET ${path}: HTTP ${response.status}`);
    return (await response.json()) as T;
  }

  async queue(vhost: string, name: string): Promise<QueueStats> {
    const q = await this.get<{
      messages?: number;
      messages_ready?: number;
      messages_unacknowledged?: number;
      consumers?: number;
    }>(`/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}`);
    return {
      messages: q.messages ?? 0,
      messagesReady: q.messages_ready ?? 0,
      messagesUnacknowledged: q.messages_unacknowledged ?? 0,
      consumers: q.consumers ?? 0,
    };
  }

  /** Channels of a vhost with their consumer count, prefetch and unacked deliveries. */
  async channels(
    vhost: string,
  ): Promise<{ name: string; consumers: number; prefetch: number; unacked: number }[]> {
    const list = await this.get<
      {
        name: string;
        consumer_count?: number;
        prefetch_count?: number;
        messages_unacknowledged?: number;
      }[]
    >(`/vhosts/${encodeURIComponent(vhost)}/channels`);
    return list.map((c) => ({
      name: c.name,
      consumers: c.consumer_count ?? 0,
      prefetch: c.prefetch_count ?? 0,
      unacked: c.messages_unacknowledged ?? 0,
    }));
  }
}

/** Polls `condition` (async) until true. */
export async function eventually(
  condition: () => Promise<boolean> | boolean,
  timeoutMs: number,
  what: string,
  intervalMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await condition()) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out after ${String(timeoutMs)} ms waiting for ${what}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

/**
 * An in-process TCP proxy in front of MySQL or the broker: `cut()` destroys every open
 * connection and refuses new ones (an outage as the client sees it); `restore()` accepts again.
 */
export class TcpProxy {
  private readonly sockets = new Set<Socket>();
  private isCut = false;
  private constructor(
    private readonly server: Server,
    readonly port: number,
  ) {}

  static async start(targetHost: string, targetPort: number): Promise<TcpProxy> {
    const ref: { proxy?: TcpProxy } = {};
    const server = createServer((client) => {
      const proxy = ref.proxy;
      if (!proxy || proxy.isCut) {
        client.destroy();
        return;
      }
      const upstream = connect({ host: targetHost, port: targetPort });
      const track = (socket: Socket) => {
        proxy.sockets.add(socket);
        socket.on('close', () => proxy.sockets.delete(socket));
        socket.on('error', () => {
          client.destroy();
          upstream.destroy();
        });
      };
      track(client);
      track(upstream);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    await new Promise<void>((done, fail) => {
      server.once('error', fail);
      server.listen(0, '127.0.0.1', () => done());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('proxy has no port');
    ref.proxy = new TcpProxy(server, address.port);
    return ref.proxy;
  }

  cut(): void {
    this.isCut = true;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
  }

  restore(): void {
    this.isCut = false;
  }

  async close(): Promise<void> {
    this.cut();
    await new Promise<void>((done) => this.server.close(() => done()));
  }
}

/** The same URL with host and port replaced (e.g. through a `TcpProxy`). */
export function urlVia(url: string, host: string, port: number): string {
  const parsed = new URL(url);
  parsed.hostname = host;
  parsed.port = String(port);
  return parsed.toString();
}
