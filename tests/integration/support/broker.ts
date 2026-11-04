import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { stack } from './env';

const REPO_ROOT = resolve(__dirname, '../../..');
const INIT_SCRIPT = resolve(REPO_ROOT, 'infrastructure/rabbitmq/init.mjs');
/** Prefix of every throwaway vhost (step 3.2 §10). */
export const TEST_VHOST_PREFIX = 'eg-it-';

/**
 * Runs `infrastructure/rabbitmq/init.mjs` with the suite's environment (administrator from
 * `.env`). The script never prints credentials, so its output is safe to put in an error.
 */
export async function runInit(args: string[]): Promise<string> {
  return new Promise<string>((done, fail) => {
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
      if (code === 0) done(output);
      else fail(new Error(`init.mjs ${args.join(' ')} exited ${code}:\n${output}`));
    });
  });
}

export interface TestVhost {
  vhost: string;
  /** Administrator AMQP URL on the throwaway vhost (never logged). */
  adminUrl: string;
  /** The same URL through another host/port (e.g. a TCP proxy). */
  adminUrlVia(host: string, port: number): string;
  cleanup(): Promise<void>;
}

/** A throwaway vhost `eg-it-<8 hex>` with the full topology v1 (exchanges, queues, policies). */
export async function createTestVhost(): Promise<TestVhost> {
  const vhost = `${TEST_VHOST_PREFIX}${randomBytes(4).toString('hex')}`;
  await runInit(['--vhost', vhost]);
  const urlFor = (host?: string, port?: number) => {
    const url = new URL(stack.rabbitmqUrl());
    url.pathname = `/${encodeURIComponent(vhost)}`;
    if (host !== undefined) url.hostname = host;
    if (port !== undefined) url.port = String(port);
    return url.toString();
  };
  return {
    vhost,
    adminUrl: urlFor(),
    adminUrlVia: (host, port) => urlFor(host, port),
    cleanup: async () => {
      await runInit(['--delete-vhost', vhost]);
    },
  };
}

export interface QueueStats {
  messages: number;
  messagesReady: number;
  messagesUnacknowledged: number;
  consumers: number;
}

interface RawQueue {
  name: string;
  type?: string;
  durable?: boolean;
  policy?: string | null;
  effective_policy_definition?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  messages?: number;
  messages_ready?: number;
  messages_unacknowledged?: number;
  consumers?: number;
}

export interface RawExchange {
  name: string;
  type: string;
  durable: boolean;
  auto_delete: boolean;
  internal: boolean;
}

export interface RawBinding {
  source: string;
  destination: string;
  destination_type: 'queue' | 'exchange';
  routing_key: string;
}

export interface RawPolicy {
  name: string;
  pattern: string;
  'apply-to': string;
  priority: number;
  definition: Record<string, unknown>;
}

/** A small reader of the RabbitMQ management API (administrator, credentials in the header). */
export class ManagementApi {
  private readonly base: string;
  private readonly authorization: string;

  constructor() {
    const base = new URL(stack.rabbitmqMgmtUrl());
    base.username = '';
    base.password = '';
    this.base = base.toString().replace(/\/+$/, '');
    const { user, password } = stack.rabbitmqAdmin();
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
    const q = await this.get<RawQueue>(
      `/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}`,
    );
    return {
      messages: q.messages ?? 0,
      messagesReady: q.messages_ready ?? 0,
      messagesUnacknowledged: q.messages_unacknowledged ?? 0,
      consumers: q.consumers ?? 0,
    };
  }

  queues(vhost: string): Promise<RawQueue[]> {
    return this.get<RawQueue[]>(`/queues/${encodeURIComponent(vhost)}`);
  }

  exchanges(vhost: string): Promise<RawExchange[]> {
    return this.get<RawExchange[]>(`/exchanges/${encodeURIComponent(vhost)}`);
  }

  bindings(vhost: string): Promise<RawBinding[]> {
    return this.get<RawBinding[]>(`/bindings/${encodeURIComponent(vhost)}`);
  }

  policies(vhost: string): Promise<RawPolicy[]> {
    return this.get<RawPolicy[]>(`/policies/${encodeURIComponent(vhost)}`);
  }

  /** Channels of a vhost with their consumer count, prefetch and unacked deliveries. */
  async channels(
    vhost: string,
  ): Promise<
    { name: string; user: string; consumers: number; prefetch: number; unacked: number }[]
  > {
    const list = await this.get<
      {
        name: string;
        user?: string;
        consumer_count?: number;
        prefetch_count?: number;
        messages_unacknowledged?: number;
      }[]
    >(`/vhosts/${encodeURIComponent(vhost)}/channels`);
    return list.map((c) => ({
      name: c.name,
      user: c.user ?? '',
      consumers: c.consumer_count ?? 0,
      prefetch: c.prefetch_count ?? 0,
      unacked: c.messages_unacknowledged ?? 0,
    }));
  }

  async vhosts(): Promise<string[]> {
    const list = await this.get<{ name: string }[]>('/vhosts');
    return list.map((v) => v.name);
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
    if (Date.now() > deadline)
      throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
