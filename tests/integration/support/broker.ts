import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { queueDefinition } from '@email-gateway/event-contracts';
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

/** A throwaway vhost `eg-it-<8 hex>` with the full topology (exchanges, queues, policies). */
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

  /** Binds a queue to an exchange (`POST /api/bindings/<vhost>/e/<exchange>/q/<queue>`). */
  async bindQueue(
    vhost: string,
    exchange: string,
    queue: string,
    routingKey: string,
  ): Promise<void> {
    const path = `/bindings/${encodeURIComponent(vhost)}/e/${encodeURIComponent(exchange)}/q/${encodeURIComponent(queue)}`;
    const response = await fetch(`${this.base}/api${path}`, {
      method: 'POST',
      headers: { authorization: this.authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ routing_key: routingKey }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`management POST ${path}: HTTP ${response.status}`);
  }

  /** Deletes every message of a queue (`DELETE /api/queues/<vhost>/<name>/contents`). */
  async purge(vhost: string, name: string): Promise<void> {
    const path = `/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}/contents`;
    const response = await fetch(`${this.base}/api${path}`, {
      method: 'DELETE',
      headers: { authorization: this.authorization },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`management DELETE ${path}: HTTP ${response.status}`);
    }
  }

  /**
   * Reads up to `count` messages of a queue WITHOUT removing them (`ackmode
   * reject_requeue_true`: each is returned to the queue). Payloads are JSON strings.
   */
  async peek(
    vhost: string,
    name: string,
    count: number,
  ): Promise<{ routingKey: string; payload: string; properties: Record<string, unknown> }[]> {
    const path = `/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}/get`;
    const response = await fetch(`${this.base}/api${path}`, {
      method: 'POST',
      headers: { authorization: this.authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ count, ackmode: 'reject_requeue_true', encoding: 'auto' }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`management POST ${path}: HTTP ${response.status}`);
    const list = (await response.json()) as {
      routing_key: string;
      payload: string;
      properties?: Record<string, unknown>;
    }[];
    return list.map((m) => ({
      routingKey: m.routing_key,
      payload: m.payload,
      properties: m.properties ?? {},
    }));
  }

  async vhosts(): Promise<string[]> {
    const list = await this.get<{ name: string }[]>('/vhosts');
    return list.map((v) => v.name);
  }
}

/**
 * The queues without a consumer until their stage exists (step 3.2 topology role `dormant`, plus
 * the analytics feed): every stack run that sends mail fills them up to their `max-length`.
 * Step 3.3 L16: suites that send mail purge them in `afterAll`. Work, delay and dead-letter
 * queues are never in this list (a purge there would lose real events).
 */
export const DORMANT_QUEUES = [
  // `scan.spam` is a work queue since topology v3 (step 4.1 S2, consumed by the scan role),
  // `scan.attachment` since v4 (step 4.2 A2, the attachment engine), `scan.url` since v5 (step
  // 4.3 U2, the URL engine).
  'scan.auth',
  'scan.dlp',
  'scan.sandbox',
  'email.policy.evaluate',
  'email.quarantine',
  'email.archive',
  'email.analytics',
] as const;

for (const name of DORMANT_QUEUES) {
  const { role } = queueDefinition(name);
  if (role !== 'dormant') throw new Error(`${name} is a ${role} queue, never purge it`);
}

/**
 * Purges the dormant queues of the topology vhost (L16). Safe while the stack runs: nothing
 * consumes them. Returns the depth each queue had just before the purge.
 */
export async function purgeDormantQueues(
  api: ManagementApi = new ManagementApi(),
  vhost: string = stack.rabbitmqVhost(),
): Promise<Record<string, number>> {
  const depths: Record<string, number> = {};
  for (const name of DORMANT_QUEUES) {
    depths[name] = (await api.queue(vhost, name).catch(() => ({ messages: 0 }))).messages;
    await api.purge(vhost, name);
  }
  return depths;
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
