import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { requireEnv } from './fixtures';

/**
 * A minimal copy of `tests/integration/support/broker.ts` (step 3.2 WP2): apps may not import
 * the repository's test support (outside the package root), so the throwaway-vhost helpers the
 * relay suites need live here. Credentials come from `.env` and are never printed.
 */
const REPO_ROOT = resolve(__dirname, '../../../..');
const INIT_SCRIPT = resolve(REPO_ROOT, 'infrastructure/rabbitmq/init.mjs');
export const TEST_VHOST_PREFIX = 'eg-it-';

/** Runs `infrastructure/rabbitmq/init.mjs` (it never prints credentials). */
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
      else fail(new Error(`init.mjs ${args.join(' ')} exited ${code}:\n${output}`));
    });
  });
}

export interface TestVhost {
  vhost: string;
  /** Administrator AMQP URL on the throwaway vhost (never logged). */
  adminUrl: string;
  /** The same URL through another host/port (a TCP proxy). */
  adminUrlVia(host: string, port: number): string;
  /** Host and port of the broker's AMQP listener. */
  amqpTarget(): { host: string; port: number };
  cleanup(): Promise<void>;
}

/** A throwaway vhost `eg-it-<8 hex>` with the full topology v1 (exchanges, queues, policies). */
export async function createTestVhost(): Promise<TestVhost> {
  const vhost = `${TEST_VHOST_PREFIX}${randomBytes(4).toString('hex')}`;
  await runInit(['--vhost', vhost]);
  const admin = new URL(requireEnv('RABBITMQ_URL'));
  const urlFor = (host?: string, port?: number) => {
    const url = new URL(admin.toString());
    url.pathname = `/${encodeURIComponent(vhost)}`;
    if (host !== undefined) url.hostname = host;
    if (port !== undefined) url.port = String(port);
    return url.toString();
  };
  return {
    vhost,
    adminUrl: urlFor(),
    adminUrlVia: (host, port) => urlFor(host, port),
    amqpTarget: () => ({
      host: admin.hostname === 'localhost' ? '127.0.0.1' : admin.hostname,
      port: Number(admin.port || 5672),
    }),
    cleanup: () => runInit(['--delete-vhost', vhost]),
  };
}

/** A small client of the RabbitMQ management API (administrator, credentials in the header). */
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

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    const response = await fetch(`${this.base}/api${path}`, {
      method,
      headers: {
        authorization: this.authorization,
        accept: 'application/json',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`management ${method} ${path}: HTTP ${response.status}`);
    return response;
  }

  async get<T>(path: string): Promise<T> {
    return (await (await this.request('GET', path)).json()) as T;
  }

  async put(path: string, body: unknown): Promise<void> {
    await this.request('PUT', path, body);
  }

  async queue(
    vhost: string,
    name: string,
  ): Promise<{ messages: number; policy: Record<string, unknown> }> {
    const q = await this.get<{
      messages?: number;
      effective_policy_definition?: Record<string, unknown>;
    }>(`/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}`);
    return { messages: q.messages ?? 0, policy: q.effective_policy_definition ?? {} };
  }

  /** Replaces the definition of policy `eg.<queue>` of the throwaway vhost (keeps its pattern). */
  async overridePolicy(vhost: string, queue: string, changes: Record<string, unknown>) {
    const name = `eg.${queue}`;
    const path = `/policies/${encodeURIComponent(vhost)}/${encodeURIComponent(name)}`;
    const policy = await this.get<{
      pattern: string;
      'apply-to': string;
      priority: number;
      definition: Record<string, unknown>;
    }>(path);
    await this.put(path, {
      pattern: policy.pattern,
      'apply-to': policy['apply-to'],
      priority: policy.priority,
      definition: { ...policy.definition, ...changes },
    });
  }
}

/** Polls `condition` until true. */
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
