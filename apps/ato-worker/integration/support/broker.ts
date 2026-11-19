import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { requireEnv } from './fixtures';

/**
 * Broker helpers of the ato-worker integration suite: a minimal copy of the delivery-worker's
 * `createTestVhost` (packages cannot include files outside them). A throwaway vhost
 * `eg-it-<8 hex>` gets the full topology (v13, the three ATO queues included) through
 * `infrastructure/rabbitmq/init.mjs`; credentials come from the repository's .env and are never
 * printed.
 */
const REPO_ROOT = resolve(__dirname, '../../../..');
const INIT_SCRIPT = resolve(REPO_ROOT, 'infrastructure/rabbitmq/init.mjs');

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

export async function createTestVhost(): Promise<TestVhost> {
  const vhost = `eg-it-${randomBytes(4).toString('hex')}`;
  await runInit(['--vhost', vhost]);
  const url = new URL(requireEnv('RABBITMQ_URL'));
  url.pathname = `/${encodeURIComponent(vhost)}`;
  return { vhost, adminUrl: url.toString(), cleanup: () => runInit(['--delete-vhost', vhost]) };
}

async function management(method: string, path: string, body?: unknown): Promise<unknown> {
  const base = requireEnv('RABBITMQ_MGMT_URL').replace(/\/+$/, '');
  const auth = Buffer.from(
    `${requireEnv('RABBITMQ_USER')}:${requireEnv('RABBITMQ_PASSWORD')}`,
    'utf8',
  ).toString('base64');
  const response = await fetch(`${base}/api${path}`, {
    method,
    headers: { authorization: `Basic ${auth}`, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) throw new Error(`management ${method} ${path}: HTTP ${response.status}`);
  const text = await response.text();
  return text ? (JSON.parse(text) as unknown) : null;
}

/**
 * TEST-ONLY on the throwaway vhost: a higher-priority policy bounding `ato.mail` at `maxLength`
 * with the same lossy semantics as topology v13 (drop-head, no dead-lettering of dropped heads),
 * so the suite can overflow it with a few hundred messages instead of 500 000.
 */
export async function boundAtoMail(vhost: string, maxLength: number): Promise<void> {
  await management('PUT', `/policies/${encodeURIComponent(vhost)}/it-ato-mail-small`, {
    pattern: '^ato\\.mail$',
    'apply-to': 'queues',
    priority: 100,
    definition: { 'max-length': maxLength, overflow: 'drop-head', 'delivery-limit': 20 },
  });
}

export async function queueDepth(
  vhost: string,
  queue: string,
): Promise<{ messages: number; policy: string | null }> {
  const q = (await management(
    'GET',
    `/queues/${encodeURIComponent(vhost)}/${encodeURIComponent(queue)}`,
  )) as { messages?: number; policy?: string | null; effective_policy_definition?: unknown };
  return { messages: q.messages ?? 0, policy: q.policy ?? null };
}
