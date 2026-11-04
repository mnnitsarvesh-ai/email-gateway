import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

/**
 * Broker helpers of the api integration suites (step 3.2 §10): a minimal copy of
 * `tests/integration/support/broker.ts` (this package's tsconfig cannot include files outside
 * it). Credentials come from the repository's .env and are never printed.
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
