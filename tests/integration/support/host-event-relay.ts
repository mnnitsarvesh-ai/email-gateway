import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, openSync } from 'node:fs';
import { join } from 'node:path';
import { composeOk, repoRoot, run, runningServices, waitFor } from './compose';

/**
 * A test-only event-relay process on the HOST (docs/plan/steps/08-message-lifecycle.md §9
 * "Stack": expiry with short deadlines on a host-run instance; the container keeps its
 * defaults). The `event-relay` container is stopped first, because the shard locks of the expiry
 * sweeper (`er:lifecycle-expiry#i/n`), the reconciler lock (`er:reconciler`) and the lifecycle
 * check lock are single-owner: a second instance would never become active. The host process
 * runs every role (outbox relay included, so the stack keeps publishing) with the suite's
 * overrides, logs to `.local/<name>.log`, and is stopped with SIGTERM; then the container is
 * started again with `docker start` (Compose would also start stopped dependencies).
 */
export interface HostRelay {
  port: number;
  metrics(): Promise<string>;
  stop(): Promise<void>;
}

const relayDir = join(repoRoot, 'apps/event-relay');

async function health(port: number, kind: 'live' | 'ready'): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health/${kind}`, {
      signal: AbortSignal.timeout(2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** Builds the event-relay (`nest build`), so the host process runs this tree's code. */
export async function buildEventRelay(): Promise<void> {
  const built = await run('pnpm', ['--filter', '@email-gateway/event-relay', 'run', 'build'], {
    timeoutMs: 180_000,
  });
  if (built.exitCode !== 0) throw new Error(`event-relay build failed:\n${built.stderr}`);
}

export async function stopRelayContainer(): Promise<boolean> {
  if (!(await runningServices()).has('event-relay')) return false;
  await composeOk(['stop', '--timeout', '30', 'event-relay'], { timeoutMs: 90_000 });
  return true;
}

export async function startRelayContainer(): Promise<void> {
  const id = (
    await composeOk(['ps', '--all', '--quiet', 'event-relay'], { timeoutMs: 20_000 })
  ).stdout.trim();
  if (!/^[0-9a-f]{12,64}$/.test(id)) throw new Error('event-relay container not found');
  const started = await run('docker', ['start', id], { timeoutMs: 60_000 });
  if (started.exitCode !== 0) throw new Error(`docker start failed: ${started.stderr.trim()}`);
  const port = Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070);
  await waitFor('the event-relay container ready', () => health(port, 'ready'), {
    timeoutMs: 120_000,
    intervalMs: 1_000,
  });
}

/**
 * Starts `node dist/main.js` of apps/event-relay with the suite environment (the local `.env`,
 * already loaded by vitest) plus `overrides`, on `port`. Waits for `/health/ready`.
 */
export async function startHostRelay(
  name: string,
  port: number,
  overrides: Record<string, string>,
): Promise<HostRelay> {
  mkdirSync(join(repoRoot, '.local'), { recursive: true });
  const log = openSync(join(repoRoot, '.local', `${name}.log`), 'a');
  const child: ChildProcess = spawn(process.execPath, ['dist/main.js'], {
    cwd: relayDir,
    env: { ...process.env, ...overrides, HTTP_PORT: String(port) },
    stdio: ['ignore', log, log],
  });
  let exited = false;
  child.on('exit', () => (exited = true));
  await waitFor(
    `the host event-relay ${name} ready on ${port}`,
    async () => {
      if (exited) throw new Error(`host event-relay exited early; see .local/${name}.log`);
      return health(port, 'ready');
    },
    { timeoutMs: 60_000, intervalMs: 500 },
  );
  return {
    port,
    metrics: async () => {
      const res = await fetch(`http://127.0.0.1:${port}/metrics`, {
        signal: AbortSignal.timeout(5_000),
      });
      return res.text();
    },
    stop: async () => {
      if (exited) return;
      child.kill('SIGTERM');
      await waitFor('the host event-relay to exit', () => Promise.resolve(exited), {
        timeoutMs: 45_000,
        intervalMs: 250,
      }).catch(() => {
        child.kill('SIGKILL');
      });
    },
  };
}

/** Sum of the samples of `name` whose labels contain every `labels` pair. */
export function metricSum(text: string, name: string, labels: Record<string, string> = {}) {
  return text
    .split('\n')
    .filter((l) => l.startsWith(`${name}{`) || l.startsWith(`${name} `))
    .filter((l) => Object.entries(labels).every(([k, v]) => l.includes(`${k}="${v}"`)))
    .reduce((sum, l) => sum + Number(l.split(' ').at(-1)), 0);
}
