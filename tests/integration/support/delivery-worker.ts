import { spawn } from 'node:child_process';
import { openSync } from 'node:fs';
import { join } from 'node:path';
import { composeOk, repoRoot, run, runningServices, waitFor } from './compose';
import { stack } from './env';

/**
 * Control of the delivery-worker for the routing stack suites (step 2.3 §9 items 7 and 8 stop
 * and start it). Either the `delivery-worker` Compose service (apps profile, CI) or a process on
 * the host listening on DELIVERY_WORKER_HOST_PORT (`pnpm --filter @email-gateway/delivery-worker
 * dev`, or `node --env-file=../../.env dist/main.js` in apps/delivery-worker). On the host the
 * suites stop the listening process with SIGTERM (graceful shutdown) and start the built worker
 * again detached, appending to `.local/delivery-worker.log`; it keeps running after the suite,
 * as before.
 */
const port = () => stack.ports.services['delivery-worker'];

export async function workerHealth(kind: 'live' | 'ready' = 'ready'): Promise<boolean> {
  try {
    const res = await fetch(`http://${stack.host}:${port()}/health/${kind}`, {
      signal: AbortSignal.timeout(2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function inContainer(): Promise<boolean> {
  return (await runningServices()).has('delivery-worker');
}

let containerMode: boolean | undefined;

async function hostPids(): Promise<number[]> {
  const result = await run('lsof', ['-nP', `-iTCP:${port()}`, '-sTCP:LISTEN', '-t'], {
    timeoutMs: 10_000,
  });
  return result.stdout
    .split('\n')
    .map((l) => Number(l.trim()))
    .filter((n) => Number.isInteger(n) && n > 0);
}

/** Stops the worker (graceful). Remembers where it ran so `startWorker` restarts it there. */
export async function stopWorker(): Promise<void> {
  containerMode ??= await inContainer();
  if (containerMode) {
    await composeOk(['stop', '--timeout', '30', 'delivery-worker'], { timeoutMs: 60_000 });
    return;
  }
  const pids = await hostPids();
  if (pids.length === 0) throw new Error(`no delivery-worker listens on port ${port()}`);
  for (const pid of pids) process.kill(pid, 'SIGTERM');
  await waitFor('the delivery-worker to stop', async () => (await hostPids()).length === 0, {
    timeoutMs: 45_000,
    intervalMs: 500,
  });
}

/**
 * Starts the worker again and waits for `/health/<waitFor>` (`live` when a dependency such as
 * Redis is down on purpose: the worker runs, readiness reports the outage).
 */
export async function startWorker(health: 'live' | 'ready' = 'ready'): Promise<void> {
  containerMode ??= await inContainer();
  if (containerMode) {
    // `docker start` of the existing container, NOT `docker compose start`: Compose would also
    // start its stopped dependencies (Redis), which the fail-closed case stops on purpose.
    const id = (
      await composeOk(['ps', '--all', '--quiet', 'delivery-worker'], { timeoutMs: 20_000 })
    ).stdout.trim();
    if (!/^[0-9a-f]{12,64}$/.test(id)) throw new Error('delivery-worker container not found');
    const started = await run('docker', ['start', id], { timeoutMs: 60_000 });
    if (started.exitCode !== 0) throw new Error(`docker start failed: ${started.stderr.trim()}`);
  } else {
    const cwd = join(repoRoot, 'apps/delivery-worker');
    const log = openSync(join(repoRoot, '.local/delivery-worker.log'), 'a');
    const child = spawn('node', ['--env-file=../../.env', 'dist/main.js'], {
      cwd,
      detached: true,
      stdio: ['ignore', log, log],
    });
    child.unref();
  }
  await waitFor(`the delivery-worker /health/${health}`, () => workerHealth(health), {
    timeoutMs: 90_000,
    intervalMs: 1_000,
  });
}
