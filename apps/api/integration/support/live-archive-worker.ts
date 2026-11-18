/**
 * Test hygiene for the api suites that simulate the archive-worker (step 8.1 WP6 fix): the
 * eDiscovery suite queues case searches and exports through the api and then writes the worker's
 * results itself (completed searches with hits, a built export package). When the `apps` Compose
 * profile is up, the live `archive-worker` container (ediscovery role) claims the same queued rows
 * within seconds — it completes or fails them, clears their hits and creates tenant keys — which
 * races with the suite's own assertions (for example the per-case limit of queued searches).
 * While such a suite runs, the container is PAUSED (`docker compose pause`; the precedent of
 * `apps/archive-worker/integration/support/live-worker.ts`) and unpaused afterwards. Nothing is
 * stopped, restarted or reconfigured. Without Docker or with the container not running, this
 * does nothing.
 *
 * `pauseLiveService` is the same for any Compose service: the webhook deliveries suite pauses the
 * live `webhook-worker` while it asserts a replay that is still `queued` (its replay loop claims
 * queued replays every second, verification of step 8.1).
 */
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';

/** Repository root: `docker compose` reads docker-compose.yml and .env from here. */
const REPO_ROOT = resolve(__dirname, '../../../..');

interface Result {
  exitCode: number;
  stdout: string;
}

function compose(args: readonly string[], timeoutMs: number): Promise<Result> {
  return new Promise((resolvePromise) => {
    execFile(
      'docker',
      ['compose', ...args],
      { cwd: REPO_ROOT, timeout: timeoutMs, killSignal: 'SIGKILL' },
      (error, stdout) =>
        resolvePromise({
          exitCode: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
          stdout: String(stdout),
        }),
    );
  });
}

/**
 * Pauses the live container of a Compose service when it is running. Returns the function that
 * unpauses it; call it in a `finally` or after the suite's fixtures are deleted.
 */
export async function pauseLiveService(service: string): Promise<() => Promise<void>> {
  const running = await compose(['ps', '--status', 'running', '--services'], 20_000);
  if (running.exitCode !== 0 || !running.stdout.split('\n').includes(service)) {
    return () => Promise.resolve();
  }
  const paused = await compose(['pause', service], 30_000);
  if (paused.exitCode !== 0) throw new Error(`docker compose pause ${service} failed`);
  return async () => {
    const unpaused = await compose(['unpause', service], 30_000);
    if (unpaused.exitCode !== 0) throw new Error(`docker compose unpause ${service} failed`);
  };
}

/** Pauses the live archive-worker container when it is running (see `pauseLiveService`). */
export function pauseLiveArchiveWorker(): Promise<() => Promise<void>> {
  return pauseLiveService('archive-worker');
}
