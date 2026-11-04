/**
 * Test hygiene for the suites that call the lifecycle write routes (step 3.3 L16): a release
 * writes `mail.delivery.approved.v1` outbox rows and a rescan writes
 * `mail.message.rescan_requested.v1` rows. These suites assert on the rows themselves and delete
 * them with their fixtures. When the `apps` Compose profile is up, the live event-relay
 * container (250 ms poll) would publish them and the live delivery-worker would consume the
 * approvals: either after the fixture cleanup (an `approval_not_issued` dead letter left in
 * `email.dead-letter`) or before it (the planner acting on a fixture message). While such a
 * suite runs, the container is stopped, so its rows are never published. After the fixture
 * cleanup the container is started again. Without Docker or with the container not running,
 * this does nothing.
 */
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';

/** Repository root: `docker compose` reads docker-compose.yml and .env from here. */
const REPO_ROOT = resolve(__dirname, '../../../..');
const SERVICE = 'event-relay';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

async function relayReady(port: number): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health/ready`, {
      signal: AbortSignal.timeout(2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Stops the live event-relay container when it is running. Returns the function that starts
 * it again and waits until it is ready; call it after the suite's fixtures are deleted.
 */
export async function pauseLiveRelay(): Promise<() => Promise<void>> {
  const running = await compose(['ps', '--status', 'running', '--services'], 20_000);
  if (running.exitCode !== 0 || !running.stdout.split('\n').includes(SERVICE)) {
    return () => Promise.resolve();
  }
  const stopped = await compose(['stop', '--timeout', '30', SERVICE], 90_000);
  if (stopped.exitCode !== 0) throw new Error(`docker compose stop ${SERVICE} failed`);
  return async () => {
    const started = await compose(['start', SERVICE], 60_000);
    if (started.exitCode !== 0) throw new Error(`docker compose start ${SERVICE} failed`);
    const port = Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070);
    const deadline = Date.now() + 120_000;
    while (!(await relayReady(port))) {
      if (Date.now() > deadline) throw new Error(`${SERVICE} not ready 120 s after its restart`);
      await sleep(1_000);
    }
  };
}
