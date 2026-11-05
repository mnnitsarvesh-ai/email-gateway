import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the email-worker integration suites (step 3.1 §9).
 *
 * The suites run the MIME ingestion stage IN-PROCESS against the shared MySQL writer, scoped to
 * their it-mime-* fixture organizations and per-run consumer names. An email-worker that is
 * already running against the same database (the `email-worker` container of the apps profile,
 * or `pnpm --filter @email-gateway/email-worker dev` on the host) polls the real
 * `email-worker.mime-parser` consumer and would parse the fixtures' received events first. So the
 * live worker is PAUSED for the duration of the suites and resumed afterwards
 * (`docker compose pause|unpause email-worker`, or SIGSTOP/SIGCONT of the process listening on
 * EMAIL_WORKER_HOST_PORT). Nothing is stopped, restarted or reconfigured.
 *
 * Step 3.2 (WP5 fix): the live `event-relay` is paused too. It publishes every unpublished outbox
 * row to the real vhost and marks it, so it would publish (and mark) the fixtures' rows that the
 * suites assert on (`published_at IS NULL`) or publish through their throwaway vhost themselves.
 *
 * Step 4.1 (WP5 fix): the live `delivery-worker` is paused too. Its development pass-through
 * reads `mail.message.scanned.v1` from the shared outbox and applies E27 (`scanned → approved`)
 * to every scanned message, so it moved the scan suites' fixture messages on to `approved`
 * (their recipients are `discarded`, so nothing was delivered, but the lifecycle assertions and
 * the rescans of a `scanned` message saw the extra transition).
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'email-worker', port: Number(process.env.EMAIL_WORKER_HOST_PORT ?? 3020) },
  { service: 'event-relay', port: Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070) },
  { service: 'delivery-worker', port: Number(process.env.DELIVERY_WORKER_HOST_PORT ?? 3040) },
];
const COMPOSE = ['compose', '--project-name', process.env.COMPOSE_PROJECT_NAME || 'email-gateway'];

function run(file: string, args: string[]): string {
  try {
    return execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
}

function runningContainers(): Set<string> {
  return new Set(
    run('docker', [...COMPOSE, 'ps', '--status', 'running', '--services'])
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0),
  );
}

function hostPids(port: number): number[] {
  return run('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'])
    .split('\n')
    .map((l) => Number(l.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid);
}

export default function setup(): () => void {
  const running = runningContainers();
  const paused: string[] = [];
  const stopped: number[] = [];
  for (const { service, port } of SERVICES) {
    if (running.has(service)) {
      run('docker', [...COMPOSE, 'pause', service]);
      paused.push(service);
      continue;
    }
    for (const pid of hostPids(port)) {
      process.kill(pid, 'SIGSTOP');
      stopped.push(pid);
    }
  }
  if (paused.length > 0 || stopped.length > 0) {
    process.stderr.write(
      `[email-worker integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
    );
  }
  return () => {
    for (const service of paused) run('docker', [...COMPOSE, 'unpause', service]);
    for (const pid of stopped) {
      try {
        process.kill(pid, 'SIGCONT');
      } catch {
        // already gone
      }
    }
  };
}
