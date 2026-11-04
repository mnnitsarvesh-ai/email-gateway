import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the delivery-worker integration suites (step 2.3 §12, WP5 fix).
 *
 * These suites run an IN-PROCESS worker against the shared MySQL writer, scoped to their it-*
 * fixture organizations. A delivery-worker that is already running against the same database —
 * the `delivery-worker` container of the apps profile (CI) or a worker on the host for the
 * routing stack suites (`pnpm test:integration` runs both) — claims due `pending` reinjections
 * of every organization and would reinject the fixtures before the in-process worker sees them.
 * So the live worker is PAUSED for the duration of these suites and resumed afterwards
 * (`docker compose pause|unpause delivery-worker`, or SIGSTOP/SIGCONT of the process listening
 * on DELIVERY_WORKER_HOST_PORT). Nothing is stopped, restarted or reconfigured. A paused worker
 * keeps its connections; the in-process consumers use their own cursor and lock names.
 *
 * Step 3.2 (WP5 fix): the live `event-relay` is paused too. It publishes every unpublished outbox
 * row to the real vhost and marks it, so it would publish (and mark) the fixtures' rows that the
 * suites publish through their throwaway vhost themselves.
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'delivery-worker', port: Number(process.env.DELIVERY_WORKER_HOST_PORT ?? 3040) },
  { service: 'event-relay', port: Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070) },
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
      `[delivery-worker integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
