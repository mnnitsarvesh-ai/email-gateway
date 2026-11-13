import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the webhook-worker integration suite (step 6.2 WP5 fix, precedent:
 * apps/delivery-worker/integration/support/live-worker.ts).
 *
 * The suite drives an IN-PROCESS delivery role restricted to its it-* fixture organizations
 * against the shared MySQL writer and Redis. A webhook-worker that already runs against the same
 * database — the `webhook-worker` container of the apps profile, or a worker on the host —
 * claims due `pending` deliveries of EVERY organization (it resolves `hooks.receiver.test`
 * through dns-sink to the TEST-ONLY webhook-receiver), so it would send the fixtures' deliveries
 * before the in-process loop sees them and its maintenance pass would cancel or purge the
 * fixtures' rows (evidence: the 2026-11-13 gate, `retries a failing receiver …` saw one attempt
 * fewer and `maintenance (W13)` cancelled nothing). The live `event-relay` would also publish the
 * fixtures' `notification.alert_requested.v1` outbox rows to the real vhost. So both are PAUSED
 * for the duration of the suite and resumed afterwards (`docker compose pause|unpause`, or
 * SIGSTOP/SIGCONT of the process listening on the host port). Nothing is stopped, restarted or
 * reconfigured.
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'webhook-worker', port: Number(process.env.WEBHOOK_WORKER_HOST_PORT ?? 3075) },
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
      `[webhook-worker integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
