import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the integration-worker integration suites (step 8.2; the pattern of
 * smtp-adapter's `live-workers.ts`).
 *
 * The suites run the worker's roles IN-PROCESS against the shared MySQL writer with an injected
 * clock and assert on exactly the rows their own runs claim and write. Processes already running
 * against the same database race with them:
 *
 * - a live `integration-worker` claims the fixtures' verifications, domain links, validation runs
 *   and health checks first (with the real clock and the Compose provider fake);
 * - a live `event-relay` publishes the fixtures' `integration.connection.health_changed.v1`
 *   outbox rows, which the webhook-worker turns into alert windows of the fixture organizations.
 *
 * So these services are PAUSED for the duration of the suites and resumed afterwards
 * (`docker compose pause|unpause <service>`, or SIGSTOP/SIGCONT of the host process listening on
 * the service's host port). Nothing is stopped, restarted or reconfigured; fixture rows (outbox
 * rows included) are deleted by the suites before the services resume.
 */
const SERVICES: { service: string; port: number }[] = [
  {
    service: 'integration-worker',
    port: Number(process.env.INTEGRATION_WORKER_HOST_PORT ?? 3086),
  },
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
      `[integration-worker integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
