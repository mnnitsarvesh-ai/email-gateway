import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the smtp-adapter integration suites (the step 3.2 `live-relay.ts`
 * pattern of event-relay; added in step 3.3 verification round 2).
 *
 * The suites run IN-PROCESS listeners against the shared MySQL writer and assert on the rows
 * their own commits wrote (outbox `publishedAt: null`, exactly the ingestion's history rows).
 * Processes already running against the same database race with them:
 *
 * - a live `event-relay` publishes the fresh `mail.message.received.v1` rows and marks them;
 * - the `delivery-worker` dev pass-through moves the fresh messages `persisted → approved` and
 *   writes history, events and outbox rows; the `email-worker` parses them.
 *
 * So these services are PAUSED for the duration of the suites and resumed afterwards
 * (`docker compose pause|unpause <service>`, or SIGSTOP/SIGCONT of the host process listening on
 * the service's host port). Nothing is stopped, restarted or reconfigured; fixture rows are
 * deleted by the suites before the services resume.
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'event-relay', port: Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070) },
  { service: 'email-worker', port: Number(process.env.EMAIL_WORKER_HOST_PORT ?? 3020) },
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
      `[smtp-adapter integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
