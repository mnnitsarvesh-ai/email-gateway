import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the policy-engine integration suites (same pattern as the
 * delivery-worker's). The suites commit evaluations of it-pe-* fixture messages on the shared
 * writer, including approval outbox rows. A live `event-relay` would publish those rows to the
 * real vhost (and the live delivery-worker would plan the fixtures), so it is PAUSED for the
 * duration, as is a live `policy-engine` (it consumes the real `email.policy.evaluate`; the
 * suites use a throwaway vhost). `docker compose pause|unpause`, or SIGSTOP/SIGCONT of a host
 * process listening on the service's port. Nothing is stopped, restarted or reconfigured.
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'event-relay', port: Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070) },
  { service: 'policy-engine', port: Number(process.env.POLICY_ENGINE_HOST_PORT ?? 3030) },
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
      `[policy-engine integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
