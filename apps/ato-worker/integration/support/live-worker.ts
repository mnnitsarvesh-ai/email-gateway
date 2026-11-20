import { execFileSync } from 'node:child_process';

/**
 * vitest globalSetup of the ato-worker integration suite (precedent:
 * apps/webhook-worker/integration/support/live-worker.ts). The suite runs every ATO consumer and job
 * in-process, restricted to its own organizations; a live ato-worker (the `ato-worker`
 * container of the apps profile or a worker on the host port) would otherwise run the platform-wide maintenance
 * sweeps (expiry, retention) beside the suites. It is PAUSED for the duration of the suite and
 * resumed afterwards (`docker compose pause|unpause`, or SIGSTOP/SIGCONT of the process listening
 * on the host port). Nothing is stopped, restarted or reconfigured.
 */
const SERVICES: { service: string; port: number }[] = [
  { service: 'ato-worker', port: Number(process.env.ATO_WORKER_HOST_PORT ?? 3085) },
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

/** Services whose container exists but is paused (left paused by an aborted earlier run). */
function pausedContainers(): Set<string> {
  return new Set(
    run('docker', [...COMPOSE, 'ps', '--status', 'paused', '--services'])
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0),
  );
}

/**
 * Host processes listening on the port, never Docker's own port forwarder: a published container
 * port is held by the Docker Desktop backend, and stopping it hangs the whole engine (step 8.5
 * WP4 fix).
 */
function hostPids(port: number): number[] {
  return run('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'])
    .split('\n')
    .map((l) => Number(l.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid)
    .filter(
      (pid) => !/docker|vpnkit|com\.docker/i.test(run('ps', ['-o', 'command=', '-p', String(pid)])),
    );
}

export default function setup(): () => void {
  const running = runningContainers();
  const alreadyPaused = pausedContainers();
  const paused: string[] = [];
  const stopped: number[] = [];
  for (const { service, port } of SERVICES) {
    if (running.has(service)) {
      run('docker', [...COMPOSE, 'pause', service]);
      paused.push(service);
      continue;
    }
    // Paused by an aborted earlier run: keep it paused for this run and resume it afterwards.
    if (alreadyPaused.has(service)) {
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
      `[ato-worker integration] paused ${[...paused, ...stopped.map(() => 'host process')].join(', ')}\n`,
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
