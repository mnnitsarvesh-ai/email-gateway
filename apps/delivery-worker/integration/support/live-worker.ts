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
 */
const PORT = Number(process.env.DELIVERY_WORKER_HOST_PORT ?? 3040);
const COMPOSE = ['compose', '--project-name', process.env.COMPOSE_PROJECT_NAME || 'email-gateway'];

function run(file: string, args: string[]): string {
  try {
    return execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
}

function containerRunning(): boolean {
  return run('docker', [...COMPOSE, 'ps', '--status', 'running', '--services'])
    .split('\n')
    .map((l) => l.trim())
    .includes('delivery-worker');
}

function hostPids(): number[] {
  return run('lsof', ['-nP', `-iTCP:${PORT}`, '-sTCP:LISTEN', '-t'])
    .split('\n')
    .map((l) => Number(l.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid);
}

export default function setup(): () => void {
  if (containerRunning()) {
    run('docker', [...COMPOSE, 'pause', 'delivery-worker']);
    process.stderr.write('[delivery-worker integration] paused the delivery-worker container\n');
    return () => {
      run('docker', [...COMPOSE, 'unpause', 'delivery-worker']);
    };
  }
  const pids = hostPids();
  for (const pid of pids) process.kill(pid, 'SIGSTOP');
  if (pids.length > 0) {
    process.stderr.write(`[delivery-worker integration] paused the host delivery-worker\n`);
  }
  return () => {
    for (const pid of pids) {
      try {
        process.kill(pid, 'SIGCONT');
      } catch {
        // already gone
      }
    }
  };
}
