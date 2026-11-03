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
 */
const PORT = Number(process.env.EMAIL_WORKER_HOST_PORT ?? 3020);
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
    .includes('email-worker');
}

function hostPids(): number[] {
  return run('lsof', ['-nP', `-iTCP:${PORT}`, '-sTCP:LISTEN', '-t'])
    .split('\n')
    .map((l) => Number(l.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid);
}

export default function setup(): () => void {
  if (containerRunning()) {
    run('docker', [...COMPOSE, 'pause', 'email-worker']);
    process.stderr.write('[email-worker integration] paused the email-worker container\n');
    return () => {
      run('docker', [...COMPOSE, 'unpause', 'email-worker']);
    };
  }
  const pids = hostPids();
  for (const pid of pids) process.kill(pid, 'SIGSTOP');
  if (pids.length > 0)
    process.stderr.write('[email-worker integration] paused the host email-worker\n');
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
