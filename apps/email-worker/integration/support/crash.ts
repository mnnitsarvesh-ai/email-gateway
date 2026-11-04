import { type ChildProcess, spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

const PACKAGE_ROOT = resolve(__dirname, '../..');

/** vite-node of the repository's vitest (runs the TypeScript child with the swc config). */
function viteNodeBin(): string {
  const fromVitest = createRequire(createRequire(__filename).resolve('vitest/package.json'));
  return join(dirname(fromVitest.resolve('vite-node/package.json')), 'vite-node.mjs');
}

export interface CrashChild {
  /** Resolves with the first IPC message starting with `prefix`. */
  message(prefix: string, timeoutMs?: number): Promise<string>;
  /** SIGKILL (no shutdown hooks, no acks, sockets dropped) and wait for the exit. */
  kill(): Promise<void>;
}

/**
 * Starts `crash-consumer.ts` in a child process with the suite's environment plus `env` (the
 * vhost URL, consumer name and crash point). Its output is discarded unless it fails to start.
 */
export function spawnCrashChild(env: Record<string, string>): CrashChild {
  const child: ChildProcess = spawn(
    process.execPath,
    [
      viteNodeBin(),
      '--config',
      join(PACKAGE_ROOT, 'vitest.integration.config.ts'),
      join(__dirname, 'crash-consumer.ts'),
    ],
    {
      cwd: PACKAGE_ROOT,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    },
  );
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
  const messages: string[] = [];
  const waiters: { prefix: string; resolve: (m: string) => void }[] = [];
  child.on('message', (message: unknown) => {
    const text = String(message);
    messages.push(text);
    for (const waiter of [...waiters]) {
      if (text.startsWith(waiter.prefix)) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve(text);
      }
    }
  });
  const exited = new Promise<void>((done) => child.once('exit', () => done()));
  return {
    message(prefix, timeoutMs = 90_000) {
      const seen = messages.find((m) => m.startsWith(prefix));
      if (seen) return Promise.resolve(seen);
      return new Promise<string>((done, fail) => {
        const timer = setTimeout(() => {
          // stderr carries error class names only (the child never prints values).
          fail(new Error(`crash child sent no ${prefix} message:\n${stderr.slice(-2000)}`));
        }, timeoutMs);
        waiters.push({
          prefix,
          resolve: (m) => {
            clearTimeout(timer);
            done(m);
          },
        });
        void exited.then(() => {
          clearTimeout(timer);
          fail(new Error(`crash child exited before ${prefix}:\n${stderr.slice(-2000)}`));
        });
      });
    },
    async kill() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited;
    },
  };
}
