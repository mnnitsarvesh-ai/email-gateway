import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stack } from './env';

/** Repository root: docker compose reads docker-compose.yml and .env from here. */
export const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  /** Kill the process after this many milliseconds (default 60 s). */
  timeoutMs?: number;
  /** Bytes written to stdin, then stdin is closed. */
  input?: string | Buffer;
  /** Working directory (default: the repository root). */
  cwd?: string;
  /** Extra environment for the child (merged over process.env). */
  env?: Record<string, string>;
}

/**
 * Runs a program with an argument ARRAY (never through a shell, so no value is ever
 * interpolated into a command line). Resolves with the exit code instead of throwing, so callers
 * can assert on failures; rejects only when the program cannot be started or times out.
 */
export function run(file: string, args: readonly string[], options: RunOptions = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  return new Promise<RunResult>((resolvePromise, reject) => {
    const child = execFile(
      file,
      [...args],
      {
        cwd: options.cwd ?? repoRoot,
        env: options.env ? { ...process.env, ...options.env } : process.env,
        timeout: timeoutMs,
        killSignal: 'SIGKILL',
        maxBuffer: 64 * 1024 * 1024,
        encoding: 'utf8',
      },
      (error, stdout, stderr) => {
        if (error && error.killed) {
          reject(
            new Error(`${file} ${args.slice(0, 4).join(' ')} … timed out after ${timeoutMs} ms`),
          );
          return;
        }
        if (error && typeof error.code !== 'number') {
          reject(error instanceof Error ? error : new Error(`${file} could not be started`));
          return;
        }
        resolvePromise({
          exitCode: error ? (error.code as number) : 0,
          stdout,
          stderr,
        });
      },
    );
    if (options.input !== undefined) child.stdin?.end(options.input);
    else child.stdin?.end();
  });
}

/** `docker compose -p <project> <args…>` from the repository root. */
export function compose(args: readonly string[], options: RunOptions = {}) {
  return run('docker', ['compose', '--project-name', stack.composeProject(), ...args], options);
}

/** Like `compose`, but throws (with stderr) on a non-zero exit code. */
export async function composeOk(args: readonly string[], options: RunOptions = {}) {
  const result = await compose(args, options);
  if (result.exitCode !== 0) {
    throw new Error(
      `docker compose ${args.slice(0, 3).join(' ')} … exited ${result.exitCode}: ${result.stderr.trim()}`,
    );
  }
  return result;
}

/** `docker compose exec -T [--user u] <service> <argv…>` (no TTY, argv passed verbatim). */
export function composeExec(
  service: string,
  argv: readonly string[],
  options: RunOptions & { user?: string } = {},
) {
  const userArgs = options.user ? ['--user', options.user] : [];
  return compose(['exec', '-T', ...userArgs, service, ...argv], options);
}

/** Services of the project that are currently running. */
export async function runningServices(): Promise<Set<string>> {
  const result = await compose(['ps', '--status', 'running', '--services'], { timeoutMs: 20_000 });
  if (result.exitCode !== 0) return new Set();
  return new Set(
    result.stdout
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean),
  );
}

/** Polls `check` until it returns a value other than undefined/false, or throws on timeout. */
export async function waitFor<T>(
  description: string,
  check: () => Promise<T | undefined | false>,
  { timeoutMs = 60_000, intervalMs = 500 }: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  for (;;) {
    try {
      const value = await check();
      if (value !== undefined && value !== false) return value;
    } catch (err) {
      lastError = err;
    }
    if (Date.now() > deadline) {
      const detail = lastError instanceof Error ? ` (last error: ${lastError.message})` : '';
      throw new Error(`Timed out after ${timeoutMs} ms waiting for ${description}${detail}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
