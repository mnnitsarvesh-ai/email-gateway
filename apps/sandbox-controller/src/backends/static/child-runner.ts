import { type ChildProcess, spawn, type SpawnOptions } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ANALYZER_VERSION } from './analyzers/analysis';
import { type ChildMessage, CODE_PATTERN, isChildMessage, type ParentMessage } from './protocol';
import { defaultSampler, type ProcessSampler } from './sampler';

/**
 * Spawns, limits and reaps ONE analyzer child per task (step 4.6 X4; the ADR-0036 pattern with
 * its own small runner: the email-worker `ChildPool` cannot be imported across apps).
 *
 * - `env: {}`; Node's permission model: `--allow-fs-read` of the analyzer's compiled directory
 *   and `<scratch>/in`, `--allow-fs-write` of `<scratch>/out`; no `--allow-child-process`, no
 *   `--allow-worker`, no `--allow-addons`; `--max-old-space-size`; cwd = the task scratch.
 * - Linux: under `prlimit --cpu=<s>:<s+1> --core=0` when found (backstop); the parent samples
 *   `/proc/<pid>` (elsewhere `ps`) and kills on RSS / CPU; a wall timer kills on time.
 * - The handshake must name `ANALYZER_VERSION`; the child is SIGKILLed and awaited in `finally`
 *   whatever happened.
 *
 * Outcomes: `result` (the child's reply, validated by the caller), `error` (the child reported
 * a code), `resources` (RSS/CPU/heap/rlimit kill: the sample is hostile to parsers → finding
 * `limit.analyzer_resources`), `timeout` (`analyzer_timeout`), `crashed` (`analyzer_crashed`),
 * `aborted` (task timeout or shutdown).
 */

export type ChildOutcome =
  | { kind: 'result'; analysis: unknown }
  | { kind: 'error'; code: string }
  | { kind: 'probe'; outcome: string }
  | { kind: 'resources'; reason: 'rss' | 'cpu' | 'heap' | 'rlimit' }
  | { kind: 'timeout' }
  | { kind: 'crashed'; reason: string }
  | { kind: 'aborted' };

export interface ChildRunnerOptions {
  /** Absolute path of the compiled `analyzer-child.js`. */
  entry: string;
  heapMb: number;
  maxRssMb: number;
  cpuSeconds: number;
  timeoutMs: number;
  /** Handshake budget (default 10 s). */
  startTimeoutMs?: number;
  /** Sampling period (default 200 ms). */
  sampleIntervalMs?: number;
  /** `undefined`: look it up; `null`: none. */
  prlimitPath?: string | null;
  sampler?: ProcessSampler;
  /** Unit tests only: lets the child honour `selftest` probes. */
  selftest?: boolean;
  spawnFn?: (command: string, args: string[], options: SpawnOptions) => ChildProcess;
}

const PRLIMIT_CANDIDATES = [
  '/usr/bin/prlimit',
  '/bin/prlimit',
  '/usr/sbin/prlimit',
  '/sbin/prlimit',
];
const STDERR_TAIL = 4096;
const HEAP_FATAL =
  /heap limit|JavaScript heap out of memory|Allocation failed|Ineffective mark-compacts/i;

/** Finds `prlimit` without spawning anything. */
export function findPrlimit(): string | null {
  return PRLIMIT_CANDIDATES.find((path) => existsSync(path)) ?? null;
}

const real = (path: string): string => {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
};

export class AnalyzerChildRunner {
  readonly prlimit: string | null;
  private readonly sampler: ProcessSampler;
  private readonly children = new Set<ChildProcess>();

  constructor(private readonly options: ChildRunnerOptions) {
    this.prlimit =
      options.prlimitPath !== undefined
        ? options.prlimitPath
        : process.platform === 'linux'
          ? findPrlimit()
          : null;
    this.sampler = options.sampler ?? defaultSampler();
  }

  /** `prlimit` (Linux, found) or `none` (readiness details). */
  get rlimitMode(): 'prlimit' | 'none' {
    return this.prlimit ? 'prlimit' : 'none';
  }

  get active(): number {
    return this.children.size;
  }

  /** The command line of one child (exported for the unit test of the permission flags). */
  command(scratchDir: string): { command: string; args: string[] } {
    const o = this.options;
    const nodeArgs = [
      '--permission',
      `--allow-fs-read=${real(dirname(o.entry))}`,
      `--allow-fs-read=${real(join(scratchDir, 'in'))}`,
      `--allow-fs-write=${real(join(scratchDir, 'out'))}`,
      `--max-old-space-size=${String(o.heapMb)}`,
      '--disable-warning=SecurityWarning',
      '--disable-warning=ExperimentalWarning',
      real(o.entry),
      ...(o.selftest ? ['--selftest'] : []),
    ];
    if (!this.prlimit) return { command: process.execPath, args: nodeArgs };
    return {
      command: this.prlimit,
      args: [
        `--cpu=${String(o.cpuSeconds + 1)}:${String(o.cpuSeconds + 2)}`,
        '--core=0',
        '--',
        process.execPath,
        ...nodeArgs,
      ],
    };
  }

  /** Runs one job in a fresh child and always kills and awaits it before resolving. */
  async run(
    scratchDir: string,
    message: ParentMessage,
    signal: AbortSignal,
  ): Promise<ChildOutcome> {
    if (signal.aborted) return { kind: 'aborted' };
    const o = this.options;
    const { command, args } = this.command(scratchDir);
    let child: ChildProcess;
    try {
      child = (o.spawnFn ?? spawn)(command, args, {
        cwd: scratchDir,
        env: {},
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
        detached: false,
        windowsHide: true,
      });
    } catch {
      return { kind: 'crashed', reason: 'spawn_failed' };
    }
    this.children.add(child);
    // Node's own fatal messages only (the child prints nothing else): the head carries V8's
    // "FATAL ERROR … heap limit" line, the tail the end of a stack dump. Never logged.
    let stderrHead = '';
    let stderrTail = '';
    child.stderr?.on('data', (chunk: Buffer | string) => {
      const text = chunk.toString();
      if (stderrHead.length < STDERR_TAIL) stderrHead = (stderrHead + text).slice(0, STDERR_TAIL);
      stderrTail = (stderrTail + text).slice(-STDERR_TAIL);
    });
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve) => {
        // `close`: after the exit AND the end of stderr (a fatal V8 message is read completely).
        child.once('close', (code, sig) => resolve({ code, signal: sig }));
        child.once('error', () => resolve({ code: null, signal: null }));
      },
    );

    let killedFor: ChildOutcome | null = null;
    const kill = (outcome: ChildOutcome): void => {
      killedFor ??= outcome;
      child.kill('SIGKILL');
    };
    const timers: NodeJS.Timeout[] = [];
    const onAbort = (): void => kill({ kind: 'aborted' });
    signal.addEventListener('abort', onAbort, { once: true });

    try {
      const outcome = await new Promise<ChildOutcome>((resolve) => {
        let ready = false;
        let sampling = false;
        const startTimer = setTimeout(() => {
          if (!ready) kill({ kind: 'crashed', reason: 'handshake_timeout' });
        }, o.startTimeoutMs ?? 10_000);
        timers.push(startTimer);
        child.on('message', (raw: unknown) => {
          if (!isChildMessage(raw)) return;
          const m: ChildMessage = raw;
          if (m.op === 'ready') {
            if (ready) return;
            if (m.version !== ANALYZER_VERSION) {
              kill({ kind: 'crashed', reason: 'version_mismatch' });
              return;
            }
            ready = true;
            clearTimeout(startTimer);
            timers.push(setTimeout(() => kill({ kind: 'timeout' }), o.timeoutMs));
            const pid = child.pid;
            if (pid !== undefined) {
              timers.push(
                setInterval(() => {
                  if (sampling) return;
                  sampling = true;
                  void this.sampler(pid)
                    .then((sample) => {
                      if (!sample) return;
                      if (sample.rssMb > o.maxRssMb) kill({ kind: 'resources', reason: 'rss' });
                      else if (sample.cpuSeconds > o.cpuSeconds)
                        kill({ kind: 'resources', reason: 'cpu' });
                    })
                    .finally(() => {
                      sampling = false;
                    });
                }, o.sampleIntervalMs ?? 200),
              );
            }
            child.send(message, (error) => {
              if (error) kill({ kind: 'crashed', reason: 'ipc_failed' });
            });
            return;
          }
          if (m.op === 'probe') {
            resolve({ kind: 'probe', outcome: m.outcome });
            return;
          }
          if (m.op === 'result') {
            if (m.ok) resolve({ kind: 'result', analysis: m.analysis });
            else
              resolve({
                kind: 'error',
                code: CODE_PATTERN.test(m.code) ? m.code : 'analyze_error',
              });
          }
        });
        void exited.then(({ code, signal: sig }) => {
          if (killedFor) return resolve(killedFor);
          if (sig === 'SIGXCPU' || (this.prlimit && sig === 'SIGKILL')) {
            return resolve({ kind: 'resources', reason: 'rlimit' });
          }
          if (HEAP_FATAL.test(stderrHead) || HEAP_FATAL.test(stderrTail))
            return resolve({ kind: 'resources', reason: 'heap' });
          resolve({
            kind: 'crashed',
            reason: sig ? 'signal' : `exit_${String(code ?? 'unknown')}`.slice(0, 32),
          });
        });
      });
      return outcome;
    } finally {
      for (const timer of timers) clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000).unref())]);
      this.children.delete(child);
    }
  }

  /** Kills every child still alive (shutdown). */
  close(): Promise<void> {
    for (const child of this.children) child.kill('SIGKILL');
    this.children.clear();
    return Promise.resolve();
  }
}
