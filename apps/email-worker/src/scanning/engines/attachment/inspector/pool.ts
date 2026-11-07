import { spawn as nodeSpawn, type SpawnOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Logger } from '@email-gateway/logger';
import type { InspectionResult, InspectLimits } from '../content';
import {
  type ChildMessage,
  type ChildReadyMessage,
  CODE_PATTERN,
  isChildMessage,
  isExtractorReady,
  type SelftestMode,
} from './protocol';
import { defaultSampler, type ProcessSampler } from './sampler';

/**
 * The resource-limited child pool (step 4.2 A4, generalized in step 4.5 D4). `ChildPool` runs any
 * child described by a `ChildDescriptor` (entry, arguments, extra read roots, handshake check,
 * reply field); `InspectorPool` is the attachment inspector built on it exactly as in 4.2 (YARA
 * bundle-id handshake, `inspect` jobs), the DLP extractor pool is another instance (step 4.5).
 *
 * The inspector pool (step 4.2 A4): `ATTACHMENT_INSPECTOR_POOL_SIZE` resource-limited child
 * processes, one job at a time each, a bounded FIFO wait queue, recycling after
 * `ATTACHMENT_INSPECTOR_MAX_JOBS` jobs and after every kill.
 *
 * Every child: `spawn` with an empty environment (NODE_ENV, PATH; EG_INSPECTOR_SELFTEST only
 * when the test hook is configured), stdio `['ignore', 'ignore', 'pipe', 'ipc']`,
 * `serialization: 'advanced'`, `--max-old-space-size`, Node's permission model (no child
 * processes, no file writes, reads of the application and the rules directory only), on Linux
 * under `prlimit --cpu=<soft:hard> --core=0` (`required` refuses to start without it), a
 * private 0700 working directory `eg-inspect-<pid>-<16 hex>` removed when the child exits.
 *
 * Per job: the worker samples the child's CPU time and RSS every 100 ms (`/proc` on Linux, `ps`
 * elsewhere) and SIGKILLs it above ATTACHMENT_INSPECT_CPU_SECONDS (→ `limit.cpu_time`, a
 * definite content result) or ATTACHMENT_INSPECT_MAX_RSS_MB (→ `limit.memory`); the wall-clock
 * timeout ATTACHMENT_INSPECT_TIMEOUT_MS (→ attempt failure `inspector_timeout`) and any other
 * exit (→ `inspector_crash`) are retryable failures, never a verdict. The handshake reports the
 * child's bundle id; a child whose id differs from the worker's is refused.
 */

export type KillReason = 'cpu' | 'memory' | 'wall' | 'crash';

/** The outcome of one job of a pool child (`TResult` = the child's reply payload). */
export type PoolOutcome<TResult> =
  | { kind: 'result'; result: TResult }
  /** A load-independent limit breach: a property of the file (A4, rule S3). */
  | { kind: 'limit'; code: 'limit.cpu_time' | 'limit.memory' }
  /** `wall` / `crash`: retryable attempt failures; `aborted`: the engine call timed out. */
  | { kind: 'failure'; reason: 'wall' | 'crash' | 'aborted' | 'unavailable' };

export type InspectOutcome = PoolOutcome<InspectionResult>;

export interface PoolState {
  idle: number;
  busy: number;
  waiting: number;
}

/** The parts of a ChildProcess the pool uses (a fake in unit tests). */
export interface InspectorChild {
  readonly pid?: number | undefined;
  readonly connected: boolean;
  readonly stderr: NodeJS.ReadableStream | null;
  send(message: unknown): boolean;
  kill(signal?: NodeJS.Signals): boolean;
  disconnect(): void;
  on(event: 'message', listener: (message: unknown) => void): this;
  on(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
}

export type SpawnFn = (command: string, args: string[], options: SpawnOptions) => InspectorChild;

/** Options every pool child kind shares (sizes, limits, isolation, test seams). */
export interface ChildPoolOptions {
  size: number;
  maxJobs: number;
  heapMb: number;
  rlimits: 'required' | 'best_effort';
  /** Parent of the private directories (ATTACHMENT_INSPECTOR_TMPDIR, default os.tmpdir()). */
  tmpDir?: string;
  wallTimeoutMs: number;
  cpuSeconds: number;
  maxRssMb: number;
  selftest: boolean;
  nodeEnv: string;
  /** Bound of the FIFO wait queue (the engine's concurrency x per-message parallelism). */
  maxWaiting: number;
  logger: Logger;
  onKill?: (reason: KillReason) => void;
  onState?: (state: PoolState) => void;
  // Test seams.
  spawn?: SpawnFn;
  sampler?: ProcessSampler;
  sampleIntervalMs?: number;
  platform?: NodeJS.Platform;
  /** Overrides the prlimit lookup (null = not available). */
  prlimitPath?: string | null;
  /** Overrides the child entry (unit tests with a fake spawn). */
  childEntry?: string;
  startTimeoutMs?: number;
}

/** What a pool child is (step 4.5 D4): the pool's only child-specific knowledge. */
export interface ChildDescriptor<TResult> {
  /** Logger component and log wording, e.g. `attachment-inspector`, `dlp-extractor`. */
  component: string;
  /** The config key of the rlimit mode (named in the no-prlimit warning). */
  rlimitsKey: string;
  /** The child entry: `child.js` next to the compiled module, `child.ts` in source runs. */
  entry: string;
  /** Arguments after the entry (no secrets: visible in the process list). */
  args: readonly string[];
  /** Directories the child may read besides the application and the workspace. */
  readRoots: readonly string[];
  /** Fields of the start log line (ids and versions only). */
  startDetails: Readonly<Record<string, string | number>>;
  /** Handshake check: null accepts the child, a code refuses it (killed, start fails). */
  checkReady(message: ChildReadyMessage): string | null;
  /** The payload of a successful reply (`result` / `extraction`); undefined = malformed. */
  resultOf(message: Record<string, unknown>): TResult | undefined;
}

export interface InspectorPoolOptions extends ChildPoolOptions {
  rulesDir: string;
  yaraTimeoutMs: number;
  /** The worker's own bundle id (A9): a child reporting another one is refused. */
  expectedBundleId: string;
}

/** The private directory of a child: `eg-inspect-<worker pid>-<16 hex>`. */
export const PRIVATE_DIR_PATTERN = /^eg-inspect-\d+-[0-9a-f]{16}$/;
/** Stale private directories older than this are removed at pool start (A4). */
const STALE_DIR_MS = 10 * 60_000;
const PRLIMIT_CANDIDATES = [
  '/usr/bin/prlimit',
  '/bin/prlimit',
  '/usr/sbin/prlimit',
  '/sbin/prlimit',
];
/** Upper bound of the per-process CPU rlimit backstop (seconds). */
const MAX_CPU_RLIMIT_SECONDS = 86_400;
const STDERR_TAIL_BYTES = 2_048;
const RESPAWN_DELAY_MS = 1_000;

interface Job {
  id: number;
  resolve: (outcome: PoolOutcome<unknown>) => void;
  killReason: KillReason | 'aborted' | null;
  baseCpu: number | null;
  sampling: boolean;
  timers: Array<NodeJS.Timeout>;
  cleanup: () => void;
}

interface Slot {
  child: InspectorChild;
  dir: string;
  ready: boolean;
  jobs: number;
  job: Job | null;
  retiring: boolean;
  exited: Promise<void>;
  stderrTail: string;
}

interface Waiter {
  run: (slot: Slot) => void;
  fail: (outcome: PoolOutcome<unknown>) => void;
}

/** A job message without its id (the pool assigns it). */
export type JobPayload = { op: string } & Record<string, unknown>;

export class InspectorPoolStartError extends Error {
  override readonly name = 'InspectorPoolStartError';
  constructor(
    readonly code: string,
    component = 'attachment-inspector',
  ) {
    super(`${component.replace('-', ' ')} pool cannot start (${code})`);
  }
}

/** The application root (the directory of package.json) of this module, src or dist. */
const APP_ROOT = resolve(__dirname, '../../../../..');

function workspaceRoot(start: string): string | null {
  let dir = start;
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

const real = (path: string): string => {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
};

/** Finds `prlimit` without spawning anything. */
export function findPrlimit(): string | null {
  return PRLIMIT_CANDIDATES.find((path) => existsSync(path)) ?? null;
}

/**
 * Removes stale `eg-inspect-*` directories of this uid older than 10 minutes in `dir` (left by
 * a worker that was killed). Returns how many were removed.
 */
export function removeStaleDirs(dir: string, now = Date.now()): number {
  let removed = 0;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return 0;
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  for (const name of names) {
    if (!PRIVATE_DIR_PATTERN.test(name)) continue;
    const path = join(dir, name);
    try {
      const stat = lstatSync(path);
      if (!stat.isDirectory() || stat.isSymbolicLink()) continue;
      if (uid !== null && stat.uid !== uid) continue;
      if (now - stat.mtimeMs < STALE_DIR_MS) continue;
      rmSync(path, { recursive: true, force: true });
      removed += 1;
    } catch {
      // Raced with another worker or not ours: leave it.
    }
  }
  return removed;
}

export class ChildPool<TResult> {
  private readonly slots = new Set<Slot>();
  private readonly waiting: Waiter[] = [];
  private readonly logger: Logger;
  private readonly sampler: ProcessSampler;
  private readonly spawnFn: SpawnFn;
  private readonly tmpDir: string;
  private readonly platform: NodeJS.Platform;
  private prlimit: string | null = null;
  private stopped = false;
  private started = false;
  private seq = 0;
  private warnedNoRlimit = false;

  constructor(
    private readonly options: ChildPoolOptions,
    private readonly descriptor: ChildDescriptor<TResult>,
  ) {
    this.logger = options.logger.child({ component: descriptor.component });
    this.sampler = options.sampler ?? defaultSampler();
    this.spawnFn = options.spawn ?? ((command, args, opts) => nodeSpawn(command, args, opts));
    this.tmpDir = options.tmpDir && options.tmpDir.length > 0 ? options.tmpDir : tmpdir();
    this.platform = options.platform ?? process.platform;
  }

  /** Whether compiled children run under Node's permission model (always outside source runs). */
  get permissionModel(): boolean {
    return !this.childEntry.endsWith('.ts');
  }

  /** The child entry (descriptor), unless a test overrides it. */
  private get childEntry(): string {
    return this.options.childEntry ?? this.descriptor.entry;
  }

  /** `prlimit` (Linux, found) or `none` (readiness details, A4). */
  get rlimitMode(): 'prlimit' | 'none' {
    return this.prlimit ? 'prlimit' : 'none';
  }

  get state(): PoolState {
    let idle = 0;
    let busy = 0;
    for (const slot of this.slots) {
      if (!slot.ready || slot.retiring) continue;
      if (slot.job) busy += 1;
      else idle += 1;
    }
    return { idle, busy, waiting: this.waiting.length };
  }

  /** Ready children (readiness: at least one). */
  get readyCount(): number {
    return [...this.slots].filter((s) => s.ready && !s.retiring).length;
  }

  /**
   * Removes stale private directories, resolves prlimit (refusing to start without it in
   * `required` mode), spawns every child and waits for their handshakes (descriptor check).
   */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    const removed = removeStaleDirs(this.tmpDir);
    if (removed > 0) this.logger.info({ removed }, 'stale child directories removed');
    this.prlimit =
      this.options.prlimitPath !== undefined
        ? this.options.prlimitPath
        : this.platform === 'linux'
          ? findPrlimit()
          : null;
    if (!this.prlimit) {
      if (this.options.rlimits === 'required') {
        throw new InspectorPoolStartError(
          this.platform === 'linux' ? 'prlimit_missing' : 'rlimits_unsupported_platform',
          this.descriptor.component,
        );
      }
      this.warnNoRlimit();
    }
    const spawned = Array.from({ length: this.options.size }, () => this.spawnSlot());
    const results = await Promise.allSettled(spawned);
    const failed = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
    if (failed) {
      await this.stop();
      const reason: unknown = failed.reason;
      throw reason instanceof InspectorPoolStartError
        ? reason
        : new InspectorPoolStartError('spawn_failed', this.descriptor.component);
    }
    this.publishState();
    this.logger.info(
      { size: this.options.size, rlimits: this.rlimitMode, ...this.descriptor.startDetails },
      `${this.descriptor.component.replace('-', ' ')} pool started`,
    );
  }

  /** Kills every child (graceful shutdown), fails waiters, removes the private directories. */
  async stop(): Promise<void> {
    this.stopped = true;
    for (const waiter of this.waiting.splice(0))
      waiter.fail({ kind: 'failure', reason: 'unavailable' });
    const exits: Array<Promise<void>> = [];
    for (const slot of this.slots) {
      slot.retiring = true;
      exits.push(slot.exited);
      try {
        slot.child.kill('SIGKILL');
      } catch {
        // already gone
      }
    }
    await Promise.race([
      Promise.all(exits),
      new Promise<void>((done) => setTimeout(done, 5_000).unref()),
    ]);
    for (const slot of this.slots) this.removeDir(slot.dir);
    this.slots.clear();
    this.publishState();
  }

  /**
   * Runs one job in a child (FIFO wait for an idle child, bounded): `payload` is the child's job
   * message without its id (`{ op: 'inspect', … }`, `{ op: 'extract', … }`).
   */
  job(payload: JobPayload, signal: AbortSignal): Promise<PoolOutcome<TResult>> {
    return this.submit(payload, signal) as Promise<PoolOutcome<TResult>>;
  }

  /** Test hook (EG_INSPECTOR_SELFTEST only; the child refuses otherwise). */
  selftest(mode: SelftestMode, signal: AbortSignal): Promise<PoolOutcome<TResult>> {
    return this.job({ op: 'selftest', mode }, signal);
  }

  private submit(payload: JobPayload, signal: AbortSignal): Promise<PoolOutcome<unknown>> {
    if (this.stopped) return Promise.resolve({ kind: 'failure', reason: 'unavailable' });
    if (signal.aborted) return Promise.resolve({ kind: 'failure', reason: 'aborted' });
    return new Promise<PoolOutcome<unknown>>((resolveOutcome) => {
      const run = (slot: Slot) => this.run(slot, payload, signal, resolveOutcome);
      const idle = this.idleSlot();
      if (idle) {
        run(idle);
        return;
      }
      if (this.waiting.length >= this.options.maxWaiting) {
        resolveOutcome({ kind: 'failure', reason: 'unavailable' });
        return;
      }
      const waiter: Waiter = {
        run: (slot) => {
          signal.removeEventListener('abort', onAbort);
          run(slot);
        },
        fail: (outcome) => {
          signal.removeEventListener('abort', onAbort);
          resolveOutcome(outcome);
        },
      };
      const onAbort = () => {
        const index = this.waiting.indexOf(waiter);
        if (index >= 0) this.waiting.splice(index, 1);
        this.publishState();
        resolveOutcome({ kind: 'failure', reason: 'aborted' });
      };
      signal.addEventListener('abort', onAbort, { once: true });
      this.waiting.push(waiter);
      this.publishState();
    });
  }

  private idleSlot(): Slot | null {
    for (const slot of this.slots) {
      if (slot.ready && !slot.retiring && !slot.job && slot.child.connected) return slot;
    }
    return null;
  }

  private run(
    slot: Slot,
    payload: JobPayload,
    signal: AbortSignal,
    resolveOutcome: (outcome: PoolOutcome<unknown>) => void,
  ): void {
    const id = ++this.seq;
    const { options } = this;
    let settled = false;
    const job: Job = {
      id,
      killReason: null,
      baseCpu: null,
      sampling: false,
      timers: [],
      cleanup: () => undefined,
      resolve: (outcome) => {
        if (settled) return;
        settled = true;
        job.cleanup();
        if (slot.job === job) slot.job = null;
        resolveOutcome(outcome);
        this.afterJob(slot);
      },
    };
    slot.job = job;
    this.publishState();

    const kill = (reason: KillReason | 'aborted') => {
      if (job.killReason !== null) return;
      job.killReason = reason;
      slot.retiring = true;
      try {
        slot.child.kill('SIGKILL');
      } catch {
        // already gone; the exit handler settles the job
      }
    };
    const onAbort = () => kill('aborted');
    signal.addEventListener('abort', onAbort, { once: true });

    const pid = slot.child.pid;
    const sample = async () => {
      if (job.sampling || job.killReason !== null || pid === undefined) return;
      job.sampling = true;
      try {
        const now = await this.sampler(pid);
        if (!now || job.killReason !== null || settled) return;
        if (job.baseCpu === null) job.baseCpu = now.cpuSeconds;
        if (now.cpuSeconds - job.baseCpu > options.cpuSeconds) kill('cpu');
        else if (now.rssMb > options.maxRssMb) kill('memory');
      } finally {
        job.sampling = false;
      }
    };
    void sample();
    const interval = setInterval(() => void sample(), options.sampleIntervalMs ?? 100);
    const wall = setTimeout(() => kill('wall'), options.wallTimeoutMs);
    interval.unref();
    wall.unref();
    job.timers.push(interval, wall);
    job.cleanup = () => {
      clearInterval(interval);
      clearTimeout(wall);
      signal.removeEventListener('abort', onAbort);
    };

    const message = { ...payload, id };
    try {
      slot.child.send(message);
    } catch {
      kill('crash');
    }
  }

  /** After a reply: recycle at MAX_JOBS, else hand the child to the next waiter. */
  private afterJob(slot: Slot): void {
    if (this.stopped) return;
    if (!slot.retiring && slot.jobs >= this.options.maxJobs) {
      slot.retiring = true;
      // Graceful: the child exits on disconnect; the exit handler spawns the replacement.
      try {
        slot.child.disconnect();
      } catch {
        slot.child.kill('SIGKILL');
      }
    }
    this.dispatch();
  }

  private dispatch(): void {
    for (;;) {
      if (this.waiting.length === 0) break;
      const idle = this.idleSlot();
      if (!idle) break;
      const waiter = this.waiting.shift()!;
      waiter.run(idle);
    }
    this.publishState();
  }

  private publishState(): void {
    this.options.onState?.(this.state);
  }

  private warnNoRlimit(): void {
    if (this.warnedNoRlimit) return;
    this.warnedNoRlimit = true;
    this.logger.warn(
      { platform: this.platform },
      `${this.descriptor.component.replace('-', ' ')} runs without prlimit (${this.descriptor.rlimitsKey}=best_effort); CPU and memory are enforced by the sampler only`,
    );
  }

  private childCommand(): { command: string; args: string[]; entry: string } {
    const { options } = this;
    const entry = this.childEntry;
    const typescript = entry.endsWith('.ts');
    const roots = new Set<string>([real(APP_ROOT), ...this.descriptor.readRoots.map(real)]);
    const workspace = workspaceRoot(APP_ROOT);
    if (workspace) roots.add(real(workspace));
    // Node's permission model (compiled children, i.e. every deployment): no child processes,
    // no worker threads, no file writes, reads of the application and the descriptor's read
    // roots (the YARA rules directory for the inspector) only. Source
    // runs (unit/integration tests and the benchmark on a development host) load the TypeScript
    // entry through tsx, whose esbuild transform needs worker threads and a child process, so
    // they run without it (the child's module graph is still checked statically by a test).
    const permission = typescript
      ? []
      : [
          '--permission',
          '--allow-addons',
          ...[...roots].map((root) => `--allow-fs-read=${root}`),
          '--disable-warning=SecurityWarning',
        ];
    const nodeArgs = [
      `--max-old-space-size=${String(options.heapMb)}`,
      ...permission,
      '--disable-warning=ExperimentalWarning',
      ...(typescript
        ? ['--import', pathToFileURL(createRequire(__filename).resolve('tsx')).href]
        : []),
      entry,
      ...this.descriptor.args,
    ];
    if (!this.prlimit) return { command: process.execPath, args: nodeArgs, entry };
    const soft = Math.min(options.cpuSeconds * options.maxJobs, MAX_CPU_RLIMIT_SECONDS);
    return {
      command: this.prlimit,
      args: [
        `--cpu=${String(soft)}:${String(soft + 5)}`,
        '--core=0',
        '--',
        process.execPath,
        ...nodeArgs,
      ],
      entry,
    };
  }

  private removeDir(dir: string): void {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort; removed at the next start when stale
    }
  }

  /** Spawns one child and resolves once its handshake was accepted. */
  private spawnSlot(): Promise<Slot> {
    const { options } = this;
    const component = this.descriptor.component;
    if (this.stopped) return Promise.reject(new InspectorPoolStartError('stopped', component));
    const dir = join(
      this.tmpDir,
      `eg-inspect-${String(process.pid)}-${randomBytes(8).toString('hex')}`,
    );
    mkdirSync(dir, { mode: 0o700 });
    const { command, args } = this.childCommand();
    const env: Record<string, string> = {
      NODE_ENV: options.nodeEnv,
      PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    };
    if (options.selftest) env.EG_INSPECTOR_SELFTEST = '1';
    let child: InspectorChild;
    try {
      child = this.spawnFn(command, args, {
        cwd: dir,
        env,
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
        serialization: 'advanced',
        detached: false,
        windowsHide: true,
      });
    } catch {
      this.removeDir(dir);
      return Promise.reject(new InspectorPoolStartError('spawn_failed', component));
    }
    let resolveExit!: () => void;
    const slot: Slot = {
      child,
      dir,
      ready: false,
      jobs: 0,
      job: null,
      retiring: false,
      exited: new Promise<void>((done) => (resolveExit = done)),
      stderrTail: '',
    };
    this.slots.add(slot);
    child.stderr?.on('data', (chunk: Buffer | string) => {
      // Node's own fatal messages only (the child prints nothing else); kept for the exit
      // classification, never logged.
      slot.stderrTail = (slot.stderrTail + chunk.toString()).slice(-STDERR_TAIL_BYTES);
    });

    return new Promise<Slot>((resolveReady, rejectReady) => {
      let handshake = true;
      const startTimer = setTimeout(() => {
        if (!handshake) return;
        handshake = false;
        child.kill('SIGKILL');
        rejectReady(new InspectorPoolStartError('handshake_timeout', component));
      }, options.startTimeoutMs ?? 30_000);
      startTimer.unref();

      child.on('message', (raw: unknown) => {
        if (!isChildMessage(raw)) return;
        this.onMessage(slot, raw, (error) => {
          if (!handshake) return;
          handshake = false;
          clearTimeout(startTimer);
          if (error) rejectReady(error);
          else resolveReady(slot);
        });
      });
      child.on('error', () => {
        // Spawn failure or IPC error; the exit handler (if any) settles a running job.
        if (handshake) {
          handshake = false;
          clearTimeout(startTimer);
          rejectReady(new InspectorPoolStartError('spawn_failed', component));
        }
      });
      child.on('exit', (code, signal) => {
        clearTimeout(startTimer);
        this.onExit(slot, code, signal);
        resolveExit();
        if (handshake) {
          handshake = false;
          rejectReady(new InspectorPoolStartError('child_exited', component));
        }
      });
    });
  }

  private onMessage(
    slot: Slot,
    message: ChildMessage,
    handshake: (error?: InspectorPoolStartError) => void,
  ): void {
    switch (message.op) {
      case 'ready': {
        const refused = this.descriptor.checkReady(message);
        if (refused !== null) {
          slot.retiring = true;
          slot.child.kill('SIGKILL');
          handshake(new InspectorPoolStartError(refused, this.descriptor.component));
          return;
        }
        slot.ready = true;
        handshake();
        this.dispatch();
        return;
      }
      case 'fatal': {
        const code = CODE_PATTERN.test(message.code) ? message.code : 'fatal';
        this.logger.error({ errorCode: code }, 'pool child could not start');
        handshake(new InspectorPoolStartError(code, this.descriptor.component));
        return;
      }
      case 'result': {
        const job = slot.job;
        if (!job || job.id !== message.id || job.killReason !== null) return;
        slot.jobs += 1;
        const result = message.ok ? this.descriptor.resultOf(message) : undefined;
        if (result !== undefined) job.resolve({ kind: 'result', result });
        else job.resolve({ kind: 'failure', reason: 'crash' });
        return;
      }
    }
  }

  private onExit(slot: Slot, code: number | null, signal: NodeJS.Signals | null): void {
    const wasReady = slot.ready;
    slot.ready = false;
    this.slots.delete(slot);
    this.removeDir(slot.dir);
    const job = slot.job;
    if (job) {
      const reason = job.killReason ?? this.classifyExit(slot, code, signal);
      if (reason !== 'aborted') this.options.onKill?.(reason);
      if (reason === 'cpu') job.resolve({ kind: 'limit', code: 'limit.cpu_time' });
      else if (reason === 'memory') job.resolve({ kind: 'limit', code: 'limit.memory' });
      else if (reason === 'aborted') job.resolve({ kind: 'failure', reason: 'aborted' });
      else job.resolve({ kind: 'failure', reason });
      this.logger.warn({ reason, exitCode: code, signal }, 'pool child ended during a job');
    }
    this.publishState();
    // A child that never became ready is retried by the spawn path (start or replace).
    if (!this.stopped && wasReady) this.replace();
  }

  /** SIGXCPU (the rlimit backstop) is CPU; a V8 heap exhaustion is memory; else a crash. */
  private classifyExit(
    slot: Slot,
    _code: number | null,
    signal: NodeJS.Signals | null,
  ): KillReason {
    if (signal === 'SIGXCPU') return 'cpu';
    if (/heap limit|heap out of memory|Allocation failed/i.test(slot.stderrTail)) return 'memory';
    return 'crash';
  }

  private replace(): void {
    this.spawnSlot()
      .then(() => this.dispatch())
      .catch((error: unknown) => {
        if (this.stopped) return;
        const code = error instanceof InspectorPoolStartError ? error.code : 'spawn_failed';
        this.logger.error({ errorCode: code }, 'pool child replacement failed; retrying');
        if (!this.stopped)
          setTimeout(() => this.stopped || this.replace(), RESPAWN_DELAY_MS).unref();
      });
  }
}

/** The entry of a child module next to the calling module (`.js` compiled, `.ts` in source runs). */
export function childEntryNextTo(dir: string, file: string, base = 'child'): string {
  return join(dir, file.endsWith('.ts') ? `${base}.ts` : `${base}.js`);
}

/** The attachment inspector descriptor (step 4.2 A4, unchanged): YARA bundle-id handshake. */
export function inspectorDescriptor(
  options: Pick<InspectorPoolOptions, 'rulesDir' | 'yaraTimeoutMs' | 'expectedBundleId'> & {
    logger: Logger;
  },
): ChildDescriptor<InspectionResult> {
  const logger = options.logger.child({ component: 'attachment-inspector' });
  return {
    component: 'attachment-inspector',
    rlimitsKey: 'ATTACHMENT_INSPECTOR_RLIMITS',
    entry: childEntryNextTo(__dirname, __filename),
    args: [options.rulesDir, String(options.yaraTimeoutMs)],
    readRoots: [options.rulesDir],
    startDetails: { bundleId: options.expectedBundleId },
    checkReady: (message) => {
      if (isExtractorReady(message) || message.bundleId !== options.expectedBundleId) {
        logger.error(
          {
            expected: options.expectedBundleId,
            reported: isExtractorReady(message) ? null : message.bundleId,
          },
          'inspector child reported another YARA bundle id; refused',
        );
        return 'bundle_mismatch';
      }
      return null;
    },
    resultOf: (message) => message.result as InspectionResult | undefined,
  };
}

/** The attachment inspector pool (step 4.2 A4): constructed and behaving exactly as in 4.2. */
export class InspectorPool extends ChildPool<InspectionResult> {
  constructor(options: InspectorPoolOptions) {
    super(options, inspectorDescriptor(options));
  }

  /** Inspects one buffer in a child (FIFO wait for an idle child, bounded). */
  inspect(bytes: Buffer, limits: InspectLimits, signal: AbortSignal): Promise<InspectOutcome> {
    return this.job({ op: 'inspect', bytes, limits }, signal);
  }
}
