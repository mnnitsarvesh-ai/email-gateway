import { EventEmitter } from 'node:events';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { createLogger } from '@email-gateway/logger';
import { afterEach, describe, expect, it } from 'vitest';
import type { InspectionResult, InspectLimits } from '../content';
import {
  type InspectorChild,
  InspectorPool,
  type InspectorPoolOptions,
  PRIVATE_DIR_PATTERN,
  removeStaleDirs,
  type SpawnFn,
} from './pool';
import type { ProcessSample } from './sampler';

const logger = createLogger({ service: 'pool-test', level: 'silent' });
const LIMITS = {} as InspectLimits;
const RESULT = { inspectorVersion: 'att-inspect/1' } as InspectionResult;

type Behaviour = 'reply' | 'hang' | 'error' | 'crash' | 'xcpu' | 'heap';

class FakeChild extends EventEmitter implements InspectorChild {
  static seq = 1000;
  readonly pid = FakeChild.seq++;
  connected = true;
  readonly stderr = new PassThrough();
  readonly sent: unknown[] = [];
  killedWith: string | null = null;

  constructor(
    readonly spawnArgs: {
      command: string;
      args: string[];
      env: Record<string, string>;
      cwd: string;
    },
    private readonly behaviour: () => Behaviour,
    bundleId: string,
  ) {
    super();
    setImmediate(() =>
      this.emit('message', { op: 'ready', yaraXVersion: '0.10.0', bundleId, ruleCount: 6 }),
    );
  }

  send(message: unknown): boolean {
    this.sent.push(message);
    const { id } = message as { id: number };
    const behaviour = this.behaviour();
    setImmediate(() => {
      if (behaviour === 'reply')
        this.emit('message', { op: 'result', id, ok: true, result: RESULT });
      else if (behaviour === 'error')
        this.emit('message', { op: 'result', id, ok: false, code: 'inspect_error' });
      else if (behaviour === 'crash') this.exit(null, 'SIGSEGV');
      else if (behaviour === 'xcpu') this.exit(null, 'SIGXCPU');
      else if (behaviour === 'heap') {
        this.stderr.write(
          'FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory\n',
        );
        setTimeout(() => this.exit(134, null), 5);
      }
    });
    return true;
  }

  kill(signal?: NodeJS.Signals): boolean {
    this.killedWith = signal ?? 'SIGTERM';
    setImmediate(() => this.exit(null, signal ?? 'SIGTERM'));
    return true;
  }

  disconnect(): void {
    setImmediate(() => this.exit(0, null));
  }

  private exit(code: number | null, signal: NodeJS.Signals | null) {
    if (!this.connected) return;
    this.connected = false;
    this.emit('exit', code, signal);
  }
}

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function setup(
  overrides: Partial<InspectorPoolOptions> = {},
  behaviour: () => Behaviour = () => 'reply',
  samples: () => ProcessSample | null = () => ({ cpuSeconds: 0, rssMb: 50 }),
  bundleId = 'yara-1-aaaaaaaaaaaa',
) {
  const tmp = mkdtempSync(join(tmpdir(), 'eg-pool-test-'));
  dirs.push(tmp);
  const children: FakeChild[] = [];
  const kills: string[] = [];
  const spawn: SpawnFn = (command, args, options) => {
    const child = new FakeChild(
      { command, args, env: options.env as Record<string, string>, cwd: options.cwd as string },
      behaviour,
      bundleId,
    );
    children.push(child);
    return child;
  };
  const pool = new InspectorPool({
    size: 2,
    maxJobs: 100,
    heapMb: 192,
    rlimits: 'best_effort',
    tmpDir: tmp,
    wallTimeoutMs: 1_000,
    cpuSeconds: 2,
    maxRssMb: 384,
    rulesDir: '/rules',
    yaraTimeoutMs: 1_000,
    expectedBundleId: 'yara-1-aaaaaaaaaaaa',
    selftest: false,
    nodeEnv: 'test',
    maxWaiting: 4,
    logger,
    spawn,
    sampler: () => Promise.resolve(samples()),
    sampleIntervalMs: 5,
    platform: 'linux',
    prlimitPath: null,
    childEntry: '/app/child.js',
    onKill: (reason) => kills.push(reason),
    ...overrides,
  });
  return { pool, children, kills, tmp };
}

const signal = () => AbortSignal.timeout(5_000);

describe('InspectorPool (step 4.2 A4)', () => {
  it('spawns children with an empty environment, IPC, the heap cap and a private 0700 directory', async () => {
    const { pool, children, tmp } = setup({
      prlimitPath: '/usr/bin/prlimit',
      rlimits: 'required',
      cpuSeconds: 10,
      maxJobs: 500,
    });
    await pool.start();
    expect(children).toHaveLength(2);
    const { command, args, env, cwd } = children[0]!.spawnArgs;
    expect(env).toEqual({
      NODE_ENV: 'test',
      PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    });
    expect(command).toBe('/usr/bin/prlimit');
    expect(args.slice(0, 4)).toEqual(['--cpu=5000:5005', '--core=0', '--', process.execPath]);
    expect(args).toContain('--max-old-space-size=192');
    expect(args.slice(-3)).toEqual(['/app/child.js', '/rules', '1000']);
    expect(cwd.startsWith(tmp)).toBe(true);
    const name = cwd.slice(tmp.length + 1);
    expect(name).toMatch(PRIVATE_DIR_PATTERN);
    expect(statSync(cwd).mode & 0o777).toBe(0o700);
    expect(pool.rlimitMode).toBe('prlimit');
    expect(pool.state).toEqual({ idle: 2, busy: 0, waiting: 0 });
    await pool.stop();
    // Children killed, private directories removed.
    expect(children.every((c) => c.killedWith === 'SIGKILL')).toBe(true);
    expect(existsSync(cwd)).toBe(false);
  });

  it('passes EG_INSPECTOR_SELFTEST only when the test hook is configured', async () => {
    const { pool, children } = setup({ selftest: true, size: 1 });
    await pool.start();
    expect(children[0]!.spawnArgs.env.EG_INSPECTOR_SELFTEST).toBe('1');
    await pool.stop();
  });

  it('refuses to start without prlimit in required mode (Linux) and on other platforms', async () => {
    await expect(setup({ rlimits: 'required', prlimitPath: null }).pool.start()).rejects.toThrow(
      /prlimit_missing/,
    );
    await expect(
      setup({ rlimits: 'required', platform: 'darwin', prlimitPath: undefined }).pool.start(),
    ).rejects.toThrow(/rlimits_unsupported_platform/);
    const lax = setup({ rlimits: 'best_effort', platform: 'darwin', prlimitPath: undefined });
    await lax.pool.start();
    expect(lax.pool.rlimitMode).toBe('none');
    expect(lax.children[0]!.spawnArgs.command).toBe(process.execPath);
    await lax.pool.stop();
  });

  it('refuses a child that reports another bundle id', async () => {
    const { pool } = setup(
      {},
      () => 'reply',
      () => ({ cpuSeconds: 0, rssMb: 1 }),
      'yara-1-bbbbbbbbbbbb',
    );
    await expect(pool.start()).rejects.toThrow(/bundle_mismatch/);
  });

  it('runs one job per child and queues the rest FIFO, bounded', async () => {
    const { pool, children } = setup({ size: 1, maxWaiting: 2 });
    await pool.start();
    const results = await Promise.all(
      [1, 2, 3].map(() => pool.inspect(Buffer.from('x'), LIMITS, signal())),
    );
    expect(results.every((r) => r.kind === 'result')).toBe(true);
    expect(children[0]!.sent).toHaveLength(3);
    // Queue full → unavailable (retryable), never a verdict.
    const hang = setup({ size: 1, maxWaiting: 1, wallTimeoutMs: 200 }, () => 'hang');
    await hang.pool.start();
    const first = hang.pool.inspect(Buffer.from('x'), LIMITS, signal());
    const second = hang.pool.inspect(Buffer.from('x'), LIMITS, signal());
    expect(await hang.pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'failure',
      reason: 'unavailable',
    });
    expect(hang.pool.state.waiting).toBe(1);
    expect(await first).toEqual({ kind: 'failure', reason: 'wall' });
    expect(await second).toEqual({ kind: 'failure', reason: 'wall' });
    await pool.stop();
    await hang.pool.stop();
  });

  it('recycles a child after MAX_JOBS jobs', async () => {
    const { pool, children } = setup({ size: 1, maxJobs: 2 });
    await pool.start();
    for (let i = 0; i < 5; i += 1) {
      expect((await pool.inspect(Buffer.from('x'), LIMITS, signal())).kind).toBe('result');
    }
    expect(children.length).toBeGreaterThanOrEqual(3);
    await pool.stop();
  });

  it('classifies CPU, memory, wall-clock and crash kills and replaces the child', async () => {
    let cpu = 0;
    const busy = setup(
      { size: 1 },
      () => 'hang',
      () => ({ cpuSeconds: (cpu += 1), rssMb: 50 }),
    );
    await busy.pool.start();
    expect(await busy.pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'limit',
      code: 'limit.cpu_time',
    });
    expect(busy.kills).toEqual(['cpu']);
    await new Promise((r) => setTimeout(r, 20));
    expect(busy.children.length).toBe(2);
    await busy.pool.stop();

    const fat = setup(
      { size: 1 },
      () => 'hang',
      () => ({ cpuSeconds: 0, rssMb: 900 }),
    );
    await fat.pool.start();
    expect(await fat.pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'limit',
      code: 'limit.memory',
    });
    await fat.pool.stop();

    const slow = setup({ size: 1, wallTimeoutMs: 50 }, () => 'hang');
    await slow.pool.start();
    expect(await slow.pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'failure',
      reason: 'wall',
    });
    expect(slow.kills).toEqual(['wall']);
    await slow.pool.stop();

    for (const [behaviour, expected, kill] of [
      ['crash', { kind: 'failure', reason: 'crash' }, 'crash'],
      ['xcpu', { kind: 'limit', code: 'limit.cpu_time' }, 'cpu'],
      ['heap', { kind: 'limit', code: 'limit.memory' }, 'memory'],
    ] as const) {
      const run = setup({ size: 1 }, () => behaviour);
      await run.pool.start();
      expect(await run.pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual(expected);
      expect(run.kills).toEqual([kill]);
      await run.pool.stop();
    }
  });

  it('reports a child-side inspection error as a crash without killing the child', async () => {
    const { pool, children, kills } = setup({ size: 1 }, () => 'error');
    await pool.start();
    expect(await pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'failure',
      reason: 'crash',
    });
    expect(kills).toEqual([]);
    expect(children[0]!.killedWith).toBeNull();
    await pool.stop();
  });

  it('kills the child when the engine call is aborted (not counted as a kill)', async () => {
    const { pool, kills } = setup({ size: 1 }, () => 'hang');
    await pool.start();
    const controller = new AbortController();
    const pending = pool.inspect(Buffer.from('x'), LIMITS, controller.signal);
    controller.abort();
    expect(await pending).toEqual({ kind: 'failure', reason: 'aborted' });
    expect(kills).toEqual([]);
    await pool.stop();
    expect(await pool.inspect(Buffer.from('x'), LIMITS, signal())).toEqual({
      kind: 'failure',
      reason: 'unavailable',
    });
  });

  it('removes stale eg-inspect-* directories of this uid older than 10 minutes', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'eg-stale-test-'));
    dirs.push(tmp);
    const stale = join(tmp, 'eg-inspect-123-0123456789abcdef');
    const fresh = join(tmp, 'eg-inspect-124-0123456789abcdef');
    const other = join(tmp, 'eg-inspect-other');
    for (const dir of [stale, fresh, other]) mkdirSync(dir);
    const old = new Date(Date.now() - 11 * 60_000);
    utimesSync(stale, old, old);
    utimesSync(other, old, old);
    expect(removeStaleDirs(tmp)).toBe(1);
    expect(readdirSync(tmp).sort()).toEqual([
      'eg-inspect-124-0123456789abcdef',
      'eg-inspect-other',
    ]);
  });
});
