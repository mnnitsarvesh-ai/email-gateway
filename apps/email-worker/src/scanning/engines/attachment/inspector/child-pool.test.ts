import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { createLogger } from '@email-gateway/logger';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type ChildDescriptor,
  ChildPool,
  type ChildPoolOptions,
  type InspectorChild,
  InspectorPool,
  type SpawnFn,
} from './pool';
import { isExtractorReady } from './protocol';
import type { ProcessSample } from './sampler';

/**
 * The generalized pool (step 4.5 D4): a second child kind (the DLP extractor) runs on the same
 * pool through a descriptor (entry, arguments, read roots, handshake check, reply field) and
 * the generic `job` method, with the 4.2 isolation, kill and recycle semantics. The 4.2
 * inspector behaviour itself is covered unchanged by pool.test.ts.
 */
const logger = createLogger({ service: 'child-pool-test', level: 'silent' });

type Behaviour = 'reply' | 'hang' | 'malformed' | 'error';

const EXTRACTION = { extractorVersion: 'dlp-extract/1', status: 'extracted', segments: [] };

class FakeExtractor extends EventEmitter implements InspectorChild {
  static seq = 5000;
  readonly pid = FakeExtractor.seq++;
  connected = true;
  readonly stderr = new PassThrough();
  readonly sent: Array<Record<string, unknown>> = [];
  killedWith: string | null = null;

  constructor(
    readonly spawnArgs: { command: string; args: string[]; env: Record<string, string> },
    private readonly behaviour: () => Behaviour,
    ready: Record<string, unknown>,
  ) {
    super();
    setImmediate(() => this.emit('message', ready));
  }

  send(message: unknown): boolean {
    const job = message as Record<string, unknown>;
    this.sent.push(job);
    const behaviour = this.behaviour();
    setImmediate(() => {
      const id = job.id as number;
      if (behaviour === 'reply')
        this.emit('message', { op: 'result', id, ok: true, extraction: EXTRACTION });
      else if (behaviour === 'malformed') this.emit('message', { op: 'result', id, ok: true });
      else if (behaviour === 'error')
        this.emit('message', { op: 'result', id, ok: false, code: 'extract_error' });
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

const EXTRACTOR_READY = { op: 'ready', kind: 'dlp-extractor', extractorVersion: 'dlp-extract/1' };

const descriptor: ChildDescriptor<typeof EXTRACTION> = {
  component: 'dlp-extractor',
  rlimitsKey: 'DLP_EXTRACTOR_RLIMITS',
  entry: '/app/dist/scanning/engines/dlp/extractor/child.js',
  args: ['200', '1000000'],
  readRoots: [],
  startDetails: { extractorVersion: 'dlp-extract/1' },
  checkReady: (message) =>
    isExtractorReady(message) && message.extractorVersion === 'dlp-extract/1'
      ? null
      : 'extractor_mismatch',
  resultOf: (message) =>
    typeof message.extraction === 'object' && message.extraction !== null
      ? (message.extraction as typeof EXTRACTION)
      : undefined,
};

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function setup(
  overrides: Partial<ChildPoolOptions> = {},
  behaviour: () => Behaviour = () => 'reply',
  samples: () => ProcessSample | null = () => ({ cpuSeconds: 0, rssMb: 50 }),
  ready: Record<string, unknown> = EXTRACTOR_READY,
) {
  const tmp = mkdtempSync(join(tmpdir(), 'eg-child-pool-test-'));
  dirs.push(tmp);
  const children: FakeExtractor[] = [];
  const kills: string[] = [];
  const spawn: SpawnFn = (command, args, options) => {
    const child = new FakeExtractor(
      { command, args, env: options.env as Record<string, string> },
      behaviour,
      ready,
    );
    children.push(child);
    return child;
  };
  const options: ChildPoolOptions = {
    size: 2,
    maxJobs: 100,
    heapMb: 256,
    rlimits: 'best_effort',
    tmpDir: tmp,
    wallTimeoutMs: 1_000,
    cpuSeconds: 10,
    maxRssMb: 512,
    selftest: false,
    nodeEnv: 'test',
    maxWaiting: 4,
    logger,
    spawn,
    sampler: () => Promise.resolve(samples()),
    sampleIntervalMs: 5,
    platform: 'linux',
    prlimitPath: '/usr/bin/prlimit',
    onKill: (reason) => kills.push(reason),
    ...overrides,
  };
  return { pool: new ChildPool(options, descriptor), children, kills };
}

const signal = () => AbortSignal.timeout(5_000);
const extract = { op: 'extract', bytes: Buffer.from('x'), limits: {}, hint: {} };

describe('ChildPool with a second child kind (step 4.5 D4)', () => {
  it('spawns the descriptor entry with its arguments under prlimit, the heap cap and an empty env', async () => {
    const { pool, children } = setup({ maxJobs: 200 });
    await pool.start();
    const { command, args, env } = children[0]!.spawnArgs;
    expect(command).toBe('/usr/bin/prlimit');
    expect(args.slice(0, 4)).toEqual(['--cpu=2000:2005', '--core=0', '--', process.execPath]);
    expect(args).toContain('--max-old-space-size=256');
    expect(args).toContain('--permission');
    expect(args.slice(-3)).toEqual([descriptor.entry, '200', '1000000']);
    expect(env).toEqual({
      NODE_ENV: 'test',
      PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    });
    await pool.stop();
  });

  it('runs generic jobs and returns the descriptor reply field', async () => {
    const { pool, children } = setup({ size: 1 });
    await pool.start();
    expect(await pool.job(extract, signal())).toEqual({ kind: 'result', result: EXTRACTION });
    expect(children[0]!.sent[0]).toMatchObject({ op: 'extract', id: expect.any(Number) });
    await pool.stop();
  });

  it('treats a reply without the payload or a child error as a crash failure', async () => {
    for (const behaviour of ['malformed', 'error'] as const) {
      const { pool } = setup({ size: 1 }, () => behaviour);
      await pool.start();
      expect(await pool.job(extract, signal())).toEqual({ kind: 'failure', reason: 'crash' });
      await pool.stop();
    }
  });

  it('refuses a child whose handshake the descriptor rejects', async () => {
    await expect(
      setup({}, undefined, undefined, {
        ...EXTRACTOR_READY,
        extractorVersion: 'dlp-extract/0',
      }).pool.start(),
    ).rejects.toThrow(/dlp extractor pool cannot start \(extractor_mismatch\)/);
    // A YARA inspector handshake is not an extractor.
    await expect(
      setup({}, undefined, undefined, {
        op: 'ready',
        yaraXVersion: '0.10.0',
        bundleId: 'yara-1-aaaaaaaaaaaa',
        ruleCount: 6,
      }).pool.start(),
    ).rejects.toThrow(/extractor_mismatch/);
  });

  it('keeps the CPU/RSS/wall kill and recycle semantics', async () => {
    let cpu = 0;
    const busy = setup(
      { size: 1 },
      () => 'hang',
      () => ({ cpuSeconds: (cpu += 5), rssMb: 50 }),
    );
    await busy.pool.start();
    expect(await busy.pool.job(extract, signal())).toEqual({
      kind: 'limit',
      code: 'limit.cpu_time',
    });
    expect(busy.kills).toEqual(['cpu']);
    await busy.pool.stop();

    const fat = setup(
      { size: 1 },
      () => 'hang',
      () => ({ cpuSeconds: 0, rssMb: 900 }),
    );
    await fat.pool.start();
    expect(await fat.pool.job(extract, signal())).toEqual({ kind: 'limit', code: 'limit.memory' });
    await fat.pool.stop();

    const slow = setup({ size: 1, wallTimeoutMs: 30 }, () => 'hang');
    await slow.pool.start();
    expect(await slow.pool.job(extract, signal())).toEqual({ kind: 'failure', reason: 'wall' });
    await slow.pool.stop();

    const recycled = setup({ size: 1, maxJobs: 2 });
    await recycled.pool.start();
    for (let i = 0; i < 5; i += 1)
      expect((await recycled.pool.job(extract, signal())).kind).toBe('result');
    expect(recycled.children.length).toBeGreaterThanOrEqual(3);
    await recycled.pool.stop();
  });

  it('the attachment inspector refuses an extractor handshake (bundle id check unchanged)', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'eg-child-pool-test-'));
    dirs.push(tmp);
    const pool = new InspectorPool({
      size: 1,
      maxJobs: 10,
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
      maxWaiting: 1,
      logger,
      spawn: (command, args, options) =>
        new FakeExtractor(
          { command, args, env: options.env as Record<string, string> },
          () => 'reply',
          EXTRACTOR_READY,
        ),
      sampler: () => Promise.resolve({ cpuSeconds: 0, rssMb: 1 }),
      platform: 'linux',
      prlimitPath: null,
      childEntry: '/app/child.js',
    });
    await expect(pool.start()).rejects.toThrow(
      /attachment inspector pool cannot start \(bundle_mismatch\)/,
    );
  });
});
