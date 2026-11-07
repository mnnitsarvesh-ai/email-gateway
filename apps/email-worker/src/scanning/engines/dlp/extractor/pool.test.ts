import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { createLogger } from '@email-gateway/logger';
import { afterEach, describe, expect, it } from 'vitest';
import type { InspectionResult } from '../../attachment/content';
import type { InspectorChild, SpawnFn } from '../../attachment/inspector/pool';
import type { ProcessSample } from '../../attachment/inspector/sampler';
import { isExtractJobLimits, notExtracted, parseExtraction, walkSummaryOf } from './extraction';
import { DlpExtractorPool, extractorDescriptor } from './pool';
import { LIMITS } from '../dlp.test-support';

const logger = createLogger({ service: 'dlp-extractor-pool-test', level: 'silent' });

const EXTRACTION = {
  extractorVersion: 'dlp-extract/1',
  status: 'extracted',
  format: 'text',
  reasons: [],
  segments: [{ path: 'attachment', format: 'text', kind: 'text', text: 'hello', truncated: false }],
  entriesVisited: 0,
};

type Reply = 'ok' | 'malformed' | 'oversized' | 'hang';

class FakeChild extends EventEmitter implements InspectorChild {
  static seq = 7000;
  readonly pid = FakeChild.seq++;
  connected = true;
  readonly stderr = new PassThrough();
  readonly sent: Array<Record<string, unknown>> = [];

  constructor(
    readonly spawn: { command: string; args: string[]; env: Record<string, string> },
    private readonly reply: () => Reply,
    ready: Record<string, unknown>,
  ) {
    super();
    setImmediate(() => this.emit('message', ready));
  }

  send(message: unknown): boolean {
    const job = message as Record<string, unknown>;
    this.sent.push(job);
    const reply = this.reply();
    setImmediate(() => {
      const id = job.id as number;
      if (reply === 'ok')
        this.emit('message', { op: 'result', id, ok: true, extraction: EXTRACTION });
      if (reply === 'malformed')
        this.emit('message', { op: 'result', id, ok: true, extraction: { status: 'weird' } });
      if (reply === 'oversized')
        this.emit('message', {
          op: 'result',
          id,
          ok: true,
          extraction: {
            ...EXTRACTION,
            segments: [{ ...EXTRACTION.segments[0], text: 'x'.repeat(50) }],
          },
        });
    });
    return true;
  }

  kill(signal?: NodeJS.Signals): boolean {
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

const READY = { op: 'ready', kind: 'dlp-extractor', extractorVersion: 'dlp-extract/1' };
const dirs: string[] = [];
const pools: DlpExtractorPool[] = [];
afterEach(async () => {
  for (const pool of pools.splice(0)) await pool.stop();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function pool(options: {
  reply?: () => Reply;
  ready?: Record<string, unknown>;
  sample?: () => ProcessSample | null;
  maxJobs?: number;
  maxTextChars?: number;
}) {
  const children: FakeChild[] = [];
  const spawn: SpawnFn = (command, args, opts) => {
    const child = new FakeChild(
      { command, args, env: opts.env as Record<string, string> },
      options.reply ?? (() => 'ok'),
      options.ready ?? READY,
    );
    children.push(child);
    return child;
  };
  const tmp = mkdtempSync(join(tmpdir(), 'dlp-pool-'));
  dirs.push(tmp);
  const p = new DlpExtractorPool({
    size: 1,
    maxJobs: options.maxJobs ?? 100,
    heapMb: 256,
    rlimits: 'best_effort',
    tmpDir: tmp,
    wallTimeoutMs: 200,
    cpuSeconds: 1,
    maxRssMb: 512,
    selftest: false,
    nodeEnv: 'test',
    maxWaiting: 4,
    maxTextChars: options.maxTextChars ?? 1_000_000,
    logger,
    spawn,
    sampler: () =>
      Promise.resolve(options.sample ? options.sample() : { cpuSeconds: 0, rssMb: 10 }),
    sampleIntervalMs: 10,
    prlimitPath: null,
    platform: 'linux',
    childEntry: '/app/dist/scanning/engines/dlp/extractor/child.js',
  });
  pools.push(p);
  return { pool: p, children };
}

const run = (p: DlpExtractorPool) =>
  p.extract(
    Buffer.from('hello'),
    { walk: LIMITS.walk, extract: LIMITS.extract },
    {
      declaredContentType: 'text/plain',
      filenameExt: 'txt',
    },
    AbortSignal.timeout(5_000),
  );

describe('DLP extractor pool (step 4.5 D4)', () => {
  it('spawns the extractor entry isolated (empty env, permission model, heap cap) and extracts', async () => {
    const { pool: p, children } = pool({});
    await p.start();
    const outcome = await run(p);
    expect(outcome).toEqual({ kind: 'result', result: EXTRACTION });
    const child = children[0]!;
    expect(child.spawn.args).toContain('--permission');
    expect(child.spawn.args).toContain('--max-old-space-size=256');
    expect(child.spawn.args.at(-1)).toBe('/app/dist/scanning/engines/dlp/extractor/child.js');
    expect(Object.keys(child.spawn.env).sort()).toEqual(['NODE_ENV', 'PATH']);
    expect(child.sent[0]).toMatchObject({ op: 'extract', hint: { filenameExt: 'txt' } });
    expect(p.permissionModel).toBe(true);
  });

  it('refuses an inspector child or another extractor version (extractor_mismatch)', async () => {
    const inspector = pool({
      ready: { op: 'ready', yaraXVersion: '1', bundleId: 'b', ruleCount: 1 },
    });
    await expect(inspector.pool.start()).rejects.toMatchObject({ code: 'extractor_mismatch' });
    const other = pool({ ready: { ...READY, extractorVersion: 'dlp-extract/2' } });
    await expect(other.pool.start()).rejects.toMatchObject({ code: 'extractor_mismatch' });
  });

  it('a malformed or oversized extraction is a crash (never a result)', async () => {
    const malformed = pool({ reply: () => 'malformed' });
    await malformed.pool.start();
    expect(await run(malformed.pool)).toEqual({ kind: 'failure', reason: 'crash' });
    const oversized = pool({ reply: () => 'oversized', maxTextChars: 10 });
    await oversized.pool.start();
    expect(await run(oversized.pool)).toEqual({ kind: 'failure', reason: 'crash' });
  });

  it('kills on CPU and RSS (definite limits) and on the wall clock (failure), then recycles', async () => {
    const cpu = pool({
      reply: () => 'hang',
      sample: (() => {
        let n = 0;
        return () => ({ cpuSeconds: (n += 1), rssMb: 10 });
      })(),
    });
    await cpu.pool.start();
    expect(await run(cpu.pool)).toEqual({ kind: 'limit', code: 'limit.cpu_time' });
    const rss = pool({ reply: () => 'hang', sample: () => ({ cpuSeconds: 0, rssMb: 9_999 }) });
    await rss.pool.start();
    expect(await run(rss.pool)).toEqual({ kind: 'limit', code: 'limit.memory' });
    const wall = pool({ reply: () => 'hang' });
    await wall.pool.start();
    expect(await run(wall.pool)).toEqual({ kind: 'failure', reason: 'wall' });
    await new Promise((r) => setTimeout(r, 50));
    expect(wall.children.length).toBeGreaterThanOrEqual(2);
    const recycle = pool({ maxJobs: 1 });
    await recycle.pool.start();
    await run(recycle.pool);
    await new Promise((r) => setTimeout(r, 50));
    expect(recycle.children.length).toBe(2);
  });

  it('the descriptor names the extractor entry, rlimit key and reply field', () => {
    const d = extractorDescriptor({ logger, maxTextChars: 100 });
    expect(d.component).toBe('dlp-extractor');
    expect(d.rlimitsKey).toBe('DLP_EXTRACTOR_RLIMITS');
    expect(d.entry).toMatch(/extractor[/\\]child\.(ts|js)$/);
    expect(d.resultOf({ extraction: EXTRACTION })).toEqual(EXTRACTION);
    expect(d.resultOf({ result: EXTRACTION })).toBeUndefined();
  });
});

describe('extraction contract helpers', () => {
  const inspection = (over: Partial<InspectionResult>): InspectionResult => ({
    inspectorVersion: 'att-inspect/1',
    type: { detected: 'zip', family: 'archive', executable: false, textLike: false },
    yara: { bundleId: 'none', matches: [] },
    archive: null,
    limits: [],
    codes: [],
    ...over,
  });

  it('maps the 4.2 walk result onto the walk summary', () => {
    expect(walkSummaryOf(inspection({}))).toEqual({
      encrypted: false,
      limitReached: false,
      malformed: false,
      unsupported: false,
    });
    expect(
      walkSummaryOf(
        inspection({
          codes: ['archive.encrypted', 'archive.malformed', 'archive.unsupported_format'],
          limits: ['limit.archive_entries'],
        }),
      ),
    ).toEqual({ encrypted: true, limitReached: true, malformed: true, unsupported: true });
    expect(walkSummaryOf(inspection({ limits: ['limit.yara_timeout'] })).limitReached).toBe(false);
  });

  it('validates job limits and replies', () => {
    expect(isExtractJobLimits({ walk: LIMITS.walk, extract: LIMITS.extract })).toBe(true);
    expect(
      isExtractJobLimits({
        walk: { ...LIMITS.walk, archiveMaxDepth: -1 },
        extract: LIMITS.extract,
      }),
    ).toBe(false);
    expect(isExtractJobLimits(null)).toBe(false);
    expect(parseExtraction(notExtracted('oversize'), 10)).toMatchObject({ reasons: ['oversize'] });
    expect(parseExtraction({ ...EXTRACTION, extra: 1 }, 100)).toBeUndefined();
    expect(
      parseExtraction(
        { ...EXTRACTION, segments: [{ ...EXTRACTION.segments[0], path: 'name.txt' }] },
        100,
      ),
    ).toBeUndefined();
  });
});
