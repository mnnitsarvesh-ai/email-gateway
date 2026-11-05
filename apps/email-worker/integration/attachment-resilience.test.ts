import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as corpus from '@email-gateway/attachment-corpus';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EngineAttemptFailedError } from '../src/scanning/engine';
import {
  inspectLimitsFromConfig,
  rulesDirOf,
} from '../src/scanning/engines/attachment/registration';
import { bundleIdOf } from '../src/scanning/engines/attachment/inspector/bundle';
import { findPrlimit, InspectorPool } from '../src/scanning/engines/attachment/inspector/pool';
import { ATTACHMENT_ONLY, AttachmentFixtures, AttachmentPipeline } from './support/attachments';
import { silentLogger, workerConfig } from './support/fixtures';
import { ScanFixtures } from './support/scan';

/**
 * Resilience of the attachment engine (step 4.2 §9, A4, A7, A14): clamd down (the client points
 * at a closed port: stopping the shared clamav container would interrupt the other suites and
 * reloads its database for about a minute), the breaker, recovery, the attempt budget ending in
 * `scan_failed` (never clean), and the inspector's CPU, memory, wall-clock and crash handling
 * with real child processes (`selftest` op, EG_INSPECTOR_SELFTEST=1, never in production).
 */
let fx: ScanFixtures;
let att: AttachmentFixtures;
let org: bigint;

beforeAll(async () => {
  fx = new ScanFixtures();
  att = new AttachmentFixtures(fx);
  org = await fx.organization('att-res');
});

afterAll(async () => {
  await att?.cleanup();
  await fx?.cleanup();
});

/** A local TCP port nothing listens on (connection refused). */
const CLOSED_PORT = '9';

describe('clamd unavailable (A7, A14)', () => {
  it('attempts fail as unavailable, the breaker opens, the round ends scan_failed, never clean', async () => {
    const down = await AttachmentPipeline.start(fx, {
      overrides: {
        CLAMAV_PORT: CLOSED_PORT,
        SCAN_ATTACHMENT_MAX_ATTEMPTS: '3',
        SCAN_BREAKER_FAILURE_THRESHOLD: '2',
        SCAN_BREAKER_FAILURE_RATIO: '0.5',
        SCAN_BREAKER_WINDOW: '10',
        SCAN_BREAKER_OPEN_MS: '60000',
      },
    });
    try {
      const pdf = corpus.pdfLike(8 * 1024, 501);
      await att.uncache(pdf);
      const message = await att.message(org, [{ bytes: pdf, filename: 'a.pdf' }]);
      const event = fx.parsed(message);
      const errors: string[] = [];
      for (let i = 0; i < 2; i += 1) {
        await expect(down.handleOnce(event)).rejects.toBeInstanceOf(EngineAttemptFailedError);
      }
      const { rows } = await att.finalOf(message);
      errors.push(...rows.map((r) => r.errorCode ?? ''));
      expect(errors).toEqual(['unavailable', 'unavailable']);
      expect(down.breaker.state).toBe('open');
      // The third attempt is the last of the budget: the open breaker finalizes it (no call).
      expect(await down.handleOnce(event)).toBe('handled');
      const { final, scan } = await att.finalOf(message);
      expect(final).toMatchObject({ outcome: 'error', errorCode: 'circuit_open' });
      expect(scan.status).toBe('failed');
      expect((await fx.state(message)).message.status).toBe('scan_failed');
      expect(await att.results(message)).toEqual([]);
      expect(await down.counter('scan_engine_circuit_state', { engine: 'attachment' })).toBe(2);
    } finally {
      await down.stop();
    }
  });

  it('recovers: a delivery retried after clamd is back completes the round', async () => {
    const down = await AttachmentPipeline.start(fx, { overrides: { CLAMAV_PORT: CLOSED_PORT } });
    const consumer = down.consumer;
    const pdf = corpus.pdfLike(8 * 1024, 502);
    await att.uncache(pdf);
    const message = await att.message(org, [{ bytes: pdf, filename: 'b.pdf' }]);
    const event = fx.parsed(message);
    try {
      await expect(down.handleOnce(event)).rejects.toBeInstanceOf(EngineAttemptFailedError);
    } finally {
      await down.stop();
    }
    const up = await AttachmentPipeline.start(fx, { consumer });
    try {
      expect(await up.handleOnce(event)).toBe('handled');
      const { rows, final } = await att.finalOf(message);
      expect(rows.map((r) => [r.attempt, r.isFinal, r.outcome])).toEqual([
        [1, false, 'error'],
        [2, true, 'clean'],
      ]);
      expect(final!.outcome).toBe('clean');
      expect((await fx.state(message)).message.status).toBe('scanned');
    } finally {
      await up.stop();
    }
  });
});

describe('inspector limits with real child processes (A4)', () => {
  const config = workerConfig({
    ...ATTACHMENT_ONLY,
    EG_INSPECTOR_SELFTEST: '1',
    ATTACHMENT_INSPECT_CPU_SECONDS: '2',
    ATTACHMENT_INSPECT_TIMEOUT_MS: '6000',
    ATTACHMENT_YARA_TIMEOUT_MS: '5000',
    ATTACHMENT_INSPECT_MAX_RSS_MB: '320',
  });
  const linuxWithPrlimit = process.platform === 'linux' && findPrlimit() !== null;

  async function pool(rlimits: 'required' | 'best_effort') {
    const tmp = mkdtempSync(join(tmpdir(), 'eg-it-pool-'));
    const kills: string[] = [];
    const instance = new InspectorPool({
      size: 1,
      maxJobs: 50,
      heapMb: config.ATTACHMENT_INSPECTOR_HEAP_MB,
      rlimits,
      tmpDir: tmp,
      wallTimeoutMs: config.ATTACHMENT_INSPECT_TIMEOUT_MS,
      cpuSeconds: config.ATTACHMENT_INSPECT_CPU_SECONDS,
      maxRssMb: config.ATTACHMENT_INSPECT_MAX_RSS_MB,
      rulesDir: rulesDirOf(config),
      yaraTimeoutMs: config.ATTACHMENT_YARA_TIMEOUT_MS,
      expectedBundleId: bundleIdOf(rulesDirOf(config)).bundleId,
      selftest: true,
      nodeEnv: 'test',
      maxWaiting: 4,
      logger: silentLogger,
      onKill: (reason) => kills.push(reason),
    });
    await instance.start();
    return {
      instance,
      kills,
      done: async () => {
        await instance.stop();
        rmSync(tmp, { recursive: true, force: true });
      },
    };
  }

  it('CPU → limit.cpu_time, RSS → limit.memory, wall clock → failure, crash → failure; recycled', async () => {
    const { instance, kills, done } = await pool('best_effort');
    try {
      const signal = () => AbortSignal.timeout(30_000);
      expect(await instance.selftest('cpu', signal())).toEqual({
        kind: 'limit',
        code: 'limit.cpu_time',
      });
      expect(await instance.selftest('memory', signal())).toEqual({
        kind: 'limit',
        code: 'limit.memory',
      });
      expect(await instance.selftest('hang', signal())).toEqual({
        kind: 'failure',
        reason: 'wall',
      });
      expect(await instance.selftest('crash', signal())).toEqual({
        kind: 'failure',
        reason: 'crash',
      });
      expect(kills).toEqual(['cpu', 'memory', 'wall', 'crash']);
      // Every kill recycled the child: the pool still inspects.
      const result = await instance.inspect(
        corpus.pdfLike(),
        inspectLimitsFromConfig(config),
        signal(),
      );
      expect(result.kind).toBe('result');
    } finally {
      await done();
    }
  }, 90_000);

  it.skipIf(!linuxWithPrlimit)(
    'runs children under prlimit in required mode (Linux only)',
    async () => {
      const { instance, done } = await pool('required');
      try {
        expect(instance.rlimitMode).toBe('prlimit');
        expect(await instance.selftest('cpu', AbortSignal.timeout(30_000))).toEqual({
          kind: 'limit',
          code: 'limit.cpu_time',
        });
      } finally {
        await done();
      }
    },
    60_000,
  );

  it('refuses required rlimits where prlimit is unavailable', async () => {
    if (linuxWithPrlimit) return;
    await expect(pool('required')).rejects.toThrow(/rlimits_unsupported_platform|prlimit_missing/);
  });
});
