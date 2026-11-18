import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Fixtures, type SeededMessage } from './support/fixtures';
import { harness, type Harness, testConfig } from './support/harness';

/**
 * Capture baseline (§9.2): 1 000 synthetic messages (registry, message, recipient, parse, headers,
 * attachment, decoded parts, a completed scan round with engine/auth/attachment/URL/risk/
 * evaluation rows, the EML in the mail bucket) journaled by the completeness sweep and captured
 * by the scheduler with the default `ARCHIVE_CAPTURE_CONCURRENCY` (4): throughput, p95 capture
 * latency and the process RSS are printed (laptop numbers, not a production claim, A30).
 * `ARCHIVE_IT_BASELINE_MESSAGES` overrides the count.
 */
const COUNT = Number(process.env.ARCHIVE_IT_BASELINE_MESSAGES ?? 1_000);
const fx = new Fixtures();
let h: Harness;

const pct = (sorted: number[], p: number): number =>
  sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;

beforeAll(async () => {
  h = await harness(fx, { config: testConfig(fx, { ARCHIVE_SWEEP_BATCH_SIZE: '1000' }) });
  await h.comps.capture!.journal.runOnce(); // cursor at "now"
}, 180_000);

afterAll(async () => {
  await h?.close();
  await fx.cleanup();
}, 600_000);

describe('capture baseline', () => {
  it(`captures ${COUNT} synthetic messages`, async () => {
    const org = await fx.organization('baseline');
    const seeded: SeededMessage[] = [];
    const seedStart = Date.now();
    for (let i = 0; i < COUNT; i += 1) seeded.push(await fx.message(org.id, { bodyBytes: 4_096 }));
    const seedMs = Date.now() - seedStart;
    for (;;) {
      const r = await h.comps.capture!.journal.runOnce();
      if (!r.more) break;
    }
    expect(await fx.prisma.archiveCaptureIntent.count({ where: { organizationId: org.id } })).toBe(
      COUNT,
    );
    // Per-capture latency: wrap the executor (measurement only).
    const executor = h.comps.capture!.executor;
    const original = executor.capture.bind(executor);
    const latencies: number[] = [];
    executor.capture = async (input) => {
      const t = process.hrtime.bigint();
      try {
        return await original(input);
      } finally {
        latencies.push(Number(process.hrtime.bigint() - t) / 1e6);
      }
    };
    let peakRss = process.memoryUsage().rss;
    const sampler = setInterval(() => {
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
    }, 200);
    const startRss = process.memoryUsage().rss;
    const start = Date.now();
    let captured = 0;
    while (captured < COUNT) {
      await h.comps.capture!.scheduler.runOnce();
      captured = await fx.prisma.emailArchive.count({ where: { organizationId: org.id } });
      if (Date.now() - start > 900_000) break;
    }
    const ms = Date.now() - start;
    clearInterval(sampler);
    expect(captured).toBe(COUNT);
    const sorted = [...latencies].sort((a, b) => a - b);
    const stored = await fx.prisma.emailArchive.aggregate({
      where: { organizationId: org.id },
      _sum: { storedBytes: true, sizeBytes: true },
    });
    const result = {
      messages: COUNT,
      concurrency: h.config.ARCHIVE_CAPTURE_CONCURRENCY,
      seedSeconds: +(seedMs / 1000).toFixed(1),
      captureSeconds: +(ms / 1000).toFixed(1),
      throughputPerSecond: +((COUNT * 1000) / ms).toFixed(1),
      latencyMs: {
        p50: +pct(sorted, 50).toFixed(1),
        p95: +pct(sorted, 95).toFixed(1),
        max: +(sorted.at(-1) ?? 0).toFixed(1),
      },
      rssMiB: { start: Math.round(startRss / 1_048_576), peak: Math.round(peakRss / 1_048_576) },
      originalBytes: Number(stored._sum.sizeBytes ?? 0),
      storedBytes: Number(stored._sum.storedBytes ?? 0),
    };
    process.stdout.write(`[archive capture baseline] ${JSON.stringify(result)}\n`);
    expect(seeded).toHaveLength(COUNT);
  }, 1_800_000);
});
