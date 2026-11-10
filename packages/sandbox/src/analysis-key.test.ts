import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { analysisKey, dedupeKey } from './analysis-key';
import {
  artifactKeyPrefix,
  artifactObjectKey,
  newArtifactRunId,
  parseArtifactKey,
  sampleObjectKey,
  taskIdOfSampleKey,
} from './object-keys';

const limits = {
  wallTimeoutMs: 60_000,
  memoryMb: 512,
  cpuMillis: 1000,
  pids: 128,
  scratchMb: 64,
  maxArtifacts: 16,
  maxArtifactBytes: 2_097_152,
  maxTotalArtifactBytes: 8_388_608,
};

describe('analysisKey (X13 step 4)', () => {
  it('is the first 16 hex of SHA-256 over the canonical { profile, limits, epoch, map }', () => {
    const key = analysisKey({ profile: 'static', limits, epoch: 1 });
    expect(key).toMatch(/^[0-9a-f]{16}$/);
    const canonical =
      '{"epoch":1,"limits":{"cpuMillis":1000,"maxArtifactBytes":2097152,"maxArtifacts":16,"maxTotalArtifactBytes":8388608,"memoryMb":512,"pids":128,"scratchMb":64,"wallTimeoutMs":60000},"map":"sandbox-map/1","profile":"static"}';
    expect(key).toBe(createHash('sha256').update(canonical).digest('hex').slice(0, 16));
  });

  it('is deterministic and independent of property order', () => {
    const reordered = Object.fromEntries(Object.entries(limits).reverse()) as typeof limits;
    expect(analysisKey({ profile: 'execute', limits: reordered, epoch: 3 })).toBe(
      analysisKey({ epoch: 3, limits, profile: 'execute' }),
    );
  });

  it('changes with the profile, any limit, the epoch and the map version', () => {
    const base = analysisKey({ profile: 'static', limits, epoch: 1 });
    expect(analysisKey({ profile: 'browser', limits, epoch: 1 })).not.toBe(base);
    expect(analysisKey({ profile: 'static', limits: { ...limits, pids: 129 }, epoch: 1 })).not.toBe(
      base,
    );
    expect(analysisKey({ profile: 'static', limits, epoch: 2 })).not.toBe(base);
    expect(analysisKey({ profile: 'static', limits, epoch: 1, map: 'sandbox-map/2' })).not.toBe(
      base,
    );
  });

  it('refuses invalid inputs', () => {
    expect(() => analysisKey({ profile: 'detonate' as never, limits, epoch: 1 })).toThrow();
    expect(() =>
      analysisKey({ profile: 'static', limits: { ...limits, pids: 1 }, epoch: 1 }),
    ).toThrow();
    expect(() => analysisKey({ profile: 'static', limits, epoch: 0 })).toThrow(/epoch/);
    expect(() => analysisKey({ profile: 'static', limits, epoch: 1.5 })).toThrow(/epoch/);
  });

  it('builds the 81-character dedupe key', () => {
    const key = analysisKey({ profile: 'static', limits, epoch: 1 });
    const d = dedupeKey('a'.repeat(64), key);
    expect(d).toBe(`${'a'.repeat(64)}:${key}`);
    expect(d).toHaveLength(81);
    expect(() => dedupeKey('A'.repeat(64), key)).toThrow();
    expect(() => dedupeKey('a'.repeat(64), 'xyz')).toThrow();
  });
});

describe('object keys (X12)', () => {
  const task = '01890a5d-ac96-774b-bcce-b302099a8070';
  const at = new Date('2026-01-31T23:59:59.999Z');
  const RUN = '0123456789abcdef';

  it('builds and parses sample and artifact keys (UTC month)', () => {
    expect(sampleObjectKey(task, at)).toBe(`samples/2026/01/${task}.bin`);
    expect(taskIdOfSampleKey(`samples/2026/01/${task}.bin`)).toBe(task);
    expect(taskIdOfSampleKey(`samples/2026/01/${task}.exe`)).toBeNull();
    expect(taskIdOfSampleKey(`org/1/part/${task}.bin`)).toBeNull();
    expect(artifactKeyPrefix(task, at)).toBe(`artifacts/2026/01/${task}/`);
    const key = artifactObjectKey(task, at, RUN, 15, 'screenshot');
    expect(key).toBe(`artifacts/2026/01/${task}/${RUN}/15-screenshot.bin`);
    expect(parseArtifactKey(key)).toEqual({
      taskId: task,
      runId: RUN,
      seq: 15,
      kind: 'screenshot',
      prefix: `artifacts/2026/01/${task}/`,
    });
  });

  it('draws a fresh 16-hex run id per run, so two runs of a task never share an object key', () => {
    const ids = new Set(Array.from({ length: 64 }, () => newArtifactRunId()));
    expect(ids.size).toBe(64);
    for (const id of ids) expect(id).toMatch(/^[0-9a-f]{16}$/);
    const [a, b] = [...ids] as [string, string];
    expect(artifactObjectKey(task, at, a, 0, 'static_report')).not.toBe(
      artifactObjectKey(task, at, b, 0, 'static_report'),
    );
  });

  it('refuses invalid parts', () => {
    expect(() => sampleObjectKey('x', at)).toThrow();
    expect(() => sampleObjectKey(task, new Date(Number.NaN))).toThrow();
    expect(() => artifactObjectKey(task, at, RUN, 16, 'screenshot')).toThrow();
    expect(() => artifactObjectKey(task, at, RUN, 0, 'memory_dump' as never)).toThrow();
    for (const run of ['', '0123456789ABCDEF', '0123456789abcde', '0123456789abcdef0', '../x']) {
      expect(() => artifactObjectKey(task, at, run, 0, 'screenshot'), run).toThrow();
    }
    for (const bad of [
      `artifacts/2026/01/${task}/${RUN}/16-screenshot.bin`,
      `artifacts/2026/01/${task}/${RUN}/01-screenshot.bin`,
      `artifacts/2026/01/${task}/${RUN}/0-memory_dump.bin`,
      `artifacts/2026/01/${task}/${RUN}/0-screenshot.png`,
      `artifacts/2026/01/${task}/0-screenshot.bin`,
      `artifacts/2026/01/${task}/0123456789ABCDEF/0-screenshot.bin`,
      `samples/2026/01/${task}.bin`,
    ]) {
      expect(parseArtifactKey(bad), bad).toBeNull();
    }
  });
});
