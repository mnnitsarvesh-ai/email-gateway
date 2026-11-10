import { createHash } from 'node:crypto';
import { NonRetryableError } from '@email-gateway/common';
import { openSample } from '@email-gateway/sandbox';
import { describe, expect, it } from 'vitest';
import type { PartRead, PartSource } from '../parts/part-reader';
import { FakeSandboxObjects, newSandboxMetrics } from './fakes.test-support';
import { isSandboxArtifactKey, isSandboxSampleKey, SampleStager } from './sample-stager';

const KEY = '4'.repeat(64);
const PREVIOUS = '5'.repeat(64);
const TASK = '0190f3a0-0000-7000-8000-000000000042';
const BYTES = Buffer.from('synthetic benign sample');
const SHA = createHash('sha256').update(BYTES).digest('hex');
const input = {
  organizationId: 7n,
  partKey: 'org/7/part/2026/11/08/9/1.att',
  sizeBytes: BYTES.length,
  sha256: SHA,
  taskId: TASK,
  sampleKey: `samples/2026/11/${TASK}.bin`,
};

function stager(read: () => Promise<PartRead>, previous?: string) {
  const objects = new FakeSandboxObjects();
  const reads: string[] = [];
  const parts: PartSource = {
    read: (key) => {
      reads.push(key);
      return read();
    },
  };
  return {
    objects,
    reads,
    stager: new SampleStager({
      parts,
      objects,
      sampleKey: KEY,
      ...(previous ? { previousSampleKey: previous } : {}),
      timeoutMs: 1_000,
    }),
  };
}

describe('sample stager (X13 step 6, X12)', () => {
  it('seals the part (never the plaintext) to the deterministic key', async () => {
    const t = stager(() => Promise.resolve({ kind: 'ok', bytes: Buffer.from(BYTES) }), PREVIOUS);
    expect(await t.stager.stage(input)).toMatchObject({ kind: 'staged' });
    const object = t.objects.objects.get(input.sampleKey)!;
    expect(object.subarray(0, 7).toString('ascii')).toBe('EGSBXS1');
    expect(object.includes(BYTES)).toBe(false);
    expect(openSample({ current: KEY }, object, { taskId: TASK, sha256: SHA }).plaintext).toEqual(
      BYTES,
    );
    // Staging again overwrites the same key (idempotent).
    await t.stager.stage(input);
    expect(t.objects.objects.size).toBe(1);
  });

  it('missing and corrupt parts are final failures; outages are thrown', async () => {
    expect(await stager(() => Promise.resolve({ kind: 'missing' })).stager.stage(input)).toEqual({
      kind: 'failed',
      errorCode: 'sample_unavailable',
    });
    expect(await stager(() => Promise.resolve({ kind: 'integrity' })).stager.stage(input)).toEqual({
      kind: 'failed',
      errorCode: 'sample_integrity',
    });
    const outage = stager(() =>
      Promise.reject(Object.assign(new Error('down'), { $metadata: {} })),
    );
    await expect(outage.stager.stage(input)).rejects.toThrow('down');
    expect(outage.objects.objects.size).toBe(0);
  });

  it('re-checks the tenant part prefix and the sample key before any read', async () => {
    const t = stager(() => Promise.resolve({ kind: 'ok', bytes: Buffer.from(BYTES) }));
    await expect(
      t.stager.stage({ ...input, partKey: 'org/8/part/2026/11/08/9/1.att' }),
    ).rejects.toThrow(NonRetryableError);
    await expect(
      t.stager.stage({ ...input, partKey: 'org/7/part/../../org/8/part/x' }),
    ).rejects.toThrow('tenant_mismatch');
    await expect(
      t.stager.stage({ ...input, sampleKey: 'samples/2026/11/other.bin' }),
    ).rejects.toThrow('sandbox_sample_key_invalid');
    expect(t.reads).toEqual([]);
  });

  it('refuses a malformed sample key at construction; recognizes deletable keys', () => {
    expect(
      () =>
        new SampleStager({
          parts: { read: () => Promise.resolve({ kind: 'missing' }) },
          objects: new FakeSandboxObjects(),
          sampleKey: 'short',
          timeoutMs: 1,
        }),
    ).toThrow('SANDBOX_SAMPLE_KEY');
    expect(isSandboxSampleKey(input.sampleKey)).toBe(true);
    expect(isSandboxSampleKey('org/7/part/x')).toBe(false);
    expect(
      isSandboxArtifactKey(`artifacts/2026/11/${TASK}/0123456789abcdef/3-screenshot.bin`),
    ).toBe(true);
    expect(isSandboxArtifactKey(`artifacts/2026/11/${TASK}/3-screenshot.bin`)).toBe(false);
    expect(
      isSandboxArtifactKey(`artifacts/2026/11/${TASK}/0123456789abcdef/3-unknown_kind.bin`),
    ).toBe(false);
  });
});

describe('sandbox metrics (X20)', () => {
  it('registers exactly the worker series with bounded labels (no tenant, hash or task labels)', async () => {
    const { registry } = newSandboxMetrics();
    const text = await registry.metrics();
    const names = [
      ...new Set(
        text
          .split('\n')
          .filter((l) => l.startsWith('scan_sandbox_'))
          .map((l) => l.split(/[{ ]/)[0]!),
      ),
    ]
      .map((n) => n.replace(/_(bucket|sum|count)$/, ''))
      .filter((n, i, all) => all.indexOf(n) === i)
      .sort();
    expect(names).toEqual([
      'scan_sandbox_analyses_total',
      'scan_sandbox_finals_total',
      'scan_sandbox_inconsistent_reads_total',
      'scan_sandbox_purge_failures_total',
      'scan_sandbox_purged_total',
      'scan_sandbox_results_rejected_total',
      'scan_sandbox_staging_failures_total',
      'scan_sandbox_staging_seconds',
      'scan_sandbox_submissions_total',
      'scan_sandbox_verdicts_total',
    ]);
    const labels = new Set(
      text
        .split('\n')
        .filter((l) => l.startsWith('scan_sandbox_'))
        .flatMap((l) => [...l.matchAll(/[{,]([a-z_]+)="/g)].map((m) => m[1]!))
        .filter((l) => l !== 'service'),
    );
    expect([...labels].sort()).toEqual([
      'kind',
      'le',
      'outcome',
      'read',
      'reason',
      'result',
      'status',
      'verdict',
    ]);
  });
});
