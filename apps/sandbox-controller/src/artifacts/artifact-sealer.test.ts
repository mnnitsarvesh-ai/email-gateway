import { createHash, randomUUID } from 'node:crypto';
import {
  generateArtifactKeyPair,
  openArtifact,
  parseArtifactKey,
  parseArtifactPrivateKey,
  parseArtifactPublicKey,
  SandboxEnvelopeError,
} from '@email-gateway/sandbox';
import { describe, expect, it } from 'vitest';
import type { RawArtifact } from '../backends/backend';
import { ArtifactSealer, PNG_SIGNATURE, selectArtifacts } from './artifact-sealer';

const pair = generateArtifactKeyPair();
const limits = { maxArtifacts: 16, maxArtifactBytes: 1024, maxTotalArtifactBytes: 2048 };
const png = (n: number): Buffer => Buffer.concat([PNG_SIGNATURE, Buffer.alloc(n)]);

describe('artifact selection (X12 caps)', () => {
  it('keeps valid artifacts in order within the caps', () => {
    const artifacts: RawArtifact[] = [
      { kind: 'static_report', contentType: 'application/json', bytes: Buffer.from('{}') },
      { kind: 'screenshot', contentType: 'image/png', bytes: png(10) },
    ];
    const { selected, limitsHit } = selectArtifacts(artifacts, limits);
    expect(selected.map((s) => [s.seq, s.artifact.kind])).toEqual([
      [0, 'static_report'],
      [1, 'screenshot'],
    ]);
    expect(limitsHit).toEqual([]);
  });

  it('drops invalid kinds, content types and PNG signatures (output_truncated)', () => {
    const { selected, limitsHit } = selectArtifacts(
      [
        { kind: 'screenshot', contentType: 'image/png', bytes: Buffer.from('GIF89a') },
        { kind: 'process_log', contentType: 'application/json', bytes: Buffer.from('x') },
        {
          kind: 'memory_dump' as never,
          contentType: 'application/octet-stream',
          bytes: Buffer.from('x'),
        },
      ],
      limits,
    );
    expect(selected).toEqual([]);
    expect(limitsHit).toEqual(['output_truncated']);
  });

  it('enforces the count, per-artifact and total caps (artifact_cap)', () => {
    const log = (n: number): RawArtifact => ({
      kind: 'process_log',
      contentType: 'text/plain',
      bytes: Buffer.alloc(n),
    });
    expect(selectArtifacts([log(1025)], limits)).toEqual({
      selected: [],
      limitsHit: ['artifact_cap'],
    });
    const total = selectArtifacts([log(1000), log(1000), log(1000)], limits);
    expect(total.selected).toHaveLength(2);
    expect(total.limitsHit).toEqual(['artifact_cap']);
    const many = selectArtifacts(
      Array.from({ length: 20 }, () => log(1)),
      { ...limits, maxArtifacts: 16 },
    );
    expect(many.selected).toHaveLength(16);
    expect(selectArtifacts([log(1)], { ...limits, maxArtifacts: 0 }).limitsHit).toEqual([
      'artifact_cap',
    ]);
  });
});

describe('ArtifactSealer', () => {
  it('seals to the public key (the controller cannot open) and stores under the task prefix', async () => {
    const puts: { key: string; body: Buffer }[] = [];
    const sealer = new ArtifactSealer(parseArtifactPublicKey(pair.publicKey), {
      putArtifact: (key, body) => {
        puts.push({ key, body });
        return Promise.resolve();
      },
    });
    const taskId = randomUUID();
    const bytes = Buffer.from('{"v":1}');
    const at = new Date(Date.UTC(2026, 10, 8));
    const { stored } = await sealer.sealAndStore({
      taskId,
      at,
      artifacts: [{ kind: 'static_report', contentType: 'application/json', bytes }],
      limits,
    });
    expect(stored).toHaveLength(1);
    const a = stored[0]!;
    expect(a.key).toMatch(
      new RegExp(`^artifacts/2026/11/${taskId}/[0-9a-f]{16}/0-static_report\\.bin$`),
    );
    expect(parseArtifactKey(a.key)).toMatchObject({ taskId, seq: 0, kind: 'static_report' });
    // Every call draws a fresh run id: a second run never writes over the first one's objects.
    const again = await sealer.sealAndStore({
      taskId,
      at,
      artifacts: [{ kind: 'static_report', contentType: 'application/json', bytes }],
      limits,
    });
    expect(again.stored[0]!.key).not.toBe(a.key);
    expect(parseArtifactKey(again.stored[0]!.key)!.runId).not.toBe(parseArtifactKey(a.key)!.runId);
    puts.splice(1);
    // A pinned run id is used as given.
    const pinned = await sealer.sealAndStore({
      taskId,
      at,
      artifacts: [{ kind: 'static_report', contentType: 'application/json', bytes }],
      limits,
      runId: '0123456789abcdef',
    });
    expect(pinned.stored[0]!.key).toBe(
      `artifacts/2026/11/${taskId}/0123456789abcdef/0-static_report.bin`,
    );
    puts.splice(1);
    expect(a.plainSha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(a.objectSha256).toBe(createHash('sha256').update(puts[0]!.body).digest('hex'));
    expect(a.algorithm).toBe('sandbox-artifact/1');
    expect(puts[0]!.body.includes(bytes)).toBe(false);
    const opened = openArtifact(
      parseArtifactPrivateKey(pair.privateKey),
      puts[0]!.body,
      a.wrappedKey,
      { taskId, seq: 0, kind: 'static_report' },
    );
    expect(opened.equals(bytes)).toBe(true);
    const other = generateArtifactKeyPair();
    expect(() =>
      openArtifact(parseArtifactPrivateKey(other.privateKey), puts[0]!.body, a.wrappedKey, {
        taskId,
        seq: 0,
        kind: 'static_report',
      }),
    ).toThrow(SandboxEnvelopeError);
  });

  it('propagates a storage failure (the task is retried)', async () => {
    const sealer = new ArtifactSealer(parseArtifactPublicKey(pair.publicKey), {
      putArtifact: () => Promise.reject(new Error('down')),
    });
    await expect(
      sealer.sealAndStore({
        taskId: randomUUID(),
        at: new Date(),
        artifacts: [{ kind: 'network_log', contentType: 'text/plain', bytes: Buffer.from('x') }],
        limits,
      }),
    ).rejects.toThrow('down');
  });
});
