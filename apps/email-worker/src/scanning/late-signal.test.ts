import { MetricsService, NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, threatLateSignalV1 } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import {
  InconsistentLateSignalReadError,
  LateSignalMetrics,
  levelRank,
  readRevisionZero,
  readRoundStatus,
  sandboxRevisionSignal,
  type SandboxRevisionInput,
  urlDynamicSignal,
  type UrlDynamicInput,
  writeLateSignalOutbox,
} from './late-signal';

/**
 * Late verdicts of the email-worker (step API-3 C2.1, contracts §38,
 * docs/plan/steps/37-api-mode-clawback-reporting.md): the sandbox revision and URL dynamic
 * decisions, the strict outbox writer and the locking reads. Synthetic hashes and ids only.
 */
const RECEIVED = new Date('2026-11-27T09:00:00.000Z');
const SIGNAL = new Date('2026-11-27T09:20:00.000Z');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);

const sandboxInput = (over: Partial<SandboxRevisionInput> = {}): SandboxRevisionInput => ({
  messageId: 42n,
  receivedAt: RECEIVED,
  scanId: 9n,
  revision: 1,
  written: { level: 'critical', verdict: 'malware', hardBlocks: ['hb.malware_sandbox'] },
  base: { level: 'low', verdict: 'clean' },
  submissions: [
    { sha256: SHA_A, sandboxVerdict: 'malicious' },
    { sha256: SHA_B, sandboxVerdict: 'clean' },
    { sha256: SHA_C, sandboxVerdict: 'suspicious' },
  ],
  signalAt: SIGNAL,
  ...over,
});

describe('levelRank', () => {
  it('orders none < low < medium < high < critical', () => {
    expect(['none', 'low', 'medium', 'high', 'critical'].map(levelRank)).toEqual([0, 1, 2, 3, 4]);
    expect(levelRank('unknown')).toBe(-1);
    expect(levelRank(null)).toBe(-1);
  });
});

describe('sandboxRevisionSignal (C2.1)', () => {
  it('a revision that raises the level writes the strict payload with the flagged hashes', () => {
    const payload = sandboxRevisionSignal(sandboxInput());
    expect(payload).toEqual({
      kind: 'sandbox_revision',
      messageId: '42',
      receivedAt: RECEIVED.toISOString(),
      scanId: '9',
      revision: 1,
      verdict: 'malware',
      level: 'critical',
      hardBlocks: ['hb.malware_sandbox'],
      attachmentSha256: [SHA_A, SHA_C],
      urlSha256: [],
      signalAt: SIGNAL.toISOString(),
    });
    expect(threatLateSignalV1.safeParse(payload).success).toBe(true);
  });

  it('a different threat verdict at the same level is a signal', () => {
    const payload = sandboxRevisionSignal(
      sandboxInput({
        written: { level: 'high', verdict: 'malware', hardBlocks: [] },
        base: { level: 'high', verdict: 'phishing' },
      }),
    );
    expect(payload).toMatchObject({ verdict: 'malware', level: 'high', hardBlocks: [] });
  });

  it('a threat verdict at level none (no level raise) is still a signal', () => {
    expect(
      sandboxRevisionSignal(
        sandboxInput({
          written: { level: 'none', verdict: 'suspicious', hardBlocks: [] },
          base: { level: 'none', verdict: 'clean' },
        }),
      ),
    ).toMatchObject({ level: 'none', verdict: 'suspicious' });
  });

  it('a revision that neither raises the level nor changes the threat verdict writes nothing', () => {
    for (const [written, base] of [
      [
        { level: 'high', verdict: 'phishing', hardBlocks: [] },
        { level: 'high', verdict: 'phishing' },
      ],
      [
        { level: 'medium', verdict: 'clean', hardBlocks: [] },
        { level: 'high', verdict: 'phishing' },
      ],
      [
        { level: 'low', verdict: 'spam', hardBlocks: [] },
        { level: 'low', verdict: 'clean' },
      ],
      [
        { level: 'high', verdict: 'phishing', hardBlocks: [] },
        { level: 'critical', verdict: 'phishing' },
      ],
    ] as const) {
      expect(sandboxRevisionSignal(sandboxInput({ written, base }))).toBeNull();
    }
  });

  it('a non-threat verdict with a raised level is a signal (level is enough)', () => {
    expect(
      sandboxRevisionSignal(
        sandboxInput({
          written: { level: 'medium', verdict: 'spam', hardBlocks: [] },
          base: { level: 'low', verdict: 'spam' },
        }),
      ),
    ).toMatchObject({ level: 'medium', verdict: 'spam' });
  });

  it('a round without revision 0 compares against level none', () => {
    expect(sandboxRevisionSignal(sandboxInput({ base: null }))).not.toBeNull();
    expect(
      sandboxRevisionSignal(
        sandboxInput({ base: null, written: { level: 'none', verdict: 'clean', hardBlocks: [] } }),
      ),
    ).toBeNull();
  });

  it('bounds and de-duplicates hard blocks (≤ 9) and hashes (≤ 20, lower case)', () => {
    const many = Array.from({ length: 25 }, (_, i) => ({
      sha256: i.toString(16).padStart(2, '0').repeat(32).toUpperCase(),
      sandboxVerdict: 'malicious',
    }));
    const payload = sandboxRevisionSignal(
      sandboxInput({
        written: {
          level: 'critical',
          verdict: 'malware',
          hardBlocks: [...Array.from({ length: 12 }, (_, i) => `hb.x${i}`), 'hb.x0'],
        },
        submissions: [...many, { sha256: many[0]!.sha256, sandboxVerdict: 'malicious' }],
      }),
    );
    expect(payload!.hardBlocks).toHaveLength(9);
    expect(payload!.attachmentSha256).toHaveLength(20);
    expect(payload!.attachmentSha256.every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true);
    expect(threatLateSignalV1.safeParse(payload).success).toBe(true);
  });
});

const urlInput = (over: Partial<UrlDynamicInput> = {}): UrlDynamicInput => ({
  messageId: 42n,
  receivedAt: RECEIVED,
  scanId: 9n,
  verdict: 'malicious',
  reasonCodes: ['url.dynamic_phishing'],
  urlSha256: SHA_A,
  roundStatus: 'completed',
  signalAt: SIGNAL,
  ...over,
});

describe('urlDynamicSignal (C2.1)', () => {
  it('malicious after completion: phishing, critical, hb.clawback.url, the URL hash', () => {
    const payload = urlDynamicSignal(urlInput());
    expect(payload).toEqual({
      kind: 'url_dynamic',
      messageId: '42',
      receivedAt: RECEIVED.toISOString(),
      scanId: '9',
      revision: null,
      verdict: 'phishing',
      level: 'critical',
      hardBlocks: ['hb.clawback.url'],
      attachmentSha256: [],
      urlSha256: [SHA_A],
      signalAt: SIGNAL.toISOString(),
    });
    expect(threatLateSignalV1.safeParse(payload).success).toBe(true);
  });

  it('suspicious: high without a hard block; phishing only with the dynamic phishing rule', () => {
    expect(
      urlDynamicSignal(urlInput({ verdict: 'suspicious', reasonCodes: ['url.dynamic_download'] })),
    ).toMatchObject({ verdict: 'suspicious', level: 'high', hardBlocks: [] });
    expect(
      urlDynamicSignal(urlInput({ verdict: 'suspicious', reasonCodes: ['url.dynamic_phishing'] })),
    ).toMatchObject({ verdict: 'phishing', level: 'high', hardBlocks: [] });
  });

  it('every finished round status counts; a running round or a benign verdict writes nothing', () => {
    for (const roundStatus of ['completed', 'failed', 'timed_out']) {
      expect(urlDynamicSignal(urlInput({ roundStatus }))).not.toBeNull();
    }
    expect(urlDynamicSignal(urlInput({ roundStatus: 'running' }))).toBeNull();
    for (const verdict of ['clean', 'unknown']) {
      expect(urlDynamicSignal(urlInput({ verdict }))).toBeNull();
    }
  });
});

function outboxTx() {
  const created: Array<Record<string, unknown>> = [];
  const tx = {
    messageOutbox: {
      create: (args: { data: Record<string, unknown> }) => {
        created.push(args.data);
        return Promise.resolve({ id: 1n });
      },
    },
  } as unknown as Prisma.TransactionClient;
  return { tx, created };
}

describe('writeLateSignalOutbox', () => {
  it('writes one message-aggregate row with a uuidv7 event id and the correlation id', async () => {
    const { tx, created } = outboxTx();
    const payload = urlDynamicSignal(urlInput())!;
    const eventId = await writeLateSignalOutbox(tx, {
      organizationId: 7n,
      payload,
      correlationId: 'corr-late-1',
    });
    expect(eventId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
    expect(created).toEqual([
      {
        eventId,
        organizationId: 7n,
        eventType: EventTypes.ThreatLateSignal,
        aggregateType: 'message',
        aggregateId: '42',
        correlationId: 'corr-late-1',
        payload,
      },
    ]);
  });

  it('refuses a payload that violates the strict contract and writes nothing', async () => {
    const { tx, created } = outboxTx();
    const bad = { ...urlDynamicSignal(urlInput())!, attachmentSha256: [SHA_B] };
    await expect(
      writeLateSignalOutbox(tx, { organizationId: 7n, payload: bad, correlationId: 'c-1234567' }),
    ).rejects.toBeInstanceOf(NonRetryableError);
    const extra = { ...sandboxRevisionSignal(sandboxInput())!, subject: 'x' };
    await expect(
      writeLateSignalOutbox(tx, {
        organizationId: 7n,
        payload: extra,
        correlationId: 'c-1234567',
      }),
    ).rejects.toBeInstanceOf(NonRetryableError);
    expect(created).toEqual([]);
  });
});

const rawTx = (rows: Array<Record<string, unknown>>) =>
  ({ $queryRaw: () => Promise.resolve(rows) }) as unknown as Prisma.TransactionClient;

describe('locking reads', () => {
  const round = { scanId: 9n, receivedAt: RECEIVED, organizationId: 7n, messageId: 42n };

  it('readRevisionZero returns level and verdict, null without a row, throws on a foreign row', async () => {
    const row = {
      scan_id: 9n,
      received_at: RECEIVED,
      organization_id: 7n,
      revision: 0,
      level: 'low',
      verdict: 'clean',
    };
    expect(await readRevisionZero(rawTx([row]), round)).toEqual({ level: 'low', verdict: 'clean' });
    expect(await readRevisionZero(rawTx([]), round)).toBeNull();
    for (const wrong of [{ scan_id: 8n }, { organization_id: 8n }, { revision: 1 }]) {
      await expect(readRevisionZero(rawTx([{ ...row, ...wrong }]), round)).rejects.toBeInstanceOf(
        InconsistentLateSignalReadError,
      );
    }
  });

  it('readRoundStatus returns the status, null when gone, throws on a foreign row', async () => {
    const row = {
      id: 9n,
      received_at: RECEIVED,
      organization_id: 7n,
      message_id: 42n,
      status: 'completed',
    };
    expect(await readRoundStatus(rawTx([row]), round)).toBe('completed');
    expect(await readRoundStatus(rawTx([]), round)).toBeNull();
    for (const wrong of [{ id: 8n }, { message_id: 43n }, { organization_id: 8n }]) {
      await expect(readRoundStatus(rawTx([{ ...row, ...wrong }]), round)).rejects.toBeInstanceOf(
        InconsistentLateSignalReadError,
      );
    }
  });
});

describe('LateSignalMetrics', () => {
  it('one counter per registry with zero series per kind', async () => {
    const registry = new MetricsService({ service: 'late-signal-test' });
    const metrics = LateSignalMetrics.for(registry);
    expect(LateSignalMetrics.for(registry)).toBe(metrics);
    metrics.signal('url_dynamic');
    const text = await registry.metrics();
    expect(text).toMatch(/scan_late_signals_total\{[^}]*kind="sandbox_revision"[^}]*\} 0/);
    expect(text).toMatch(/scan_late_signals_total\{[^}]*kind="url_dynamic"[^}]*\} 1/);
  });
});
