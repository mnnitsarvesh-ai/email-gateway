import { MetricsService, NonRetryableError } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import {
  EventTypes,
  type EventEnvelope,
  type UrlInspectionCompletedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { DynamicCacheValue, UrlCache } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import { UrlMetrics } from './url-metrics';
import { dynamicVerdict, highConfidenceOf, UrlResultsService } from './url-results';
import { InconsistentUrlReadError } from './url-store';

const signals = (over: Partial<UrlInspectionCompletedV1['signals']> = {}) => ({
  passwordFields: 0,
  forms: 0,
  crossOriginFormAction: false,
  formActionHosts: [],
  downloadAttempted: false,
  blockedRequests: 0,
  requests: 1,
  bytes: 10,
  titleBrandMatches: [],
  jsRedirect: false,
  dialogs: 0,
  ...over,
});

describe('dynamic verdict (U10 M5, S9, U3)', () => {
  it('maps the dynamic rules only', () => {
    expect(dynamicVerdict('completed', signals(), false)).toEqual({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
    });
    expect(dynamicVerdict('completed', signals({ passwordFields: 1 }), true)).toEqual({
      verdict: 'malicious',
      reasonCodes: ['url.dynamic_phishing'],
    });
    expect(
      dynamicVerdict(
        'completed',
        signals({ passwordFields: 1, titleBrandMatches: ['paypal'] }),
        false,
      ).verdict,
    ).toBe('malicious');
    // A password form alone (no lookalike, no brand title) is not M5.
    expect(dynamicVerdict('completed', signals({ passwordFields: 1 }), false).verdict).toBe(
      'clean',
    );
    expect(
      dynamicVerdict(
        'completed',
        signals({
          downloadAttempted: true,
          crossOriginFormAction: true,
          jsRedirect: true,
          blockedRequests: 2,
        }),
        false,
      ),
    ).toEqual({
      verdict: 'suspicious',
      reasonCodes: [
        'url.dynamic_cross_origin_form',
        'url.dynamic_download',
        'url.redirect_blocked_internal',
      ],
    });
    expect(dynamicVerdict('failed', null, true)).toEqual({
      verdict: 'unknown',
      reasonCodes: ['url.dynamic_failed'],
    });
  });

  it('derives high confidence from stored lookalike entries', () => {
    expect(highConfidenceOf(null, 0.85)).toBe(false);
    expect(highConfidenceOf([{ rule: 'L1' }], 0.85)).toBe(true);
    expect(highConfidenceOf(JSON.stringify([{ rule: 'L3', score: 0.8 }]), 0.85)).toBe(true);
    expect(highConfidenceOf([{ rule: 'L2', score: 0.86 }], 0.85)).toBe(true);
    expect(
      highConfidenceOf([{ rule: 'L2', score: 0.8 }, { rule: 'L4' }, { rule: 'L6' }], 0.85),
    ).toBe(false);
    expect(highConfidenceOf([{ rule: 'L5', score: 0.6 }, 'junk', null], 0.85)).toBe(false);
  });
});

const AT = new Date('2026-11-05T10:00:00.123Z');
const SHA = 'a'.repeat(64);
const row = (over: Record<string, unknown> = {}) => ({
  id: 11n,
  receivedAt: new Date(AT),
  organizationId: 7n,
  messageId: 55n,
  scanId: 99n,
  urlSeq: 2,
  urlSha256: SHA,
  status: 'pending',
  ...over,
});

function service(state: { row: unknown; scanResult?: unknown; updated?: number }) {
  const updates: unknown[] = [];
  const cacheWrites: Array<[string, DynamicCacheValue]> = [];
  const tx = {
    messageIdempotency: { create: () => Promise.resolve({}) },
    urlDynamicInspection: {
      findFirst: () => Promise.resolve(state.row),
      updateMany: (args: unknown) => {
        updates.push(args);
        return Promise.resolve({ count: state.updated ?? 1 });
      },
    },
    urlScanResult: { findFirst: () => Promise.resolve(state.scanResult ?? null) },
  };
  const prisma = {
    $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx),
  } as unknown as PrismaClient;
  const registry = new MetricsService({ service: 'url-results-test' });
  const cache = {
    setDynamic: (sha: string, value: DynamicCacheValue) => {
      cacheWrites.push([sha, value]);
      return Promise.resolve(true);
    },
  } as unknown as UrlCache;
  const results = new UrlResultsService({
    prisma,
    txTimeoutMs: 120_000,
    cache,
    metrics: UrlMetrics.for(registry),
    logger: createLogger({ service: 'url-results-test', level: 'silent' }),
    highScore: 0.85,
  });
  return { results, updates, cacheWrites, registry };
}

const event = (
  over: Partial<UrlInspectionCompletedV1> = {},
  organizationId = '7',
): EventEnvelope<UrlInspectionCompletedV1> => ({
  eventId: '01900000-0000-7000-8000-000000000001',
  eventType: EventTypes.UrlInspectionCompleted,
  occurredAt: AT.toISOString(),
  correlationId: 'c',
  organizationId,
  payload: {
    inspectionId: '11',
    messageId: '55',
    receivedAt: AT.toISOString(),
    urlSeq: 2,
    urlSha256: SHA,
    status: 'completed',
    errorCode: null,
    workerVersion: 'w/1',
    browserVersion: 'b/1',
    finalUrlSha256: null,
    finalHost: null,
    navigations: [],
    signals: signals(),
    durationMs: 5,
    completedAt: '2026-11-05T10:01:00.000Z',
    ...over,
  },
});

describe('results consumer (U15)', () => {
  it('updates a pending row with the dynamic verdict and writes the dynamic cache entry', async () => {
    const s = service({
      row: row(),
      scanResult: {
        scanId: 99n,
        urlSeq: 2,
        organizationId: 7n,
        messageId: 55n,
        urlSha256: SHA,
        lookalike: [{ rule: 'L3', score: 0.8 }],
      },
    });
    expect(await s.results.handle(event({ signals: signals({ passwordFields: 2 }) }))).toBe(
      'handled',
    );
    expect(s.updates[0]).toMatchObject({
      where: { id: 11n, receivedAt: AT, status: 'pending' },
      data: {
        status: 'completed',
        verdict: 'malicious',
        reasonCodes: ['url.dynamic_phishing'],
        workerVersion: 'w/1',
        completedAt: new Date('2026-11-05T10:01:00.000Z'),
      },
    });
    expect(s.cacheWrites).toEqual([
      [
        SHA,
        {
          inspectionId: '11',
          status: 'completed',
          verdict: 'malicious',
          reasonCodes: ['url.dynamic_phishing'],
          signals: signals({ passwordFields: 2 }),
          finalUrlSha256: null,
          finalHost: null,
          completedAt: '2026-11-05T10:01:00.000Z',
        },
      ],
    ]);
    expect(await s.registry.metrics()).toMatch(
      /scan_url_dynamic_inspections_total\{[^}]*status="completed"[^}]*\} 1/,
    );
  });

  it('drops unknown ids and results of another organization, message or URL (no update)', async () => {
    for (const [state, ev] of [
      [{ row: null }, event()],
      [{ row: row() }, event({}, '8')],
      [{ row: row() }, event({ messageId: '56' })],
      [{ row: row() }, event({ urlSeq: 3 })],
      [{ row: row() }, event({ urlSha256: 'b'.repeat(64) })],
    ] as const) {
      const s = service(state);
      expect(await s.results.handle(ev)).toBe('handled');
      expect(s.updates).toEqual([]);
      expect(s.cacheWrites).toEqual([]);
      expect(await s.registry.metrics()).toMatch(
        /scan_url_dynamic_inspections_total\{[^}]*status="dropped"[^}]*\} 1/,
      );
    }
  });

  it('a row that is no longer pending, or updated concurrently, is a no-op', async () => {
    const expired = service({ row: row({ status: 'expired' }) });
    expect(await expired.results.handle(event())).toBe('handled');
    expect(expired.updates).toEqual([]);
    const raced = service({ row: row(), updated: 0 });
    expect(await raced.results.handle(event())).toBe('handled');
    expect(raced.cacheWrites).toEqual([]);
  });

  it('a row of another id (wrong read) or a foreign scan result is thrown, not dropped', async () => {
    const wrong = service({ row: row({ id: 12n }) });
    await expect(wrong.results.handle(event())).rejects.toBeInstanceOf(InconsistentUrlReadError);
    expect(await wrong.registry.metrics()).toMatch(
      /scan_url_inconsistent_reads_total\{[^}]*read="inspection"[^}]*\} 1/,
    );
    const foreign = service({
      row: row(),
      scanResult: {
        scanId: 98n,
        urlSeq: 2,
        organizationId: 7n,
        messageId: 55n,
        urlSha256: SHA,
        lookalike: null,
      },
    });
    await expect(foreign.results.handle(event())).rejects.toBeInstanceOf(InconsistentUrlReadError);
  });

  it('refuses a payload that violates the event contract (dead-lettered)', async () => {
    const s = service({ row: row() });
    await expect(
      s.results.handle(event({ status: 'failed', errorCode: null })),
    ).rejects.toBeInstanceOf(NonRetryableError);
  });
});
