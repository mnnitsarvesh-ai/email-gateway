import { resolveArchiveSettings } from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { FakeStorage, metricValue, silentLogger, testMetrics } from '../archive.test-support';
import type { TenantKeyService } from '../keys/tenant-keys';
import { DeterministicCaptureError } from '../shared/errors';
import type { CaptureExecutor } from './executor';
import type { OrgArchiveContext, OrgContextCache } from './org-context';
import { CaptureScheduler } from './scheduler';

const ORG = 42n;
const NOW = new Date('2026-11-16T12:00:00.000Z');
const receivedAt = new Date('2026-11-16T11:00:00.000Z');

const ctx = (over: Partial<OrgArchiveContext> = {}): OrgArchiveContext => ({
  organizationId: ORG,
  entitled: true,
  enabled: true,
  settings: resolveArchiveSettings(null),
  settingsValid: true,
  generation: 1n,
  journalEnabledAt: new Date(0),
  objectLockMode: 'none',
  defaultRetentionPolicyId: 1n,
  matcher: () => false,
  unresolved: 0,
  scopeTruncated: false,
  ...over,
});

const intent = (over: Record<string, unknown> = {}) => ({
  id: 1n,
  receivedAt,
  organizationId: ORG,
  messageId: 100n,
  leaseUntil: new Date('2026-11-16T12:10:00.000Z'),
  status: 'pending' as const,
  sourceJournal: true,
  sourcePolicy: false,
  policyRuleRef: null,
  category: null as string | null,
  attempts: 0,
  createdAt: new Date('2026-11-16T11:58:00.000Z'),
  capturedAt: null,
  archiveId: null,
  archiveReceivedAt: null,
  merged: false,
  ...over,
});

function db(message: { status: string; statusReason?: string | null } | null, cas = 1) {
  const sets: Prisma.Sql[] = [];
  return {
    sets,
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      sets.push(Prisma.sql(strings, ...values));
      return Promise.resolve(cas);
    },
    emailMessage: {
      findUnique: () =>
        Promise.resolve(
          message === null
            ? null
            : {
                id: 100n,
                receivedAt,
                organizationId: ORG,
                direction: 'inbound',
                status: message.status,
                statusReason: message.statusReason ?? null,
                statusChangedAt: receivedAt,
                lifecycleRound: 0,
                internetMessageId: null,
                envelopeFrom: 'a@b',
                headerFrom: null,
                subject: null,
                sizeBytes: 1,
                attachmentCount: 0,
                emlObjectKey: `org/${ORG}/eml/x`,
                emlSha256: 'a'.repeat(64),
                clientIp: null,
                clientHelo: null,
                clientName: null,
                finalVerdict: null,
                finalAction: null,
                riskScore: null,
              },
        ),
    },
    messageIdentity: {
      findUnique: () =>
        Promise.resolve({
          id: 100n,
          organizationId: ORG,
          publicId: '0190a5d0-0000-7000-8000-0000000000aa',
        }),
    },
    emailRecipient: {
      findMany: () =>
        Promise.resolve([
          {
            id: 1n,
            messageId: 100n,
            organizationId: ORG,
            rcptSeq: 0,
            address: 'u@corp.example',
            direction: 'inbound',
            status: message?.status === 'delivered' ? 'delivered' : 'pending',
            finalAction: null,
          },
        ]),
    },
  };
}

function scheduler(
  d: ReturnType<typeof db>,
  c: OrgArchiveContext,
  executor: Partial<CaptureExecutor> = {},
) {
  const { metrics, service } = testMetrics();
  const s = new CaptureScheduler(d as never, {
    orgs: { get: () => Promise.resolve(c) } as unknown as OrgContextCache,
    executor: executor as CaptureExecutor,
    storage: new FakeStorage().asStorage(),
    keys: {} as TenantKeyService,
    metrics,
    logger: silentLogger,
    concurrency: 2,
    leaseSeconds: 600,
    retryBaseMs: 1_000,
    retryMaxMs: 4_000,
    maxAgeDays: 25,
    outcomeWindowDays: 7,
    chunkBytes: 65_536,
    random: () => 1,
    now: () => NOW,
  });
  return { s, service };
}

const lastSet = (d: ReturnType<typeof db>) => d.sets.at(-1)!;

describe('CaptureScheduler decisions (A3, A6)', () => {
  it('waits for a non-final message on the 1-2-5-15-30-min schedule (CAS on the claimed lease)', async () => {
    const d = db({ status: 'scanning' });
    const { s } = scheduler(d, ctx());
    expect(await s.process(intent())).toBe('waiting');
    const sql = lastSet(d);
    expect(sql.sql).toContain('next_check_at');
    expect(sql.sql).toContain('lease_until = NULL');
    expect(sql.values).toContainEqual(new Date(NOW.getTime() + 2 * 60_000)); // created 2 min ago: second wait
    expect(sql.values).toContainEqual(intent().leaseUntil);
    // Not a wait in quarantine: no marker, and a wait clears the last error code.
    expect(sql.sql).toContain('category = ?');
    expect(sql.sql).toContain('last_error_code = NULL');
    expect(sql.values).toContain(null);
    expect(sql.values).not.toContain('quarantined');
  });

  it('a wait in quarantine is marked and outlives the intent max age (review fix)', async () => {
    const d = db({ status: 'quarantined', statusReason: 'policy_quarantine' });
    const { s, service } = scheduler(d, ctx());
    const old = intent({ createdAt: new Date(NOW.getTime() - 40 * 86_400_000) });
    expect(await s.process(old)).toBe('waiting');
    expect(lastSet(d).values).toContain('quarantined');
    const ancient = intent({ createdAt: new Date(NOW.getTime() - 101 * 86_400_000) });
    expect(await s.process(ancient)).toBe('skipped');
    expect(lastSet(d).values).toContain('max_age');
    expect(await metricValue(service, 'archive_capture_skipped_total', { reason: 'max_age' })).toBe(
      1,
    );
  });

  it('skips not entitled / disabled; records lost messages', async () => {
    const skipped = db({ status: 'delivered' });
    expect(await scheduler(skipped, ctx({ entitled: false })).s.process(intent())).toBe('skipped');
    expect(lastSet(skipped).values).toContain('not_entitled');
    const s2 = scheduler(db({ status: 'delivered' }), ctx({ enabled: false }));
    expect(await s2.s.process(intent())).toBe('skipped');
    expect(
      await metricValue(s2.service, 'archive_capture_skipped_total', {
        reason: 'archiving_disabled',
      }),
    ).toBe(1);
    const lost = db(null);
    expect(await scheduler(lost, ctx()).s.process(intent())).toBe('lost');
    expect(lastSet(lost).values).toContain('message_missing');
  });

  it('captures delivered mail through the executor and counts it', async () => {
    const d = db({ status: 'delivered', statusReason: 'delivery_complete' });
    let called = 0;
    const { s, service } = scheduler(d, ctx(), {
      capture: (input) => {
        called += 1;
        expect(input.category).toBe('delivered');
        return Promise.resolve({ status: 'captured', archiveId: 9n, storedBytes: 10 });
      },
    });
    expect(await s.process(intent())).toBe('captured');
    expect(called).toBe(1);
    expect(
      await metricValue(service, 'archive_capture_total', {
        result: 'captured',
        source: 'journal',
        category: 'delivered',
      }),
    ).toBe(1);
  });

  it('fails deterministic errors at once; retries others with backoff; fails retries past the max age', async () => {
    const det = db({ status: 'delivered' });
    expect(
      await scheduler(det, ctx(), {
        capture: () => Promise.reject(new DeterministicCaptureError('integrity_mismatch')),
      }).s.process(intent()),
    ).toBe('failed');
    expect(lastSet(det).values).toContain('integrity_mismatch');
    const retry = db({ status: 'delivered' });
    expect(
      await scheduler(retry, ctx(), {
        capture: () => Promise.reject(Object.assign(new Error('s3'), { name: 'TimeoutError' })),
      }).s.process(intent({ attempts: 2 })),
    ).toBe('retry');
    expect(lastSet(retry).values).toEqual(
      expect.arrayContaining([3, 'TimeoutError', new Date(NOW.getTime() + 4_000)]),
    );
    const aged = db({ status: 'delivered' });
    expect(
      await scheduler(aged, ctx(), { capture: () => Promise.reject(new Error('x')) }).s.process(
        intent({ createdAt: new Date(NOW.getTime() - 26 * 86_400_000) }),
      ),
    ).toBe('failed');
    expect(lastSet(aged).sql).toContain("status = 'failed'");
  });

  it('a lost lease writes nothing more (another replica took the intent)', async () => {
    const d = db({ status: 'scanning' }, 0);
    expect(await scheduler(d, ctx()).s.process(intent())).toBe('lease_lost');
  });
});
