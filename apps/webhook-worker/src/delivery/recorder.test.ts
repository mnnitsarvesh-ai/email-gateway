import { notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import { DEFAULT_WEBHOOK_RETRY_CONFIG, webhookEventId } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { type SeenSql, sqlOf } from '../worker.test-support';
import type { ClaimedDelivery } from './claimer';
import { type AttemptResult, DeliveryRecorder } from './recorder';

const NOW = new Date('2026-11-13T12:00:00.000Z');
const SUB_PUBLIC = '01890a5d-ac96-774b-bcce-b3020990b501';
const DELIVERY_PUBLIC = '01890a5d-ac96-774b-bcce-b3020990d001';

function claimed(overrides: Partial<ClaimedDelivery> = {}): ClaimedDelivery {
  return {
    id: 11n,
    eventOccurredAt: new Date('2026-11-13T11:59:00.000Z'),
    publicId: DELIVERY_PUBLIC,
    organizationId: 42n,
    subscriptionId: 501n,
    eventId: '0193a1b2-0000-8000-8000-000000000001',
    eventType: 'email.received',
    attemptNo: 1,
    firstAttemptAt: NOW,
    claimedAt: NOW,
    subscription: {} as ClaimedDelivery['subscription'],
    reservation: { organizationId: 42n, subscriptionId: 501n, rateKey: 'r', token: 't' },
    ...overrides,
  };
}

function attempt(overrides: Partial<AttemptResult> = {}): AttemptResult {
  return {
    outcome: 'http_error',
    httpStatus: 500,
    latencyMs: 120.4,
    retryAfter: null,
    snippetBytes: Buffer.from('oops token=abcdef0123'),
    errorCode: 'http_500',
    signatureCount: 1,
    attemptedAt: NOW,
    ...overrides,
  };
}

interface SubState {
  status: string;
  consecutive_failures: number;
  failing_since: Date | null;
}

function harness(options: { cas?: number; sub?: Partial<SubState>; window?: number } = {}) {
  const statements: SeenSql[] = [];
  const attempts: Array<Record<string, unknown>> = [];
  const audits: Array<Record<string, unknown>> = [];
  const outbox: Array<Record<string, unknown>> = [];
  const sub: SubState = {
    status: 'active',
    consecutive_failures: 0,
    failing_since: null,
    ...options.sub,
  };
  const tx = {
    $executeRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.startsWith('UPDATE webhook_deliveries')) return Promise.resolve(options.cas ?? 1);
      if (s.text.includes('consecutive_failures = consecutive_failures + 1')) {
        sub.consecutive_failures += 1;
        sub.failing_since ??= s.values[0] as Date;
        return Promise.resolve(1);
      }
      if (s.text.includes("SET status = 'disabled'")) {
        if (sub.status !== 'active') return Promise.resolve(0);
        sub.status = 'disabled';
        return Promise.resolve(1);
      }
      if (s.text.startsWith('INSERT INTO notification_alert_windows')) {
        return Promise.resolve(options.window ?? 1);
      }
      return Promise.resolve(1);
    },
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.includes('FROM webhook_subscriptions')) {
        return Promise.resolve([{ id: 501n, organization_id: 42n, public_id: SUB_PUBLIC, ...sub }]);
      }
      return Promise.resolve([]);
    },
    webhookDeliveryAttempt: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        attempts.push(data);
        return Promise.resolve({ id: 1n });
      },
    },
    auditLog: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        audits.push(data);
        return Promise.resolve({ id: 1n });
      },
    },
    notificationSettings: { findUnique: () => Promise.resolve(null) },
    messageOutbox: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        outbox.push(data);
        return Promise.resolve({ id: 1n });
      },
    },
  };
  const prisma = { $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx) };
  const sinks: string[] = [];
  const recorder = new DeliveryRecorder(prisma as never, {
    retry: { ...DEFAULT_WEBHOOK_RETRY_CONFIG, maxAttempts: 3 },
    autoDisable: { failures: 5, hours: 1 },
    sink: (read) => void sinks.push(read),
    random: () => 0.5,
  });
  return { recorder, statements, attempts, audits, outbox, sub, sinks };
}

describe('DeliveryRecorder.nextState (W10)', () => {
  const { recorder } = harness();

  it('2xx → succeeded', () => {
    expect(
      recorder.nextState(
        claimed(),
        attempt({ outcome: 'succeeded', httpStatus: 204, errorCode: null }),
        NOW,
      ),
    ).toEqual({
      status: 'succeeded',
      nextAttemptAt: null,
      lastError: null,
      retryAfterSeconds: null,
    });
  });

  it('blocked → failed immediately (blocked:<reason>), never retried', () => {
    expect(
      recorder.nextState(
        claimed(),
        attempt({ outcome: 'blocked', httpStatus: null, errorCode: 'blocked:loopback' }),
        NOW,
      ),
    ).toMatchObject({ status: 'failed', lastError: 'blocked:loopback', nextAttemptAt: null });
  });

  it('a retryable outcome is scheduled with the backoff (base × 2^(n−1), jitter 1.0 at random 0.5)', () => {
    expect(recorder.nextState(claimed(), attempt(), NOW)).toMatchObject({
      status: 'pending',
      lastError: 'http_500',
      nextAttemptAt: new Date(NOW.getTime() + 30_000),
    });
    expect(
      recorder.nextState(
        claimed({ attemptNo: 2 }),
        attempt({ outcome: 'timeout', httpStatus: null, errorCode: 'timeout' }),
        NOW,
      ),
    ).toMatchObject({
      status: 'pending',
      nextAttemptAt: new Date(NOW.getTime() + 60_000),
    });
  });

  it('honours Retry-After when longer than the backoff (and records its seconds)', () => {
    expect(
      recorder.nextState(claimed(), attempt({ httpStatus: 429, retryAfter: '120' }), NOW),
    ).toMatchObject({
      status: 'pending',
      nextAttemptAt: new Date(NOW.getTime() + 120_000),
      retryAfterSeconds: 120,
    });
    // Shorter than the backoff: the backoff wins.
    expect(
      recorder.nextState(claimed(), attempt({ httpStatus: 429, retryAfter: '2' }), NOW)
        .nextAttemptAt,
    ).toEqual(new Date(NOW.getTime() + 30_000));
    // Above the cap (3600 s): clamped, never ignored.
    expect(
      recorder.nextState(claimed(), attempt({ httpStatus: 503, retryAfter: '999999' }), NOW)
        .nextAttemptAt,
    ).toEqual(new Date(NOW.getTime() + 3_600_000));
  });

  it('dead after max attempts or max age', () => {
    expect(recorder.nextState(claimed({ attemptNo: 3 }), attempt(), NOW)).toMatchObject({
      status: 'dead',
      lastError: 'http_500',
    });
    expect(
      recorder.nextState(
        claimed({ firstAttemptAt: new Date(NOW.getTime() - 25 * 3_600_000) }),
        attempt(),
        NOW,
      ).status,
    ).toBe('dead');
  });
});

describe('DeliveryRecorder.record (W8 step 4, W11)', () => {
  it('writes the attempt (sanitized snippet, never headers) and the CAS update', async () => {
    const h = harness();
    const report = await h.recorder.record(claimed(), attempt(), NOW);
    expect(report).toMatchObject({ state: 'retry', disabled: false });
    const cas = h.statements.find((s) => s.text.startsWith('UPDATE webhook_deliveries'))!;
    expect(cas.text).toContain("status = 'pending' AND attempt_count = ?");
    expect(cas.values).toEqual(expect.arrayContaining([11n, 1, 42n]));
    expect(h.attempts[0]).toMatchObject({
      attemptNo: 1,
      outcome: 'http_error',
      httpStatus: 500,
      latencyMs: 120,
      errorCode: 'http_500',
      signatureCount: 1,
      deliveryId: 11n,
      organizationId: 42n,
      subscriptionId: 501n,
    });
    expect(h.attempts[0]!.responseSnippet).toBe('oops [redacted]');
    expect(h.sub.consecutive_failures).toBe(1);
  });

  it('a success resets the failure streak', async () => {
    const h = harness({ sub: { consecutive_failures: 3, failing_since: NOW } });
    await h.recorder.record(
      claimed(),
      attempt({ outcome: 'succeeded', httpStatus: 200, errorCode: null }),
      NOW,
    );
    expect(
      h.statements.some((s) => s.text.includes('consecutive_failures = 0, failing_since = NULL')),
    ).toBe(true);
    expect(h.attempts[0]!.errorCode).toBeNull();
  });

  it('a lost CAS writes nothing and is counted', async () => {
    const h = harness({ cas: 0 });
    expect((await h.recorder.record(claimed(), attempt(), NOW)).state).toBe('lost');
    expect(h.attempts).toHaveLength(0);
    expect(h.sinks).toEqual(['delivery_cas']);
  });

  it('secret_unavailable is retried but never counted against the endpoint', async () => {
    const h = harness();
    await h.recorder.record(
      claimed(),
      attempt({
        outcome: 'secret_unavailable',
        httpStatus: null,
        errorCode: 'secret_unavailable',
        signatureCount: 0,
      }),
      NOW,
    );
    expect(h.sub.consecutive_failures).toBe(0);
  });

  it('does not disable below the failure count or before the failing window', async () => {
    const few = harness({
      sub: { consecutive_failures: 2, failing_since: new Date(NOW.getTime() - 2 * 3_600_000) },
    });
    expect((await few.recorder.record(claimed(), attempt(), NOW)).disabled).toBe(false);
    const young = harness({
      sub: { consecutive_failures: 10, failing_since: new Date(NOW.getTime() - 30 * 60_000) },
    });
    expect((await young.recorder.record(claimed(), attempt(), NOW)).disabled).toBe(false);
    expect(young.audits).toHaveLength(0);
  });

  it('disables after sustained failure: audit row (system, ids/counts) and one alert', async () => {
    const since = new Date(NOW.getTime() - 2 * 3_600_000);
    const h = harness({ sub: { consecutive_failures: 4, failing_since: since } });
    const report = await h.recorder.record(claimed(), attempt(), NOW);
    expect(report).toMatchObject({ disabled: true, alert: 'requested' });
    expect(h.sub.status).toBe('disabled');
    const disable = h.statements.find((s) => s.text.includes("SET status = 'disabled'"))!;
    expect(disable.values).toContain('sustained_failure');
    expect(h.audits).toEqual([
      {
        organizationId: 42n,
        actorType: 'system',
        actorId: null,
        action: 'webhook.auto_disabled',
        resourceType: 'webhook',
        resourceId: SUB_PUBLIC,
        correlationId: `webhook-delivery:${DELIVERY_PUBLIC}`,
        sourceIp: null,
        metadata: {
          subscriptionId: SUB_PUBLIC,
          consecutiveFailures: 5,
          failingSince: since.toISOString(),
        },
      },
    ]);
    expect(h.outbox).toHaveLength(1);
    expect(h.outbox[0]).toMatchObject({
      eventId: webhookEventId(DELIVERY_PUBLIC, 'alert:webhook_disabled'),
      aggregateType: 'organization',
      aggregateId: '42',
    });
    expect(notificationAlertRequestedV1.parse(h.outbox[0]!.payload)).toMatchObject({
      kind: 'webhook_disabled',
      refs: { subscriptionId: SUB_PUBLIC },
    });
  });

  it('a blocked attempt counts toward auto-disable too', async () => {
    const h = harness({
      sub: { consecutive_failures: 4, failing_since: new Date(NOW.getTime() - 2 * 3_600_000) },
    });
    const report = await h.recorder.record(
      claimed(),
      attempt({ outcome: 'blocked', httpStatus: null, errorCode: 'blocked:private' }),
      NOW,
    );
    expect(report).toMatchObject({ state: 'failed', disabled: true });
  });

  it('a subscription already disabled is not disabled twice', async () => {
    const h = harness({
      sub: { status: 'paused', consecutive_failures: 99, failing_since: new Date(0) },
    });
    expect((await h.recorder.record(claimed(), attempt(), NOW)).disabled).toBe(false);
    expect(h.audits).toHaveLength(0);
  });
});
