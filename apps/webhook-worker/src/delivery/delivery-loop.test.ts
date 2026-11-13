import { Writable } from 'node:stream';
import { createLogger } from '@email-gateway/logger';
import type { PostRequest, PostResult } from '@email-gateway/url-security';
import { secretAad, verifyWebhookSignature, WebhookSecretCipher } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { silentLogger, testMetrics } from '../worker.test-support';
import type { ClaimedDelivery, ClaimReport, DeliveryClaimer } from './claimer';
import { DeliveryLoop } from './delivery-loop';
import { FakeCounterRedis } from './delivery.test-support';
import { InflightCounters } from './inflight';
import type { AttemptResult, DeliveryRecorder, RecordReport } from './recorder';
import { SecretProvider } from './secrets';

const NOW = new Date('2026-11-13T12:00:00.000Z');
const cipher = new WebhookSecretCipher({ key: '1'.repeat(64) });
const SUB = '01890a5d-ac96-774b-bcce-b3020990b501';
const EVENT_ID = '0193a1b2-0000-8000-8000-000000000001';
const JSON_BODY = JSON.stringify({ id: EVENT_ID, type: 'email.received', version: 1 });

function delivery(org: bigint, overrides: Partial<ClaimedDelivery> = {}): ClaimedDelivery {
  return {
    id: 11n,
    eventOccurredAt: new Date('2026-11-13T11:59:00.000Z'),
    publicId: `01890a5d-ac96-774b-bcce-${org.toString().padStart(12, '0')}`,
    organizationId: org,
    subscriptionId: 500n + org,
    eventId: EVENT_ID,
    eventType: 'email.received',
    attemptNo: 2,
    firstAttemptAt: NOW,
    claimedAt: NOW,
    subscription: {
      id: 500n + org,
      organizationId: org,
      publicId: SUB,
      url: `https://hooks.receiver.test/${org}`,
      status: 'active',
      maxConcurrency: null,
      secretVersion: 1,
      secretCiphertext: cipher.encrypt('whsec_unit_secret', secretAad(org, SUB, 1)),
      previousSecretCiphertext: null,
      previousSecretExpiresAt: null,
    },
    reservation: { organizationId: org, subscriptionId: 500n + org, rateKey: 'r', token: 't' },
    ...overrides,
  };
}

const ok = (overrides: Partial<PostResult> = {}): PostResult => ({
  outcome: 'succeeded',
  httpStatus: 204,
  latencyMs: 12,
  retryAfter: null,
  snippetBytes: Buffer.alloc(0),
  blockedReason: null,
  errorCode: null,
  ...overrides,
});

function harness(options: {
  orgs?: bigint[];
  claims?: Record<string, ClaimedDelivery[]>;
  poster?: (request: PostRequest) => Promise<PostResult>;
  events?: boolean;
  concurrency?: number;
  orgInflight?: number;
  logger?: ReturnType<typeof createLogger>;
}) {
  const redis = new FakeCounterRedis();
  const counters = new InflightCounters(redis, {
    leaseMs: 70_000,
    maxPerOrganization: 16,
    ratePerMinute: 600,
  });
  const posts: PostRequest[] = [];
  const recorded: Array<{ delivery: ClaimedDelivery; attempt: AttemptResult }> = [];
  const expired: ClaimedDelivery[] = [];
  const claimCalls: bigint[] = [];
  const claimer = {
    dueOrganizations: () => Promise.resolve(options.orgs ?? [42n]),
    claim: (org: bigint): Promise<ClaimReport> => {
      claimCalls.push(org);
      return Promise.resolve({
        claimed: options.claims?.[org.toString()] ?? [delivery(org)],
        cancelled: [],
        limited: [],
        paused: 0,
        lost: 0,
      });
    },
  } as unknown as DeliveryClaimer;
  const recorder = {
    record: (d: ClaimedDelivery, a: AttemptResult): Promise<RecordReport> => {
      recorded.push({ delivery: d, attempt: a });
      return Promise.resolve({
        state: 'succeeded',
        nextAttemptAt: null,
        disabled: false,
        alert: null,
      });
    },
    expire: (d: ClaimedDelivery) => {
      expired.push(d);
      return Promise.resolve(true);
    },
  } as unknown as DeliveryRecorder;
  const prisma = {
    $queryRaw: (): Promise<unknown[]> =>
      Promise.resolve(
        options.events === false
          ? []
          : [
              {
                organization_id: 42n,
                event_id: EVENT_ID,
                event_type: 'email.received',
                payload_json: JSON_BODY,
              },
            ],
      ),
  };
  const { metrics, registry } = testMetrics();
  const loop = new DeliveryLoop({
    prisma: prisma as never,
    claimer,
    recorder,
    counters,
    poster: {
      post: (request) => {
        posts.push(request);
        return options.poster ? options.poster(request) : Promise.resolve(ok());
      },
    },
    secrets: new SecretProvider(cipher, () => NOW.getTime()),
    metrics,
    sink: () => undefined,
    logger: options.logger ?? silentLogger,
    pollIntervalMs: 100,
    concurrency: options.concurrency ?? 32,
    maxPerOrganization: 16,
    now: () => NOW,
  });
  if (options.orgInflight !== undefined) {
    // Unexpired slots held by other attempts (score = lease expiry, far in the future).
    redis.zsets.set(
      'wh:slots:org:42',
      new Map(Array.from({ length: options.orgInflight }, (_, i) => [`t${i}`, 8.64e15])),
    );
  }
  return { loop, redis, posts, recorded, expired, claimCalls, registry, prisma };
}

/** The fake event row must echo the delivery's organization. */
function withOrg(h: ReturnType<typeof harness>, org: bigint): void {
  h.prisma.$queryRaw = () =>
    Promise.resolve([
      {
        organization_id: org,
        event_id: EVENT_ID,
        event_type: 'email.received',
        payload_json: JSON_BODY,
      },
    ]);
}

describe('DeliveryLoop (W8)', () => {
  it('sends nothing while Redis is unavailable (fail closed)', async () => {
    const h = harness({});
    h.redis.down = true;
    expect((await h.loop.tick()).outcome).toBe('store_unavailable');
    expect(h.claimCalls).toEqual([]);
    expect(await h.registry.metrics()).toMatch(/webhook_rate_limit_store_errors_total\{[^}]*\} 1/);
  });

  it('POSTs the stored bytes with the §4.2 headers and a signature the receiver verifies', async () => {
    const h = harness({});
    withOrg(h, 42n);
    await h.loop.tick();
    await h.loop.drain();
    expect(h.posts).toHaveLength(1);
    const post = h.posts[0]!;
    expect(post.url).toBe('https://hooks.receiver.test/42');
    expect(post.body).toBe(JSON_BODY);
    expect(Object.keys(post.headers).sort()).toEqual([
      'EG-Delivery-Attempt',
      'EG-Delivery-Id',
      'EG-Event-Id',
      'EG-Event-Type',
      'EG-Signature',
      'EG-Subscription-Id',
      'Idempotency-Key',
    ]);
    expect(post.headers).toMatchObject({
      'EG-Event-Id': EVENT_ID,
      'Idempotency-Key': EVENT_ID,
      'EG-Event-Type': 'email.received',
      'EG-Delivery-Attempt': '2',
      'EG-Subscription-Id': SUB,
      'EG-Delivery-Id': delivery(42n).publicId,
    });
    expect(
      verifyWebhookSignature({
        header: post.headers['EG-Signature']!,
        rawBody: JSON_BODY,
        secrets: ['whsec_unit_secret'],
        now: NOW,
      }),
    ).toEqual({ ok: true });
    expect(h.recorded[0]!.attempt).toMatchObject({
      outcome: 'succeeded',
      signatureCount: 1,
      attemptedAt: NOW,
    });
    expect(h.redis.size('wh:slots:org:42')).toBe(0);
  });

  it('signs with both secrets during a rotation overlap', async () => {
    const d = delivery(42n);
    d.subscription = {
      ...d.subscription,
      secretVersion: 2,
      secretCiphertext: cipher.encrypt('whsec_new', secretAad(42n, SUB, 2)),
      previousSecretCiphertext: cipher.encrypt('whsec_old', secretAad(42n, SUB, 1)),
      previousSecretExpiresAt: new Date(NOW.getTime() + 3_600_000),
    };
    const h = harness({ claims: { '42': [d] } });
    withOrg(h, 42n);
    await h.loop.tick();
    await h.loop.drain();
    const header = h.posts[0]!.headers['EG-Signature']!;
    expect(header.match(/v1=/g)).toHaveLength(2);
    for (const secret of ['whsec_new', 'whsec_old']) {
      expect(
        verifyWebhookSignature({ header, rawBody: JSON_BODY, secrets: [secret], now: NOW }).ok,
      ).toBe(true);
    }
    expect(h.recorded[0]!.attempt.signatureCount).toBe(2);
  });

  it('records secret_unavailable without sending when the secret cannot be decrypted', async () => {
    const d = delivery(42n);
    d.subscription = { ...d.subscription, secretCiphertext: 'v1.k1.bad.bad.bad' };
    const h = harness({ claims: { '42': [d] } });
    withOrg(h, 42n);
    await h.loop.tick();
    await h.loop.drain();
    expect(h.posts).toEqual([]);
    expect(h.recorded[0]!.attempt).toMatchObject({
      outcome: 'secret_unavailable',
      signatureCount: 0,
    });
  });

  it('expires a delivery whose stored event is gone (no POST)', async () => {
    const h = harness({ events: false });
    await h.loop.tick();
    await h.loop.drain();
    expect(h.posts).toEqual([]);
    expect(h.expired).toHaveLength(1);
  });

  it('counts SSRF blocks by reason', async () => {
    const h = harness({
      poster: () =>
        Promise.resolve(
          ok({
            outcome: 'blocked',
            httpStatus: null,
            blockedReason: 'metadata',
            errorCode: 'blocked:metadata',
          }),
        ),
    });
    withOrg(h, 42n);
    await h.loop.tick();
    await h.loop.drain();
    const text = await h.registry.metrics();
    expect(text).toMatch(/webhook_ssrf_blocked_total\{[^}]*reason="metadata"[^}]*\} 1/);
    expect(text).toMatch(/webhook_delivery_attempts_total\{[^}]*outcome="blocked"[^}]*\} 1/);
  });

  it('skips an organization at its in-flight cap', async () => {
    const h = harness({ orgInflight: 16 });
    await h.loop.tick();
    expect(h.claimCalls).toEqual([]);
    expect(await h.registry.metrics()).toMatch(
      /webhook_rate_limited_total\{[^}]*scope="organization"[^}]*\} 1/,
    );
  });

  it('a slow organization never blocks another one: both are claimed in the same tick', async () => {
    let releaseSlow: () => void = () => undefined;
    const h = harness({
      orgs: [1n, 2n],
      poster: (request) =>
        request.url.endsWith('/1')
          ? new Promise<PostResult>((resolve) => {
              releaseSlow = () => resolve(ok());
            })
          : Promise.resolve(ok()),
    });
    // The stored event echoes the organization of the delivery being loaded (in claim order).
    const order: bigint[] = [];
    const claim = h.loop['options'].claimer.claim.bind(h.loop['options'].claimer);
    h.loop['options'].claimer.claim = (org: bigint, limit: number, now: Date) => {
      order.push(org);
      return claim(org, limit, now);
    };
    let loads = 0;
    h.prisma.$queryRaw = () => {
      const org = order[loads] ?? 0n;
      loads += 1;
      return Promise.resolve([
        {
          organization_id: org,
          event_id: EVENT_ID,
          event_type: 'email.received',
          payload_json: JSON_BODY,
        },
      ]);
    };
    const report = await h.loop.tick();
    expect(report.claimed).toBe(2);
    expect([...h.claimCalls].sort()).toEqual([1n, 2n]);
    // The fast organization's attempt completes while the slow one is still in flight.
    await new Promise((r) => setTimeout(r, 20));
    expect(h.recorded.map((r) => r.delivery.organizationId)).toEqual([2n]);
    expect(h.loop.active).toBe(1);
    releaseSlow();
    await h.loop.drain();
    expect(h.recorded.map((r) => r.delivery.organizationId).sort()).toEqual([1n, 2n]);
  });

  it('bounds the attempts in flight in the process (saturated tick claims nothing)', async () => {
    let release: () => void = () => undefined;
    const h = harness({
      concurrency: 1,
      poster: () => new Promise<PostResult>((resolve) => (release = () => resolve(ok()))),
    });
    withOrg(h, 42n);
    await h.loop.tick();
    expect((await h.loop.tick()).outcome).toBe('saturated');
    expect(h.claimCalls).toHaveLength(1);
    release();
    await h.loop.drain();
  });

  it('never logs a secret, a URL or a header', async () => {
    const lines: string[] = [];
    const logger = createLogger({
      service: 'webhook-worker-test',
      level: 'debug',
      destination: new Writable({
        write(chunk: Buffer, _enc, done) {
          lines.push(chunk.toString('utf8'));
          done();
        },
      }),
    });
    const h = harness({ logger });
    withOrg(h, 42n);
    // Recording fails: the warning names the delivery and the error class only.
    (h as unknown as { recorded: unknown[] }).recorded = [];
    const failing = new DeliveryLoop({
      ...(h.loop as unknown as { options: ConstructorParameters<typeof DeliveryLoop>[0] }).options,
      recorder: {
        record: () =>
          Promise.reject(Object.assign(new Error('whsec_unit_secret leaked?'), { code: 'P2034' })),
        expire: () => Promise.resolve(true),
      } as unknown as DeliveryRecorder,
      logger,
    });
    await failing.tick();
    await failing.drain();
    const text = lines.join('');
    expect(text).toContain('could not be recorded');
    expect(text).not.toContain('whsec_');
    expect(text).not.toContain('hooks.receiver.test');
    expect(text).not.toContain('EG-Signature');
  });
});
