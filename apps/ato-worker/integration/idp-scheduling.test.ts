import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  GS_DOMAIN,
  GS_EXTERNAL_DOMAIN,
  GS_USERS,
  MS_IPS,
  MS_USERS,
  msRiskDetection,
  msSignIn,
} from '@email-gateway/idp-adapters/testing';
import { RedisRateBudget } from '../src/provider/stores';
import type { DetectRequest } from '../src/detect/pipeline';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { DAY, IdpWorld, MIN, gsCustomerAs, msDirectoryAs } from './support/idp';
import { accountOf, configure } from './support/scenario';

/**
 * Step 8.5 §11.3 stream scheduling and robustness on the real MySQL writer and Redis: claims with
 * `FOR UPDATE SKIP LOCKED` by two concurrent passes, companions never polled, failure backoff and
 * the early probe, provider throttling (`throttled_until`), the Redis rate budget, cursor reset,
 * page-transaction idempotency (a crash mid-page has one effect), cursor-confirmed snapshot state
 * (a crash before the commit re-emits the change once) and backfill in historical mode (PX3).
 */
const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);

const T = (n: number) => `55555555-0000-4000-8000-${n.toString().padStart(12, '0')}`;
const D = (n: number) => `sched-${n}.example`;

beforeAll(async () => {
  const now = clock.now();
  await w.start(
    {
      microsoft: [1, 2, 3, 4, 5, 6].map((n) => msDirectoryAs(now, T(n), D(n))),
      google: [gsCustomerAs(now, 'Cexample77', 'sched-gs.example')],
    },
    { ATO_IDP_CLAIM_BATCH: '3', ATO_PROVIDER_POLL_INTERVAL_SECONDS: '60' },
  );
});

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
});

async function bound(n: number, options: Parameters<IdpWorld['bind']>[1] = {}) {
  const org = await fx.organization(`s${n}`);
  await configure(w.h, org.id);
  const integration = await w.bind(
    w.connect(org.id, 'microsoft_entra', { tenantId: T(n), domain: D(n) }),
    options,
  );
  await w.probe();
  return { org, integration };
}

const streamsOf = (integrationId: bigint) =>
  fx.prisma.atoProviderStream.findMany({ where: { integrationId }, orderBy: { id: 'asc' } });

describe('claims, backoff, throttling and budgets (D7)', () => {
  it('two concurrent passes claim disjoint streams (SKIP LOCKED); companions are never claimed', async () => {
    const { integration } = await bound(1);
    await w.due(integration.id);
    // Claim batch 3, four due primaries: two passes in parallel never take the same row.
    await Promise.all([w.h.comps.streamRunner!.runOnce(), w.h.comps.streamRunner!.runOnce()]);
    await w.poll();
    const streams = await streamsOf(integration.id);
    for (const s of streams.filter((x) => x.role === 'primary')) {
      expect(s.pagesTotal).toBeGreaterThanOrEqual(1n);
      expect(s.lastSuccessAt).not.toBeNull();
    }
    for (const s of streams.filter((x) => x.role === 'companion')) {
      expect(s.lastAttemptAt).toBeNull();
      expect(s.pagesTotal).toBe(0n);
    }
    // Every sign-in of the directory was processed exactly once.
    const auth = await fx.prisma.atoAuthEvent.findMany({
      where: { organizationId: integration.organizationId, source: 'idp_sign_in' },
    });
    const keys = auth.map((a) => `${a.dedupeKey}|${a.occurredAt.toISOString()}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('failures back off per stream and probe the integration after three in a row', async () => {
    const { integration } = await bound(2);
    w.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 500,
      times: 1000,
    });
    for (let i = 1; i <= 3; i++) {
      await w.due(integration.id);
      await w.poll(3);
      const signIns = (await streamsOf(integration.id)).find((s) => s.stream === 'sign_ins')!;
      expect(signIns.consecutiveFailures).toBe(i);
      expect(signIns.lastErrorCode).toBe('provider_unavailable');
      expect(signIns.nextPollAt.getTime()).toBeGreaterThan(clock.now().getTime() + 60_000);
    }
    const row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration.id },
    });
    expect(row.consecutiveFailures).toBe(3);
    expect(row.nextHealthAt!.getTime()).toBeLessThanOrEqual(clock.now().getTime());
    w.sims.script.reset(w.sims.script.dataset);
  });

  it('provider throttling sets throttled_until from Retry-After, not a failure', async () => {
    const { integration } = await bound(3);
    w.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/identityProtection/riskDetections',
      status: 429,
      retryAfter: '120',
      times: 5,
    });
    await w.due(integration.id);
    await w.poll(3);
    const risk = (await streamsOf(integration.id)).find((s) => s.stream === 'risk_events')!;
    expect(risk.consecutiveFailures).toBe(0);
    expect(risk.throttledUntil!.getTime()).toBeGreaterThanOrEqual(clock.now().getTime() + 119_000);
    expect(risk.nextPollAt.getTime()).toBeGreaterThanOrEqual(clock.now().getTime() + 119_000);
    expect(
      await w.h.metric('ato_idp_throttled_total', { provider: 'microsoft_entra', family: 'graph' }),
    ).toBeGreaterThan(0);
    w.sims.script.reset(w.sims.script.dataset);
  });

  it('the Redis rate budget counts per integration, family and second (INCR + EXPIRE 5)', async () => {
    const budget = new RedisRateBudget(w.h.redis, {
      graph: 2,
      o365: 1,
      google_reports: 1,
      google_directory: 1,
      gmail: 1,
    });
    const id = '9000000000001';
    const signal = AbortSignal.timeout(5000);
    // Within one wall-clock second (retry at a second boundary).
    let results: string[] = [];
    for (let attempt = 0; attempt < 3; attempt++) {
      const second = Math.floor(Date.now() / 1000);
      results = [];
      for (let i = 0; i < 3; i++) results.push(await budget.take(id, 'graph', signal));
      if (Math.floor(Date.now() / 1000) === second) break;
    }
    expect(results).toEqual(['ok', 'ok', 'exhausted']);
    expect(await budget.take(id, 'gmail', signal)).toBe('ok');
    const keys = await w.h.redis.keys(`ato:idp:rb:${id}:graph:s*`);
    expect(keys.length).toBeGreaterThan(0);
    expect(await w.h.redis.ttl(keys[0]!)).toBeLessThanOrEqual(5);
    await expect(budget.take('not-a-number', 'graph', signal)).rejects.toThrow();
  });

  it('a malformed cursor restarts at now − overlap (counted), never at the epoch', async () => {
    const { integration } = await bound(4);
    await w.due(integration.id);
    await w.poll();
    await fx.prisma.atoProviderStream.updateMany({
      where: { integrationId: integration.id, stream: 'sign_ins' },
      data: { cursor: 'not-a-valid-cursor' },
    });
    const before = await w.h.metric('ato_idp_cursor_resets_total', { stream: 'sign_ins' });
    await w.due(integration.id);
    await w.poll();
    expect(await w.h.metric('ato_idp_cursor_resets_total', { stream: 'sign_ins' })).toBe(
      before + 1,
    );
    const signIns = (await streamsOf(integration.id)).find((s) => s.stream === 'sign_ins')!;
    expect(signIns.cursor).not.toBe('not-a-valid-cursor');
    expect(signIns.cursorSeq).toBeGreaterThan(1_000_000_000n);
    expect(signIns.watermarkAt!.getTime()).toBeGreaterThan(clock.now().getTime() - 30 * MIN);
  });
});

describe('idempotency and crash recovery (D7.1, D8.3)', () => {
  it('a crash in the middle of a page commits nothing; the retry has exactly one effect', async () => {
    const { org, integration } = await bound(5);
    const dir = w.sims.script.dataset.microsoft!.directories.find((d) => d.tenantId === T(5))!;
    const now = clock.now();
    for (let i = 0; i < 6; i++) {
      dir.signIns.push(
        msSignIn(now, {
          minutesAgo: 4,
          userId: MS_USERS.blake,
          userPrincipalName: `blake@${D(5)}`,
          ipAddress: MS_IPS.attacker,
          status: { errorCode: 50126 },
          deviceDetail: null,
        }),
      );
    }
    const pipeline = w.h.comps.pipeline;
    const original = pipeline.run.bind(pipeline);
    let calls = 0;
    pipeline.run = async (tx, req: DetectRequest, after) => {
      // The fourth of blake's sign-ins fails inside the page transaction.
      if (req.subject.kind === 'mailbox' && req.subject.address.startsWith('blake@')) {
        calls += 1;
        if (calls === 4) throw new Error('simulated crash');
      }
      return original(tx, req, after);
    };
    await w.due(integration.id);
    try {
      await w.poll(1);
    } finally {
      pipeline.run = original;
    }
    const signIns = (await streamsOf(integration.id)).find((s) => s.stream === 'sign_ins')!;
    expect(signIns.consecutiveFailures).toBe(1);
    expect(signIns.cursor).toBeNull();
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } })).toBe(0);
    await w.due(integration.id);
    await w.poll();
    const failures = await fx.prisma.atoAuthEvent.count({
      where: { organizationId: org.id, outcome: 'failure' },
    });
    expect(failures).toBe(7); // six injected + the dataset's own failure of blake
    await w.due(integration.id);
    clock.advance(MIN);
    await w.poll();
    expect(
      await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id, outcome: 'failure' } }),
    ).toBe(7);
  });

  it('snapshot state is cursor-confirmed: a crash before the commit re-emits the change once', async () => {
    const org = await fx.organization('ssnap');
    await configure(w.h, org.id);
    const integration = await w.bind(
      w.connect(org.id, 'google_workspace', { tenantId: 'Cexample77', domain: 'sched-gs.example' }),
    );
    await w.probe();
    await w.due(integration.id);
    await w.poll(); // initial sweep (historical)
    const customer = w.sims.script.dataset.google!.customers[0]!;
    customer.gmail[GS_USERS.alex]!.autoForwarding = {
      enabled: true,
      emailAddress: `x@${GS_EXTERNAL_DOMAIN}`,
      disposition: 'leaveInInbox',
    };
    await fx.prisma.atoAccountIdentity.updateMany({
      where: { organizationId: org.id },
      data: { mailboxRefreshRequestedAt: clock.now() },
    });
    const pipeline = w.h.comps.pipeline;
    const original = pipeline.run.bind(pipeline);
    pipeline.run = () => Promise.reject(new Error('simulated crash'));
    clock.advance(MIN);
    await w.due(integration.id);
    try {
      await w.poll(1);
    } finally {
      pipeline.run = original;
    }
    // The item row was written by the adapter, but its page was not committed.
    await w.due(integration.id);
    await w.poll();
    const alex = await accountOf(fx, org.id, 'mailbox', `alex@sched-gs.example`);
    const live = await fx.prisma.atoRiskSignal.findMany({
      where: {
        organizationId: org.id,
        accountId: alex!.id,
        ruleCode: 'ato.mailbox.external_forwarding',
        status: 'active',
      },
    });
    expect(live).toHaveLength(1);
    void GS_DOMAIN;
  });
});

describe('backfill in historical mode (D8.1, D8.2, PX3)', () => {
  it('7 days of history build auth events and day rows, signals informational, no incident; then live', async () => {
    const n = 6;
    const dir = w.sims.script.dataset.microsoft!.directories.find((d) => d.tenantId === T(n))!;
    const now = clock.now();
    // An impossible-travel pair three days ago and a high risk detection five days ago.
    const alex = `alex@${D(n)}`;
    dir.signIns.push(
      msSignIn(now, { minutesAgo: 3 * 1440, ipAddress: MS_IPS.office, userPrincipalName: alex }),
      msSignIn(now, {
        minutesAgo: 3 * 1440 - 20,
        ipAddress: MS_IPS.attacker,
        userPrincipalName: alex,
      }),
    );
    for (let i = 0; i < 12; i++) {
      dir.signIns.push(
        msSignIn(now, {
          minutesAgo: 4 * 1440 + i,
          userId: MS_USERS.blake,
          userPrincipalName: `blake@${D(n)}`,
          ipAddress: MS_IPS.attacker,
          status: { errorCode: 50126 },
          deviceDetail: null,
        }),
      );
    }
    dir.riskDetections.push(
      msRiskDetection(now, { minutesAgo: 5 * 1440, riskLevel: 'high', userPrincipalName: alex }),
    );
    const { org, integration } = await bound(n, { backfillDays: 7 });
    const backfilling = await streamsOf(integration.id);
    expect(backfilling.find((s) => s.stream === 'sign_ins')!.status).toBe('backfilling');
    await w.due(integration.id);
    await w.poll(200);
    const streams = await streamsOf(integration.id);
    const signIns = streams.find((s) => s.stream === 'sign_ins')!;
    expect(signIns.status).toBe('active');
    expect(signIns.backfillCompletedAt).not.toBeNull();
    expect(signIns.watermarkAt!.getTime()).toBeGreaterThan(clock.now().getTime() - 20 * MIN);
    // Every signal of the backfill (the brute force four days ago, the risk detection five days
    // ago, the default dataset's recent events excepted) is informational.
    const historical = await fx.prisma.atoRiskSignal.findMany({
      where: {
        organizationId: org.id,
        ruleCode: { in: ['ato.auth.bruteforce', 'ato.provider.risk_event'] },
        status: 'informational',
      },
    });
    expect(historical.map((s) => s.ruleCode)).toEqual(
      expect.arrayContaining(['ato.auth.bruteforce', 'ato.provider.risk_event']),
    );
    expect(historical.every((s) => s.weight === 0)).toBe(true);
    expect(
      await fx.prisma.atoRiskSignal.count({
        where: { organizationId: org.id, ruleCode: 'ato.auth.bruteforce', status: 'active' },
      }),
    ).toBe(0);
    expect(
      await fx.prisma.atoAuthEvent.count({
        where: { organizationId: org.id, occurredAt: { lt: new Date(now.getTime() - DAY) } },
      }),
    ).toBeGreaterThanOrEqual(14);
    expect(
      await fx.prisma.atoAccountActivityDaily.count({ where: { organizationId: org.id } }),
    ).toBeGreaterThan(1);
    // Live again: a fresh brute force is an active signal.
    for (let i = 0; i < 10; i++) {
      dir.signIns.push(
        msSignIn(clock.now(), {
          minutesAgo: 3,
          userId: MS_USERS.blake,
          userPrincipalName: `blake@${D(n)}`,
          ipAddress: MS_IPS.attacker,
          status: { errorCode: 50126 },
          deviceDetail: null,
        }),
      );
    }
    clock.advance(2 * MIN);
    await w.due(integration.id);
    await w.poll();
    const live = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, ruleCode: 'ato.auth.bruteforce', status: 'active' },
    });
    expect(live).toHaveLength(1);
  });
});

describe('ATO switched off (WP6)', () => {
  it('a stream and a probe of an organization whose ATO is off retry within a minute, reading nothing', async () => {
    const org = await fx.organization('s9');
    await configure(w.h, org.id);
    const integration = await w.bind(
      w.connect(org.id, 'microsoft_entra', { tenantId: T(7), domain: D(7) }),
    );
    await fx.prisma.organizationFeature.updateMany({
      where: { organizationId: org.id, featureKey: 'ato_detection' },
      data: { enabled: false },
    });
    w.h.comps.orgs.invalidate(org.id);
    await w.healthDue(integration.id);
    await w.due(integration.id);
    w.sims.script.clearCalls();
    await w.probe();
    await w.h.comps.streamRunner!.runOnce();
    const now = clock.now().getTime();
    const row = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration.id },
    });
    expect(row.healthCheckedAt).toBeNull();
    expect(row.nextHealthAt!.getTime() - now).toBeLessThanOrEqual(60_000);
    for (const s of (await streamsOf(integration.id)).filter((x) => x.role === 'primary')) {
      expect(s.lastSuccessAt).toBeNull();
      expect(s.nextPollAt.getTime() - now).toBeLessThanOrEqual(60_000);
    }
    expect(w.sims.script.calls()).toEqual([]);
    await fx.prisma.organizationFeature.updateMany({
      where: { organizationId: org.id, featureKey: 'ato_detection' },
      data: { enabled: true },
    });
    w.h.comps.orgs.invalidate(org.id);
  });
});
