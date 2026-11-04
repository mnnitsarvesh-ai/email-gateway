/**
 * Background verification and re-verification (step 2.1 D11, design §9 `domain-jobs`): the
 * scheduler's `runOnce(now)` against MySQL, Redis and an in-process `TestDnsServer`.
 *
 * Isolation: the job scans every tenant's due domains. Each test makes its own domains due at a
 * fixed tick time in the past (`TICK`, 2001-01-01) and calls `runOnce(TICK)`, so only domains
 * whose `next_check_at` was moved before that time are due — never another suite's or the
 * seeded demo domain. After each test the suite's domains are parked far in the future.
 *
 * Other schedulers: an api running elsewhere against the same MySQL and Redis (the `apps`
 * Compose profile) ticks with the real clock, for which every domain made due at `TICK` is due
 * too. The suite therefore holds the shared tick lock (`fenceSchedulers`) whenever its own
 * scheduler is not ticking, so such a replica's ticks return null instead of claiming the
 * suite's domains.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { domainKvKeys } from '../src/modules/domains/domains.constants';
import {
  DomainCheckScheduler,
  type DomainJobSummary,
} from '../src/modules/domains/services/domain-check-scheduler.service';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import {
  createDomainApp,
  DomainApi,
  type DomainBody,
  domainAudit,
  domainEvents,
  domainRow,
  GATEWAY_MX,
  jittered,
  publishFromApi,
  publishGatewaySpf,
  SCHEDULE,
  secondsAfter,
  uniqueDomainName,
  updateDomain,
} from './support/domains';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';

const TICK = new Date(Date.UTC(2001, 0, 1, 0, 0, 0));
const PARKED = new Date(Date.UTC(2100, 0, 1));
const at = (base: Date, seconds: number) => new Date(base.getTime() + seconds * 1000);

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let api: DomainApi;
const suiteOrgs: bigint[] = [];

async function adminApi(target: FixtureOrganization): Promise<DomainApi> {
  const user = await fx.createUser(target, { roles: ['organization_admin'] });
  return new DomainApi(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
}

/** A pending domain of `org`, due at `dueAt`. */
async function dueDomain(
  label: string,
  dueAt: Date = at(TICK, -1),
  client: DomainApi = api,
): Promise<DomainBody> {
  const domain = await client.okCreate(uniqueDomainName(label));
  await updateDomain(ctx, domain.id, { nextCheckAt: dueAt });
  return domain;
}

const FENCE_OWNER = 'domain-jobs-integration-fence';

/** Holds the tick lock for the suite, keeping every other replica's ticks out (see above). */
async function fenceSchedulers(): Promise<void> {
  await ctx.kv.set(domainKvKeys.tickLock, FENCE_OWNER, 300);
}

/** One scheduler tick at `now` on `app`: the fence is lifted just for this tick. */
async function tick(now: Date, app: IntegrationApp = ctx): Promise<DomainJobSummary> {
  await ctx.kv.del(domainKvKeys.tickLock);
  try {
    const summary = await app.get(DomainCheckScheduler).runOnce(now);
    if (!summary) throw new Error('the tick lock was not acquired');
    return summary;
  } finally {
    await fenceSchedulers();
  }
}

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ctx = await createDomainApp(dns);
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  suiteOrgs.push(org.id);
  await ctx.prisma.organizationLimit.update({
    where: { organizationId_limitKey: { organizationId: org.id, limitKey: 'max_domains' } },
    data: { limitValue: 1000n },
  });
  api = await adminApi(org);
  await fenceSchedulers();
});

afterEach(async () => {
  // Nothing this suite created may become due at a later test's tick time.
  await ctx.prisma.domain.updateMany({
    where: { organizationId: { in: suiteOrgs }, nextCheckAt: { not: null } },
    data: { nextCheckAt: PARKED },
  });
  await fenceSchedulers();
});

afterAll(async () => {
  await ctx?.kv.del(domainKvKeys.tickLock);
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('DomainCheckScheduler.runOnce', () => {
  it('is disabled on a timer in tests and checks only due domains', async () => {
    expect(ctx.get(DomainCheckScheduler).scheduled).toBe(false);
    const due = await dueDomain('due');
    const later = await dueDomain('later', at(TICK, 3600));

    const summary = await tick(TICK);
    expect(summary).toMatchObject({ due: 1, claimed: 1, checked: 1, errors: 0 });

    const checked = await domainRow(ctx, due.id);
    expect(checked.lastCheckedAt).toEqual(TICK);
    expect(checked.status).toBe('pending_verification');
    expect(checked.verifications[0]!.attempts).toBe(1);
    // Pending, first attempt: base × 2^1.
    const [low, high] = jittered(SCHEDULE.retryBase * 2);
    expect(secondsAfter(checked.nextCheckAt, TICK)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(checked.nextCheckAt, TICK)).toBeLessThanOrEqual(high);

    const untouched = await domainRow(ctx, later.id);
    expect(untouched.lastCheckedAt).toBeNull();
    expect(untouched.nextCheckAt).toEqual(at(TICK, 3600));
    expect(untouched.verifications[0]!.attempts).toBe(0);
  });

  it('backs off pending domains exponentially, and indeterminate checks from the base again', async () => {
    const domain = await dueDomain('backoff');
    let now = TICK;
    const delays: number[] = [];
    for (let i = 0; i < 3; i++) {
      await tick(now);
      const row = await domainRow(ctx, domain.id);
      delays.push(secondsAfter(row.nextCheckAt, now));
      now = row.nextCheckAt!;
    }
    [120, 240, 480].forEach((expected, i) => {
      const [low, high] = jittered(expected);
      expect(delays[i]).toBeGreaterThanOrEqual(low);
      expect(delays[i]).toBeLessThanOrEqual(high);
    });
    expect((await domainRow(ctx, domain.id)).verifications[0]!.attempts).toBe(3);

    // DNS failures: check_failures k → base × 2^(k−1), status untouched.
    dns.fail(domain.verification!.host, 'servfail');
    for (const [k, expected] of [
      [1, 60],
      [2, 120],
      [3, 240],
    ] as const) {
      const summary = await tick(now);
      expect(summary.indeterminate).toBe(1);
      const row = await domainRow(ctx, domain.id);
      expect(row).toMatchObject({ status: 'pending_verification', checkFailures: k });
      const [low, high] = jittered(expected);
      expect(secondsAfter(row.nextCheckAt, now)).toBeGreaterThanOrEqual(low);
      expect(secondsAfter(row.nextCheckAt, now)).toBeLessThanOrEqual(high);
      now = row.nextCheckAt!;
    }
    dns.clearFailure(domain.verification!.host);
    expect((await domainAudit(ctx, domain.id)).map((a) => a.action)).toEqual(['domain.created']);
    expect(await domainEvents(ctx, domain.id)).toHaveLength(0);
  });

  it('verifies due domains and never double-processes them across concurrent ticks and replicas', async () => {
    const domains: DomainBody[] = [];
    for (let i = 0; i < 6; i++) {
      const domain = await dueDomain(`par${i}`);
      await publishFromApi(api, dns, domain.id, ['verification']);
      domains.push(domain);
    }

    // Two replicas start a tick at the same time: the tick lock lets one through.
    const replica = await createDomainApp(dns);
    try {
      await ctx.kv.del(domainKvKeys.tickLock);
      const both = await Promise.all([
        ctx.get(DomainCheckScheduler).runOnce(TICK),
        replica.get(DomainCheckScheduler).runOnce(TICK),
      ]);
      expect(both.filter((s) => s === null)).toHaveLength(1);
      const winner = both.find((s) => s !== null)!;
      expect(winner).toMatchObject({ due: 6, claimed: 6, checked: 6, verified: 6 });
    } finally {
      await replica.close();
    }
    for (const domain of domains) {
      expect((await domainRow(ctx, domain.id)).status).toBe('verified');
      expect(await domainAudit(ctx, domain.id, 'domain.verified')).toHaveLength(1);
      const events = await domainEvents(ctx, domain.id);
      expect(events).toHaveLength(1);
      expect(events[0]!.correlationId).toMatch(/^domain-job:/);
      const audit = (await domainAudit(ctx, domain.id, 'domain.verified'))[0]!;
      expect(audit).toMatchObject({ actorType: 'system' });
    }
  });

  it('claims each due domain once even when two ticks overlap (expired tick lock)', async () => {
    const domains: DomainBody[] = [];
    for (let i = 0; i < 8; i++) {
      const domain = await dueDomain(`claim${i}`);
      await publishFromApi(api, dns, domain.id, ['verification']);
      domains.push(domain);
    }
    const replica = await createDomainApp(dns);
    try {
      // The replica's tick lock "expired" (a tick slower than the lock): both ticks run, and
      // the conditional claim plus the per-domain lock keep every domain to one check.
      const setIfAbsent = replica.kv.setIfAbsent.bind(replica.kv);
      vi.spyOn(replica.kv, 'setIfAbsent').mockImplementation((key, value, ttl) =>
        key === domainKvKeys.tickLock ? Promise.resolve(true) : setIfAbsent(key, value, ttl),
      );
      await ctx.kv.del(domainKvKeys.tickLock);
      const [first, second] = await Promise.all([
        ctx.get(DomainCheckScheduler).runOnce(TICK),
        replica.get(DomainCheckScheduler).runOnce(TICK),
      ]);
      expect(first).not.toBeNull();
      expect(second).not.toBeNull();
      expect(first!.claimed + second!.claimed).toBe(8);
      expect(first!.verified + second!.verified).toBe(8);
      expect(first!.errors + second!.errors).toBe(0);
    } finally {
      vi.restoreAllMocks();
      await replica.close();
    }
    for (const domain of domains) {
      const row = await domainRow(ctx, domain.id);
      expect(row.status).toBe('verified');
      expect(row.verifications[0]!.attempts).toBe(1);
      expect(await domainAudit(ctx, domain.id, 'domain.verified')).toHaveLength(1);
      expect(await domainEvents(ctx, domain.id)).toHaveLength(1);
    }
  });

  it('fails pending domains whose verification expired, even when DNS is failing', async () => {
    const expired = await dueDomain('expired');
    const flaky = await dueDomain('expired-flaky');
    for (const domain of [expired, flaky]) {
      const row = await domainRow(ctx, domain.id);
      await ctx.prisma.domainVerification.update({
        where: { id: row.verifications[0]!.id },
        data: { expiresAt: at(TICK, -60) },
      });
    }
    dns.fail(flaky.verification!.host, 'timeout');

    const summary = await tick(TICK);
    dns.clearFailure(flaky.verification!.host);
    expect(summary).toMatchObject({ claimed: 2, failed: 2 });

    for (const domain of [expired, flaky]) {
      const row = await domainRow(ctx, domain.id);
      expect(row).toMatchObject({
        status: 'failed',
        statusReason: 'verification_expired',
        nextCheckAt: null,
        statusChangedAt: TICK,
      });
      expect(row.verifications[0]!.status).toBe('expired');
      const audit = await domainAudit(ctx, domain.id, 'domain.verification_expired');
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actorType: 'system', organizationId: org.id });
      const events = await domainEvents(ctx, domain.id);
      expect(events.map((e) => e.payload)).toEqual([
        expect.objectContaining({
          previousStatus: 'pending_verification',
          status: 'failed',
          reason: 'verification_expired',
        }),
      ]);
    }

    // Failed domains are not due any more.
    expect((await tick(at(TICK, 3600))).due).toBe(0);
  });

  it('skips domains of organizations that are not active and reschedules them', async () => {
    const other = await fx.createOrganization();
    suiteOrgs.push(other.id);
    const otherApi = await adminApi(other);
    const domain = await dueDomain('suspended-org', at(TICK, -1), otherApi);
    await ctx.prisma.organization.update({
      where: { id: other.id },
      data: { status: 'suspended' },
    });

    const summary = await tick(TICK);
    expect(summary).toMatchObject({ due: 1, claimed: 0, checked: 0, skipped: 1 });
    const row = await domainRow(ctx, domain.id);
    expect(row.lastCheckedAt).toBeNull();
    expect(row.status).toBe('pending_verification');
    expect(row.nextCheckAt).toEqual(at(TICK, SCHEDULE.recheckInterval));
    expect(row.verifications[0]!.attempts).toBe(0);
  });

  it('returns null while another replica holds the tick lock', async () => {
    const domain = await dueDomain('locked');
    await ctx.kv.set(domainKvKeys.tickLock, 'another-replica', 30);
    expect(await ctx.get(DomainCheckScheduler).runOnce(TICK)).toBeNull();
    expect((await domainRow(ctx, domain.id)).lastCheckedAt).toBeNull();
    await fenceSchedulers();

    // A per-domain check lock (a manual verification running) skips that domain; the claim
    // keeps it away until the claim expires.
    const row = await domainRow(ctx, domain.id);
    await ctx.kv.set(domainKvKeys.checkLock(row.id), 'manual-verification', 30);
    const summary = await tick(TICK);
    await ctx.kv.del(domainKvKeys.checkLock(row.id));
    expect(summary).toMatchObject({ claimed: 1, checked: 0, skipped: 1 });
    const after = await domainRow(ctx, domain.id);
    expect(after.lastCheckedAt).toBeNull();
    expect(after.nextCheckAt).toEqual(at(TICK, 5 * 60));
  });

  it('materializes the configuration of an owned domain that has none (seeded / pre-2.1 row)', async () => {
    // The state the seed and the 20261102110046_domain_check_backfill migration leave: an active
    // domain with no verification row, no DKIM key and no record rows, due now.
    const name = uniqueDomainName('owned');
    const created = await ctx.prisma.domain.create({
      data: {
        organizationId: org.id,
        name,
        status: 'active',
        verifiedAt: at(TICK, -3600),
        activatedAt: at(TICK, -3600),
        statusChangedAt: at(TICK, -3600),
        nextCheckAt: at(TICK, -1),
      },
      select: { publicId: true },
    });

    const summary = await tick(TICK);
    expect(summary).toMatchObject({ checked: 1 });
    const row = await domainRow(ctx, created.publicId);
    expect(row).toMatchObject({ status: 'active', lastCheckedAt: TICK });
    expect(row.verifications).toHaveLength(1);
    expect(row.verifications[0]).toMatchObject({ status: 'verified' });
    expect(row.dkimKeys).toHaveLength(1);
    expect(row.dkimKeys[0]).toMatchObject({ algorithm: 'rsa_2048', status: 'pending' });
    expect(row.dkimKeys[0]!.privateKeyCiphertext).toMatch(/^v1\./);
    const selector = row.dkimKeys[0]!.selector;
    expect(row.dnsRecords.map((r) => r.recordKey).sort()).toEqual(
      [
        'verification',
        ...GATEWAY_MX.map((mx) => `mx:${mx.exchange}`),
        'spf',
        `dkim:${selector}`,
        'dmarc',
      ].sort(),
    );
    // Nothing published yet: incomplete configuration, rechecked on the D11 schedule.
    const [low, high] = jittered(SCHEDULE.recheckIncomplete);
    expect(secondsAfter(row.nextCheckAt, TICK)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(row.nextCheckAt, TICK)).toBeLessThanOrEqual(high);

    // The API now lists what to publish.
    const records = await api.dnsRecords(created.publicId).expect(200);
    expect((records.body as { records: unknown[] }).records).toHaveLength(row.dnsRecords.length);
  });

  it('rechecks healthy active domains daily; indeterminate checks never change their status', async () => {
    const domain = await api.okCreate(uniqueDomainName('healthy'));
    await publishFromApi(api, dns, domain.id);
    expect((await api.okVerify(domain.id)).status).toBe('verified');
    await api.setStatus(domain.id, { status: 'active' }).expect(200);
    await updateDomain(ctx, domain.id, { nextCheckAt: at(TICK, -1) });

    let summary = await tick(TICK);
    expect(summary).toMatchObject({ checked: 1, indeterminate: 0 });
    let row = await domainRow(ctx, domain.id);
    expect(row).toMatchObject({ status: 'active', checkFailures: 0, lastCheckedAt: TICK });
    expect(row.dnsRecords.every((r) => r.status === 'valid')).toBe(true);
    let [low, high] = jittered(SCHEDULE.recheckInterval);
    expect(secondsAfter(row.nextCheckAt, TICK)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(row.nextCheckAt, TICK)).toBeLessThanOrEqual(high);
    const auditBefore = (await domainAudit(ctx, domain.id)).length;
    const eventsBefore = (await domainEvents(ctx, domain.id)).length;

    // A DNS outage: every query of the domain fails.
    const hosts = [...new Set(row.dnsRecords.map((r) => r.host))];
    for (const host of hosts) dns.fail(host, 'servfail');
    const second = at(TICK, 60);
    await updateDomain(ctx, domain.id, { nextCheckAt: second });
    summary = await tick(second);
    for (const host of hosts) dns.clearFailure(host);
    expect(summary).toMatchObject({ checked: 1, indeterminate: 1 });
    row = await domainRow(ctx, domain.id);
    expect(row).toMatchObject({ status: 'active', checkFailures: 1, lastCheckedAt: second });
    for (const record of row.dnsRecords) {
      expect(record).toMatchObject({ status: 'valid', lastOutcome: 'indeterminate' });
      expect(record.lastError).toMatch(/^servfail: /);
    }
    [low, high] = jittered(SCHEDULE.retryBase);
    expect(secondsAfter(row.nextCheckAt, second)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(row.nextCheckAt, second)).toBeLessThanOrEqual(high);
    expect(await domainAudit(ctx, domain.id)).toHaveLength(auditBefore);
    expect(await domainEvents(ctx, domain.id)).toHaveLength(eventsBefore);

    // A configuration change is noticed: incomplete → rechecked sooner, still active.
    dns.remove(`_dmarc.${domain.name}`);
    const third = at(TICK, 120);
    await updateDomain(ctx, domain.id, { nextCheckAt: third });
    await tick(third);
    row = await domainRow(ctx, domain.id);
    expect(row).toMatchObject({ status: 'active', checkFailures: 0 });
    expect(row.dnsRecords.find((r) => r.recordKey === 'dmarc')!.status).toBe('missing');
    [low, high] = jittered(SCHEDULE.recheckIncomplete);
    expect(secondsAfter(row.nextCheckAt, third)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(row.nextCheckAt, third)).toBeLessThanOrEqual(high);
  });
});
