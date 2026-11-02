import { getCorrelationId } from '@email-gateway/logger';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createDomainTestbed,
  ORG_A,
  ORG_B,
  scriptedReport,
} from '../../../../test/support/domains/domain-testbed';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { CLAIM_SECONDS, domainKvKeys } from '../domains.constants';
import { forEachWithConcurrency } from './domain-check-scheduler.service';

const DAY = 86_400_000;

afterEach(() => {
  vi.restoreAllMocks();
});

function due(bed: ReturnType<typeof createDomainTestbed>, name: string, at: Date, org = ORG_A) {
  return bed.store.addDomain(org, name, { nextCheckAt: at });
}

describe('DomainCheckScheduler.runOnce (D11)', () => {
  it('checks due domains only and reschedules them', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    const a = due(bed, 'a.example.com', new Date(now.getTime() - 1000));
    const notYet = due(bed, 'b.example.com', new Date(now.getTime() + 60_000));
    bed.store.addDomain(ORG_A, 'failed.example.com', { status: 'failed' });

    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ due: 1, claimed: 1, checked: 1, errors: 0, skipped: 0 });
    expect(bed.check).toHaveBeenCalledTimes(1);
    expect(bed.check).toHaveBeenCalledWith(expect.objectContaining({ domain: 'a.example.com' }), {
      bypassCache: false,
    });
    // attempt 1 → 2 minutes after the tick time.
    expect(bed.store.domain(a.id).nextCheckAt).toEqual(new Date(now.getTime() + 120_000));
    expect(bed.store.domain(notYet.id).nextCheckAt).toEqual(new Date(now.getTime() + 60_000));
    // The per-domain lock is released.
    expect(await bed.kv.exists(domainKvKeys.checkLock(a.id))).toBe(false);
  });

  it('runs one tick per lock period across replicas', async () => {
    const bed = createDomainTestbed();
    expect(await bed.scheduler.runOnce()).not.toBeNull();
    expect(await bed.scheduler.runOnce()).toBeNull();
    expect(await bed.kv.ttl(domainKvKeys.tickLock)).toBeLessThanOrEqual(29);
  });

  it('skips the tick when the key-value store is unavailable', async () => {
    const bed = createDomainTestbed();
    due(bed, 'a.example.com', new Date(Date.now() - 1000));
    bed.kv.failing = true;
    expect(await bed.scheduler.runOnce()).toBeNull();
    expect(bed.check).not.toHaveBeenCalled();
  });

  it('claims each domain once even when two replicas read the same due row', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    const d = due(bed, 'a.example.com', new Date(now.getTime() - 1000));
    const jobs = bed.repos.jobs;
    const original = jobs.findDue.bind(jobs);
    // Another replica claims the row between our read and our claim.
    vi.spyOn(jobs, 'findDue').mockImplementation(async (at, limit) => {
      const rows = await original(at, limit);
      await jobs.claim(d.id, rows[0]!.nextCheckAt, new Date(now.getTime() + CLAIM_SECONDS * 1000));
      return rows;
    });
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ due: 1, claimed: 0, checked: 0 });
    expect(bed.check).not.toHaveBeenCalled();
  });

  it('skips a domain whose per-domain lock is held (manual verification running)', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    const d = due(bed, 'a.example.com', new Date(now.getTime() - 1000));
    await bed.kv.setIfAbsent(domainKvKeys.checkLock(d.id), 'manual', 120);
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ claimed: 1, checked: 0, skipped: 1 });
    // The claim keeps it away for 5 minutes, then it is retried.
    expect(bed.store.domain(d.id).nextCheckAt).toEqual(
      new Date(now.getTime() + CLAIM_SECONDS * 1000),
    );
  });

  it('postpones domains of organizations that are not active', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    bed.store.organizationStatus.set(ORG_B, 'suspended');
    const d = due(bed, 'b.example.com', new Date(now.getTime() - 1000), ORG_B);
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ due: 1, claimed: 0, skipped: 1 });
    expect(bed.check).not.toHaveBeenCalled();
    expect(bed.store.domain(d.id).nextCheckAt).toEqual(new Date(now.getTime() + DAY));
  });

  it('expires pending verifications after their expiry', async () => {
    const bed = createDomainTestbed();
    const d = due(bed, 'exp.example.com', new Date(Date.now() - 1000));
    await bed.configuration.ensure(systemScope(ORG_A), d.id);
    const expiresAt = bed.store.verificationsOf(d.id)[0]!.expiresAt;
    const summary = await bed.scheduler.runOnce(new Date(expiresAt.getTime() + 1000));
    expect(summary).toMatchObject({ checked: 1, failed: 1 });
    expect(bed.store.domain(d.id)).toMatchObject({
      status: 'failed',
      statusReason: 'verification_expired',
      nextCheckAt: null,
    });
    expect(bed.store.audits.at(-1)).toMatchObject({
      action: 'domain.verification_expired',
      actor: { type: 'system', id: null },
    });
    expect(bed.store.outbox).toHaveLength(1);
  });

  it('counts verified and indeterminate checks and tags writes with a job correlation id', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    const verified = due(bed, 'v.example.com', new Date(now.getTime() - 2000));
    due(bed, 'i.example.com', new Date(now.getTime() - 1000));
    const ids: Array<string | undefined> = [];
    bed.check.mockImplementation((input) => {
      ids.push(getCorrelationId());
      const outcome = input.domain === 'v.example.com' ? 'valid' : 'indeterminate';
      return Promise.resolve(scriptedReport(input, () => outcome, bed.gatewayHosts));
    });
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ checked: 2, verified: 1, indeterminate: 1 });
    expect(ids[0]).toMatch(/^domain-job:[0-9a-f-]{36}$/);
    expect(ids[1]).toBe(ids[0]);
    expect(bed.store.domain(verified.id).status).toBe('verified');
  });

  it('logs per-domain errors and keeps going', async () => {
    const bed = createDomainTestbed();
    const now = new Date();
    due(bed, 'a.example.com', new Date(now.getTime() - 2000));
    due(bed, 'b.example.com', new Date(now.getTime() - 1000));
    bed.check.mockRejectedValueOnce(new Error('resolver exploded'));
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ claimed: 2, checked: 1, errors: 1 });
  });

  it('retires rotating keys whose overlap ended', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'k.example.com', { status: 'active' });
    bed.store.addKey(d, 'old', { status: 'rotating', retireAfter: new Date(Date.now() - 1000) });
    const summary = await bed.scheduler.runOnce();
    expect(summary).toMatchObject({ retired: 1 });
    expect(bed.store.keysOf(d.id)[0]).toMatchObject({
      status: 'retired',
      privateKeyCiphertext: null,
    });
  });

  it('honours the check concurrency limit', async () => {
    const bed = createDomainTestbed({ DOMAIN_CHECK_CONCURRENCY: '2' });
    const now = new Date();
    for (let i = 0; i < 5; i++) due(bed, `c${i}.example.com`, new Date(now.getTime() - 1000 + i));
    let inFlight = 0;
    let max = 0;
    vi.spyOn(bed.verification, 'runCheck').mockImplementation(async () => {
      inFlight++;
      max = Math.max(max, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 20));
      inFlight--;
      return 'checked';
    });
    const summary = await bed.scheduler.runOnce(now);
    expect(summary).toMatchObject({ checked: 5 });
    expect(max).toBe(2);
  });
});

describe('DomainCheckScheduler timer', () => {
  it('stays off when DOMAIN_BACKGROUND_JOBS_ENABLED is false', async () => {
    const bed = createDomainTestbed();
    bed.scheduler.onApplicationBootstrap();
    expect(bed.scheduler.scheduled).toBe(false);
    await bed.scheduler.onModuleDestroy();
  });

  it('runs on an unref’ed interval when enabled and stops on shutdown', async () => {
    vi.useFakeTimers();
    try {
      const bed = createDomainTestbed({
        DOMAIN_BACKGROUND_JOBS_ENABLED: 'true',
        DOMAIN_JOBS_INTERVAL_SECONDS: '5',
      });
      const runOnce = vi.spyOn(bed.scheduler, 'runOnce').mockRejectedValue(new Error('down'));
      bed.scheduler.onApplicationBootstrap();
      expect(bed.scheduler.scheduled).toBe(true);
      await vi.advanceTimersByTimeAsync(5_000);
      expect(runOnce).toHaveBeenCalledTimes(1); // the rejection is logged, never thrown
      await bed.scheduler.onModuleDestroy();
      expect(bed.scheduler.scheduled).toBe(false);
      await vi.advanceTimersByTimeAsync(20_000);
      expect(runOnce).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('forEachWithConcurrency', () => {
  it('processes every item', async () => {
    const seen: number[] = [];
    await forEachWithConcurrency([1, 2, 3], 8, (n) => {
      seen.push(n);
      return Promise.resolve();
    });
    expect(seen.sort()).toEqual([1, 2, 3]);
    await forEachWithConcurrency([], 2, () => Promise.reject(new Error('never')));
  });
});
