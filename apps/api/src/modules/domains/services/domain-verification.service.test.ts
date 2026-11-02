import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SYSTEM_ACTOR } from '../../../audit/audit.service';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import {
  client,
  createDomainTestbed,
  type DomainTestbed,
  ORG_A,
  ORG_B,
  userPrincipal,
} from '../../../../test/support/domains/domain-testbed';
import { domainKvKeys } from '../domains.constants';
import { TooManyVerificationsException } from '../domains.errors';

const scopeA = systemScope(ORG_A);
const scopeB = systemScope(ORG_B);

async function create(bed: DomainTestbed, name: string, scope = scopeA) {
  return bed.service.create(
    userPrincipal(scope.organizationId),
    scope,
    { name, inboundEnabled: true },
    client,
  );
}

const verify = (bed: DomainTestbed, id: string, scope = scopeA) =>
  bed.verification.verifyNow(userPrincipal(scope.organizationId), scope, id, client);

const everything = () => 'valid' as const;

afterEach(() => {
  vi.useRealTimers();
});

describe('DomainVerificationService.verifyNow', () => {
  it('records missing records and schedules the next attempt without a transition', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'm.example.com');
    const before = Date.now();
    const view = await verify(bed, created.id);
    expect(bed.check).toHaveBeenCalledWith(expect.anything(), { bypassCache: true });
    expect(view).toMatchObject({
      status: 'pending_verification',
      readyForActivation: false,
      checkFailures: 0,
      checks: { ownership: { status: 'missing', lastOutcome: 'missing' } },
    });
    const row = bed.store.domains[0]!;
    // attempt 1 → base × 2^1 = 2 minutes (no jitter in tests)
    expect(row.nextCheckAt!.getTime() - before).toBeGreaterThanOrEqual(119_000);
    expect(row.nextCheckAt!.getTime() - before).toBeLessThan(125_000);
    const verification = bed.store.verificationsOf(row.id)[0]!;
    expect(verification).toMatchObject({ attempts: 1, lastOutcome: 'missing' });
    expect(verification.nextCheckAt).toEqual(row.nextCheckAt);
    expect(bed.store.audits.map((a) => a.action)).toEqual(['domain.created']);
    expect(bed.store.outbox).toEqual([]);
    // The lock is released afterwards.
    expect(await bed.kv.exists(domainKvKeys.checkLock(row.id))).toBe(false);
  });

  it('verifies on a definitive ownership TXT and activates DKIM keys whose record is valid', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'v.example.com');
    bed.script(everything);
    const view = await verify(bed, created.id);
    expect(view).toMatchObject({
      status: 'verified',
      readyForActivation: true,
      mailFlowReady: false,
      checks: {
        ownership: { status: 'valid' },
        mx: {
          status: 'valid',
          observed: [
            { priority: 10, host: 'mx1.mail-gateway.test', pointsToGateway: true },
            { priority: 20, host: 'mx2.mail-gateway.test', pointsToGateway: true },
          ],
        },
        dkim: { status: 'valid', selectors: [expect.objectContaining({ keyStatus: 'active' })] },
      },
    });
    const actions = bed.store.audits.map((a) => a.action);
    expect(actions).toEqual(['domain.created', 'domain.verified', 'domain.dkim_key_activated']);
    expect(bed.store.outbox.map((e) => e.payload.status)).toEqual(['verified']);
    expect(bed.store.verificationsOf(bed.store.domains[0]!.id)[0]!.status).toBe('verified');
    // Re-running the same check is idempotent: no new audit rows or events.
    await verify(bed, created.id);
    expect(bed.store.audits).toHaveLength(3);
    expect(bed.store.outbox).toHaveLength(1);
  });

  it('first to verify wins: other organizations’ pending claims are superseded (system actor)', async () => {
    const bed = createDomainTestbed();
    const a = await create(bed, 'race.example.com', scopeA);
    const b = await create(bed, 'race.example.com', scopeB);
    bed.script(everything);
    await verify(bed, a.id, scopeA);

    const rowB = bed.store.domains.find((d) => d.publicId === b.id)!;
    expect(rowB).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
      nextCheckAt: null,
    });
    expect(bed.store.verificationsOf(rowB.id)[0]!.status).toBe('failed');
    const superseded = bed.store.audits.find((x) => x.action === 'domain.claim_superseded')!;
    expect(superseded).toMatchObject({
      organizationId: ORG_B,
      actor: SYSTEM_ACTOR,
      resourceId: b.id,
      metadata: {
        from: 'pending_verification',
        to: 'failed',
        reason: 'claimed_by_another_organization',
      },
    });
    expect(bed.store.outbox.map((e) => [e.organizationId, e.payload.status])).toEqual([
      [ORG_A, 'verified'],
      [ORG_B, 'failed'],
    ]);

    // The loser restarting verification fails again: the name is owned.
    const view = await verify(bed, b.id, scopeB);
    expect(view).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
    });
    expect(bed.store.audits.filter((x) => x.organizationId === ORG_B).map((x) => x.action)).toEqual(
      [
        'domain.created',
        'domain.claim_superseded',
        'domain.verification_restarted',
        'domain.claim_superseded',
      ],
    );
  });

  it('retries once on a concurrent winner (verified_name unique key) and lands in the lost branch', async () => {
    const bed = createDomainTestbed();
    const a = await create(bed, 'dup.example.com', scopeA);
    const rowA = bed.store.domains[0]!;
    bed.script(everything);
    let injected = false;
    bed.store.beforeDomainUpdate = (id, data) => {
      if (!injected && id === rowA.id && data.status === 'verified') {
        injected = true;
        bed.store.addDomain(ORG_B, 'dup.example.com', { status: 'verified' });
      }
    };
    const view = await verify(bed, a.id);
    expect(injected).toBe(true);
    expect(view).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
    });
    expect(bed.store.outbox.map((e) => e.payload.status)).toEqual(['failed']);
  });

  it('keeps status and record statuses on indeterminate results and backs off', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'i.example.com');
    bed.script(everything);
    await verify(bed, created.id);
    await bed.service.changeStatus(
      userPrincipal(),
      scopeA,
      created.id,
      { status: 'active' },
      client,
    );
    bed.script(() => 'indeterminate');
    const before = Date.now();
    const view = await verify(bed, created.id);
    expect(view).toMatchObject({
      status: 'active',
      mailFlowReady: true,
      checkFailures: 1,
      checks: {
        ownership: { status: 'valid', lastOutcome: 'indeterminate' },
        mx: { status: 'valid', lastOutcome: 'indeterminate' },
      },
    });
    const row = bed.store.domains[0]!;
    expect(row.nextCheckAt!.getTime() - before).toBeLessThan(65_000);
    const ownership = bed.store.recordsOf(row.id).find((r) => r.recordKey === 'verification')!;
    expect(ownership).toMatchObject({ status: 'valid', lastError: 'timeout: no answer' });
    await verify(bed, created.id);
    expect(bed.store.domain(row.id).checkFailures).toBe(2);
    // No audit rows or events for indeterminate checks.
    expect(bed.store.audits.map((a) => a.action)).not.toContain('domain.ownership_record_missing');
  });

  it('audits a disappearing ownership record of an owned domain without changing its status', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'o.example.com');
    bed.script(everything);
    await verify(bed, created.id);
    bed.script((key) => (key === 'verification' ? 'missing' : 'valid'));
    const view = await verify(bed, created.id);
    expect(view.status).toBe('verified');
    expect(bed.store.audits.at(-1)).toMatchObject({
      action: 'domain.ownership_record_missing',
      metadata: { recordPurpose: 'verification', outcome: 'missing' },
    });
    await verify(bed, created.id);
    expect(
      bed.store.audits.filter((a) => a.action === 'domain.ownership_record_missing'),
    ).toHaveLength(1);
  });

  it('limits manual verification to 6 per domain per minute (429 with Retry-After)', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'r.example.com');
    for (let i = 0; i < 6; i++) await verify(bed, created.id);
    const err = (await verify(bed, created.id).catch(
      (e: unknown) => e,
    )) as TooManyVerificationsException;
    expect(err).toBeInstanceOf(TooManyVerificationsException);
    expect(err.getStatus()).toBe(429);
    expect(err.retryAfterSeconds).toBeGreaterThan(0);
    expect(err.retryAfterSeconds).toBeLessThanOrEqual(60);
    expect(bed.check).toHaveBeenCalledTimes(6);
  });

  it('answers 409 while another check of the domain holds the lock', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'l.example.com');
    const row = bed.store.domains[0]!;
    await bed.kv.setIfAbsent(domainKvKeys.checkLock(row.id), 'someone', 120);
    await expect(verify(bed, created.id)).rejects.toThrow(
      new ConflictException('Verification already in progress'),
    );
    expect(bed.check).not.toHaveBeenCalled();
    // Not ours: the lock stays.
    expect(await bed.kv.get(domainKvKeys.checkLock(row.id))).toBe('someone');
  });

  it('fails closed with 503 when the key-value store is unavailable', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'k.example.com');
    bed.kv.failing = true;
    await expect(verify(bed, created.id)).rejects.toThrow(ServiceUnavailableException);
    expect(bed.check).not.toHaveBeenCalled();
  });

  it('releases the lock when the check throws', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'e.example.com');
    bed.check.mockRejectedValueOnce(new Error('boom'));
    await expect(verify(bed, created.id)).rejects.toThrow('boom');
    expect(await bed.kv.exists(domainKvKeys.checkLock(bed.store.domains[0]!.id))).toBe(false);
  });

  it('restarts a failed (expired) verification with the same token and a new expiry', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'x.example.com');
    const row = bed.store.domains[0]!;
    const first = bed.store.verificationsOf(row.id)[0]!;
    // Expire it through a check after the expiry.
    await bed.verification.applyReport(
      scopeA,
      row.id,
      {
        checkedAt: new Date(),
        records: [],
        mx: { observed: null, propagation: [] },
        spf: { lookupCount: 0, lookupCountExact: true, recommendedValue: '' },
        dmarc: { stage: 'missing', partial: false, recommendedValue: '', nextStep: '' },
        indeterminate: false,
      },
      { actor: SYSTEM_ACTOR, sourceIp: null, now: new Date(first.expiresAt.getTime() + 1) },
    );
    expect(bed.store.domain(row.id)).toMatchObject({
      status: 'failed',
      statusReason: 'verification_expired',
      nextCheckAt: null,
    });
    expect(first.status).toBe('expired');

    bed.script(() => 'missing');
    // The restart happens later than the creation (an in-memory run can share a millisecond).
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 60_000 });
    const view = await verify(bed, created.id).finally(() => vi.useRealTimers());
    expect(view.status).toBe('pending_verification');
    const rows = bed.store.verificationsOf(row.id);
    expect(rows).toHaveLength(2);
    expect(rows[1]!.token).toBe(first.token);
    expect(rows[1]!.expiresAt.getTime()).toBeGreaterThan(first.expiresAt.getTime());
    expect(bed.store.audits.map((a) => a.action)).toEqual([
      'domain.created',
      'domain.verification_expired',
      'domain.verification_restarted',
    ]);
    expect(bed.store.outbox.map((e) => [e.payload.previousStatus, e.payload.status])).toEqual([
      ['pending_verification', 'failed'],
      ['failed', 'pending_verification'],
    ]);
  });

  it('answers 404 for another tenant’s and deleted domains', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'n.example.com');
    await expect(verify(bed, created.id, scopeB)).rejects.toThrow(NotFoundException);
    await bed.service.remove(userPrincipal(), scopeA, created.id, client);
    await expect(verify(bed, created.id)).rejects.toThrow(NotFoundException);
    expect(bed.check).not.toHaveBeenCalled();
  });
});

describe('DomainVerificationService.applyReport', () => {
  it('skips deleted domains and domains that left the checked statuses', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'f.example.com', {
      status: 'failed',
      nextCheckAt: new Date(),
    });
    bed.script(everything);
    const result = await bed.verification.runCheck(scopeA, d.id, {
      bypassCache: false,
      actor: SYSTEM_ACTOR,
      sourceIp: null,
    });
    expect(result).toBe('skipped');
    expect(bed.check).not.toHaveBeenCalled();
    expect(bed.store.domain(d.id).nextCheckAt).toBeNull();
  });

  it('materializes a verification row for an owned domain created before this step', async () => {
    const bed = createDomainTestbed();
    const d = bed.store.addDomain(ORG_A, 'seeded.example.com', {
      status: 'active',
      verifiedAt: new Date('2026-01-01T00:00:00Z'),
    });
    bed.script(everything);
    const result = await bed.verification.runCheck(scopeA, d.id, {
      bypassCache: false,
      actor: SYSTEM_ACTOR,
      sourceIp: null,
    });
    expect(result).toBe('checked');
    expect(bed.store.verificationsOf(d.id)[0]).toMatchObject({
      status: 'verified',
      verifiedAt: new Date('2026-01-01T00:00:00Z'),
      attempts: 1,
    });
    expect(bed.store.domain(d.id).status).toBe('active');
    expect(bed.store.keysOf(d.id).map((k) => k.status)).toEqual(['active']);
  });
});
