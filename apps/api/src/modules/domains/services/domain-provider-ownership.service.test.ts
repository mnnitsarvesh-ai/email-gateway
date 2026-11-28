import { ConflictException } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
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
import { TooManyProviderChecksException } from '../domains.errors';

const scopeA = systemScope(ORG_A);
const scopeB = systemScope(ORG_B);
const CONNECTION = { id: 77n, publicId: '0192f3a0-3333-7000-8000-000000000003' };

async function create(bed: DomainTestbed, name: string, scope = scopeA) {
  return bed.service.create(
    userPrincipal(scope.organizationId),
    scope,
    { name, inboundEnabled: false },
    client,
  );
}

function bind(bed: DomainTestbed, organizationId = ORG_A) {
  bed.capableConnections.set(organizationId, [CONNECTION]);
  bed.store.providerConnections.set(organizationId, [CONNECTION]);
}

const request = (bed: DomainTestbed, domainId: string, body: unknown = {}, scope = scopeA) =>
  bed.providerOwnership.request(
    userPrincipal(scope.organizationId),
    scope,
    domainId,
    { idempotencyKey: 'key-provider-check-0001', body },
    client,
  );

/** The integration-worker's answer, written directly to the row (as in MySQL). */
function answer(
  bed: DomainTestbed,
  verificationId: string,
  result: 'verified' | 'unverified' | 'absent' | 'alias' | 'error',
  at = new Date(),
) {
  const p = bed.store.providerRows.get(BigInt(verificationId))!;
  p.providerResult = result;
  p.providerCheckedAt = at;
  if (result === 'error') p.providerErrorCode = 'http_503';
}

const codeOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof CodedHttpException) return e.code;
    if (e instanceof ConflictException) return 'conflict';
    throw e;
  }
};

afterEach(() => {
  vi.useRealTimers();
});

describe('DomainProviderOwnershipService (step API-4 B3)', () => {
  it('requests a pending provider row and reuses it; audit has the connection only', async () => {
    const bed = createDomainTestbed();
    bind(bed);
    const created = await create(bed, 'p.example.com');
    const first = await request(bed, created.id);
    expect(first.statusCode).toBe(202);
    expect(first.body).toMatchObject({
      status: 'pending',
      connectionId: CONNECTION.publicId,
      reused: false,
    });
    const domain = bed.store.domains[0]!;
    const rows = bed.store.verifications.filter((v) => v.method === 'provider_tenant');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ token: 'provider-tenant', status: 'pending' });
    // The TXT verification stays the current one.
    expect((await bed.repos.verifications.findCurrent(scopeA, domain.id))?.method).toBe('dns_txt');
    expect(bed.store.audits.at(-1)).toMatchObject({
      action: 'domain.provider_verification_requested',
      metadata: { connectionId: CONNECTION.publicId, name: 'p.example.com' },
    });
    const again = await request(bed, created.id, { connectionId: CONNECTION.publicId });
    expect(again.body).toMatchObject({ verificationId: first.body.verificationId, reused: true });
    expect(bed.store.verifications.filter((v) => v.method === 'provider_tenant')).toHaveLength(1);
  });

  it('refuses without a capable connection, an unknown connection and an owned domain', async () => {
    const bed = createDomainTestbed();
    const created = await create(bed, 'n.example.com');
    expect(await codeOf(request(bed, created.id))).toBe('domain_provider_connection_unavailable');
    bed.store.providerConnections.set(ORG_A, [CONNECTION]);
    expect(await codeOf(request(bed, created.id, { connectionId: CONNECTION.publicId }))).toBe(
      'domain_provider_connection_unavailable',
    );
    expect(
      await codeOf(
        request(bed, created.id, { connectionId: '0192f3a0-0000-7000-8000-000000000000' }),
      ),
    ).toBe('connection_not_found');
    bind(bed);
    bed.store.domains[0]!.status = 'active';
    expect(await codeOf(request(bed, created.id))).toBe('domain_not_pending');
  });

  it('a name owned by another organization is the existing 409', async () => {
    const bed = createDomainTestbed();
    bind(bed, ORG_B);
    bed.store.addDomain(ORG_A, 'owned.example.com', { status: 'active' });
    const b = await create(bed, 'owned.example.com', scopeB).catch(() => null);
    // Creation is already refused while A owns the name; a pending B row added directly is too.
    expect(b).toBeNull();
    const pendingB = bed.store.addDomain(ORG_B, 'owned.example.com');
    expect(await codeOf(request(bed, pendingB.publicId, {}, scopeB))).toBe('conflict');
  });

  it('restarts a failed domain first, exactly as verify does', async () => {
    const bed = createDomainTestbed();
    bind(bed);
    const created = await create(bed, 'f.example.com');
    bed.store.domains[0]!.status = 'failed';
    await request(bed, created.id);
    expect(bed.store.domains[0]!.status).toBe('pending_verification');
    expect(bed.store.audits.map((a) => a.action)).toEqual([
      'domain.created',
      'domain.verification_restarted',
      'domain.provider_verification_requested',
    ]);
  });

  it('limits checks per organization per hour (429 with the window)', async () => {
    const bed = createDomainTestbed({ DOMAIN_PROVIDER_CHECKS_PER_HOUR: '2' });
    bind(bed);
    const created = await create(bed, 'r.example.com');
    await request(bed, created.id);
    await request(bed, created.id);
    const error = await request(bed, created.id).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TooManyProviderChecksException);
    expect((error as TooManyProviderChecksException).retryAfterSeconds).toBeGreaterThan(0);
    expect(await bed.kv.exists(domainKvKeys.providerCheckCounter(ORG_A))).toBe(true);
  });

  it('the scheduler wins ownership through the provider (first to verify wins, system actor)', async () => {
    const bed = createDomainTestbed();
    bind(bed);
    const a = await create(bed, 'win.example.com');
    const b = await create(bed, 'win.example.com', scopeB);
    const { body } = await request(bed, a.id);
    answer(bed, body.verificationId, 'verified');
    const summary = await bed.scheduler.runOnce(new Date());
    expect(summary).toMatchObject({ providerVerified: 1 });
    const rowA = bed.store.domains.find((d) => d.publicId === a.id)!;
    expect(rowA).toMatchObject({ status: 'verified', ownershipMethod: 'provider_tenant' });
    expect(rowA.verifiedAt).not.toBeNull();
    const provider = bed.store.verifications.find((v) => v.method === 'provider_tenant')!;
    expect(provider.status).toBe('verified');
    const verified = bed.store.audits.find((x) => x.action === 'domain.verified')!;
    expect(verified.metadata).toMatchObject({
      method: 'provider_tenant',
      connectionId: CONNECTION.publicId,
      to: 'verified',
    });
    expect(bed.store.domains.find((d) => d.publicId === b.id)).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
    });
    expect(bed.store.outbox.map((e) => e.payload.status)).toContain('verified');
    // The detail view shows the method and the finished provider check.
    const detail = await bed.service.get(scopeA, a.id);
    expect(detail.ownership).toMatchObject({
      method: 'provider_tenant',
      providerCheck: { status: 'verified', result: 'verified', connectionId: CONNECTION.publicId },
      providerCheckAvailable: false,
    });
  });

  it('other results fail the row only (domain stays pending; TXT still works); expiry expires', async () => {
    const bed = createDomainTestbed();
    bind(bed);
    const created = await create(bed, 'nope.example.com');
    const { body } = await request(bed, created.id);
    answer(bed, body.verificationId, 'error');
    await bed.providerOwnership.applyDue(new Date());
    expect(bed.store.domains[0]!.status).toBe('pending_verification');
    const rows = () => bed.store.verifications.filter((v) => v.method === 'provider_tenant');
    expect(rows()[0]).toMatchObject({ status: 'failed', lastError: 'error:http_503' });
    const second = await request(bed, created.id);
    expect(second.body.reused).toBe(false);
    const later = new Date(Date.now() + 2 * 3_600_000);
    expect(await bed.providerOwnership.applyDue(later)).toMatchObject({ expired: 1 });
    expect(rows()[1]!.status).toBe('expired');
    expect(bed.store.domains[0]!.status).toBe('pending_verification');
  });

  it('a TXT win writes ownership_method dns_txt and fails a still-pending provider row', async () => {
    const bed = createDomainTestbed();
    bind(bed);
    const created = await create(bed, 'txt.example.com');
    const { body } = await request(bed, created.id);
    bed.script(() => 'valid');
    await bed.verification.verifyNow(userPrincipal(ORG_A), scopeA, created.id, client);
    expect(bed.store.domains[0]).toMatchObject({ status: 'verified', ownershipMethod: 'dns_txt' });
    expect(bed.store.audits.find((x) => x.action === 'domain.verified')?.metadata).toMatchObject({
      method: 'dns_txt',
    });
    answer(bed, body.verificationId, 'verified');
    await bed.providerOwnership.applyDue(new Date());
    expect(bed.store.verifications.find((v) => v.method === 'provider_tenant')).toMatchObject({
      status: 'failed',
      lastError: 'domain_not_pending',
    });
    expect(bed.store.domains[0]!.ownershipMethod).toBe('dns_txt');
  });
});
