/**
 * `POST /domains/{domainId}/ownership/provider-check` (step API-4 B3, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md §10.4) over HTTP with MySQL and Redis stubbed:
 * the domains module's repositories on `InMemoryDomainStore`, the provider rows and the
 * bound-connection reader in memory, the real services, the Idempotency-Key store in memory.
 * Success (202), 401, 403 (a read-only user), 404 for another organization's domain, the coded
 * 409s, Idempotency-Key replay, the per-organization 429 with `Retry-After`, and the `ownership`
 * block of the domain views. The scheduler's ownership win runs in the unit tests and in
 * integration/api-mode-onboarding.test.ts (real MySQL).
 */
// @covers post /api/v1/domains/:domainId/ownership/provider-check
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { DkimKeysRepository } from '../src/modules/domains/repositories/dkim-keys.repository';
import { DnsRecordsRepository } from '../src/modules/domains/repositories/dns-records.repository';
import { DomainJobsRepository } from '../src/modules/domains/repositories/domain-jobs.repository';
import { DomainOutboxRepository } from '../src/modules/domains/repositories/domain-outbox.repository';
import { DomainOwnershipRepository } from '../src/modules/domains/repositories/domain-ownership.repository';
import { DomainsRepository } from '../src/modules/domains/repositories/domains.repository';
import { MxObservationsRepository } from '../src/modules/domains/repositories/mx-observations.repository';
import { ProviderVerificationsRepository } from '../src/modules/domains/repositories/provider-verifications.repository';
import { VerificationsRepository } from '../src/modules/domains/repositories/verifications.repository';
import { BoundConnectionsReader } from '../src/modules/provider-connections/repositories/bound-connections.repository';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { InMemoryDomainStore } from './support/domains/in-memory-domain-store';

const CONNECTION = { id: 501n, publicId: '0192f3a0-3333-7000-8000-000000000003' };
const OTHER_ORG = 999n;

describe('POST /domains/{domainId}/ownership/provider-check (step API-4 B3, e2e)', () => {
  let api: StubbedApiApp;
  const domains = new InMemoryDomainStore();
  const store = new InMemoryIdempotencyStore();
  const capable = new Map<bigint, Array<{ id: bigint; publicId: string }>>();
  let org: bigint;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { DOMAIN_PROVIDER_CHECKS_PER_HOUR: '3' },
      {
        override: (b) =>
          store.override(
            b
              .overrideProvider(DomainsRepository)
              .useValue(domains.domainsRepository())
              .overrideProvider(VerificationsRepository)
              .useValue(domains.verificationsRepository())
              .overrideProvider(DnsRecordsRepository)
              .useValue(domains.dnsRecordsRepository())
              .overrideProvider(DkimKeysRepository)
              .useValue(domains.dkimKeysRepository())
              .overrideProvider(MxObservationsRepository)
              .useValue(domains.mxObservationsRepository())
              .overrideProvider(DomainOwnershipRepository)
              .useValue(domains.ownershipRepository())
              .overrideProvider(DomainOutboxRepository)
              .useValue(domains.outboxRepository())
              .overrideProvider(DomainJobsRepository)
              .useValue(domains.jobsRepository())
              .overrideProvider(ProviderVerificationsRepository)
              .useValue(domains.providerVerificationsRepository())
              .overrideProvider(BoundConnectionsReader)
              .useValue({
                ownershipCapableConnections: (scope: { organizationId: bigint }) =>
                  Promise.resolve(
                    (capable.get(scope.organizationId) ?? []).map((c) => ({
                      ...c,
                      provider: 'microsoft_365',
                      displayName: 'Contoso Microsoft 365',
                    })),
                  ),
              })
              .overrideProvider(AuditService)
              .useValue(domains.auditService()),
          ),
      },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    domains.domains = [];
    domains.verifications = [];
    domains.audits = [];
    domains.outbox = [];
    domains.providerRows.clear();
    domains.providerConnections.clear();
    capable.clear();
    store.rows.clear();
    api.kv.entries.clear();
    capable.set(org, [CONNECTION]);
    domains.providerConnections.set(org, [CONNECTION]);
  });

  const path = (id: string) => `/api/v1/domains/${id}/ownership/provider-check`;
  async function check(
    id: string,
    options: { perms?: string[] | null; key?: string | null; body?: object } = {},
  ) {
    const req = api.http().post(path(id));
    if (options.perms !== null) {
      req.set(
        await api.principals.user(options.perms ?? ['domain:manage', 'domain:read']).bearer(),
      );
    }
    if (options.key !== null) req.set('Idempotency-Key', options.key ?? randomUUID());
    return req.send(options.body ?? {});
  }
  const pending = () => domains.addDomain(org, `p-${randomUUID().slice(0, 8)}.example.com`);

  it('202 with the pending row; the detail and status views show the ownership block', async () => {
    const domain = pending();
    const res = await check(domain.publicId, { body: { connectionId: CONNECTION.publicId } });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({
      status: 'pending',
      connectionId: CONNECTION.publicId,
      reused: false,
    });
    expect(domains.audits.at(-1)).toMatchObject({
      action: 'domain.provider_verification_requested',
      metadata: { connectionId: CONNECTION.publicId },
    });
    const reader = await api.principals.user(['domain:read']).bearer();
    const detail = await api.http().get(`/api/v1/domains/${domain.publicId}`).set(reader);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.ownership).toMatchObject({
      method: null,
      providerCheck: { status: 'pending', result: null, connectionId: CONNECTION.publicId },
      providerCheckAvailable: true,
    });
    const status = await api.http().get(`/api/v1/domains/${domain.publicId}/status`).set(reader);
    expect(status.body.ownership.providerCheck.status).toBe('pending');
  });

  it('401 without credentials, 403 without domain:manage (a read-only user)', async () => {
    const domain = pending();
    expect((await check(domain.publicId, { perms: null })).status).toBe(401);
    const denied = await check(domain.publicId, { perms: ['domain:read'] });
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe('forbidden');
  });

  it('another organization’s domain and unknown ids are 404; a bad id is 400', async () => {
    const foreign = domains.addDomain(OTHER_ORG, 'foreign.example.com');
    expect((await check(foreign.publicId)).status).toBe(404);
    expect((await check(randomUUID())).status).toBe(404);
    expect((await check('not-a-uuid')).status).toBe(400);
  });

  it('the coded 409s and the unknown connection', async () => {
    const domain = pending();
    capable.clear();
    const none = await check(domain.publicId);
    expect(none.status).toBe(409);
    expect(none.body).toMatchObject({
      code: 'domain_provider_connection_unavailable',
      reason: 'none',
    });
    capable.set(org, [CONNECTION]);
    const unknown = await check(domain.publicId, { body: { connectionId: randomUUID() } });
    expect(unknown.status).toBe(404);
    expect(unknown.body.code).toBe('connection_not_found');
    const active = domains.addDomain(org, 'active.example.com', { status: 'active' });
    const notPending = await check(active.publicId);
    expect(notPending.status).toBe(409);
    expect(notPending.body).toMatchObject({ code: 'domain_not_pending', status: 'active' });
  });

  it('Idempotency-Key: required, replayed with the same response', async () => {
    const domain = pending();
    const noKey = await check(domain.publicId, { key: null });
    expect(noKey.status).toBe(400);
    expect(noKey.body.code).toBe('idempotency_key_required');
    const key = randomUUID();
    const first = await check(domain.publicId, { key });
    const replay = await check(domain.publicId, { key });
    expect(replay.status).toBe(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    expect(domains.verifications.filter((v) => v.method === 'provider_tenant')).toHaveLength(1);
    const strict = await check(domain.publicId, { body: { connectionId: 'x', extra: 1 } });
    expect(strict.status).toBe(400);
  });

  it('at most DOMAIN_PROVIDER_CHECKS_PER_HOUR per organization: 429 with Retry-After', async () => {
    const domain = pending();
    for (let i = 0; i < 3; i++) expect((await check(domain.publicId)).status).toBe(202);
    const limited = await check(domain.publicId);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });
});
