import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  jsonCache,
  metricValue,
  newMetrics,
  prismaService,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { DomainPolicyService } from './domain-policy.service';

function harness() {
  const prisma = {
    domain: {
      findUnique: vi.fn(({ where }: { where: { verifiedName: string } }) =>
        Promise.resolve(
          where.verifiedName === 'tenant.test'
            ? {
                id: 11n,
                publicId: '0190a0a0-0000-7000-8000-000000000011',
                organizationId: 7n,
                name: 'tenant.test',
                status: 'active',
                inboundEnabled: true,
                outboundEnabled: false,
                organization: { status: 'active' },
              }
            : null,
        ),
      ),
    },
    domainSetting: {
      findUnique: vi.fn(() =>
        Promise.resolve({
          recipientValidation: 'list',
          rejectUnknownRecipients: true,
          maxMessageSizeBytes: 1234,
        }),
      ),
    },
    domainDkimKey: { findFirst: vi.fn(() => Promise.resolve({ id: 1n })) },
  };
  const redis = new FakeRedis();
  const metrics = newMetrics();
  const service = new DomainPolicyService(
    prismaService(prisma),
    jsonCache(redis, metrics),
    testConfig(),
  );
  return { prisma, redis, metrics, service };
}

const expected = {
  domainId: 11n,
  domainPublicId: '0190a0a0-0000-7000-8000-000000000011',
  organizationId: 7n,
  name: 'tenant.test',
  inboundEnabled: true,
  outboundEnabled: false,
  recipientValidation: 'list',
  rejectUnknownRecipients: true,
  maxMessageSizeBytes: 1234,
  hasActiveDkimKey: true,
};

describe('DomainPolicyService (D5)', () => {
  it('loads on a miss (three indexed queries) and caches the JSON view with the positive TTL', async () => {
    const h = harness();
    expect(await h.service.get('Tenant.TEST.')).toEqual(expected);
    expect(h.prisma.domain.findUnique).toHaveBeenCalledTimes(1);
    expect(h.prisma.domainSetting.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { domainId: 11n } }),
    );
    expect(h.prisma.domainDkimKey.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { domainId: 11n, status: 'active' } }),
    );
    const cached = JSON.parse(h.redis.store.get('sa:dom:tenant.test')!.value) as Record<
      string,
      unknown
    >;
    expect(cached.domainId).toBe('11');
    expect(h.redis.ttlMs.get('sa:dom:tenant.test')).toBe(60_000);
  });

  it('serves hits from Redis without touching the database', async () => {
    const h = harness();
    await h.service.get('tenant.test');
    expect(await h.service.get('tenant.test')).toEqual(expected);
    expect(h.prisma.domain.findUnique).toHaveBeenCalledTimes(1);
  });

  it('caches a negative result as null with the negative TTL', async () => {
    const h = harness();
    expect(await h.service.get('unknown.test')).toBeNull();
    expect(h.redis.store.get('sa:dom:unknown.test')?.value).toBe('null');
    expect(h.redis.ttlMs.get('sa:dom:unknown.test')).toBe(30_000);
    expect(await h.service.get('unknown.test')).toBeNull();
    expect(h.prisma.domain.findUnique).toHaveBeenCalledTimes(1);
  });

  it('defaults to accept-all without a settings row and reports a missing DKIM key', async () => {
    const h = harness();
    h.prisma.domainSetting.findUnique.mockResolvedValueOnce(null as never);
    h.prisma.domainDkimKey.findFirst.mockResolvedValueOnce(null as never);
    expect(await h.service.get('tenant.test')).toMatchObject({
      recipientValidation: 'none',
      rejectUnknownRecipients: false,
      maxMessageSizeBytes: null,
      hasActiveDkimKey: false,
    });
  });

  it('returns null for invalid names without a query', async () => {
    const h = harness();
    expect(await h.service.get('not a domain')).toBeNull();
    expect(await h.service.get('')).toBeNull();
    expect(h.prisma.domain.findUnique).not.toHaveBeenCalled();
  });

  it('falls back to the database when Redis fails and counts smtp_cache_errors_total', async () => {
    const h = harness();
    h.redis.failing = true;
    expect(await h.service.get('tenant.test')).toEqual(expected);
    // read + write both failed.
    expect(await metricValue(h.metrics, 'smtp_cache_errors_total', { cache: 'domain' })).toBe(2);
  });

  it('treats a corrupt cache entry as a miss', async () => {
    const h = harness();
    h.redis.store.set('sa:dom:tenant.test', { value: '{"domainId":true}' });
    expect(await h.service.get('tenant.test')).toEqual(expected);
    expect(await metricValue(h.metrics, 'smtp_cache_errors_total', { cache: 'domain' })).toBe(1);
  });

  it('propagates database errors (the caller fails closed)', async () => {
    const h = harness();
    h.prisma.domain.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.get('tenant.test')).rejects.toThrow('db down');
  });

  it('invalidates the view and the derived route key', async () => {
    const h = harness();
    await h.service.get('tenant.test');
    h.redis.store.set('sa:route:tenant.test', { value: 'null' });
    await h.service.invalidate('TENANT.test');
    expect(h.redis.store.has('sa:dom:tenant.test')).toBe(false);
    expect(h.redis.store.has('sa:route:tenant.test')).toBe(false);
  });
});
