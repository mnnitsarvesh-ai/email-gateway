import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  metricValue,
  newMetrics,
  prismaService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { type DkimProbeClient, DkimReadinessService } from './dkim-readiness.service';
import { SuppressionService } from './suppression.service';

describe('SuppressionService (D11 step 5)', () => {
  const now = new Date('2026-11-02T12:00:00Z');
  function harness(row: { expiresAt: Date | null } | null) {
    const findUnique = vi.fn(() => Promise.resolve(row));
    return {
      findUnique,
      service: new SuppressionService(prismaService({ deliverySuppression: { findUnique } })),
    };
  }

  it('point-queries (organization, lower-cased address)', async () => {
    const h = harness({ expiresAt: null });
    expect(await h.service.isSuppressed(7n, ' Bob@Example.COM ', now)).toBe(true);
    expect(h.findUnique).toHaveBeenCalledWith({
      where: { organizationId_address: { organizationId: 7n, address: 'bob@example.com' } },
      select: { expiresAt: true },
    });
  });

  it('honours expiry', async () => {
    expect(
      await harness({ expiresAt: new Date('2026-11-03T00:00:00Z') }).service.isSuppressed(
        7n,
        'a@b.test',
        now,
      ),
    ).toBe(true);
    expect(
      await harness({ expiresAt: new Date('2026-11-01T00:00:00Z') }).service.isSuppressed(
        7n,
        'a@b.test',
        now,
      ),
    ).toBe(false);
    expect(await harness(null).service.isSuppressed(7n, 'a@b.test', now)).toBe(false);
  });

  it('never queries impossible addresses and propagates database errors', async () => {
    const h = harness(null);
    expect(await h.service.isSuppressed(7n, `${'a'.repeat(320)}@b.test`, now)).toBe(false);
    expect(h.findUnique).not.toHaveBeenCalled();
    h.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.isSuppressed(7n, 'a@b.test', now)).rejects.toThrow('db down');
  });
});

const probe = (redis: FakeRedis) => redis as unknown as DkimProbeClient;

describe('DkimReadinessService (D11 reinject-outbound)', () => {
  function harness(url: string | undefined, client: DkimProbeClient) {
    const metrics = newMetrics();
    const factory = vi.fn(() => client);
    const service = new DkimReadinessService(
      testConfig(url ? { REDIS_DKIM_PROBE_URL: url } : {}),
      metrics,
      silentLogger(),
      factory,
    );
    return { service, metrics, factory };
  }

  it('is ready when dkim_selectors has the domain (HEXISTS)', async () => {
    const redis = new FakeRedis();
    redis.hashes.set('dkim_selectors', new Map([['tenant.test', 's2026']]));
    const h = harness('redis://dkim-probe:x@localhost:6391/0', probe(redis));
    expect(h.factory).toHaveBeenCalledWith('redis://dkim-probe:x@localhost:6391/0');
    expect(await h.service.isReady('tenant.test')).toBe(true);
    expect(await h.service.isReady('other.test')).toBe(false);
    await h.service.onModuleDestroy();
  });

  it('is never ready without REDIS_DKIM_PROBE_URL', async () => {
    const h = harness(undefined, probe(new FakeRedis()));
    expect(h.factory).not.toHaveBeenCalled();
    expect(await h.service.isReady('tenant.test')).toBe(false);
  });

  it('treats redis-dkim errors as not ready and counts them', async () => {
    const redis = new FakeRedis();
    redis.failing = true;
    const h = harness('redis://dkim-probe:x@localhost:6391/0', probe(redis));
    expect(await h.service.isReady('tenant.test')).toBe(false);
    expect(await metricValue(h.metrics, 'smtp_dkim_probe_errors_total')).toBe(1);
  });
});
