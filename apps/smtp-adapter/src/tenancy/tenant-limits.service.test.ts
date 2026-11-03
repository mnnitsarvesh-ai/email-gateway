import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  jsonCache,
  metricValue,
  newMetrics,
  prismaService,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { TenantLimitsService } from './tenant-limits.service';

function harness(rows: { limitKey: string; limitValue: bigint }[]) {
  const prisma = { organizationLimit: { findMany: vi.fn(() => Promise.resolve(rows)) } };
  const redis = new FakeRedis();
  const metrics = newMetrics();
  const service = new TenantLimitsService(
    prismaService(prisma),
    jsonCache(redis, metrics),
    testConfig(),
  );
  return { prisma, redis, metrics, service };
}

describe('TenantLimitsService (D6)', () => {
  it('reads organization_limits rows and caches them for 60 s', async () => {
    const h = harness([
      { limitKey: 'inbound_recipients_per_minute', limitValue: 600n },
      { limitKey: 'outbound_recipients_per_minute', limitValue: 0n },
      { limitKey: 'outbound_recipients_per_day', limitValue: 2000n },
      { limitKey: 'max_message_size_bytes', limitValue: 26_214_400n },
    ]);
    const expected = {
      inboundRecipientsPerMinute: 600,
      outboundRecipientsPerMinute: 0,
      outboundRecipientsPerDay: 2000,
      maxMessageSizeBytes: 26_214_400,
    };
    expect(await h.service.get(7n)).toEqual(expected);
    expect(await h.service.get(7n)).toEqual(expected);
    expect(h.prisma.organizationLimit.findMany).toHaveBeenCalledTimes(1);
    expect(h.prisma.organizationLimit.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          organizationId: 7n,
          limitKey: {
            in: [
              'inbound_recipients_per_minute',
              'outbound_recipients_per_minute',
              'outbound_recipients_per_day',
              'max_message_size_bytes',
            ],
          },
        },
      }),
    );
    expect(h.redis.ttlMs.get('sa:lim:7')).toBe(60_000);
  });

  it('falls back to the SMTP_RATE_TENANT_* defaults for missing rows', async () => {
    const h = harness([]);
    expect(await h.service.get(7n)).toEqual({
      inboundRecipientsPerMinute: 6000,
      outboundRecipientsPerMinute: 600,
      outboundRecipientsPerDay: 100_000,
      maxMessageSizeBytes: null,
    });
  });

  it('uses the database when Redis is down (counted)', async () => {
    const h = harness([{ limitKey: 'inbound_recipients_per_minute', limitValue: 5n }]);
    h.redis.failing = true;
    expect((await h.service.get(7n)).inboundRecipientsPerMinute).toBe(5);
    expect(await metricValue(h.metrics, 'smtp_cache_errors_total', { cache: 'limits' })).toBe(2);
  });

  it('clamps values beyond 2^53', async () => {
    const h = harness([{ limitKey: 'outbound_recipients_per_day', limitValue: 2n ** 60n }]);
    expect((await h.service.get(7n)).outboundRecipientsPerDay).toBe(Number.MAX_SAFE_INTEGER);
  });
});
