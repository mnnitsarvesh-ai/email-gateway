import type { PrismaService } from '@email-gateway/common';
import { parseEgressCidr } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { metricValue, newMetrics, silentLogger } from '../../integration/in-session-support/fakes';
import { EgressIndexService, EgressIndexUnavailableError } from './egress-index.service';
import { ProviderRelayMetrics } from './provider-relay.metrics';

const row = (provider: string, cidr: string) => {
  const parsed = parseEgressCidr(cidr);
  return {
    provider,
    ipVersion: parsed.ipVersion,
    rangeStart: parsed.rangeStart,
    rangeEnd: parsed.rangeEnd,
  };
};

const ip = (text: string) => ({
  version: 4 as const,
  bytes: Uint8Array.from(text.split('.').map(Number)),
});

function harness(
  extra: Record<string, string[]> = {},
  flags: { relay?: boolean; intakeDomain?: string } = {},
) {
  const metrics = newMetrics();
  const findMany = vi.fn(() =>
    Promise.resolve<unknown[]>([
      row('microsoft_365', '40.92.0.0/15'),
      row('google_workspace', '209.85.128.0/17'),
    ]),
  );
  const service = new EgressIndexService(
    { providerEgressRange: { findMany } } as unknown as PrismaService,
    new ProviderRelayMetrics(metrics),
    {
      PROVIDER_EGRESS_CACHE_SECONDS: 60,
      PROVIDER_EGRESS_EXTRA_RANGES: extra,
      PROVIDER_RELAY_ENABLED: flags.relay ?? true,
      JOURNAL_INTAKE_ENABLED: true,
      JOURNAL_INTAKE_DOMAIN: flags.intakeDomain,
    },
    silentLogger(),
  );
  return { service, metrics, findMany };
}

describe('EgressIndexService (D7.2)', () => {
  it('loads the active sets and the extra ranges, with gauges', async () => {
    const { service, metrics, findMany } = harness({ microsoft_365: ['172.31.250.70/32'] });
    expect(() => service.current()).toThrow(EgressIndexUnavailableError);
    await service.refresh();
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { set: { status: 'active' } } }),
    );
    expect(service.loaded).toBe(true);
    expect(service.current().providersFor(ip('40.93.1.1'))).toEqual(['microsoft_365']);
    expect(service.current().providersFor(ip('172.31.250.70'))).toEqual(['microsoft_365']);
    expect(service.current().providersFor(ip('209.85.200.1'))).toEqual(['google_workspace']);
    expect(
      await metricValue(metrics, 'smtp_provider_egress_ranges', { provider: 'microsoft_365' }),
    ).toBe(2);
    expect(
      await metricValue(metrics, 'smtp_provider_egress_ranges', { provider: 'google_workspace' }),
    ).toBe(1);
  });

  it('keeps the last loaded set when a refresh fails, and counts the error', async () => {
    const { service, metrics, findMany } = harness();
    await service.refresh();
    findMany.mockRejectedValueOnce(new Error('db down'));
    await service.refresh();
    expect(service.current().providersFor(ip('40.92.0.1'))).toEqual(['microsoft_365']);
    expect(await metricValue(metrics, 'smtp_provider_egress_load_errors_total')).toBe(1);
    // A malformed row is a load error too.
    findMany.mockResolvedValueOnce([
      {
        provider: 'microsoft_365',
        ipVersion: 5,
        rangeStart: Buffer.alloc(4),
        rangeEnd: Buffer.alloc(4),
      },
    ]);
    await service.refresh();
    expect(await metricValue(metrics, 'smtp_provider_egress_load_errors_total')).toBe(2);
    expect(service.current().count('microsoft_365')).toBe(1);
  });

  it('stays unavailable when the first load fails (fail closed)', async () => {
    const { service, findMany } = harness();
    findMany.mockRejectedValueOnce(new Error('db down'));
    await service.refresh();
    expect(service.loaded).toBe(false);
    expect(() => service.current()).toThrow(EgressIndexUnavailableError);
  });

  it('an empty active set means no provider relay', async () => {
    const { service, findMany } = harness();
    findMany.mockResolvedValueOnce([]);
    await service.refresh();
    expect(service.current().providersFor(ip('40.92.0.1'))).toEqual([]);
  });

  it('loads for journal intake with the relay off, and not at all without either (step 8.6)', async () => {
    const intake = harness({}, { relay: false, intakeDomain: 'journal.gateway.test' });
    expect(intake.service.needed).toBe(true);
    await intake.service.onModuleInit();
    intake.service.onModuleDestroy();
    expect(intake.service.loaded).toBe(true);
    const neither = harness({}, { relay: false });
    expect(neither.service.needed).toBe(false);
    await neither.service.onModuleInit();
    expect(neither.findMany).not.toHaveBeenCalled();
  });

  it('shares one load between concurrent refreshes', async () => {
    const { service, findMany } = harness();
    await Promise.all([service.refresh(), service.refresh()]);
    expect(findMany).toHaveBeenCalledTimes(1);
  });
});
