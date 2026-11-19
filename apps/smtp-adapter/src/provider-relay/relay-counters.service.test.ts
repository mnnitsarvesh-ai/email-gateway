import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { metricValue, newMetrics, silentLogger } from '../../integration/in-session-support/fakes';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import { MAX_FLUSH_FAILURES, RelayCountersService, utcHour } from './relay-counters.service';

function harness() {
  const metrics = newMetrics();
  const statements: { sql: string; values: unknown[] }[] = [];
  const executeRaw = vi.fn((strings: TemplateStringsArray, ...values: unknown[]) => {
    statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
    return Promise.resolve(1);
  });
  const service = new RelayCountersService(
    { $executeRaw: executeRaw } as unknown as PrismaService,
    new ProviderRelayMetrics(metrics),
    { PROVIDER_RELAY_COUNTER_FLUSH_SECONDS: 30 },
    silentLogger(),
  );
  return { service, metrics, statements, executeRaw };
}

const AT = new Date('2026-11-18T10:42:13.123Z');

describe('RelayCountersService (D8.2)', () => {
  it('aggregates per connection and UTC hour and upserts additively', async () => {
    const { service, statements } = harness();
    service.record(7n, 5n, 'accepted', AT);
    service.record(7n, 5n, 'accepted', new Date(AT.getTime() + 1000));
    service.record(7n, 5n, 'proofFailed', AT);
    service.record(7n, 5n, 'probes', AT, 2);
    service.record(7n, 5n, 'probes', AT, 0);
    service.record(7n, 5n, 'tempFailed', new Date('2026-11-18T11:00:00.000Z'));
    expect(service.pending).toBe(2);
    await service.flush();
    expect(service.pending).toBe(0);
    const inserts = statements.filter((s) =>
      s.sql.startsWith('INSERT INTO provider_relay_counters'),
    );
    expect(inserts).toHaveLength(2);
    expect(inserts[0]!.sql).toContain('ON DUPLICATE KEY UPDATE accepted = accepted + ?');
    expect(inserts[0]!.values.slice(0, 7)).toEqual([7n, 5n, utcHour(AT), 2, 1, 0, 2]);
    expect(inserts[1]!.values.slice(0, 7)).toEqual([
      7n,
      5n,
      new Date('2026-11-18T11:00:00.000Z'),
      0,
      0,
      1,
      0,
    ]);
    const update = statements.find((s) => s.sql.startsWith('UPDATE provider_connections'));
    expect(update!.sql).toContain('SET last_relay_accepted_at = ?');
    expect(update!.sql).not.toContain('row_version');
    expect(update!.values[0]).toEqual(new Date(AT.getTime() + 1000));
  });

  it('retries a failed bucket and drops it after three failures', async () => {
    const { service, metrics, executeRaw } = harness();
    executeRaw.mockRejectedValue(new Error('db down'));
    service.record(7n, 5n, 'accepted', AT);
    for (let i = 1; i < MAX_FLUSH_FAILURES; i++) {
      await service.flush();
      expect(service.pending).toBe(1);
    }
    await service.flush();
    expect(service.pending).toBe(0);
    expect(await metricValue(metrics, 'smtp_provider_relay_counter_flush_errors_total')).toBe(3);
  });

  it('merges counts recorded while a flush failed', async () => {
    const { service, statements, executeRaw } = harness();
    executeRaw.mockRejectedValueOnce(new Error('db down'));
    service.record(7n, 5n, 'proofFailed', AT);
    await service.flush();
    service.record(7n, 5n, 'proofFailed', AT);
    await service.flush();
    const insert = statements.find((s) => s.sql.startsWith('INSERT'));
    expect(insert!.values[4]).toBe(2);
  });

  it('a failed last-accepted update never re-adds written counts', async () => {
    const { service, statements, executeRaw } = harness();
    executeRaw
      .mockImplementationOnce((strings: TemplateStringsArray, ...values: unknown[]) => {
        statements.push({ sql: strings.join('?'), values });
        return Promise.resolve(1);
      })
      .mockRejectedValueOnce(new Error('lock wait timeout'));
    service.record(7n, 5n, 'accepted', AT);
    await service.flush();
    expect(service.pending).toBe(0);
  });

  it('computes UTC hours', () => {
    expect(utcHour(AT).toISOString()).toBe('2026-11-18T10:00:00.000Z');
  });
});
