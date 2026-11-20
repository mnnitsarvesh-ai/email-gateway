import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import {
  counterDay,
  counterKey,
  INTAKE_COUNTER_FIELDS,
  JournalIntakeCountersService,
  parseBucket,
} from './journal-intake-counters.service';
import { JournalIntakeMetrics } from './journal-intake.metrics';
import {
  JournalIntakeSourceRepository,
  parseClientCertFingerprints,
  parseIntakeNetworks,
} from './source-snapshot';
import { metricValue, newMetrics, silentLogger } from '../../integration/in-session-support/fakes';
import type { RedisService } from '@email-gateway/common';

const HASH = 'a'.repeat(64);
const PREVIOUS = 'b'.repeat(64);

function prismaFake(overrides: { features?: unknown[]; limits?: unknown[]; source?: object } = {}) {
  return {
    journalIntakeSource: {
      findFirst: vi.fn(() =>
        Promise.resolve({
          id: 42n,
          publicId: '0190a0a0-0000-7000-8000-00000000a042',
          organizationId: 7n,
          kind: 'microsoft_365_journal',
          status: 'pending_verification',
          providerConnectionId: 9n,
          networks: null,
          requireTls: true,
          clientCertFingerprints: null,
          maxMessageBytes: 1000,
          addressHash: HASH,
          previousAddressHash: PREVIOUS,
          headerTokenHash: null,
          previousHeaderTokenHash: null,
          previousValidUntil: new Date('2026-11-27T00:00:00.000Z'),
          verifiedAt: null,
          organization: {
            status: 'active',
            plan: {
              defaultFeatures: { archiving: true, journal_intake: true },
              defaultLimits: {
                journal_intake_messages_per_minute: 6000,
                journal_intake_max_message_bytes: 52428800,
              },
            },
          },
          ...overrides.source,
        }),
      ),
    },
    organizationFeature: { findMany: vi.fn(() => Promise.resolve(overrides.features ?? [])) },
    organizationLimit: { findMany: vi.fn(() => Promise.resolve(overrides.limits ?? [])) },
    archiveSetting: { findUnique: vi.fn(() => Promise.resolve({ enabled: true })) },
    providerConnection: {
      findUnique: vi.fn(() =>
        Promise.resolve({
          id: 9n,
          publicId: '0190a0a0-0000-7000-8000-00000000c009',
          provider: 'microsoft_365',
          organizationId: 7n,
          status: 'active',
          externalTenantId: 'tid',
          activeTenantKey: 'microsoft_365:tid',
          domains: [{ domain: { name: 'Example.com' } }],
        }),
      ),
    },
    domain: {
      findMany: vi.fn(() => Promise.resolve([{ id: 100n, name: 'Example.com', status: 'active' }])),
    },
  };
}

describe('JournalIntakeSourceRepository.loadByAddressHash', () => {
  it('builds the snapshot with plan defaults for missing feature and limit rows', async () => {
    const prisma = prismaFake();
    const repository = new JournalIntakeSourceRepository(prisma as unknown as PrismaService);
    const snapshot = await repository.loadByAddressHash(HASH);
    expect(prisma.journalIntakeSource.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { OR: [{ addressHash: HASH }, { previousAddressHash: HASH }] },
      }),
    );
    expect(snapshot).toMatchObject({
      source: { id: '42', status: 'pending_verification', matchedPrevious: false, verified: false },
      organization: {
        active: true,
        archivingFeature: true,
        journalIntakeFeature: true,
        archivingEnabled: true,
        messagesPerMinute: 6000,
        maxMessageBytes: 52428800,
      },
      connection: { provider: 'microsoft_365', bound: true, linkedDomains: ['example.com'] },
      domains: [{ id: '100', name: 'example.com', status: 'active' }],
    });
  });

  it('organization rows override the plan; a previous-hash match is flagged', async () => {
    const prisma = prismaFake({
      features: [{ featureKey: 'journal_intake', enabled: false }],
      limits: [{ limitKey: 'journal_intake_messages_per_minute', limitValue: 10n }],
    });
    const snapshot = await new JournalIntakeSourceRepository(
      prisma as unknown as PrismaService,
    ).loadByAddressHash(PREVIOUS);
    expect(snapshot?.organization).toMatchObject({
      journalIntakeFeature: false,
      archivingFeature: true,
      messagesPerMinute: 10,
    });
    expect(snapshot?.source).toMatchObject({
      matchedPrevious: true,
      previousValidUntil: '2026-11-27T00:00:00.000Z',
    });
  });

  it('a plan without intake limits allows nothing; a malformed hash looks nothing up', async () => {
    const prisma = prismaFake({
      source: {
        organization: { status: 'suspended', plan: { defaultFeatures: {}, defaultLimits: {} } },
      },
    });
    const repository = new JournalIntakeSourceRepository(prisma as unknown as PrismaService);
    expect((await repository.loadByAddressHash(HASH))?.organization).toEqual({
      active: false,
      archivingFeature: false,
      journalIntakeFeature: false,
      archivingEnabled: true,
      messagesPerMinute: 0,
      maxMessageBytes: 0,
    });
    expect(await repository.loadByAddressHash('not-a-hash')).toBeNull();
  });
});

describe('stored source columns', () => {
  it('parses client certificate fingerprints (array, colons, case) and refuses junk', () => {
    const fp = 'ab'.repeat(32);
    expect(parseClientCertFingerprints(null)).toEqual({ list: [], invalid: false });
    expect(parseClientCertFingerprints([fp.toUpperCase().match(/../g)!.join(':'), fp])).toEqual({
      list: [fp],
      invalid: false,
    });
    expect(parseClientCertFingerprints({ fingerprints: [fp] })).toEqual({
      list: [fp],
      invalid: false,
    });
    expect(parseClientCertFingerprints(['md5:00'])).toEqual({ list: [], invalid: true });
    expect(parseClientCertFingerprints('x')).toEqual({ list: [], invalid: true });
    expect(parseClientCertFingerprints(['1', '2', '3', '4', '5'].map((d) => d.repeat(64)))).toEqual(
      { list: [], invalid: true },
    );
  });

  it('parses intake-networks/1', () => {
    expect(parseIntakeNetworks({ v: 1, cidrs: ['203.0.113.0/24'] })).toEqual({
      cidrs: ['203.0.113.0/24'],
      invalid: false,
    });
    expect(parseIntakeNetworks(null)).toEqual({ cidrs: [], invalid: false });
    expect(parseIntakeNetworks({ v: 1, cidrs: ['203.0.113.1/24'] })).toEqual({
      cidrs: [],
      invalid: true,
    });
  });
});

describe('journal intake counters (D2.8)', () => {
  it('keys per source and UTC day', () => {
    const at = new Date('2026-11-20T23:59:59.999Z');
    expect(counterDay(at)).toBe('20261120');
    expect(counterKey(42n, at)).toBe('sa:jintake:cnt:42:20261120');
  });

  it('parses a taken hash', () => {
    const bucket = parseBucket('sa:jintake:cnt:42:20261120', [
      'accepted',
      '3',
      'bytes',
      '900',
      'refused_network',
      '2',
      'last_accepted_at',
      String(Date.UTC(2026, 10, 20, 10)),
      'last_refused_at',
      String(Date.UTC(2026, 10, 20, 11)),
      'last_refusal_code',
      'refused_network',
      'failures',
      '1',
    ]);
    expect(bucket).toMatchObject({
      sourceId: 42n,
      day: new Date('2026-11-20T00:00:00.000Z'),
      lastAcceptedAt: new Date('2026-11-20T10:00:00.000Z'),
      lastRefusedAt: new Date('2026-11-20T11:00:00.000Z'),
      lastRefusalCode: 'refused_network',
      failures: 1,
    });
    expect(bucket?.counts).toEqual({
      ...Object.fromEntries(INTAKE_COUNTER_FIELDS.map((f) => [f, 0])),
      accepted: 3,
      bytes: 900,
      refused_network: 2,
    });
    expect(parseBucket('sa:jintake:cnt:42:20261120', [])).toBeNull();
    expect(parseBucket('other', ['accepted', '1'])).toBeNull();
  });

  it('recording never throws when Redis fails (counted)', async () => {
    const metrics = newMetrics();
    const redis = {
      client: {
        evalsha: () => Promise.reject(new Error('down')),
        eval: () => Promise.reject(new Error('down')),
      },
    };
    const service = new JournalIntakeCountersService(
      {} as PrismaService,
      redis as unknown as RedisService,
      new JournalIntakeMetrics(metrics),
      { JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: 30 },
      silentLogger(),
    );
    await service.recordNow(42n, { counts: { accepted: 1 } }, new Date());
    expect(await metricValue(metrics, 'journal_intake_counter_flush_errors_total')).toBe(1);
  });
});
