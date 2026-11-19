import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  metricValue,
  newMetrics,
  prismaService,
  redisService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { AtoRestrictionService, mailboxSha256, restrictionCacheKey } from './restriction.service';

const ORG = 7n;
const NOW = new Date('2026-11-18T10:00:00.000Z');
const LATER = new Date('2026-11-18T12:00:00.000Z');

interface Row {
  kind: string;
  scope: string;
  connectorId: bigint | null;
  mailboxSha256: string | null;
  ipVersion: number | null;
  rangeStart: Uint8Array | null;
  rangeEnd: Uint8Array | null;
  mode: string;
  expiresAt: Date;
}

const row = (overrides: Partial<Row>): Row => ({
  kind: 'send_block',
  scope: 'connector',
  connectorId: 12n,
  mailboxSha256: null,
  ipVersion: null,
  rangeStart: null,
  rangeEnd: null,
  mode: 'reject',
  expiresAt: LATER,
  ...overrides,
});

function harness(rows: Row[], env: Record<string, string> = {}) {
  const redis = new FakeRedis();
  const queryRaw = vi.fn((_: TemplateStringsArray, ...values: unknown[]) => {
    expect(values[0]).toBe(ORG);
    return Promise.resolve(rows);
  });
  const metrics = newMetrics();
  const service = new AtoRestrictionService(
    prismaService({ $queryRaw: queryRaw }),
    redisService(redis),
    metrics,
    testConfig(env),
    silentLogger(),
  );
  return { service, redis, queryRaw, metrics };
}

describe('AtoRestrictionService (step 8.4 D14)', () => {
  it('matches a send_block on the connector or the mailbox hash; other tenants and mailboxes pass', async () => {
    const h = harness([
      row({ scope: 'connector', connectorId: 12n, mode: 'defer' }),
      row({ scope: 'mailbox', connectorId: null, mailboxSha256: mailboxSha256('ceo@tenant.test') }),
    ]);
    expect(await h.service.sendBlock(ORG, 12n, 'someone@tenant.test', NOW)).toBe('defer');
    expect(await h.service.sendBlock(ORG, 13n, 'CEO@Tenant.test', NOW)).toBe('reject');
    expect(await h.service.sendBlock(ORG, 13n, 'other@tenant.test', NOW)).toBeNull();
    // Both match: reject wins.
    expect(await h.service.sendBlock(ORG, 12n, 'ceo@tenant.test', NOW)).toBe('reject');
    // Cached: one database read.
    expect(h.queryRaw).toHaveBeenCalledTimes(1);
    expect(h.redis.ttlMs.get(restrictionCacheKey(ORG))).toBe(15_000);
    expect(
      await metricValue(h.metrics, 'smtp_ato_restriction_lookups_total', { result: 'miss' }),
    ).toBe(1);
    expect(
      await metricValue(h.metrics, 'smtp_ato_restriction_lookups_total', { result: 'hit' }),
    ).toBe(3);
    expect(
      await metricValue(h.metrics, 'smtp_ato_restrictions_enforced_total', {
        kind: 'send_block',
        mode: 'reject',
      }),
    ).toBe(2);
  });

  it('equals the security-contracts mailbox hash (SHA-256 of the lower-cased address)', () => {
    // Reference value of `atoMailboxSha256('a@b.test')` (@email-gateway/security-contracts).
    const reference = 'd98fb7ed563d6a2727d2de61d3ec97dbdf76dbc88916a54cefb32e3f54d531fa';
    expect(mailboxSha256('a@b.test')).toBe(reference);
    expect(mailboxSha256('A@B.TEST')).toBe(reference);
  });

  it('ignores expired rows at read time (even while cached)', async () => {
    const h = harness([row({ expiresAt: new Date('2026-11-18T10:30:00.000Z') })]);
    expect(await h.service.sendBlock(ORG, 12n, 'a@tenant.test', NOW)).toBe('reject');
    expect(
      await h.service.sendBlock(ORG, 12n, 'a@tenant.test', new Date('2026-11-18T10:30:00.001Z')),
    ).toBeNull();
  });

  it('auth_block: connector scope and connector_ip ranges (IPv4 and IPv6)', async () => {
    const h = harness([
      row({ kind: 'auth_block', scope: 'connector', connectorId: 20n }),
      row({
        kind: 'auth_block',
        scope: 'connector_ip',
        connectorId: 21n,
        ipVersion: 4,
        rangeStart: Buffer.from([198, 51, 100, 0]),
        rangeEnd: Buffer.from([198, 51, 100, 255]),
      }),
      row({
        kind: 'auth_block',
        scope: 'connector_ip',
        connectorId: 22n,
        ipVersion: 6,
        rangeStart: Buffer.from('20010db8000000000000000000000000', 'hex'),
        rangeEnd: Buffer.from('20010db800000000ffffffffffffffff', 'hex'),
      }),
      // A send_block never blocks authentication.
      row({ kind: 'send_block', scope: 'connector', connectorId: 23n }),
    ]);
    expect(await h.service.authBlocked(ORG, 20n, '192.0.2.1', NOW)).toBe(true);
    expect(await h.service.authBlocked(ORG, 21n, '198.51.100.77', NOW)).toBe(true);
    expect(await h.service.authBlocked(ORG, 21n, '198.51.101.1', NOW)).toBe(false);
    expect(await h.service.authBlocked(ORG, 21n, '::ffff:198.51.100.7', NOW)).toBe(true);
    expect(await h.service.authBlocked(ORG, 22n, '2001:db8::1', NOW)).toBe(true);
    expect(await h.service.authBlocked(ORG, 22n, '2001:db8:1::1', NOW)).toBe(false);
    expect(await h.service.authBlocked(ORG, 22n, '', NOW)).toBe(false);
    expect(await h.service.authBlocked(ORG, 23n, '192.0.2.1', NOW)).toBe(false);
    expect(await h.service.authBlocked(ORG, 24n, '192.0.2.1', NOW)).toBe(false);
  });

  it('fails closed: Redis and database errors propagate', async () => {
    const h = harness([]);
    h.redis.failing = true;
    await expect(h.service.sendBlock(ORG, 1n, 'a@tenant.test', NOW)).rejects.toThrow('redis');
    await expect(h.service.authBlocked(ORG, 1n, '192.0.2.1', NOW)).rejects.toThrow('redis');
    h.redis.failing = false;
    h.queryRaw.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.sendBlock(ORG, 1n, 'a@tenant.test', NOW)).rejects.toThrow('db down');
    expect(
      await metricValue(h.metrics, 'smtp_ato_restriction_lookups_total', { result: 'error' }),
    ).toBe(3);
  });

  it('reloads after invalidation and on an unusable cache entry', async () => {
    const h = harness([]);
    expect(await h.service.sendBlock(ORG, 1n, 'a@tenant.test', NOW)).toBeNull();
    await h.service.invalidate(ORG);
    expect(h.redis.store.has(restrictionCacheKey(ORG))).toBe(false);
    await h.redis.set(restrictionCacheKey(ORG), '{"version":99}', 'EX', 15);
    expect(await h.service.sendBlock(ORG, 1n, 'a@tenant.test', NOW)).toBeNull();
    expect(h.queryRaw).toHaveBeenCalledTimes(2);
  });

  it('kill switch: SMTP_ATO_ENFORCEMENT_ENABLED=false never looks anything up', async () => {
    const h = harness([row({})], { SMTP_ATO_ENFORCEMENT_ENABLED: 'false' });
    h.redis.failing = true;
    expect(await h.service.sendBlock(ORG, 12n, 'a@tenant.test', NOW)).toBeNull();
    expect(await h.service.authBlocked(ORG, 12n, '192.0.2.1', NOW)).toBe(false);
    expect(h.queryRaw).not.toHaveBeenCalled();
  });
});
