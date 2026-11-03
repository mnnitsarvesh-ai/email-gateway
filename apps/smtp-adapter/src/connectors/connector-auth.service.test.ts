import { hash } from 'argon2';
import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  newMetrics,
  prismaService,
  redisService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import { argon2PasswordVerifier, ConnectorAuthService } from './connector-auth.service';

const SECRET = 'correct-horse-battery-staple';

async function harness(env: Record<string, string> = {}) {
  const secretHash = await hash(SECRET, { timeCost: 2, memoryCost: 4096, parallelism: 1 });
  const connector = {
    id: 5n,
    organizationId: 7n,
    authType: 'sasl',
    status: 'active',
    secretHash,
    updatedAt: new Date('2026-11-01T00:00:00Z'),
    organization: { status: 'active' },
  };
  const prisma = {
    smtpConnector: {
      findUnique: vi.fn(({ where }: { where: { saslUsername: string } }) =>
        Promise.resolve<Record<string, unknown> | null>(
          where.saslUsername === 'egc-abc' ? { ...connector } : null,
        ),
      ),
    },
  };
  const redis = new FakeRedis();
  const verify = vi.fn(argon2PasswordVerifier);
  const service = new ConnectorAuthService(
    prismaService(prisma),
    redisService(redis),
    new FixedWindowLimiter(redisService(redis), newMetrics()),
    testConfig({ SMTP_AUTH_MAX_FAILURES_PER_IP: '3', ...env }),
    silentLogger(),
    verify,
  );
  return { service, prisma, redis, verify, connector };
}

describe('ConnectorAuthService (D10)', () => {
  it('accepts the right secret (Argon2id) and caches the verification', async () => {
    const h = await harness();
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toEqual({
      result: 'ok',
      connectorId: 5n,
      organizationId: 7n,
    });
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toMatchObject({
      result: 'ok',
    });
    expect(h.verify).toHaveBeenCalledTimes(1);
    // Status is still read on every AUTH.
    expect(h.prisma.smtpConnector.findUnique).toHaveBeenCalledTimes(2);
  });

  it('re-verifies after the connector changes (updated_at is part of the cache key)', async () => {
    const h = await harness();
    await h.service.authenticate('egc-abc', SECRET, '192.0.2.1');
    h.prisma.smtpConnector.findUnique.mockResolvedValueOnce({
      ...h.connector,
      updatedAt: new Date('2026-11-02T00:00:00Z'),
    });
    await h.service.authenticate('egc-abc', SECRET, '192.0.2.1');
    expect(h.verify).toHaveBeenCalledTimes(2);
  });

  it('does not cache when SMTP_AUTH_VERIFY_CACHE_SECONDS=0', async () => {
    const h = await harness({ SMTP_AUTH_VERIFY_CACHE_SECONDS: '0' });
    await h.service.authenticate('egc-abc', SECRET, '192.0.2.1');
    await h.service.authenticate('egc-abc', SECRET, '192.0.2.1');
    expect(h.verify).toHaveBeenCalledTimes(2);
  });

  it('fails wrong secrets and unknown users, counting failures per IP', async () => {
    const h = await harness();
    expect(await h.service.authenticate('egc-abc', 'wrong', '192.0.2.1')).toEqual({
      result: 'fail',
    });
    expect(await h.service.authenticate('egc-nobody', SECRET, '192.0.2.1')).toEqual({
      result: 'fail',
    });
    expect(h.redis.store.get('sa:authfail:192.0.2.1')?.value).toBe('2');
    expect(h.redis.ttlMs.get('sa:authfail:192.0.2.1')).toBe(900_000);
  });

  it.each([
    ['disabled connector', { status: 'disabled' }],
    ['suspended organization', { organization: { status: 'suspended' } }],
    ['non-sasl connector', { authType: 'source_ip' }],
    ['connector without a hash', { secretHash: null }],
  ])('fails a %s even with the right secret', async (_, overrides) => {
    const h = await harness();
    h.prisma.smtpConnector.findUnique.mockResolvedValueOnce({ ...h.connector, ...overrides });
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toEqual({
      result: 'fail',
    });
  });

  it('throttles an IP after SMTP_AUTH_MAX_FAILURES_PER_IP failures, even with the right secret', async () => {
    const h = await harness();
    for (let i = 0; i < 3; i += 1) await h.service.authenticate('egc-abc', 'wrong', '192.0.2.9');
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.9')).toEqual({
      result: 'throttled',
    });
    // Other IPs are unaffected.
    expect((await h.service.authenticate('egc-abc', SECRET, '192.0.2.10')).result).toBe('ok');
  });

  it('answers temp on Redis or database failure and on an unverifiable hash', async () => {
    const h = await harness();
    h.redis.failing = true;
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toEqual({
      result: 'temp',
    });
    h.redis.failing = false;
    h.prisma.smtpConnector.findUnique.mockRejectedValueOnce(new Error('db down'));
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toEqual({
      result: 'temp',
    });
    h.prisma.smtpConnector.findUnique.mockResolvedValueOnce({
      ...h.connector,
      secretHash: 'not-a-phc-string',
    });
    expect(await h.service.authenticate('egc-abc', SECRET, '192.0.2.1')).toEqual({
      result: 'temp',
    });
  });
});
