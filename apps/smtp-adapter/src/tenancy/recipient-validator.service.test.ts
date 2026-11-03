import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  jsonCache,
  metricValue,
  newMetrics,
  prismaService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { DomainPolicyView } from './domain-policy.service';
import { normalizeLocalPart, RecipientValidator } from './recipient-validator.service';

const domain = (overrides: Partial<DomainPolicyView> = {}): DomainPolicyView => ({
  domainId: 11n,
  domainPublicId: '0190a0a0-0000-7000-8000-000000000011',
  organizationId: 7n,
  name: 'tenant.test',
  inboundEnabled: true,
  outboundEnabled: true,
  recipientValidation: 'list',
  rejectUnknownRecipients: true,
  maxMessageSizeBytes: null,
  hasActiveDkimKey: false,
  ...overrides,
});

function harness(listed: string[], env: Record<string, string> = {}) {
  const prisma = {
    domainRecipientAddress: {
      findUnique: vi.fn(({ where }: { where: { domainId_localPart: { localPart: string } } }) =>
        Promise.resolve(listed.includes(where.domainId_localPart.localPart) ? { id: 1n } : null),
      ),
    },
  };
  const redis = new FakeRedis();
  const metrics = newMetrics();
  const logger = silentLogger();
  // The validator logs through logger.child(); hand it the same instance so tests can spy.
  const child = vi.spyOn(logger, 'child').mockReturnValue(logger as never);
  const validator = new RecipientValidator(
    prismaService(prisma),
    jsonCache(redis, metrics),
    metrics,
    testConfig(env),
    logger,
  );
  child.mockRestore();
  return { prisma, redis, metrics, validator, logger };
}

describe('RecipientValidator (D3)', () => {
  it('accepts everything in accept-all mode without a lookup', async () => {
    const h = harness([]);
    expect(await h.validator.validate(domain({ recipientValidation: 'none' }), 'x')).toBe('accept');
    expect(h.prisma.domainRecipientAddress.findUnique).not.toHaveBeenCalled();
  });

  it('authoritative mode: listed → accept, unknown → reject (counted as enforced)', async () => {
    const h = harness(['alice']);
    expect(await h.validator.validate(domain(), 'Alice')).toBe('accept');
    expect(await h.validator.validate(domain(), 'mallory')).toBe('reject');
    expect(
      await metricValue(h.metrics, 'smtp_policy_recipient_unknown_total', { enforced: 'true' }),
    ).toBe(1);
  });

  it('monitor mode accepts unknown recipients and counts them as not enforced', async () => {
    const h = harness([]);
    expect(await h.validator.validate(domain({ rejectUnknownRecipients: false }), 'x')).toBe(
      'accept',
    );
    expect(
      await metricValue(h.metrics, 'smtp_policy_recipient_unknown_total', { enforced: 'false' }),
    ).toBe(1);
  });

  it('retries with the part before the first delimiter', async () => {
    const h = harness(['alice']);
    expect(await h.validator.validate(domain(), 'alice+news')).toBe('accept');
    expect(await h.validator.validate(domain(), 'alice+a+b')).toBe('accept');
    expect(await h.validator.validate(domain(), '+alice')).toBe('reject');
    const lookups = h.prisma.domainRecipientAddress.findUnique.mock.calls.map(
      ([arg]) => arg.where.domainId_localPart.localPart,
    );
    expect(lookups).toEqual(['alice+news', 'alice', 'alice+a+b', '+alice']);
  });

  it('supports several delimiter characters and an empty (disabled) delimiter', async () => {
    const multi = harness(['alice'], { SMTP_RECIPIENT_DELIMITER: '-+' });
    expect(await multi.validator.validate(domain(), 'alice-x+y')).toBe('accept');
    const none = harness(['alice'], { SMTP_RECIPIENT_DELIMITER: '' });
    expect(await none.validator.validate(domain(), 'alice+x')).toBe('reject');
  });

  it('caches per address (positive and negative TTL)', async () => {
    const h = harness(['alice']);
    await h.validator.validate(domain(), 'alice');
    await h.validator.validate(domain(), 'alice');
    await h.validator.validate(domain(), 'bob');
    await h.validator.validate(domain(), 'bob');
    expect(h.prisma.domainRecipientAddress.findUnique).toHaveBeenCalledTimes(2);
    expect(h.redis.ttlMs.get('sa:rcpt:11:alice')).toBe(60_000);
    expect(h.redis.ttlMs.get('sa:rcpt:11:bob')).toBe(30_000);
  });

  it('never queries local parts longer than 64 octets', async () => {
    const h = harness([]);
    expect(await h.validator.validate(domain(), 'x'.repeat(65))).toBe('reject');
    expect(h.prisma.domainRecipientAddress.findUnique).not.toHaveBeenCalled();
  });

  it('accepts unsupported modes, counts them and warns at most once a minute per domain', async () => {
    const h = harness([]);
    const warn = vi.spyOn(h.logger, 'warn');
    for (const mode of ['smtp_callout', 'ldap', 'ldap'] as const) {
      expect(await h.validator.validate(domain({ recipientValidation: mode }), 'x')).toBe('accept');
    }
    expect(await metricValue(h.metrics, 'smtp_policy_recipient_validation_unsupported_total')).toBe(
      3,
    );
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('propagates database errors', async () => {
    const h = harness([]);
    h.prisma.domainRecipientAddress.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(h.validator.validate(domain(), 'x')).rejects.toThrow('db down');
  });

  it('normalizes local parts to lower-case NFC', () => {
    expect(normalizeLocalPart('Amélie')).toBe('amélie');
  });
});
