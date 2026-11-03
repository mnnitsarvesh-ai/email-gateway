import { describe, expect, it, vi } from 'vitest';
import { FakeRedis, jsonCache, prismaService } from '../../integration/in-session-support/fakes';
import { parseIpKey } from './addresses';
import { connectorAllowsIp, ConnectorResolver } from './connector-resolver.service';

const row = (overrides: Record<string, unknown> = {}) => ({
  id: 5n,
  publicId: '0190a0a0-0000-7000-8000-0000000000c5',
  organizationId: 7n,
  authType: 'sasl',
  status: 'active',
  requireTls: true,
  organization: { status: 'active' },
  ...overrides,
});

function harness() {
  const prisma = {
    smtpConnector: { findUnique: vi.fn(() => Promise.resolve<unknown>(null)) },
    $queryRaw: vi.fn(() => Promise.resolve<unknown[]>([])),
  };
  const redis = new FakeRedis();
  return {
    prisma,
    redis,
    resolver: new ConnectorResolver(prismaService(prisma), jsonCache(redis)),
  };
}

const fingerprint = 'ab'.repeat(32);

describe('ConnectorResolver (D11)', () => {
  it('resolves an active sasl connector by username and caches it for 30 s', async () => {
    const h = harness();
    h.prisma.smtpConnector.findUnique.mockResolvedValue(row());
    const first = await h.resolver.bySaslUsername('egc-abc');
    expect(first).toMatchObject({ id: 5n, organizationId: 7n, authType: 'sasl', networks: [] });
    await h.resolver.bySaslUsername('egc-abc');
    expect(h.prisma.smtpConnector.findUnique).toHaveBeenCalledTimes(1);
    expect(h.redis.ttlMs.get('sa:conn:sasl:egc-abc')).toBe(30_000);
    // The cached JSON never contains a secret hash.
    expect(h.redis.store.get('sa:conn:sasl:egc-abc')?.value).not.toContain('secret');
  });

  it.each([
    ['disabled connector', { status: 'disabled' }],
    ['suspended organization', { organization: { status: 'suspended' } }],
    ['other auth type', { authType: 'source_ip' }],
  ])('never resolves a %s', async (_, overrides) => {
    const h = harness();
    h.prisma.smtpConnector.findUnique.mockResolvedValue(row(overrides));
    expect(await h.resolver.bySaslUsername('egc-abc')).toBeNull();
  });

  it('refuses usernames that cannot exist without a query', async () => {
    const h = harness();
    expect(await h.resolver.bySaslUsername('a b')).toBeNull();
    expect(await h.resolver.bySaslUsername('x'.repeat(65))).toBeNull();
    expect(h.prisma.smtpConnector.findUnique).not.toHaveBeenCalled();
  });

  it('resolves a certificate connector by normalized fingerprint, with its networks', async () => {
    const h = harness();
    h.prisma.smtpConnector.findUnique.mockResolvedValue(
      row({
        authType: 'client_certificate',
        networks: [
          {
            ipVersion: 4,
            rangeStart: Buffer.from([10, 0, 0, 0]),
            rangeEnd: Buffer.from([10, 0, 0, 255]),
          },
        ],
      }),
    );
    const postfix = fingerprint.toUpperCase().match(/../g)!.join(':');
    const connector = await h.resolver.byCertificateFingerprint(postfix);
    expect(h.prisma.smtpConnector.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { certFingerprintSha256: fingerprint } }),
    );
    expect(connector?.networks).toEqual([
      { version: 4, start: Buffer.from([10, 0, 0, 0]), end: Buffer.from([10, 0, 0, 255]) },
    ]);
    expect(connectorAllowsIp(connector!, parseIpKey('10.0.0.7'))).toBe(true);
    expect(connectorAllowsIp(connector!, parseIpKey('10.0.1.7'))).toBe(false);
    expect(connectorAllowsIp(connector!, null)).toBe(false);
    // Served from the cache the second time (networks survive the JSON round trip).
    expect((await h.resolver.byCertificateFingerprint(fingerprint))?.networks).toEqual(
      connector?.networks,
    );
    expect(h.prisma.smtpConnector.findUnique).toHaveBeenCalledTimes(1);
  });

  it('resolves a source-IP connector through the range query', async () => {
    const h = harness();
    h.prisma.$queryRaw.mockResolvedValue([
      {
        rangeEnd: new Uint8Array([198, 51, 100, 255]),
        id: 9n,
        publicId: 'p',
        organizationId: 7n,
        authType: 'source_ip',
        status: 'active',
        requireTls: 0,
        organizationStatus: 'active',
      },
    ]);
    const connector = await h.resolver.byClientAddress(parseIpKey('198.51.100.20')!);
    expect(connector).toMatchObject({ id: 9n, authType: 'source_ip', requireTls: false });
    const [, version, start] = h.prisma.$queryRaw.mock.calls[0] as unknown as [
      unknown,
      number,
      Buffer,
    ];
    expect(version).toBe(4);
    expect(start).toEqual(Buffer.from([198, 51, 100, 20]));
  });

  it('refuses an IP past the closest range end, and non-source-IP or inactive matches', async () => {
    const h = harness();
    const match = {
      rangeEnd: new Uint8Array([198, 51, 100, 15]),
      id: 9n,
      publicId: 'p',
      organizationId: 7n,
      authType: 'source_ip',
      status: 'active',
      requireTls: 1,
      organizationStatus: 'active',
    };
    h.prisma.$queryRaw.mockResolvedValueOnce([match]);
    expect(await h.resolver.byClientAddress(parseIpKey('198.51.100.20')!)).toBeNull();
    h.prisma.$queryRaw.mockResolvedValueOnce([
      { ...match, rangeEnd: new Uint8Array([198, 51, 100, 255]), authType: 'client_certificate' },
    ]);
    expect(await h.resolver.byClientAddress(parseIpKey('198.51.100.21')!)).toBeNull();
    h.prisma.$queryRaw.mockResolvedValueOnce([
      { ...match, rangeEnd: new Uint8Array([198, 51, 100, 255]), organizationStatus: 'suspended' },
    ]);
    expect(await h.resolver.byClientAddress(parseIpKey('198.51.100.22')!)).toBeNull();
  });

  it('propagates database errors', async () => {
    const h = harness();
    h.prisma.$queryRaw.mockRejectedValue(new Error('db down'));
    await expect(h.resolver.byClientAddress(parseIpKey('192.0.2.1')!)).rejects.toThrow('db down');
  });
});
