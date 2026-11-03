import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  jsonCache,
  prismaService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { ConnectorResolver, ConnectorView } from '../connectors/connector-resolver.service';
import type { DomainPolicyService, DomainPolicyView } from '../tenancy/domain-policy.service';
import { SocketmapLookupService } from './socketmap-lookup.service';

const view = (name: string, overrides: Partial<DomainPolicyView> = {}): DomainPolicyView => ({
  domainId: 11n,
  domainPublicId: 'p',
  organizationId: 7n,
  name,
  inboundEnabled: true,
  outboundEnabled: true,
  recipientValidation: 'none',
  rejectUnknownRecipients: false,
  maxMessageSizeBytes: null,
  hasActiveDkimKey: true,
  ...overrides,
});

const connector: ConnectorView = {
  id: 1n,
  publicId: 'c',
  organizationId: 7n,
  authType: 'source_ip',
  requireTls: true,
  networks: [],
};

function harness(env: Record<string, string> = {}) {
  const views = new Map([
    ['tenant.test', view('tenant.test')],
    ['nomail.test', view('nomail.test', { inboundEnabled: false })],
  ]);
  const domains = {
    get: vi.fn((name: string) => Promise.resolve(views.get(name.toLowerCase()) ?? null)),
  };
  const connectors = {
    byClientAddress: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
    byCertificateFingerprint: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
  };
  const prisma = {
    domainMailServer: {
      findFirst: vi.fn(() =>
        Promise.resolve<{ host: string | null; port: number } | null>({
          host: 'MX.Tenant-Server.example.',
          port: 2525,
        }),
      ),
      findMany: vi.fn(() => Promise.resolve<{ tlsMode: string }[]>([])),
    },
  };
  const redis = new FakeRedis();
  const service = new SocketmapLookupService(
    prismaService(prisma),
    domains as unknown as DomainPolicyService,
    connectors as unknown as ConnectorResolver,
    jsonCache(redis),
    testConfig({
      GATEWAY_MX_HOSTS: '10:mx1.gateway.example,20:mx2.gateway.example',
      ...env,
    }),
    silentLogger(),
  );
  return { service, views, domains, connectors, prisma, redis };
}

describe('SocketmapLookupService', () => {
  it('relay_domain: OK active only for active inbound-enabled tenant domains', async () => {
    const h = harness();
    expect(await h.service.lookup('relay_domain', 'tenant.test')).toBe('OK active');
    expect(await h.service.lookup('relay_domain', 'TENANT.test')).toBe('OK active');
    expect(await h.service.lookup('relay_domain', 'nomail.test')).toBe('NOTFOUND ');
    expect(await h.service.lookup('relay_domain', 'unknown.test')).toBe('NOTFOUND ');
  });

  it.each(['.tenant.test', 'user@tenant.test', '*', ''])(
    'relay_domain: NOTFOUND for probed key %j without a lookup',
    async (key) => {
      const h = harness();
      expect(await h.service.lookup('relay_domain', key)).toBe('NOTFOUND ');
      expect(h.domains.get).not.toHaveBeenCalled();
    },
  );

  it.each(['.tenant.test', '*', '', '@tenant.test', 'a@b@tenant.test', 'user@.tenant.test'])(
    'transport: NOTFOUND for probed key %j without a lookup',
    async (key) => {
      const h = harness();
      expect(await h.service.lookup('transport', key)).toBe('NOTFOUND ');
      expect(h.domains.get).not.toHaveBeenCalled();
    },
  );

  it('transport: resolves the full recipient address Postfix sends (socketmap is not indexed)', async () => {
    const h = harness();
    expect(await h.service.lookup('transport', 'Inbox+tag@tenant.test')).toBe(
      'OK smtp:[mx.tenant-server.example]:2525',
    );
    expect(h.domains.get).toHaveBeenCalledWith('tenant.test');
    expect(await h.service.lookup('transport', 'someone@gmail.example')).toBe('NOTFOUND ');
  });

  it('transport: the highest-priority enabled inbound destination, normalized and cached', async () => {
    const h = harness();
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[mx.tenant-server.example]:2525',
    );
    expect(h.prisma.domainMailServer.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          domainId: 11n,
          role: 'inbound_destination',
          enabled: true,
          host: { not: null },
        },
        orderBy: [{ priority: 'asc' }, { id: 'asc' }],
      }),
    );
    await h.service.lookup('transport', 'tenant.test');
    expect(h.prisma.domainMailServer.findFirst).toHaveBeenCalledTimes(1);
    expect(h.redis.store.has('sa:route:tenant.test')).toBe(true);
  });

  it('transport: NOTFOUND for non-tenant domains (Postfix MX resolution)', async () => {
    const h = harness();
    expect(await h.service.lookup('transport', 'gmail.example')).toBe('NOTFOUND ');
  });

  it('transport: defers a tenant domain without a destination', async () => {
    const h = harness();
    h.prisma.domainMailServer.findFirst.mockResolvedValue(null);
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
  });

  it.each(['mx1.gateway.example', 'MX2.gateway.example.', 'mx.gateway.local', 'out.gateway.local'])(
    'transport: never routes to the gateway itself (%s)',
    async (host) => {
      const h = harness();
      h.prisma.domainMailServer.findFirst.mockResolvedValue({ host, port: 25 });
      expect(await h.service.lookup('transport', 'tenant.test')).toBe(
        'OK retry:4.4.1 Destination not configured',
      );
    },
  );

  it('transport: defers destinations that are not valid host names', async () => {
    const h = harness();
    h.prisma.domainMailServer.findFirst.mockResolvedValue({ host: 'bad host,x', port: 25 });
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
  });

  it('tls_policy: strictest mode of the destinations sharing [host]:port', async () => {
    const h = harness();
    h.prisma.domainMailServer.findMany.mockResolvedValue([
      { tlsMode: 'opportunistic' },
      { tlsMode: 'required' },
    ]);
    expect(await h.service.lookup('tls_policy', '[MX.tenant-server.example]:2525')).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          host: 'mx.tenant-server.example',
          port: 2525,
          domain: { status: 'active', organization: { status: 'active' } },
        }) as unknown,
      }),
    );
  });

  it.each([
    ['none', 'OK none'],
    ['opportunistic', 'OK may'],
    ['required', 'OK encrypt protocols=>=TLSv1.2'],
    ['verify', 'OK secure match=nexthop protocols=>=TLSv1.2'],
  ])('tls_policy: %s → %s', async (mode, answer) => {
    const h = harness();
    h.prisma.domainMailServer.findMany.mockResolvedValue([{ tlsMode: mode }]);
    expect(await h.service.lookup('tls_policy', '[mx.tenant-server.example]')).toBe(answer);
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ port: 25 }) as unknown }),
    );
  });

  it('tls_policy: NOTFOUND for bare domains and unknown destinations', async () => {
    const h = harness();
    expect(await h.service.lookup('tls_policy', 'remote.example')).toBe('NOTFOUND ');
    expect(await h.service.lookup('tls_policy', '[unknown.example]:25')).toBe('NOTFOUND ');
  });

  it('relay_client: OK OK only for full IPs of an active source_ip connector', async () => {
    const h = harness();
    h.connectors.byClientAddress.mockResolvedValue(connector);
    expect(await h.service.lookup('relay_client', '198.51.100.7')).toBe('OK OK');
    expect(await h.service.lookup('relay_client', '198.51.100')).toBe('NOTFOUND ');
    expect(h.connectors.byClientAddress).toHaveBeenCalledTimes(1);
    h.connectors.byClientAddress.mockResolvedValue(null);
    expect(await h.service.lookup('relay_client', '192.0.2.1')).toBe('NOTFOUND ');
  });

  it('relay_ccert: OK OK for an active certificate connector fingerprint', async () => {
    const h = harness();
    h.connectors.byCertificateFingerprint.mockResolvedValueOnce({
      ...connector,
      authType: 'client_certificate',
    });
    expect(await h.service.lookup('relay_ccert', 'AB:CD')).toBe('OK OK');
    expect(await h.service.lookup('relay_ccert', 'EF:01')).toBe('NOTFOUND ');
  });

  it('answers PERM for unknown maps and propagates lookup errors', async () => {
    const h = harness();
    expect(await h.service.lookup('virtual', 'x')).toBe('PERM Unknown map');
    h.domains.get.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.lookup('relay_domain', 'tenant.test')).rejects.toThrow('db down');
  });
});
