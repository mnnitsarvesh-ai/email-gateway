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

/** The seeded presets as stored (`mail_destination_presets`). */
const PRESET_ROWS = [
  {
    provider: 'google_workspace',
    displayName: 'Google Workspace (Gmail)',
    hostPatterns: ['^(?:aspmx\\.l|alt[1-4]\\.aspmx\\.l)\\.google\\.com$'],
    hostHint: null,
    defaultServers: [{ host: 'aspmx.l.google.com', priority: 1 }],
    port: 25,
    tlsMode: 'verify',
    tlsVerifyNames: 'nexthop:mx.google.com:.aspmx.l.google.com',
    maxServers: 5,
    documentationUrl: null,
  },
];

function harness(env: Record<string, string> = {}, logger = silentLogger()) {
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
  /** Destination rows of tenant.test (domainId 11) in next-hop order. */
  let destinations: { host: string; port: number }[] = [
    { host: 'MX.Tenant-Server.example.', port: 2525 },
  ];
  /** TLS rows returned for any host lookup. */
  let tlsRows: {
    organizationId?: bigint;
    port: number;
    tlsMode: string;
    tlsVerifyNames: string | null;
    provider: string;
  }[] = [];
  const prisma = {
    domainMailServer: {
      findMany: vi.fn((args: { where: { domainId?: bigint; host?: string } }) =>
        Promise.resolve(
          args.where.domainId !== undefined
            ? destinations.map((d, i) => ({
                publicId: `p${i}`,
                priority: i,
                tlsMode: 'opportunistic',
                tlsVerifyNames: null,
                provider: 'custom',
                ...d,
              }))
            : tlsRows,
        ),
      ),
    },
    mailDestinationPreset: {
      findMany: vi.fn(() => Promise.resolve(PRESET_ROWS)),
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
    logger,
  );
  return {
    service,
    views,
    domains,
    connectors,
    prisma,
    redis,
    setDestinations: (rows: { host: string; port: number }[]) => {
      destinations = rows;
    },
    setTlsRows: (rows: typeof tlsRows) => {
      tlsRows = rows;
    },
  };
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

  it('transport: every enabled inbound destination as a next-hop list, normalized and cached', async () => {
    const h = harness();
    h.setDestinations([
      { host: 'Primary.Tenant.example', port: 25 },
      { host: 'backup.tenant.example.', port: 2525 },
      { host: '45.33.32.156', port: 25 },
    ]);
    expect(await h.service.lookup('transport', 'user@tenant.test')).toBe(
      'OK smtp:[primary.tenant.example]:25,[backup.tenant.example]:2525,[45.33.32.156]:25',
    );
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledWith(
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
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledTimes(1);
    expect(h.redis.store.has('sa:route:v2:tenant.test')).toBe(true);
    // A step 2.2 single-host entry under the old key is never read.
    expect(h.redis.store.has('sa:route:tenant.test')).toBe(false);
  });

  it('transport: ignores an unparseable cached entry and reloads', async () => {
    const h = harness();
    await h.redis.set('sa:route:v2:tenant.test', JSON.stringify({ host: 'old.example', port: 25 }));
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[mx.tenant-server.example]:2525',
    );
  });

  it('transport: skips invalid, private and internal hosts but keeps the valid ones', async () => {
    const h = harness();
    h.setDestinations([
      { host: '10.0.0.5', port: 25 },
      { host: '169.254.169.254', port: 25 },
      { host: 'mysql', port: 3306 },
      { host: 'smtp.corp.internal', port: 25 },
      { host: 'bad host,x', port: 25 },
      { host: 'ok.tenant.example', port: 0 },
      { host: 'ok.tenant.example', port: 25 },
      { host: 'OK.tenant.example', port: 25 },
    ]);
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[ok.tenant.example]:25',
    );
  });

  it('transport: private IP literals are allowed with ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS', async () => {
    const h = harness({ ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: 'true' });
    h.setDestinations([
      { host: '10.0.0.5', port: 25 },
      { host: '169.254.169.254', port: 25 },
    ]);
    expect(await h.service.lookup('transport', 'tenant.test')).toBe('OK smtp:[10.0.0.5]:25');
  });

  it('transport: refuses ROUTING_DENIED_DESTINATION_SUFFIXES', async () => {
    const h = harness({ ROUTING_DENIED_DESTINATION_SUFFIXES: 'example' });
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
  });

  it('transport: caps the list at ROUTING_MAX_DESTINATIONS_PER_DOMAIN', async () => {
    const h = harness({ ROUTING_MAX_DESTINATIONS_PER_DOMAIN: '2' });
    h.setDestinations([1, 2, 3].map((n) => ({ host: `mx${n}.tenant.example`, port: 25 })));
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[mx1.tenant.example]:25,[mx2.tenant.example]:25',
    );
  });

  it('transport: NOTFOUND for non-tenant domains (Postfix MX resolution)', async () => {
    const h = harness();
    expect(await h.service.lookup('transport', 'gmail.example')).toBe('NOTFOUND ');
  });

  it('transport: defers a tenant domain without a destination or without a valid one', async () => {
    const h = harness();
    h.setDestinations([]);
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
    const other = harness();
    other.setDestinations([{ host: '192.168.1.1', port: 25 }]);
    expect(await other.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
  });

  it.each([
    'mx1.gateway.example',
    'MX2.gateway.example.',
    'mx.gateway.local',
    'out.gateway.local',
    'bounces.gateway.internal',
    'x.bounces.gateway.internal',
  ])(
    'transport: never routes to the gateway itself, even next to a valid host (%s)',
    async (host) => {
      const h = harness();
      h.setDestinations([
        { host: 'ok.tenant.example', port: 25 },
        { host, port: 25 },
      ]);
      expect(await h.service.lookup('transport', 'tenant.test')).toBe(
        'OK retry:4.4.1 Destination not configured',
      );
    },
  );

  it('tls_policy: strictest mode of the destinations sharing [host]:port', async () => {
    const h = harness();
    h.setTlsRows([
      { port: 2525, tlsMode: 'opportunistic', tlsVerifyNames: null, provider: 'custom' },
      { port: 2525, tlsMode: 'required', tlsVerifyNames: null, provider: 'custom' },
      { port: 25, tlsMode: 'none', tlsVerifyNames: null, provider: 'custom' },
    ]);
    expect(await h.service.lookup('tls_policy', '[MX.tenant-server.example]:2525')).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    expect(await h.service.lookup('tls_policy', '[mx.tenant-server.example]:25')).toBe('OK none');
    expect(await h.service.lookup('tls_policy', '[mx.tenant-server.example]:587')).toBe(
      'NOTFOUND ',
    );
    // One query and one cache entry per host, for every port.
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledTimes(1);
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          host: 'mx.tenant-server.example',
          domain: { status: 'active', organization: { status: 'active' } },
        }) as unknown,
      }),
    );
    expect(h.redis.store.has('sa:tls:v2:mx.tenant-server.example')).toBe(true);
  });

  it.each([
    ['none', null, 'OK none'],
    ['opportunistic', null, 'OK may'],
    ['required', null, 'OK encrypt protocols=>=TLSv1.2'],
    ['verify', null, 'OK secure match=nexthop protocols=>=TLSv1.2'],
    [
      'verify',
      'nexthop:mx.google.com:.aspmx.l.google.com',
      'OK secure match=nexthop:mx.google.com:.aspmx.l.google.com protocols=>=TLSv1.2',
    ],
  ])('tls_policy: %s (%s) → %s', async (mode, names, answer) => {
    const h = harness();
    h.setTlsRows([{ port: 25, tlsMode: mode, tlsVerifyNames: names, provider: 'custom' }]);
    expect(await h.service.lookup('tls_policy', '[mx.tenant-server.example]')).toBe(answer);
  });

  it('tls_policy: disagreeing verify names → the preset names, else nexthop', async () => {
    const google = harness();
    google.setTlsRows([
      {
        port: 25,
        tlsMode: 'verify',
        tlsVerifyNames: 'mx.google.com',
        provider: 'google_workspace',
      },
      { port: 25, tlsMode: 'verify', tlsVerifyNames: null, provider: 'google_workspace' },
    ]);
    expect(await google.service.lookup('tls_policy', '[aspmx.l.google.com]:25')).toBe(
      'OK secure match=nexthop:mx.google.com:.aspmx.l.google.com protocols=>=TLSv1.2',
    );
    const mixed = harness();
    mixed.setTlsRows([
      { port: 25, tlsMode: 'verify', tlsVerifyNames: 'a.example', provider: 'custom' },
      { port: 25, tlsMode: 'verify', tlsVerifyNames: 'b.example', provider: 'custom' },
      { port: 25, tlsMode: 'required', tlsVerifyNames: 'c.example', provider: 'custom' },
    ]);
    expect(await mixed.service.lookup('tls_policy', '[shared.example]:25')).toBe(
      'OK secure match=nexthop protocols=>=TLSv1.2',
    );
  });

  it('tls_policy: rows of several organizations that disagree → strictest (never weaker), error logged', async () => {
    const logger = silentLogger();
    const child = { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() };
    vi.spyOn(logger, 'child').mockReturnValue(child as never);
    const h = harness({}, logger);
    h.setTlsRows([
      {
        organizationId: 1n,
        port: 25,
        tlsMode: 'opportunistic',
        tlsVerifyNames: null,
        provider: 'custom',
      },
      {
        organizationId: 2n,
        port: 25,
        tlsMode: 'required',
        tlsVerifyNames: null,
        provider: 'custom',
      },
    ]);
    expect(await h.service.lookup('tls_policy', '[shared.example]:25')).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    expect(child.error).toHaveBeenCalledWith(
      { host: 'shared.example', port: 25, organizations: ['1', '2'] },
      'destinations of several organizations disagree on the TLS policy of a shared next hop',
    );
    // Same policy across organizations: no error.
    child.error.mockClear();
    const agree = harness({}, logger);
    agree.setTlsRows([
      {
        organizationId: 1n,
        port: 25,
        tlsMode: 'required',
        tlsVerifyNames: null,
        provider: 'custom',
      },
      {
        organizationId: 2n,
        port: 25,
        tlsMode: 'required',
        tlsVerifyNames: null,
        provider: 'custom',
      },
    ]);
    await agree.service.lookup('tls_policy', '[shared.example]:25');
    expect(child.error).not.toHaveBeenCalled();
  });

  it('transport: a destination port outside ROUTING_ALLOWED_DESTINATION_PORTS is skipped', async () => {
    const h = harness();
    h.setDestinations([
      { host: 'evil.example.com', port: 10052 },
      { host: 'mx.tenant-server.example', port: 25 },
    ]);
    expect(await h.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[mx.tenant-server.example]:25',
    );
    const only = harness();
    only.setDestinations([{ host: 'mx.tenant-server.example', port: 8025 }]);
    expect(await only.service.lookup('transport', 'tenant.test')).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
    const allowed = harness({ ROUTING_ALLOWED_DESTINATION_PORTS: '25,8025' });
    allowed.setDestinations([{ host: 'mx.tenant-server.example', port: 8025 }]);
    expect(await allowed.service.lookup('transport', 'tenant.test')).toBe(
      'OK smtp:[mx.tenant-server.example]:8025',
    );
  });

  it('tls_policy: unsafe verify names written directly to the database fall back to nexthop', async () => {
    const h = harness();
    h.setTlsRows([
      { port: 25, tlsMode: 'verify', tlsVerifyNames: 'x protocols=SSLv3', provider: 'custom' },
    ]);
    expect(await h.service.lookup('tls_policy', '[mx.tenant-server.example]:25')).toBe(
      'OK secure match=nexthop protocols=>=TLSv1.2',
    );
  });

  it('tls_policy: IP literals (v4 and v6) are looked up in canonical form', async () => {
    const h = harness();
    h.setTlsRows([{ port: 25, tlsMode: 'required', tlsVerifyNames: null, provider: 'custom' }]);
    expect(await h.service.lookup('tls_policy', '[2001:DB8:0::1]:25')).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    expect(h.prisma.domainMailServer.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ host: '2001:db8::1' }) as unknown,
      }),
    );
  });

  it('tls_policy: NOTFOUND for bare domains and unknown destinations', async () => {
    const h = harness();
    expect(await h.service.lookup('tls_policy', 'remote.example')).toBe('NOTFOUND ');
    expect(await h.service.lookup('tls_policy', '[unknown.example]:25')).toBe('NOTFOUND ');
  });

  it('propagates database errors of the route and TLS loaders (TEMP)', async () => {
    const h = harness();
    h.prisma.domainMailServer.findMany.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.lookup('transport', 'tenant.test')).rejects.toThrow('db down');
    h.prisma.domainMailServer.findMany.mockRejectedValueOnce(new Error('db down'));
    await expect(h.service.lookup('tls_policy', '[x.example]:25')).rejects.toThrow('db down');
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
