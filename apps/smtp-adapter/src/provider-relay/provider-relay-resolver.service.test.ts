import type { PrismaService } from '@email-gateway/common';
import { egressRangesFromCidrs, ProviderEgressIndex } from '@email-gateway/mail-routing';
import { describe, expect, it, vi } from 'vitest';
import { FakeRedis, jsonCache } from '../../integration/in-session-support/fakes';
import type { DomainPolicyService, DomainPolicyView } from '../tenancy/domain-policy.service';
import type { EgressIndexService } from './egress-index.service';
import { EgressIndexUnavailableError } from './egress-index.service';
import { providerRelayCacheKey, ProviderRelayResolver } from './provider-relay-resolver.service';

const ORG = 7n;

function domainView(overrides: Partial<DomainPolicyView> = {}): DomainPolicyView {
  return {
    domainId: 100n,
    domainPublicId: '0190a0a0-0000-7000-8000-000000000000',
    organizationId: ORG,
    name: 'acme.test',
    inboundEnabled: true,
    outboundEnabled: true,
    recipientValidation: 'none',
    rejectUnknownRecipients: false,
    maxMessageSizeBytes: null,
    hasActiveDkimKey: true,
    ...overrides,
  };
}

interface LinkOverrides {
  provider?: string;
  status?: string;
  outboundMode?: string;
  organizationId?: bigint;
  organizationStatus?: string;
  connector?: null | Partial<{ authType: string; status: string; organizationId: bigint }>;
}

function link(overrides: LinkOverrides = {}) {
  return {
    connection: {
      id: 5n,
      publicId: '0190a0a0-0000-7000-8000-000000000c05',
      organizationId: overrides.organizationId ?? ORG,
      provider: overrides.provider ?? 'microsoft_365',
      status: overrides.status ?? 'active',
      outboundMode: overrides.outboundMode ?? 'active',
      externalTenantId: '11111111-2222-3333-4444-555555555555',
      organization: { status: overrides.organizationStatus ?? 'active' },
      smtpConnector:
        overrides.connector === null
          ? null
          : {
              id: 9n,
              publicId: '0190a0a0-0000-7000-8000-00000000beef',
              organizationId: ORG,
              authType: 'provider_relay',
              status: 'active',
              requireTls: true,
              ...overrides.connector,
            },
    },
  };
}

function harness(options: { enabled?: boolean; loaded?: boolean } = {}) {
  const redis = new FakeRedis();
  const index = ProviderEgressIndex.build([
    ...egressRangesFromCidrs('microsoft_365', ['40.92.0.0/15']),
    ...egressRangesFromCidrs('google_workspace', ['209.85.128.0/17']),
  ]);
  const egress = {
    current: () => {
      if (options.loaded === false) throw new EgressIndexUnavailableError();
      return index;
    },
  };
  const domains = {
    get: vi.fn((name: string) => Promise.resolve(name === 'acme.test' ? domainView() : null)),
  };
  const findUnique = vi.fn(() => Promise.resolve<unknown>(link()));
  const prisma = { providerConnectionDomain: { findUnique } };
  const resolver = new ProviderRelayResolver(
    prisma as unknown as PrismaService,
    jsonCache(redis),
    domains as unknown as DomainPolicyService,
    egress as unknown as EgressIndexService,
    { PROVIDER_RELAY_ENABLED: options.enabled ?? true },
  );
  return { resolver, redis, domains, findUnique };
}

const request = (overrides: Record<string, string> = {}) => ({
  client_address: '40.92.10.20',
  sender: 'alice@ACME.test',
  ...overrides,
});

describe('ProviderRelayResolver (D7.3)', () => {
  it('resolves a linked, active, outbound connection of the client provider', async () => {
    const { resolver, findUnique } = harness();
    const view = await resolver.resolve(request());
    expect(view).toEqual({
      id: 9n,
      publicId: '0190a0a0-0000-7000-8000-00000000beef',
      organizationId: ORG,
      authType: 'provider_relay',
      requireTls: true,
      networks: [],
      providerRelay: {
        provider: 'microsoft_365',
        connectionId: 5n,
        connectionPublicId: '0190a0a0-0000-7000-8000-000000000c05',
        outboundMode: 'active',
        tenantId: '11111111-2222-3333-4444-555555555555',
      },
    });
    expect(findUnique).toHaveBeenCalledWith(expect.objectContaining({ where: { domainId: 100n } }));
  });

  it('caches per (provider, domain) for 30 s, including misses', async () => {
    const { resolver, redis, findUnique } = harness();
    await resolver.resolve(request());
    await resolver.resolve(request({ sender: 'bob@acme.test' }));
    expect(findUnique).toHaveBeenCalledTimes(1);
    const key = providerRelayCacheKey('microsoft_365', 'acme.test');
    expect(key).toBe('sa:prelay:conn:microsoft_365:acme.test');
    expect(redis.ttlMs.get(key)).toBe(30_000);
    findUnique.mockResolvedValueOnce(null);
    redis.store.clear();
    expect(await resolver.resolve(request())).toBeNull();
    expect(await resolver.resolve(request())).toBeNull();
    expect(findUnique).toHaveBeenCalledTimes(2);
  });

  it.each<[string, Record<string, string>]>([
    ['a client outside every egress range', { client_address: '203.0.113.9' }],
    ['an unparsable client address', { client_address: 'unknown' }],
    ['a null sender', { sender: '' }],
    ['a sender without a domain', { sender: 'alice@' }],
    ['a sender domain that is not a tenant domain', { sender: 'alice@other.test' }],
    ['the other provider’s ranges', { client_address: '209.85.130.1' }],
  ])('returns null for %s', async (_, overrides) => {
    const { resolver } = harness();
    expect(await resolver.resolve(request(overrides))).toBeNull();
  });

  it.each<[string, LinkOverrides]>([
    ['a connection of another provider', { provider: 'google_workspace' }],
    ['a connection that is not active', { status: 'configuring' }],
    ['outbound mode off', { outboundMode: 'off' }],
    ['another organization', { organizationId: 8n }],
    ['a suspended organization', { organizationStatus: 'suspended' }],
    ['no relay connector', { connector: null }],
    ['a disabled relay connector', { connector: { status: 'disabled' } }],
    ['a connector of another type', { connector: { authType: 'source_ip' } }],
    ['a connector of another organization', { connector: { organizationId: 8n } }],
  ])('returns null for %s', async (_, overrides) => {
    const { resolver, findUnique } = harness();
    findUnique.mockResolvedValue(link(overrides));
    expect(await resolver.resolve(request())).toBeNull();
  });

  it('resolves probe_only and suspended (the policy answers them)', async () => {
    for (const outboundMode of ['probe_only', 'suspended']) {
      const { resolver, findUnique } = harness();
      findUnique.mockResolvedValue(link({ outboundMode }));
      expect((await resolver.resolve(request()))?.providerRelay.outboundMode).toBe(outboundMode);
    }
  });

  it('needs an outbound-enabled domain and no link resolves nothing', async () => {
    const { resolver, domains, findUnique } = harness();
    domains.get.mockResolvedValueOnce(domainView({ outboundEnabled: false }));
    expect(await resolver.resolve(request())).toBeNull();
    expect(findUnique).not.toHaveBeenCalled();
  });

  it('is disabled by PROVIDER_RELAY_ENABLED=false and fails closed before the first egress load', async () => {
    expect(await harness({ enabled: false }).resolver.resolve(request())).toBeNull();
    expect(harness({ enabled: false }).resolver.providersOf('40.92.10.20')).toEqual([]);
    await expect(harness({ loaded: false }).resolver.resolve(request())).rejects.toBeInstanceOf(
      EgressIndexUnavailableError,
    );
  });

  it('propagates database errors (the policy tempfails)', async () => {
    const { resolver, findUnique } = harness();
    findUnique.mockRejectedValue(new Error('db down'));
    await expect(resolver.resolve(request())).rejects.toThrow('db down');
  });
});
