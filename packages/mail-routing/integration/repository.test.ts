import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  loadActiveSuppressions,
  loadDestinationPresets,
  loadDomainViews,
  loadInboundDestinations,
  matchesProviderHost,
  planRecipientRoutes,
  recipientDomain,
  validateDestinationHost,
} from '../src';
import { Fixtures } from './support/fixtures';

const fx = new Fixtures();
const prisma = fx.prisma;
let orgA: bigint;
let orgB: bigint;
let orgSuspended: bigint;
const names = {
  active: fx.name('active'),
  second: fx.name('second'),
  suspendedDomain: fx.name('susp-domain'),
  suspendedOrg: fx.name('susp-org'),
  pending: fx.name('pending'),
  other: fx.name('other'),
};
const domainIds: Record<string, bigint> = {};

beforeAll(async () => {
  orgA = await fx.organization('a');
  orgB = await fx.organization('b');
  orgSuspended = await fx.organization('s', 'suspended');
  domainIds.active = (await fx.domain(orgA, names.active)).id;
  domainIds.second = (await fx.domain(orgA, names.second)).id;
  domainIds.suspendedDomain = (await fx.domain(orgA, names.suspendedDomain, 'suspended')).id;
  domainIds.suspendedOrg = (await fx.domain(orgSuspended, names.suspendedOrg)).id;
  domainIds.pending = (await fx.domain(orgA, names.pending, 'pending_verification')).id;
  domainIds.other = (await fx.domain(orgB, names.other)).id;
});
afterAll(async () => {
  await fx.cleanup();
});

describe('loadDomainViews', () => {
  it('reports owner, status and domain id with resolveDomainOwner semantics', async () => {
    const unknown = fx.name('unknown');
    const views = await loadDomainViews(prisma, [
      names.active,
      names.suspendedDomain,
      names.suspendedOrg,
      names.pending,
      names.other,
      unknown,
      names.active.toUpperCase(),
      names.active,
    ]);
    expect(views.size).toBe(7);
    expect(views.get(names.active)).toEqual({
      domainId: domainIds.active,
      ownerOrganizationId: orgA,
      ownerStatus: 'active',
    });
    expect(views.get(names.active.toUpperCase())).toEqual(views.get(names.active));
    expect(views.get(names.suspendedDomain)).toEqual({
      domainId: domainIds.suspendedDomain,
      ownerOrganizationId: orgA,
      ownerStatus: 'suspended',
    });
    expect(views.get(names.suspendedOrg)).toMatchObject({
      ownerOrganizationId: orgSuspended,
      ownerStatus: 'suspended',
    });
    for (const name of [names.pending, unknown]) {
      expect(views.get(name), name).toEqual({
        domainId: null,
        ownerOrganizationId: null,
        ownerStatus: 'none',
      });
    }
    expect(views.get(names.other)).toMatchObject({
      ownerOrganizationId: orgB,
      ownerStatus: 'active',
    });
  });

  it('feeds planRecipientRoutes: internal, cross-tenant outbound and refused inbound', async () => {
    const recipients = [
      { recipientId: 1n, rcptSeq: 0, address: `u@${names.active}`, storedDirection: null },
      { recipientId: 2n, rcptSeq: 1, address: `u@${names.other}`, storedDirection: null },
      { recipientId: 3n, rcptSeq: 2, address: `u@${names.second}`, storedDirection: null },
    ];
    const domains = await loadDomainViews(
      prisma,
      recipients.map((r) => recipientDomain(r.address)!),
    );
    const outbound = planRecipientRoutes({
      listenerDirection: 'outbound',
      messageOrganizationId: orgA,
      recipients,
      domains,
      suppressedAddresses: new Set(),
      maxRecipientsPerGroup: 100,
    });
    expect(outbound.decisions.map((d) => d.direction)).toEqual([
      'internal',
      'outbound',
      'internal',
    ]);
    expect(outbound.groups.map((g) => g.destinationKey).sort()).toEqual(
      [`mx:${names.other}`, `tenant:${domainIds.active}`, `tenant:${domainIds.second}`].sort(),
    );
    const inbound = planRecipientRoutes({
      listenerDirection: 'inbound',
      messageOrganizationId: orgA,
      recipients,
      domains,
      suppressedAddresses: new Set(),
      maxRecipientsPerGroup: 100,
    });
    expect(inbound.decisions[1]).toMatchObject({
      kind: 'refusal',
      reason: 'recipient_domain_inactive',
    });
  });
});

describe('loadActiveSuppressions', () => {
  it('returns the organization’s active suppressions among the addresses, lower-cased', async () => {
    const past = new Date(Date.now() - 60_000);
    const future = new Date(Date.now() + 3_600_000);
    await prisma.deliverySuppression.createMany({
      data: [
        {
          organizationId: orgA,
          address: 'hard@ext.test',
          reason: 'hard_bounce',
          expiresAt: future,
        },
        { organizationId: orgA, address: 'Manual@Ext.test', reason: 'manual', expiresAt: null },
        { organizationId: orgA, address: 'old@ext.test', reason: 'hard_bounce', expiresAt: past },
        { organizationId: orgA, address: 'resume@ext.test', reason: 'manual' },
        { organizationId: orgB, address: 'other@ext.test', reason: 'manual' },
      ],
    });
    const many = Array.from({ length: 1200 }, (_, i) => `bulk${i}@ext.test`);
    const suppressed = await loadActiveSuppressions(prisma, orgA, [
      'HARD@ext.test',
      'manual@ext.test',
      'old@ext.test',
      'other@ext.test',
      'résumé@ext.test',
      'clean@ext.test',
      ...many,
    ]);
    expect([...suppressed].sort()).toEqual(['hard@ext.test', 'manual@ext.test']);
    expect(await loadActiveSuppressions(prisma, orgA, [])).toEqual(new Set());
  });
});

describe('loadInboundDestinations', () => {
  it('returns enabled inbound destinations in (priority, id) order', async () => {
    const domainId = domainIds.active!;
    const create = (host: string | null, priority: number, extra: Record<string, unknown> = {}) =>
      prisma.domainMailServer.create({
        data: {
          organizationId: orgA,
          domainId,
          role: 'inbound_destination',
          host,
          priority,
          ...extra,
        },
      });
    const b = await create('mx-b.acme.example', 20, { port: 2525, tlsMode: 'required' });
    const a1 = await create('mx-a1.acme.example', 10, {
      tlsMode: 'verify',
      tlsVerifyNames: 'nexthop:.acme.example',
    });
    const a2 = await create('mx-a2.acme.example', 10);
    await create('mx-off.acme.example', 1, { enabled: false });
    await create(null, 1);
    await create('src.acme.example', 1, { role: 'outbound_source' });
    const rows = await loadInboundDestinations(prisma, domainId);
    expect(rows.map((r) => r.host)).toEqual([
      'mx-a1.acme.example',
      'mx-a2.acme.example',
      'mx-b.acme.example',
    ]);
    expect(rows[0]).toEqual({
      publicId: a1.publicId,
      host: 'mx-a1.acme.example',
      port: 25,
      priority: 10,
      tlsMode: 'verify',
      tlsVerifyNames: 'nexthop:.acme.example',
      provider: 'custom',
    });
    expect(rows[1]!.publicId).toBe(a2.publicId);
    expect(rows[2]).toMatchObject({ publicId: b.publicId, port: 2525, tlsMode: 'required' });
    expect(await loadInboundDestinations(prisma, domainIds.other!)).toEqual([]);
  });
});

describe('loadDestinationPresets', () => {
  it('parses the seeded presets (pnpm db:seed) into views with compiled patterns', async () => {
    const presets = await loadDestinationPresets(prisma);
    const byProvider = new Map(presets.map((p) => [p.provider, p]));
    const m365 = byProvider.get('microsoft_365');
    const google = byProvider.get('google_workspace');
    expect(m365).toMatchObject({
      port: 25,
      tlsMode: 'verify',
      maxServers: 1,
      defaultServers: null,
    });
    expect(google).toMatchObject({ port: 25, tlsMode: 'verify', maxServers: 5 });
    expect(google!.defaultServers).toHaveLength(5);
    expect(matchesProviderHost(m365!, 'contoso-com.mail.protection.outlook.com')).toBe(true);
    for (const server of google!.defaultServers!) {
      expect(
        validateDestinationHost(server.host, google!.port, {
          allowNonPublic: false,
          deniedSuffixes: [],
          gatewayHosts: new Set(),
          provider: google!,
        }),
        server.host,
      ).toEqual({ ok: true, host: server.host, port: 25 });
    }
  });
});
