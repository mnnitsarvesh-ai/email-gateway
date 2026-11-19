import { randomBytes, randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { DEFAULT_PROVIDER_RELAY_PROOF } from '@email-gateway/mail-routing';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { type CodedHttpException } from '../../../http/coded-exception';
import type { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import type { DomainDestinationsService } from '../../domain-destinations/services/domain-destinations.service';
import type { MailFlowChange } from '../dto/provider-connections.schemas';
import type {
  ConnectionAggregate,
  ConnectionChanges,
  ProviderConnectionsRepository,
} from '../repositories/provider-connections.repository';
import type { ProviderGrantsRepository } from '../repositories/provider-grants.repository';
import type { ProviderRunsRepository } from '../repositories/provider-runs.repository';
import type { ProviderConnectionsService } from './provider-connections.service';
import {
  changePermission,
  decodeImpactToken,
  encodeImpactToken,
  ProviderMailFlowService,
} from './provider-mail-flow.service';

Logger.overrideLogger(false);

const SCOPE = systemScope(42n);
const T0 = new Date('2026-11-18T08:00:00.000Z');
const CONNECTION_ID = '0196f0aa-0000-7000-8000-0000000000c1';
const DOMAIN_ID = '0196f0aa-0000-7000-8000-0000000000d1';
const ALL = ['integration:read', 'integration:manage', 'domain:routing_manage', 'connector:manage'];

function user(permissions: string[] = ALL, publicId = randomUUID()): UserPrincipal {
  return {
    kind: 'user',
    userId: 10n,
    userPublicId: publicId,
    organizationId: 42n,
    organizationPublicId: randomUUID(),
    organizationKind: 'customer',
    sessionId: randomUUID(),
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(permissions),
  };
}

function aggregate(over: Partial<ConnectionAggregate['connection']> = {}): ConnectionAggregate {
  return {
    connection: {
      id: 5n,
      publicId: CONNECTION_ID,
      organizationId: 42n,
      provider: 'microsoft_365',
      displayName: 'Contoso',
      status: 'active',
      externalTenantId: '11111111-2222-3333-4444-555555555555',
      externalTenantName: 'Contoso',
      tenantVerifiedAt: T0,
      activeTenantKey: 'microsoft_365:11111111-2222-3333-4444-555555555555',
      outboundMode: 'off',
      internalRouting: false,
      relayProof: null,
      routeTokenVersion: 1,
      routeTokenPendingVersion: null,
      attestations: null,
      healthStatus: 'healthy',
      healthCheckedAt: null,
      healthChangedAt: null,
      nextHealthCheckAt: null,
      lastRelayAcceptedAt: null,
      disabledAt: null,
      rowVersion: 3,
      createdAt: T0,
      updatedAt: T0,
      ...over,
    },
    grants: [],
    domains: [
      {
        domainId: 70n,
        domainPublicId: DOMAIN_ID,
        name: 'contoso.example',
        gatewayStatus: 'active',
        outboundEnabled: true,
        providerVerification: 'verified',
        providerCheckedAt: T0,
        providerMxHost: 'contoso-example.mail.protection.outlook.com',
        inboundAppliedAt: null,
      },
    ],
    connector: null,
  };
}

/** The service over in-memory collaborators; `state` is what the repositories hold. */
function bed() {
  const state = {
    aggregate: aggregate(),
    destinations: [] as Array<{
      host: string;
      port: number;
      priority: number;
      tlsMode: string;
      provider: 'custom' | 'microsoft_365' | 'google_workspace';
    }>,
    probePassed: false,
    wizardValidateDone: false,
    updates: [] as ConnectionChanges[],
    connectorsCreated: 0,
    replaced: [] as string[],
    audit: [] as Array<{ action: string; metadata: unknown }>,
    failDestinations: false,
  };
  const connections = {
    writer: {},
    aggregate: () => Promise.resolve(state.aggregate),
    lock: () => Promise.resolve(state.aggregate),
    destinations: () => Promise.resolve(new Map([[70n, state.destinations]])),
    markInboundApplied: () => Promise.resolve(),
    countConnectors: () => Promise.resolve(0),
    createRelayConnector: () => {
      state.connectorsCreated += 1;
      return Promise.resolve({ id: 1n, publicId: randomUUID() });
    },
    setRelayConnectorStatus: () => Promise.resolve(),
    update: (
      _tx: unknown,
      _s: unknown,
      _id: bigint,
      rowVersion: number,
      changes: ConnectionChanges,
    ) => {
      if (rowVersion !== state.aggregate.connection.rowVersion) return Promise.resolve(false);
      state.updates.push(changes);
      return Promise.resolve(true);
    },
  } as unknown as ProviderConnectionsRepository;
  const destinations = {
    plan: (input: { provider: string; host?: string }) =>
      Promise.resolve(
        input.provider === 'microsoft_365'
          ? [
              {
                host: input.host!,
                port: 25,
                priority: 0,
                tlsMode: 'verify',
                provider: 'microsoft_365',
              },
            ]
          : [1, 5, 5, 10, 10].map((priority, i) => ({
              host: `aspmx${i}.l.google.com`,
              port: 25,
              priority,
              tlsMode: 'verify',
              provider: 'google_workspace',
            })),
      ),
    replaceInTransaction: (_tx: unknown, _p: unknown, _s: unknown, publicId: string) => {
      if (state.failDestinations) return Promise.reject(new Error('destination write failed'));
      state.replaced.push(publicId);
      return Promise.resolve({ changed: true, view: {} });
    },
  } as unknown as DomainDestinationsService;
  const runs = {
    probePassedSince: () => Promise.resolve(state.probePassed),
  } as unknown as ProviderRunsRepository;
  const grants = { revokeAll: () => Promise.resolve() } as unknown as ProviderGrantsRepository;
  const idempotency = {
    execute: async (
      _req: unknown,
      fn: (tx: unknown) => Promise<{ statusCode: number; body: unknown }>,
    ) => {
      const r = await fn({});
      return { ...r, replayed: false };
    },
  } as unknown as IdempotencyService;
  const base = {
    record: (
      _tx: unknown,
      _p: unknown,
      _s: unknown,
      _ip: unknown,
      e: { action: string; metadata: unknown },
    ) => {
      state.audit.push({ action: e.action, metadata: e.metadata });
      return Promise.resolve();
    },
    wizardInput: () =>
      Promise.resolve({
        provider: 'microsoft_365',
        connectionStatus: 'active',
        outboundMode: state.aggregate.connection.outboundMode,
        internalRouting: false,
        tenantVerified: true,
        mailFlowGrant: 'active',
        domains: [
          { gatewayActive: true, providerVerified: true, destinationProvider: 'microsoft_365' },
        ],
        relayConnector: state.aggregate.connector?.status === 'active',
        attestations: ['m365.inbound_connector_created', 'm365.enhanced_filtering_enabled'],
        latestFullRun: state.wizardValidateDone ? 'passed' : null,
      }),
  } as unknown as ProviderConnectionsService;
  const service = new ProviderMailFlowService(
    {
      PROVIDER_IMPACT_TOKEN_KEY: randomBytes(32).toString('hex'),
      PROVIDER_IMPACT_TOKEN_TTL_SECONDS: 900,
      PROVIDER_ROUTE_TOKEN_KEY: randomBytes(32).toString('hex'),
      SMTP_CONNECTORS_MAX_PER_ORGANIZATION: 50,
    },
    connections,
    grants,
    runs,
    destinations,
    idempotency,
    base,
  );
  let clock = T0;
  service.now = () => clock;
  return { service, state, tick: (ms: number) => (clock = new Date(clock.getTime() + ms)) };
}

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(Error);
  expect(typeof (err as { code?: unknown }).code).toBe('string');
  return (err as CodedHttpException).code;
};

const apply = (
  b: ReturnType<typeof bed>,
  principal: Principal,
  change: MailFlowChange,
  impactToken: string,
) =>
  b.service.apply(
    principal,
    SCOPE,
    {
      id: CONNECTION_ID,
      idempotencyKey: randomUUID(),
      body: { change, impactToken, confirm: true },
    },
    { ip: '203.0.113.7', userAgent: 'vitest' },
  );

describe('mail-flow helpers (D13, I4)', () => {
  it('inbound needs domain:routing_manage, every other change connector:manage', () => {
    expect(changePermission('inbound')).toBe('domain:routing_manage');
    for (const kind of [
      'outbound',
      'activate',
      'proof',
      'suspend',
      'disable_outbound',
      'disable',
    ] as const) {
      expect(changePermission(kind)).toBe('connector:manage');
    }
  });

  it('impact tokens carry the HMAC and the bound expiry; malformed tokens decode to null', () => {
    const sig = 'a'.repeat(43);
    const at = new Date('2026-11-18T08:15:00.000Z');
    const token = encodeImpactToken(sig, at);
    expect(decodeImpactToken(token)).toEqual({ signature: sig, expiresAt: at });
    for (const bad of [
      '',
      sig,
      `${sig}.x`,
      `${'a'.repeat(42)}.1763453700`,
      `${sig}.1763453700.1`,
    ]) {
      expect(decodeImpactToken(bad)).toBeNull();
    }
  });
});

describe('ProviderMailFlowService preview → apply (D13)', () => {
  let b: ReturnType<typeof bed>;
  let principal: UserPrincipal;
  beforeEach(() => {
    b = bed();
    principal = user();
  });

  it('inbound: current vs proposed per domain, the provider MX host prefilled; apply writes it', async () => {
    b.state.destinations = [
      {
        host: 'old.contoso.example',
        port: 25,
        priority: 10,
        tlsMode: 'opportunistic',
        provider: 'custom',
      },
    ];
    const change: MailFlowChange = { kind: 'inbound', domainIds: [DOMAIN_ID] };
    const preview = await b.service.preview(principal, SCOPE, CONNECTION_ID, { change }, null);
    expect(preview.changeSet.domains).toEqual([
      {
        domainId: DOMAIN_ID,
        name: 'contoso.example',
        current: {
          provider: 'custom',
          servers: [
            { host: 'old.contoso.example', port: 25, priority: 10, tlsMode: 'opportunistic' },
          ],
        },
        proposed: {
          provider: 'microsoft_365',
          servers: [
            {
              host: 'contoso-example.mail.protection.outlook.com',
              port: 25,
              priority: 0,
              tlsMode: 'verify',
            },
          ],
        },
        changed: true,
      },
    ]);
    expect(preview.warnings).toEqual([]);
    expect(b.state.audit.at(-1)).toEqual({
      action: 'integration.mail_flow_previewed',
      metadata: { kind: 'inbound', domains: 1, changedDomains: 1, fields: [] },
    });
    const res = await apply(b, principal, change, preview.impactToken);
    expect(res.statusCode).toBe(200);
    expect(b.state.replaced).toEqual([DOMAIN_ID]);
    expect(b.state.audit.at(-1)!.action).toBe('integration.mail_flow_applied');
    expect(JSON.stringify(b.state.audit.at(-1)!.metadata)).toContain('contoso.example');
  });

  it('a host differing from the tenant MX target warns; an unlinked domain is refused', async () => {
    const change: MailFlowChange = {
      kind: 'inbound',
      domainIds: [DOMAIN_ID],
      microsoftHosts: { [DOMAIN_ID]: 'other-example.mail.protection.outlook.com' },
    };
    const preview = await b.service.preview(principal, SCOPE, CONNECTION_ID, { change }, null);
    expect(preview.warnings).toEqual(['destination_differs_from_provider_mx']);
    expect(
      await codeOf(
        b.service.preview(
          principal,
          SCOPE,
          CONNECTION_ID,
          {
            change: { kind: 'inbound', domainIds: [randomUUID()] },
          },
          null,
        ),
      ),
    ).toBe('domain_not_linked');
  });

  it('refuses changes before the tenant binding (409 connection_not_bound)', async () => {
    b.state.aggregate = aggregate({ status: 'configuring' });
    for (const change of [
      { kind: 'inbound', domainIds: [DOMAIN_ID] },
      { kind: 'outbound', mode: 'probe_only' },
    ] as MailFlowChange[]) {
      expect(
        await codeOf(b.service.preview(principal, SCOPE, CONNECTION_ID, { change }, null)),
      ).toBe('connection_not_bound');
    }
  });

  it('needs the change’s own permission next to integration:manage (403)', async () => {
    const noRouting = user(['integration:read', 'integration:manage', 'connector:manage']);
    expect(
      await codeOf(
        b.service.preview(
          noRouting,
          SCOPE,
          CONNECTION_ID,
          {
            change: { kind: 'inbound', domainIds: [DOMAIN_ID] },
          },
          null,
        ),
      ),
    ).toBe('forbidden');
    const noConnector = user(['integration:read', 'integration:manage', 'domain:routing_manage']);
    expect(
      await codeOf(
        b.service.preview(
          noConnector,
          SCOPE,
          CONNECTION_ID,
          {
            change: { kind: 'outbound', mode: 'probe_only' },
          },
          null,
        ),
      ),
    ).toBe('forbidden');
  });

  it('refuses a tampered, foreign-user, expired or stale token with 409 impact_changed', async () => {
    const change: MailFlowChange = { kind: 'outbound', mode: 'probe_only' };
    const { impactToken } = await b.service.preview(
      principal,
      SCOPE,
      CONNECTION_ID,
      { change },
      null,
    );
    const [sig, exp] = impactToken.split('.') as [string, string];
    // Flip the first character: the last base64url character of a 32-byte HMAC carries two
    // padding bits, so changing it (A ↔ B) can decode to the same bytes.
    const flipped = `${sig.startsWith('A') ? 'B' : 'A'}${sig.slice(1)}.${exp}`;
    expect(await codeOf(apply(b, principal, change, flipped))).toBe('impact_changed');
    // The expiry is bound by the HMAC: extending it breaks the signature.
    expect(await codeOf(apply(b, principal, change, `${sig}.${Number(exp) + 600}`))).toBe(
      'impact_changed',
    );
    // Another user with the same permissions cannot use the token.
    expect(await codeOf(apply(b, user(), change, impactToken))).toBe('impact_changed');
    // A changed connection (row version) invalidates it.
    b.state.aggregate = aggregate({ rowVersion: 4 });
    expect(await codeOf(apply(b, principal, change, impactToken))).toBe('impact_changed');
    b.state.aggregate = aggregate();
    // Past its expiry.
    b.tick(901_000);
    expect(await codeOf(apply(b, principal, change, impactToken))).toBe('impact_changed');
    expect(b.state.updates).toEqual([]);
    expect(b.state.connectorsCreated).toBe(0);
  });

  it('outbound probe_only creates the relay connector once; activate needs validation and a probe', async () => {
    const outbound: MailFlowChange = { kind: 'outbound', mode: 'probe_only' };
    const p1 = await b.service.preview(principal, SCOPE, CONNECTION_ID, { change: outbound }, null);
    expect(p1.changeSet.connector).toEqual({ action: 'create', id: null });
    expect(p1.changeSet.connection).toEqual([
      { field: 'outboundMode', from: 'off', to: 'probe_only' },
    ]);
    await apply(b, principal, outbound, p1.impactToken);
    expect(b.state.connectorsCreated).toBe(1);
    expect(b.state.updates.at(-1)).toMatchObject({ outboundMode: 'probe_only' });

    b.state.aggregate = aggregate({ outboundMode: 'probe_only', rowVersion: 4 });
    b.state.aggregate.connector = { id: 1n, publicId: randomUUID(), status: 'active' };
    const activate: MailFlowChange = {
      kind: 'activate',
      outboundMode: 'active',
      internalRouting: false,
    };
    expect(
      await codeOf(b.service.preview(principal, SCOPE, CONNECTION_ID, { change: activate }, null)),
    ).toBe('validation_required');
    b.state.wizardValidateDone = true;
    expect(
      await codeOf(b.service.preview(principal, SCOPE, CONNECTION_ID, { change: activate }, null)),
    ).toBe('validation_required');
    b.state.probePassed = true;
    const p2 = await b.service.preview(principal, SCOPE, CONNECTION_ID, { change: activate }, null);
    expect(p2.changeSet.connection).toEqual([
      { field: 'outboundMode', from: 'probe_only', to: 'active' },
    ]);
    await apply(b, principal, activate, p2.impactToken);
    expect(b.state.updates.at(-1)).toMatchObject({ outboundMode: 'active' });
  });

  it('proof policies are bounded per provider; the default is stored as NULL', async () => {
    // At least one rule always stays required; DKIM may never be off for Google.
    const off = {
      ...DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      tenantHeader: 'off',
      dkimAligned: 'off',
    };
    expect(
      await codeOf(
        b.service.preview(
          principal,
          SCOPE,
          CONNECTION_ID,
          {
            change: { kind: 'proof', relayProof: off } as MailFlowChange,
          },
          null,
        ),
      ),
    ).toBe('proof_policy_invalid');
    // The tenant header off without the DKIM freshness window and replay limit: unbounded replay.
    expect(
      await codeOf(
        b.service.preview(
          principal,
          SCOPE,
          CONNECTION_ID,
          {
            change: {
              kind: 'proof',
              relayProof: { ...DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365, tenantHeader: 'off' },
            },
          },
          null,
        ),
      ),
    ).toBe('proof_policy_invalid');
    const relaxed = {
      ...DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365,
      tenantHeader: 'off',
      dkimMaxAgeSeconds: 3600,
      dkimReplayMax: 5,
    };
    const p = await b.service.preview(
      principal,
      SCOPE,
      CONNECTION_ID,
      {
        change: { kind: 'proof', relayProof: relaxed } as MailFlowChange,
      },
      null,
    );
    expect(p.warnings).toEqual(['tenant_header_off']);
    expect(
      await codeOf(
        b.service.preview(
          principal,
          SCOPE,
          CONNECTION_ID,
          {
            change: {
              kind: 'proof',
              relayProof: { ...DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365 },
            },
          },
          null,
        ),
      ),
    ).toBe('change_not_applicable');
  });

  it('suspend and disable_outbound only when outbound is on; the disconnect change revokes grants', async () => {
    expect(
      await codeOf(
        b.service.preview(principal, SCOPE, CONNECTION_ID, { change: { kind: 'suspend' } }, null),
      ),
    ).toBe('change_not_applicable');
    b.state.aggregate = aggregate({ outboundMode: 'active', internalRouting: true });
    b.state.aggregate.connector = { id: 1n, publicId: randomUUID(), status: 'active' };
    const s = await b.service.preview(
      principal,
      SCOPE,
      CONNECTION_ID,
      { change: { kind: 'suspend' } },
      null,
    );
    expect(s.changeSet.connection).toEqual([
      { field: 'outboundMode', from: 'active', to: 'suspended' },
      { field: 'internalRouting', from: true, to: false },
    ]);
    const d = await b.service.preview(
      principal,
      SCOPE,
      CONNECTION_ID,
      { change: { kind: 'disable_outbound' } },
      null,
    );
    expect(d.changeSet.connector).toMatchObject({ action: 'disable' });
    // `disable` is only applied through DELETE /provider-connections/{id}.
    expect(await codeOf(apply(b, principal, { kind: 'disable' }, s.impactToken))).toBe(
      'change_not_applicable',
    );
  });

  it('a failing destination write aborts the apply before the connection changes', async () => {
    b.state.failDestinations = true;
    const change: MailFlowChange = { kind: 'inbound', domainIds: [DOMAIN_ID] };
    const preview = await b.service.preview(principal, SCOPE, CONNECTION_ID, { change }, null);
    await expect(apply(b, principal, change, preview.impactToken)).rejects.toThrow(
      'destination write failed',
    );
    expect(b.state.updates).toEqual([]);
    expect(b.state.audit.map((a) => a.action)).toEqual(['integration.mail_flow_previewed']);
  });
});
