/**
 * In-memory doubles of the step 8.2 provider-connection repositories (docs/plan/steps/
 * 25-m365-google-connectors.md §5) for the unit and e2e suites: connections, grants (the
 * ciphertext is kept so tests can assert it is written, wiped and never returned), consent states,
 * gateway domains and their links, inbound destinations (planned with the real step 2.3 planner
 * and the seeded presets), the `provider_relay` connector rows, validation runs, probe
 * observations, health rows, relay counters and the active egress sets. `worker` simulates the
 * integration-worker's writes (verification, provider domain checks, probe evidence, run
 * completion), which the api itself never performs. Nothing here is used by production code.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { MAIL_DESTINATION_PRESETS } from '@email-gateway/database';
import { mailDestinationPresetSchema } from '@email-gateway/mail-routing';
import type { AuditEntry } from '../../src/audit/audit.service';
import { AuditService } from '../../src/audit/audit.service';
import type { Principal } from '../../src/auth-contracts/principal';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type { ApiConfig } from '../../src/config';
import {
  planDestinations,
  type PlannedServer,
} from '../../src/modules/domain-destinations/domain/destination-plan';
import type { PutDestinationsInput } from '../../src/modules/domain-destinations/dto/domain-destinations.schemas';
import { DestinationRefusedException } from '../../src/modules/domain-destinations/domain-destinations.errors';
import {
  DomainDestinationsService,
  hostRulesFrom,
} from '../../src/modules/domain-destinations/services/domain-destinations.service';
import {
  type ConnectionAggregate,
  type ConnectionChanges,
  type ConnectionListRow,
  type ConnectionRow,
  type DomainDestinationRow,
  type DomainDnsSummary,
  type GrantRow,
  ProviderConnectionsRepository,
  type ScopeDomainRow,
} from '../../src/modules/provider-connections/repositories/provider-connections.repository';
import {
  type ConsentStateRow,
  type GrantWrite,
  ProviderGrantsRepository,
} from '../../src/modules/provider-connections/repositories/provider-grants.repository';
import {
  type EgressSetRow,
  type HealthCheckRow,
  type HealthEventRow,
  ProviderRunsRepository,
  type RelayActivity,
  type ValidationRunDetailRow,
  type ValidationRunRow,
} from '../../src/modules/provider-connections/repositories/provider-runs.repository';
import { OrganizationLimitsService } from '../../src/tenancy/organization-limits.service';

/** The destination presets as seeded (step 2.3 R2). */
export const SEEDED_PRESETS = MAIL_DESTINATION_PRESETS.map((preset) =>
  mailDestinationPresetSchema.parse({
    ...preset,
    hostPatterns: [...preset.hostPatterns],
    defaultServers: preset.defaultServers ? [...preset.defaultServers] : null,
  }),
);

/** A stored grant: the api's row plus the write-only columns. */
export interface StoredGrant extends GrantRow {
  credentialCiphertext: string | null;
  consecutiveFailures: number;
  consentedByUserId: bigint | null;
}

export interface StoredDomain {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  status: string;
  outboundEnabled: boolean;
}

export interface StoredLink {
  organizationId: bigint;
  connectionId: bigint;
  domainId: bigint;
  providerVerification: 'unknown' | 'verified' | 'unverified' | 'absent' | 'alias';
  providerCheckedAt: Date | null;
  providerMxHost: string | null;
  inboundAppliedAt: Date | null;
}

export interface StoredConnector {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  providerConnectionId: bigint | null;
  status: 'active' | 'disabled';
}

export interface StoredRun extends ValidationRunRow {
  organizationId: bigint;
  connectionId: bigint;
  probeTokenSha256: string | null;
  results: unknown;
}

export interface StoredObservation {
  organizationId: bigint;
  connectionId: bigint;
  runId: bigint | null;
  receivedAt: Date;
  proofResult: 'pass' | 'fail' | 'temperror';
}

/** A destination-change event written by the destinations double (`domain.routing.changed.v1`). */
export interface RoutingEvent {
  organizationId: bigint;
  domainPublicId: string;
  hosts: string[];
}

const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

/**
 * The world of one test run. Rows are plain objects; every double filters by the scope's
 * organization exactly as the Prisma repositories do (`tenantWhere`).
 */
export class ProviderWorld {
  connections: Array<ConnectionRow & { createdByUserId: bigint | null }> = [];
  grants: StoredGrant[] = [];
  consentStates: Array<ConsentStateRow & { organizationId: bigint; stateSha256: string }> = [];
  domains: StoredDomain[] = [];
  links: StoredLink[] = [];
  destinations = new Map<bigint, DomainDestinationRow[]>();
  dns = new Map<bigint, DomainDnsSummary>();
  connectors: StoredConnector[] = [];
  /** Other connectors per organization (the SMTP connector cap). */
  otherConnectors = new Map<bigint, number>();
  runs: StoredRun[] = [];
  observations: StoredObservation[] = [];
  healthChecks: Array<HealthCheckRow & { organizationId: bigint; connectionId: bigint }> = [];
  healthEvents: Array<HealthEventRow & { organizationId: bigint; connectionId: bigint }> = [];
  counters: Array<
    RelayActivity & { organizationId: bigint; connectionId: bigint; hourStart: Date }
  > = [];
  egressSets: EgressSetRow[] = [];
  routingEvents: RoutingEvent[] = [];
  /** Failure injection: the next destination write throws (rollback tests). */
  failNextDestinationWrite = false;
  private nextId = 100n;

  reset(): void {
    this.connections = [];
    this.grants = [];
    this.consentStates = [];
    this.domains = [];
    this.links = [];
    this.destinations.clear();
    this.dns.clear();
    this.connectors = [];
    this.otherConnectors.clear();
    this.runs = [];
    this.observations = [];
    this.healthChecks = [];
    this.healthEvents = [];
    this.counters = [];
    this.egressSets = [];
    this.routingEvents = [];
    this.failNextDestinationWrite = false;
  }

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  /** A deep snapshot / restore pair (a rolled-back transaction). */
  snapshot(): () => void {
    const clone = <T>(rows: T[]): T[] => rows.map((r) => ({ ...r }));
    const state = {
      connections: clone(this.connections),
      grants: clone(this.grants),
      consentStates: clone(this.consentStates),
      links: clone(this.links),
      destinations: new Map([...this.destinations].map(([k, v]) => [k, clone(v)])),
      connectors: clone(this.connectors),
      runs: clone(this.runs),
      routingEvents: clone(this.routingEvents),
    };
    return () => {
      Object.assign(this, state);
    };
  }

  // ---- Seeding --------------------------------------------------------------------------

  addDomain(
    organizationId: bigint,
    name: string,
    options: { status?: string; outboundEnabled?: boolean; publicId?: string } = {},
  ): StoredDomain {
    const domain: StoredDomain = {
      id: this.id(),
      publicId: options.publicId ?? randomUUID(),
      organizationId,
      name,
      status: options.status ?? 'active',
      outboundEnabled: options.outboundEnabled ?? true,
    };
    this.domains.push(domain);
    this.dns.set(domain.id, { mx: 'valid', spf: 'valid', dkim: 'valid' });
    return domain;
  }

  addConnection(
    organizationId: bigint,
    overrides: Partial<ConnectionRow> = {},
  ): ConnectionRow & { createdByUserId: bigint | null } {
    const now = new Date();
    const row = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId,
      provider: 'microsoft_365' as const,
      displayName: `Connection ${this.nextId}`,
      status: 'draft' as const,
      externalTenantId: null,
      externalTenantName: null,
      tenantVerifiedAt: null,
      activeTenantKey: null,
      outboundMode: 'off' as const,
      internalRouting: false,
      relayProof: null,
      routeTokenVersion: 1,
      routeTokenPendingVersion: null,
      attestations: null,
      healthStatus: 'unknown' as const,
      healthCheckedAt: null,
      healthChangedAt: null,
      nextHealthCheckAt: null,
      lastRelayAcceptedAt: null,
      disabledAt: null,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      createdByUserId: null,
      ...overrides,
    };
    this.connections.push(row);
    return row;
  }

  addGrant(
    connection: Pick<ConnectionRow, 'id' | 'organizationId' | 'provider'>,
    overrides: Partial<StoredGrant> = {},
  ): StoredGrant {
    const now = new Date();
    const m365 = connection.provider === 'microsoft_365';
    const grant: StoredGrant = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId: connection.organizationId,
      connectionId: connection.id,
      profile: m365 ? 'm365.mail_flow' : 'google.mail_flow',
      profileVersion: 1,
      authMethod: m365 ? 'platform_app' : 'platform_service_account',
      status: 'pending_consent',
      clientId: null,
      subjectEmail: null,
      credentialKeyId: null,
      credentialVersion: 0,
      credentialFingerprint: null,
      credentialSetAt: null,
      credentialExpiresAt: null,
      requestedPermissions: [],
      observedPermissions: null,
      missingPermissions: null,
      excessPermissions: null,
      claimedTenantId: null,
      consentedAt: null,
      verifyRequestedAt: null,
      verifiedAt: null,
      lastErrorCode: null,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      credentialCiphertext: null,
      consecutiveFailures: 0,
      consentedByUserId: null,
      ...overrides,
    };
    this.grants.push(grant);
    return grant;
  }

  link(
    connection: Pick<ConnectionRow, 'id' | 'organizationId'>,
    domain: StoredDomain,
    overrides: Partial<StoredLink> = {},
  ): StoredLink {
    const link: StoredLink = {
      organizationId: connection.organizationId,
      connectionId: connection.id,
      domainId: domain.id,
      providerVerification: 'unknown',
      providerCheckedAt: null,
      providerMxHost: null,
      inboundAppliedAt: null,
      ...overrides,
    };
    this.links.push(link);
    return link;
  }

  // ---- What the integration-worker would write (never the api) ------------------------------

  readonly worker = {
    /** D3.4/D4: the grant verified for its claimed tenant and the domains verified → `active`. */
    bind: (connection: ConnectionRow, options: { mxHost?: string } = {}): void => {
      const row = this.connections.find((c) => c.id === connection.id)!;
      const tenant = '11111111-2222-3333-4444-555555555555';
      for (const g of this.grants.filter(
        (x) => x.connectionId === row.id && x.status !== 'revoked',
      )) {
        Object.assign(g, {
          status: 'active',
          verifiedAt: new Date(),
          observedPermissions: g.requestedPermissions,
          missingPermissions: [],
          excessPermissions: [],
          rowVersion: g.rowVersion + 1,
        });
      }
      for (const l of this.links.filter((x) => x.connectionId === row.id)) {
        l.providerVerification = 'verified';
        l.providerCheckedAt = new Date();
        const domain = this.domains.find((d) => d.id === l.domainId)!;
        if (row.provider === 'microsoft_365') {
          l.providerMxHost =
            options.mxHost ?? `${domain.name.replace(/\./g, '-')}.mail.protection.outlook.com`;
        }
      }
      Object.assign(row, {
        status: 'active',
        externalTenantId: tenant,
        externalTenantName: 'Contoso Ltd',
        tenantVerifiedAt: new Date(),
        activeTenantKey: `${row.provider}:${tenant}:${row.publicId}`,
        rowVersion: row.rowVersion + 1,
      });
    },
    /** A probe of the connection arrived and passed the proof (D10). */
    probePassed: (connection: ConnectionRow, at: Date = new Date()): void => {
      this.observations.push({
        organizationId: connection.organizationId,
        connectionId: connection.id,
        runId: null,
        receivedAt: at,
        proofResult: 'pass',
      });
    },
    /** Completes the newest run of the connection with `status`. */
    completeRun: (connection: ConnectionRow, status: 'passed' | 'warning' | 'failed'): void => {
      const run = [...this.runs].reverse().find((r) => r.connectionId === connection.id);
      if (!run) throw new Error('no run');
      Object.assign(run, {
        status,
        completedAt: new Date(),
        summary: {
          pass: 10,
          warn: status === 'warning' ? 1 : 0,
          fail: status === 'failed' ? 1 : 0,
          skipped: 0,
          error: 0,
        },
        results: [
          {
            code: 'credentials.token',
            subject: 'm365.mail_flow',
            status: 'pass',
            severity: 'critical',
            evidence: { tokenAcquired: true },
            remediation: 'connect',
          },
        ],
      });
    },
  };

  // ---- Repository doubles ---------------------------------------------------------------

  private aggregateOf(scope: TenantScope, c: ConnectionRow): ConnectionAggregate {
    const org = scope.organizationId;
    return {
      connection: { ...c },
      grants: this.grants
        .filter((g) => g.organizationId === org && g.connectionId === c.id)
        .map((g) => this.grantRow(g)),
      domains: this.links
        .filter((l) => l.organizationId === org && l.connectionId === c.id)
        .map((l) => {
          const d = this.domains.find((x) => x.id === l.domainId)!;
          return {
            domainId: d.id,
            domainPublicId: d.publicId,
            name: d.name,
            gatewayStatus: d.status,
            outboundEnabled: d.outboundEnabled,
            providerVerification: l.providerVerification,
            providerCheckedAt: l.providerCheckedAt,
            providerMxHost: l.providerMxHost,
            inboundAppliedAt: l.inboundAppliedAt,
          };
        }),
      connector: (() => {
        const k = this.connectors.find(
          (x) => x.organizationId === org && x.providerConnectionId === c.id,
        );
        return k ? { id: k.id, publicId: k.publicId, status: k.status } : null;
      })(),
    };
  }

  /** The api's view of a grant: never the ciphertext (grantSelect). */
  private grantRow(g: StoredGrant): GrantRow {
    const { credentialCiphertext: _c, consecutiveFailures: _f, consentedByUserId: _u, ...row } = g;
    return { ...row };
  }

  private connection(scope: TenantScope, pred: (c: ConnectionRow) => boolean) {
    return this.connections.find((c) => c.organizationId === scope.organizationId && pred(c));
  }

  connectionsDouble(): ProviderConnectionsRepository {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the doubles' methods close over the world
    const w = this;
    const double = {
      list: (
        scope: TenantScope,
        page: {
          take: number;
          beforeId?: bigint;
          providers?: string[];
          statuses?: string[];
          health?: string[];
        },
      ): Promise<ConnectionListRow[]> =>
        Promise.resolve(
          w.connections
            .filter(
              (c) =>
                c.organizationId === scope.organizationId &&
                (page.beforeId === undefined || c.id < page.beforeId) &&
                (!page.providers || page.providers.includes(c.provider)) &&
                (!page.statuses || page.statuses.includes(c.status)) &&
                (!page.health || page.health.includes(c.healthStatus)),
            )
            .sort((a, b) => (a.id > b.id ? -1 : 1))
            .slice(0, page.take)
            .map((c) => ({
              ...c,
              domainCount: w.links.filter((l) => l.connectionId === c.id).length,
            })),
        ),
      aggregate: (scope: TenantScope, publicId: string) => {
        const c = w.connection(scope, (x) => x.publicId === publicId);
        return Promise.resolve(c ? w.aggregateOf(scope, c) : null);
      },
      lock: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const c = w.connection(scope, (x) => x.publicId === publicId);
        return Promise.resolve(c ? w.aggregateOf(scope, c) : null);
      },
      countLive: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.connections.filter(
            (c) => c.organizationId === scope.organizationId && c.status !== 'disabled',
          ).length,
        ),
      nameTaken: (_tx: unknown, scope: TenantScope, name: string, exceptId?: bigint) =>
        Promise.resolve(!!w.connection(scope, (c) => c.displayName === name && c.id !== exceptId)),
      create: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          publicId: string;
          provider: 'microsoft_365' | 'google_workspace';
          displayName: string;
          createdByUserId: bigint | null;
        },
      ) => {
        const row = w.addConnection(scope.organizationId, {
          publicId: data.publicId,
          provider: data.provider,
          displayName: data.displayName,
        });
        row.createdByUserId = data.createdByUserId;
        return Promise.resolve({ id: row.id, publicId: row.publicId });
      },
      update: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        rowVersion: number,
        changes: ConnectionChanges,
      ) => {
        const c = w.connection(scope, (x) => x.id === id && x.rowVersion === rowVersion);
        if (!c) return Promise.resolve(false);
        const { disabledByUserId: _d, ...rest } = changes;
        Object.assign(c, rest, { rowVersion: c.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      scopeDomains: (_tx: unknown, scope: TenantScope, publicIds: readonly string[]) =>
        Promise.resolve(
          w.domains
            .filter(
              (d) =>
                d.organizationId === scope.organizationId &&
                publicIds.includes(d.publicId) &&
                d.status !== 'deleted',
            )
            .map((d): ScopeDomainRow => ({
              id: d.id,
              publicId: d.publicId,
              name: d.name,
              status: d.status,
              linkedConnectionId:
                w.links.find(
                  (l) => l.domainId === d.id && l.organizationId === scope.organizationId,
                )?.connectionId ?? null,
            })),
        ),
      linkDomains: (_tx: unknown, scope: TenantScope, connectionId: bigint, ids: bigint[]) => {
        for (const domainId of ids) {
          if (w.links.some((l) => l.domainId === domainId)) {
            throw new Error('unique violation: provider_connection_domains.domain_id');
          }
          w.links.push({
            organizationId: scope.organizationId,
            connectionId,
            domainId,
            providerVerification: 'unknown',
            providerCheckedAt: null,
            providerMxHost: null,
            inboundAppliedAt: null,
          });
        }
        return Promise.resolve();
      },
      unlinkDomains: (_tx: unknown, scope: TenantScope, connectionId: bigint, ids: bigint[]) => {
        w.links = w.links.filter(
          (l) =>
            !(
              l.organizationId === scope.organizationId &&
              l.connectionId === connectionId &&
              ids.includes(l.domainId)
            ),
        );
        return Promise.resolve();
      },
      markInboundApplied: (
        _tx: unknown,
        scope: TenantScope,
        connectionId: bigint,
        ids: bigint[],
        _userId: bigint | null,
        at: Date,
      ) => {
        for (const l of w.links) {
          if (
            l.organizationId === scope.organizationId &&
            l.connectionId === connectionId &&
            ids.includes(l.domainId)
          ) {
            l.inboundAppliedAt = at;
          }
        }
        return Promise.resolve();
      },
      dnsSummaries: (scope: TenantScope, ids: readonly bigint[]) =>
        Promise.resolve(
          new Map(
            ids.map((id) => [
              id,
              w.domains.find((d) => d.id === id)?.organizationId === scope.organizationId
                ? (w.dns.get(id) ?? { mx: null, spf: null, dkim: null })
                : { mx: null, spf: null, dkim: null },
            ]),
          ),
        ),
      destinations: (scope: TenantScope, ids: readonly bigint[]) =>
        Promise.resolve(
          new Map(
            ids.map((id) => [
              id,
              w.domains.find((d) => d.id === id)?.organizationId === scope.organizationId
                ? [...(w.destinations.get(id) ?? [])]
                : [],
            ]),
          ),
        ),
      countConnectors: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          w.connectors.filter((k) => k.organizationId === scope.organizationId).length +
            (w.otherConnectors.get(scope.organizationId) ?? 0),
        ),
      createRelayConnector: (
        _tx: unknown,
        scope: TenantScope,
        data: { name: string; providerConnectionId: bigint },
      ) => {
        const row: StoredConnector = {
          id: w.id(),
          publicId: randomUUID(),
          organizationId: scope.organizationId,
          name: data.name,
          providerConnectionId: data.providerConnectionId,
          status: 'active',
        };
        w.connectors.push(row);
        return Promise.resolve({ id: row.id, publicId: row.publicId });
      },
      setRelayConnectorStatus: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        status: 'active' | 'disabled',
      ) => {
        const k = w.connectors.find(
          (x) => x.id === id && x.organizationId === scope.organizationId,
        );
        if (k) k.status = status;
        return Promise.resolve();
      },
      writer: {},
    };
    return double as unknown as ProviderConnectionsRepository;
  }

  grantsDouble(): ProviderGrantsRepository {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the doubles' methods close over the world
    const w = this;
    const find = (scope: TenantScope, pred: (g: StoredGrant) => boolean) =>
      w.grants.find((g) => g.organizationId === scope.organizationId && pred(g));
    const double = {
      lockGrant: (_tx: unknown, scope: TenantScope, connectionId: bigint, profile: string) => {
        const g = find(scope, (x) => x.connectionId === connectionId && x.profile === profile);
        return Promise.resolve(g ? w.grantRow(g) : null);
      },
      create: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          publicId: string;
          connectionId: bigint;
          profile: string;
          profileVersion: number;
          authMethod: StoredGrant['authMethod'];
          clientId: string | null;
          requestedPermissions: string[];
        },
      ) => {
        if (
          w.grants.some((g) => g.connectionId === data.connectionId && g.profile === data.profile)
        ) {
          throw new Error('unique violation: (connection_id, profile)');
        }
        const g = w.addGrant(
          w.connections.find((c) => c.id === data.connectionId)!,
          { ...data, organizationId: scope.organizationId, status: 'pending_consent' },
        );
        return Promise.resolve(w.grantRow(g));
      },
      update: (
        _tx: unknown,
        scope: TenantScope,
        grant: Pick<GrantRow, 'id' | 'rowVersion'>,
        data: GrantWrite,
      ) => {
        const g = find(scope, (x) => x.id === grant.id && x.rowVersion === grant.rowVersion);
        if (!g) return Promise.resolve(null);
        Object.assign(g, data, { rowVersion: g.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(w.grantRow(g));
      },
      revokeAll: (_tx: unknown, scope: TenantScope, connectionId: bigint) => {
        let count = 0;
        for (const g of w.grants) {
          if (
            g.organizationId === scope.organizationId &&
            g.connectionId === connectionId &&
            g.status !== 'revoked'
          ) {
            Object.assign(g, {
              status: 'revoked',
              credentialCiphertext: null,
              credentialKeyId: null,
              verifyRequestedAt: null,
              rowVersion: g.rowVersion + 1,
            });
            count += 1;
          }
        }
        return Promise.resolve(count);
      },
      insertConsentState: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          connectionId: bigint;
          grantId: bigint;
          userId: bigint;
          stateSha256: string;
          expiresAt: Date;
        },
      ) => {
        const id = w.id();
        w.consentStates.push({ id, organizationId: scope.organizationId, usedAt: null, ...data });
        return Promise.resolve({ id });
      },
      lockConsentState: (_tx: unknown, scope: TenantScope, stateSha256: string) => {
        const s = w.consentStates.find(
          (x) => x.organizationId === scope.organizationId && x.stateSha256 === stateSha256,
        );
        return Promise.resolve(
          s
            ? {
                id: s.id,
                connectionId: s.connectionId,
                grantId: s.grantId,
                userId: s.userId,
                expiresAt: s.expiresAt,
                usedAt: s.usedAt,
              }
            : null,
        );
      },
      markConsentUsed: (_tx: unknown, scope: TenantScope, id: bigint, at: Date) => {
        const s = w.consentStates.find(
          (x) => x.id === id && x.organizationId === scope.organizationId && x.usedAt === null,
        );
        if (!s) return Promise.resolve(false);
        s.usedAt = at;
        return Promise.resolve(true);
      },
      closeConsentStates: (_tx: unknown, scope: TenantScope, grantId: bigint, at: Date) => {
        for (const s of w.consentStates) {
          if (
            s.organizationId === scope.organizationId &&
            s.grantId === grantId &&
            s.usedAt === null
          ) {
            s.usedAt = at;
          }
        }
        return Promise.resolve();
      },
      findById: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const g = find(scope, (x) => x.id === id);
        return Promise.resolve(g ? w.grantRow(g) : null);
      },
      connectionOf: (_tx: unknown, scope: TenantScope, connectionId: bigint) => {
        const c = w.connection(scope, (x) => x.id === connectionId);
        return Promise.resolve(
          c ? { id: c.id, publicId: c.publicId, status: c.status, rowVersion: c.rowVersion } : null,
        );
      },
    };
    return double;
  }

  runsDouble(): ProviderRunsRepository {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the doubles' methods close over the world
    const w = this;
    const runRow = (r: StoredRun): ValidationRunRow & { id: bigint } => ({
      id: r.id,
      publicId: r.publicId,
      kind: r.kind,
      status: r.status,
      requestedByType: r.requestedByType,
      requestedById: r.requestedById,
      probeExpiresAt: r.probeExpiresAt,
      summary: r.summary,
      startedAt: r.startedAt,
      completedAt: r.completedAt,
      createdAt: r.createdAt,
    });
    const double = {
      insertRun: (
        _tx: unknown,
        scope: TenantScope,
        data: {
          publicId: string;
          connectionId: bigint;
          kind: StoredRun['kind'];
          requestedByType: StoredRun['requestedByType'];
          requestedById: string | null;
          probeTokenSha256: string | null;
          probeExpiresAt: Date | null;
        },
      ) => {
        const run: StoredRun = {
          id: w.id(),
          organizationId: scope.organizationId,
          status: 'queued',
          summary: null,
          results: null,
          startedAt: null,
          completedAt: null,
          createdAt: new Date(),
          ...data,
        };
        w.runs.push(run);
        return Promise.resolve(runRow(run));
      },
      listRuns: (
        scope: TenantScope,
        connectionId: bigint,
        page: { take: number; beforeId?: bigint; kinds?: string[]; statuses?: string[] },
      ) =>
        Promise.resolve(
          w.runs
            .filter(
              (r) =>
                r.organizationId === scope.organizationId &&
                r.connectionId === connectionId &&
                (page.beforeId === undefined || r.id < page.beforeId) &&
                (!page.kinds || page.kinds.includes(r.kind)) &&
                (!page.statuses || page.statuses.includes(r.status)),
            )
            .sort((a, b) => (a.id > b.id ? -1 : 1))
            .slice(0, page.take)
            .map(runRow),
        ),
      findRun: (scope: TenantScope, connectionId: bigint, publicId: string) => {
        const r = w.runs.find(
          (x) =>
            x.organizationId === scope.organizationId &&
            x.connectionId === connectionId &&
            x.publicId === publicId,
        );
        if (!r) return Promise.resolve(null);
        const detail: ValidationRunDetailRow = {
          ...runRow(r),
          results: r.results ?? null,
          observations: w.observations
            .filter((o) => o.runId === r.id)
            .map((o) => ({
              receivedAt: o.receivedAt,
              clientIp: '40.107.1.10',
              tlsProtocol: 'TLSv1.3',
              envelopeFromDomain: 'contoso.example',
              headerFromDomain: 'contoso.example',
              tenantHeader: 'match',
              dkim: 'aligned_pass',
              dkimDomains: ['contoso.example'],
              proofResult: o.proofResult,
              failureCode: null,
            })),
        };
        return Promise.resolve(detail);
      },
      latestFullRunStatus: (scope: TenantScope, connectionId: bigint) =>
        Promise.resolve(
          [...w.runs]
            .reverse()
            .find(
              (r) =>
                r.organizationId === scope.organizationId &&
                r.connectionId === connectionId &&
                r.kind === 'full',
            )?.status ?? null,
        ),
      probePassedSince: (_tx: unknown, scope: TenantScope, connectionId: bigint, since: Date) =>
        Promise.resolve(
          w.observations.some(
            (o) =>
              o.organizationId === scope.organizationId &&
              o.connectionId === connectionId &&
              o.proofResult === 'pass' &&
              o.receivedAt >= since,
          ),
        ),
      healthChecks: (scope: TenantScope, connectionId: bigint) =>
        Promise.resolve(
          w.healthChecks.filter(
            (h) => h.organizationId === scope.organizationId && h.connectionId === connectionId,
          ),
        ),
      healthEvents: (scope: TenantScope, connectionId: bigint, take: number) =>
        Promise.resolve(
          w.healthEvents
            .filter(
              (h) => h.organizationId === scope.organizationId && h.connectionId === connectionId,
            )
            .slice(-take)
            .reverse(),
        ),
      relayActivity: (scope: TenantScope, connectionId: bigint, since: Date) =>
        Promise.resolve(
          w.counters
            .filter(
              (c) =>
                c.organizationId === scope.organizationId &&
                c.connectionId === connectionId &&
                c.hourStart >= since,
            )
            .reduce<RelayActivity>(
              (sum, c) => ({
                accepted: sum.accepted + c.accepted,
                proofFailed: sum.proofFailed + c.proofFailed,
                tempFailed: sum.tempFailed + c.tempFailed,
                probes: sum.probes + c.probes,
              }),
              { accepted: 0, proofFailed: 0, tempFailed: 0, probes: 0 },
            ),
        ),
      activeEgressSets: () => Promise.resolve([...w.egressSets]),
    };
    return double as unknown as ProviderRunsRepository;
  }

  /**
   * `DomainDestinationsService.plan` / `replaceInTransaction` with the real step 2.3 planner and
   * the seeded presets; a write records one audit row and one routing event like the service.
   */
  destinationsDouble(
    config: Parameters<typeof hostRulesFrom>[0],
    audit: AuditService,
  ): DomainDestinationsService {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the doubles' methods close over the world
    const w = this;
    const rules = hostRulesFrom(config);
    const plan = (input: PutDestinationsInput): PlannedServer[] => {
      const result = planDestinations(input, SEEDED_PRESETS, rules);
      if (!result.ok) throw new DestinationRefusedException(result.reason, result.field);
      return [...result.servers].sort((a, b) => a.priority - b.priority);
    };
    const double = {
      plan: (input: PutDestinationsInput) => Promise.resolve(plan(input)),
      replaceInTransaction: async (
        _tx: unknown,
        principal: Principal,
        scope: TenantScope,
        publicId: string,
        input: PutDestinationsInput,
        client: { ip: string | null },
      ) => {
        if (w.failNextDestinationWrite) {
          w.failNextDestinationWrite = false;
          throw new Error('injected destination write failure');
        }
        const domain = w.domains.find(
          (d) => d.publicId === publicId && d.organizationId === scope.organizationId,
        );
        if (!domain) throw new Error('domain not found');
        const servers = plan(input);
        const previous = w.destinations.get(domain.id) ?? [];
        w.destinations.set(
          domain.id,
          servers.map((s) => ({
            host: s.host,
            port: s.port,
            priority: s.priority,
            tlsMode: s.tlsMode,
            provider: s.provider,
          })),
        );
        await audit.record({
          organizationId: scope.organizationId,
          actor: audit.actorFrom(principal),
          action: 'domain.destinations_replaced',
          resourceType: 'domain',
          resourceId: publicId,
          sourceIp: client.ip,
          metadata: { provider: input.provider, hosts: servers.map((s) => s.host) },
        });
        w.routingEvents.push({
          organizationId: scope.organizationId,
          domainPublicId: publicId,
          hosts: [...servers.map((s) => s.host), ...previous.map((p) => p.host)],
        });
        return { changed: true, view: {} };
      },
    };
    return double as unknown as DomainDestinationsService;
  }
}

/** Records audit rows (and lets tests scan them for secrets). */
export class RecordingProviderAudit extends AuditService {
  readonly entries: AuditEntry[] = [];
  constructor() {
    super({} as never);
  }
  override record(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
    return Promise.resolve();
  }
}

/** Overrides the provider repositories, destinations service, audit and the organization lock. */
export function overrideProviders(
  builder: TestingModuleBuilder,
  world: ProviderWorld,
  audit: RecordingProviderAudit,
  config: Readonly<ApiConfig>,
): TestingModuleBuilder {
  return builder
    .overrideProvider(ProviderConnectionsRepository)
    .useValue(world.connectionsDouble())
    .overrideProvider(ProviderGrantsRepository)
    .useValue(world.grantsDouble())
    .overrideProvider(ProviderRunsRepository)
    .useValue(world.runsDouble())
    .overrideProvider(DomainDestinationsService)
    .useValue(world.destinationsDouble(config, audit))
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(OrganizationLimitsService)
    .useValue({ lockOrganization: () => Promise.resolve() });
}

/** SHA-256 hex of a value (consent states, probe tokens). */
export { sha256 };
