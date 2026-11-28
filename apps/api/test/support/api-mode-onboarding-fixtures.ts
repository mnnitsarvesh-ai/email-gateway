/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md A10, B3, B6, B8): in-memory doubles
 * of `ApiModeOnboardingRepository`, `ProviderVerificationsRepository` (the ownership block) and
 * the provider-connections reader, over `ApiModeWorld` (domains, connections, mailboxes, copies)
 * plus the onboarding state the world does not model (domain lifecycle facts, scope rows,
 * departments, journal acceptance, provider checks). Every read filters by the scope's
 * organization, as the real repositories do.
 */
import type { TestingModuleBuilder } from '@nestjs/testing';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { ApiModeOnboardingRepository } from '../../src/modules/api-mode/repositories/api-mode-onboarding.repository';
import type {
  DomainMailboxStats,
  DomainSettingsRow,
  FirstCopyRow,
  OnboardingDomainRow,
} from '../../src/modules/api-mode/repositories/api-mode-onboarding.repository';
import { ProviderVerificationsRepository } from '../../src/modules/domains/repositories/provider-verifications.repository';
import { BoundConnectionsReader } from '../../src/modules/provider-connections/repositories/bound-connections.repository';
import type { ApiModeWorld, StoredDomain, StoredMailbox } from './api-mode-fixtures';

type DomainStatus = OnboardingDomainRow['status'];

export interface DomainFacts {
  status: DomainStatus;
  ownershipMethod: 'dns_txt' | 'provider_tenant' | null;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  createdAt: Date;
  activatedAt: Date | null;
}

export class OnboardingStore {
  /** Lifecycle facts per domain id (absent = active, TXT-owned, created 2 h ago). */
  readonly domainFacts = new Map<bigint, Partial<DomainFacts>>();
  readonly settings = new Map<
    bigint,
    DomainSettingsRow & { organizationId: bigint; scopeChangedAt: Date | null }
  >();
  readonly departments: Array<{
    organizationId: bigint;
    publicId: string;
    name: string;
    members: number;
  }> = [];
  /** Journal sources' last acceptance (public id → time). */
  readonly lastAccepted = new Map<string, Date>();
  /** Mail-flow grant status per provider connection id. */
  readonly mailFlow = new Map<bigint, string>();
  /** Capable (bound, mail-flow active) connections per organization. */
  readonly capable = new Map<bigint, Array<{ id: bigint; publicId: string }>>();
  /** Provider rows per domain id (newest last). */
  readonly providerRows = new Map<
    bigint,
    Array<{
      id: bigint;
      organizationId: bigint;
      status: 'pending' | 'verified' | 'failed' | 'expired';
      providerResult: 'verified' | 'unverified' | 'absent' | 'alias' | 'error' | null;
      providerConnectionId: bigint | null;
      connectionPublicId: string | null;
      createdAt: Date;
      providerCheckedAt: Date | null;
      expiresAt: Date;
    }>
  >();
  /** Scope writes the double performed (assertions). */
  readonly selectionWrites: Array<{ domainId: bigint; selected: number }> = [];

  reset(): void {
    this.domainFacts.clear();
    this.settings.clear();
    this.departments.length = 0;
    this.lastAccepted.clear();
    this.mailFlow.clear();
    this.capable.clear();
    this.providerRows.clear();
    this.selectionWrites.length = 0;
  }
}

const HOUR = 3_600_000;

export function onboardingRepositoryDouble(
  world: ApiModeWorld,
  store: OnboardingStore,
): Partial<Record<keyof ApiModeOnboardingRepository, unknown>> {
  const orgMode = (organizationId: bigint) =>
    world.organizations.find((o) => o.id === organizationId)?.protectionMode ?? 'inline';
  const row = (d: StoredDomain): OnboardingDomainRow => {
    const f = store.domainFacts.get(d.id) ?? {};
    return {
      id: d.id,
      publicId: d.publicId,
      name: d.name,
      status: f.status ?? 'active',
      configuredMode: d.configured,
      organizationMode: orgMode(d.organizationId),
      inboundEnabled: f.inboundEnabled ?? false,
      outboundEnabled: f.outboundEnabled ?? false,
      ownershipMethod: f.ownershipMethod === undefined ? 'dns_txt' : f.ownershipMethod,
      createdAt: f.createdAt ?? new Date(Date.now() - 2 * HOUR),
      activatedAt: f.activatedAt === undefined ? new Date(Date.now() - HOUR) : f.activatedAt,
      mxPointsToGateway: d.mxPointsToGateway,
      linkedConnectionId: d.connectionId,
    };
  };
  const mine = (scope: TenantScope) =>
    world.domains.filter(
      (d) =>
        d.organizationId === scope.organizationId &&
        (store.domainFacts.get(d.id)?.status ?? 'active') !== ('deleted' as DomainStatus),
    );
  const domainMailboxes = (scope: TenantScope, domainId: bigint): StoredMailbox[] => {
    const d = world.domains.find((x) => x.id === domainId);
    return world.mailboxes.filter(
      (m) =>
        m.organizationId === scope.organizationId &&
        d !== undefined &&
        m.domain?.publicId === d.publicId &&
        m.status !== 'deleted',
    );
  };
  const copyRow = (c: (typeof world.copies)[number]): FirstCopyRow => ({
    publicId: c.publicId,
    receivedAt: c.receivedAt,
    verdict: c.verdict,
    lagMs: c.lagMs,
    source: c.source,
    policyState: c.policyState,
    remediationState: c.remediationState,
  });
  return {
    domains: (scope: TenantScope, page: { take: number; beforeId?: bigint; modes?: string[] }) =>
      Promise.resolve(
        mine(scope)
          .map(row)
          .filter(
            (d) =>
              (page.beforeId === undefined || d.id < page.beforeId) &&
              (!page.modes || page.modes.includes(d.configuredMode ?? d.organizationMode)),
          )
          .sort((a, b) => (a.id < b.id ? 1 : -1))
          .slice(0, page.take),
      ),
    domain: (scope: TenantScope, publicId: string) =>
      Promise.resolve(
        mine(scope)
          .map(row)
          .find((d) => d.publicId === publicId) ?? null,
      ),
    lockDomain: (_tx: unknown, scope: TenantScope, publicId: string) =>
      Promise.resolve(
        mine(scope)
          .map(row)
          .find((d) => d.publicId === publicId) ?? null,
      ),
    mailboxStats: (scope: TenantScope, domainIds: readonly bigint[]) => {
      const out = new Map<bigint, DomainMailboxStats>();
      for (const id of domainIds) {
        const list = domainMailboxes(scope, id);
        if (list.length === 0) continue;
        const inScope = list.filter((m) => (m.scopeState ?? 'in_scope') === 'in_scope');
        const active = inScope.filter((m) => m.status === 'active');
        out.set(id, {
          total: list.length,
          inScope: inScope.length,
          excluded: list.length - inScope.length,
          covered: active.filter((m) => m.coverageState === 'covered').length,
          gap: active.filter((m) => m.coverageState === 'gap').length,
          feedsActive: active.filter((m) => m.feedStatus === 'active').length,
          selected: list.filter((m) => m.scopeSelected === true).length,
          lastSeenAt:
            list
              .map((m) => m.journalLastSeenAt)
              .filter((d): d is Date => d !== null)
              .sort((a, b) => b.getTime() - a.getTime())[0] ?? null,
        });
      }
      return Promise.resolve(out);
    },
    settings: (scope: TenantScope, domainIds: readonly bigint[]) =>
      Promise.resolve(
        new Map(
          [...store.settings.entries()]
            .filter(
              ([id, s]) => domainIds.includes(id) && s.organizationId === scope.organizationId,
            )
            .map(([id, s]) => [id, structuredClone(s)]),
        ),
      ),
    copy: (scope: TenantScope, id: bigint) => {
      const c = world.copies.find((x) => x.id === id && x.organizationId === scope.organizationId);
      return Promise.resolve(c ? copyRow(c) : null);
    },
    newestCopy: (scope: TenantScope, domainId: bigint, now: Date) => {
      const ids = new Set(domainMailboxes(scope, domainId).map((m) => m.id));
      const c = world.copies
        .filter(
          (x) =>
            x.organizationId === scope.organizationId &&
            ids.has(x.mailboxId) &&
            x.direction !== 'outbound' &&
            x.receivedAt.getTime() >= now.getTime() - 7 * 24 * HOUR,
        )
        .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())[0];
      return Promise.resolve(c ? copyRow(c) : null);
    },
    failedCopies: (scope: TenantScope, apiConnectionId: bigint, since: Date, cap: number) =>
      Promise.resolve(
        Math.min(
          cap,
          world.copies.filter(
            (c) =>
              c.organizationId === scope.organizationId &&
              c.apiConnectionId === apiConnectionId &&
              c.receivedAt >= since &&
              (c.status === 'scan_failed' || c.status === 'parse_failed'),
          ).length,
        ),
      ),
    journalSources: (scope: TenantScope, connectionId: bigint) => {
      const c = world.connections.find(
        (x) => x.id === connectionId && x.organizationId === scope.organizationId,
      );
      return Promise.resolve(
        (c?.journalSources ?? []).map((s) => ({
          publicId: s.publicId,
          status: s.status,
          healthStatus: s.healthStatus,
          verifiedAt: s.verifiedAt,
          lastAcceptedAt: store.lastAccepted.get(s.publicId) ?? null,
        })),
      );
    },
    mailFlowGrants: (_scope: TenantScope, ids: readonly bigint[]) =>
      Promise.resolve(
        new Map(
          ids.flatMap((id) => (store.mailFlow.has(id) ? [[id, store.mailFlow.get(id)!]] : [])),
        ),
      ),
    departments: (scope: TenantScope, publicIds: readonly string[]) =>
      Promise.resolve(
        store.departments
          .filter(
            (d) => d.organizationId === scope.organizationId && publicIds.includes(d.publicId),
          )
          .map((d) => ({ publicId: d.publicId, name: d.name, memberCount: d.members })),
      ),
    lockDepartments: (_tx: unknown, scope: TenantScope, publicIds: readonly string[]) =>
      Promise.resolve(
        new Set(
          store.departments
            .filter(
              (d) => d.organizationId === scope.organizationId && publicIds.includes(d.publicId),
            )
            .map((d) => d.publicId),
        ),
      ),
    lockSettings: (_tx: unknown, scope: TenantScope, domainId: bigint) => {
      const s = store.settings.get(domainId);
      return Promise.resolve(
        s && s.organizationId === scope.organizationId ? structuredClone(s) : null,
      );
    },
    domainMailboxIds: (
      _tx: unknown,
      scope: TenantScope,
      domainId: bigint,
      publicIds: readonly string[],
    ) =>
      Promise.resolve(
        domainMailboxes(scope, domainId)
          .filter((m) => publicIds.map((p) => p.toLowerCase()).includes(m.publicId))
          .map((m) => m.id),
      ),
    writeSettings: (
      _tx: unknown,
      scope: TenantScope,
      domainId: bigint,
      rowVersion: number | null,
      data: {
        scopeKind: DomainSettingsRow['scopeKind'];
        scopeDepartmentIds: string[] | null;
        now: Date;
      },
    ) => {
      const current = store.settings.get(domainId);
      if (rowVersion === null) {
        if (current) {
          const error = new Error('unique') as Error & { code: string };
          error.code = 'P2002';
          throw error;
        }
      } else if (!current || current.rowVersion !== rowVersion) {
        return Promise.resolve(false);
      }
      store.settings.set(domainId, {
        organizationId: scope.organizationId,
        domainId,
        scopeKind: data.scopeKind,
        scopeDepartmentIds: data.scopeDepartmentIds,
        scopeChangedAt: data.now,
        scopeRecomputeRequestedAt: data.now,
        firstCopyId: current?.firstCopyId ?? null,
        firstCopyReceivedAt: current?.firstCopyReceivedAt ?? null,
        rowVersion: (current?.rowVersion ?? 0) + 1,
        updatedAt: data.now,
      });
      return Promise.resolve(true);
    },
    replaceSelection: (
      _tx: unknown,
      scope: TenantScope,
      domainId: bigint,
      ids: readonly bigint[],
    ) => {
      const list = domainMailboxes(scope, domainId);
      let cleared = 0;
      for (const m of list) {
        if (m.scopeSelected) cleared++;
        m.scopeSelected = ids.includes(m.id);
      }
      store.selectionWrites.push({ domainId, selected: ids.length });
      return Promise.resolve({ cleared, selected: ids.length });
    },
  };
}

/** The ownership block's two reads (provider rows of a domain, capable connections). */
export function providerVerificationsDouble(
  store: OnboardingStore,
): Partial<Record<keyof ProviderVerificationsRepository, unknown>> {
  return {
    latest: (scope: TenantScope, domainId: bigint) => {
      const rows = (store.providerRows.get(domainId) ?? []).filter(
        (r) => r.organizationId === scope.organizationId,
      );
      const r = rows.at(-1);
      return Promise.resolve(
        r
          ? {
              id: r.id,
              domainId,
              status: r.status,
              providerConnectionId: r.providerConnectionId,
              providerResult: r.providerResult,
              providerCheckedAt: r.providerCheckedAt,
              providerErrorCode: null,
              expiresAt: r.expiresAt,
              createdAt: r.createdAt,
              connectionPublicId: r.connectionPublicId,
            }
          : null,
      );
    },
  };
}

export function connectionsReaderDouble(
  store: OnboardingStore,
): Partial<Record<keyof BoundConnectionsReader, unknown>> {
  return {
    ownershipCapableConnections: (scope: TenantScope) =>
      Promise.resolve(
        (store.capable.get(scope.organizationId) ?? []).map((c) => ({
          ...c,
          provider: 'microsoft_365' as const,
          displayName: 'Contoso Microsoft 365',
        })),
      ),
  };
}

/** Overrides the onboarding repository and the ownership reads (after `overrideApiMode`). */
export function overrideOnboarding(
  builder: TestingModuleBuilder,
  world: ApiModeWorld,
  store: OnboardingStore,
): TestingModuleBuilder {
  return builder
    .overrideProvider(ApiModeOnboardingRepository)
    .useValue(onboardingRepositoryDouble(world, store))
    .overrideProvider(ProviderVerificationsRepository)
    .useValue(providerVerificationsDouble(store))
    .overrideProvider(BoundConnectionsReader)
    .useValue(connectionsReaderDouble(store));
}
