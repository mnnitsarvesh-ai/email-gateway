/**
 * In-memory doubles of the step API-1 API-mode repository for the e2e suite: organizations and
 * domains with their protection modes and MX facts, 8.2 provider connections with their API-mode
 * rows, mailbox-access grants and journal sources, mailboxes with aliases and feed state
 * (subscription ids and client-state hashes included, so the public callbacks can be exercised),
 * per-mailbox copies with the copy message's subject and sender, hourly counters and risk reason
 * codes; plus the doubles of `ApiModeStatusService` and the feature lookup. Nothing here is used
 * by production code.
 */
/* eslint-disable @typescript-eslint/no-this-alias -- the doubles close over the world's state */
import type { TestingModuleBuilder } from '@nestjs/testing';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import {
  type ApiConnectionRow,
  type ApiConnectionUpdate,
  ApiModeRepository,
  type ConnectionFacts,
  type CopyFilter,
  type CopyRow,
  type CounterRow,
  type DomainModeRow,
  type MailboxDetailRow,
  type MailboxFilter,
  type OrganizationModeRow,
} from '../../src/modules/api-mode/repositories/api-mode.repository';
import type { OrganizationAccess } from '../../src/modules/organizations/domain/organization-access';
import {
  ApiModeStatusService,
  effectiveModeCounts,
  type ProtectionModeValue,
} from '../../src/tenancy/api-mode-status.service';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';

const copy = <T>(value: T): T => structuredClone(value);

export type StoredOrganization = OrganizationModeRow;

export interface StoredDomain extends DomainModeRow {
  organizationId: bigint;
  connectionId: bigint | null;
}

export interface StoredConnection extends ConnectionFacts {
  organizationId: bigint;
}

export interface StoredMailbox extends MailboxDetailRow {
  organizationId: bigint;
  apiConnectionId: bigint;
  providerUserId: string | null;
  feedCursor: string | null;
  subscriptionId: string | null;
  clientStateHash: string | null;
  syncRequestedAt: Date | null;
  nextSyncAt: Date | null;
  grantActive: boolean;
}

export interface StoredCopy extends CopyRow {
  organizationId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
}

export class ApiModeWorld {
  organizations: StoredOrganization[] = [];
  domains: StoredDomain[] = [];
  connections: StoredConnection[] = [];
  mailboxes: StoredMailbox[] = [];
  copies: StoredCopy[] = [];
  counters: Array<CounterRow & { organizationId: bigint }> = [];
  reasonCodes = new Map<string, string[]>();
  /** Organizations whose plan entitles `api_mode_protection`. */
  entitled = new Set<bigint>();
  /** The UPDATEs of the public callbacks (mailbox id → effect). */
  notifications: Array<{ mailboxId: bigint; effect: Record<string, boolean> }> = [];
  private nextId = 7000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.organizations = [];
    this.domains = [];
    this.connections = [];
    this.mailboxes = [];
    this.copies = [];
    this.counters = [];
    this.reasonCodes.clear();
    this.entitled.clear();
    this.notifications = [];
  }

  addOrganization(id: bigint, publicId: string, mode: ProtectionModeValue = 'inline') {
    const row: StoredOrganization = {
      id,
      publicId,
      status: 'active',
      protectionMode: mode,
      protectionModeChangedAt: null,
    };
    this.organizations.push(row);
    return row;
  }

  addDomain(organizationId: bigint, name: string, patch: Partial<StoredDomain> = {}): StoredDomain {
    const row: StoredDomain = {
      id: this.id(),
      publicId: crypto.randomUUID(),
      name,
      organizationId,
      configured: null,
      changedAt: null,
      mxPointsToGateway: false,
      connectionId: null,
      ...patch,
    };
    this.domains.push(row);
    return row;
  }

  addConnection(organizationId: bigint, patch: Partial<StoredConnection> = {}): StoredConnection {
    const row: StoredConnection = {
      id: this.id(),
      organizationId,
      publicId: crypto.randomUUID(),
      displayName: `Connection ${this.nextId}`,
      provider: 'microsoft_365',
      status: 'active',
      externalTenantId: '11111111-2222-3333-4444-555555555555',
      activeTenantKey: 'microsoft_365:11111111-2222-3333-4444-555555555555',
      attestations: null,
      grant: null,
      api: null,
      journalSources: [],
      ...patch,
    };
    this.connections.push(row);
    return row;
  }

  apiRow(patch: Partial<ApiConnectionRow> = {}): ApiConnectionRow {
    return {
      id: this.id(),
      publicId: crypto.randomUUID(),
      feedsEnabled: false,
      feedMode: 'poll',
      feedsEnabledAt: null,
      inventoryStatus: 'never',
      inventorySyncedAt: null,
      inventoryRequestedAt: null,
      nextInventoryAt: null,
      mailboxesTotal: null,
      healthStatus: 'unknown',
      healthChecks: null,
      healthChangedAt: null,
      throttledUntil: null,
      lastErrorCode: null,
      rowVersion: 1,
      ...patch,
    };
  }

  addMailbox(connection: StoredConnection, address: string, patch: Partial<StoredMailbox> = {}) {
    if (connection.api === null) connection.api = this.apiRow();
    const domain = this.domains.find(
      (d) => d.organizationId === connection.organizationId && address.endsWith(`@${d.name}`),
    );
    const row: StoredMailbox = {
      id: this.id(),
      publicId: crypto.randomUUID(),
      organizationId: connection.organizationId,
      apiConnectionId: connection.api.id,
      connectionPublicId: connection.publicId,
      providerUserId: `user-${this.nextId}`,
      primaryAddress: address,
      domain: domain === undefined ? null : { publicId: domain.publicId, name: domain.name },
      status: 'active',
      coverageState: 'covered',
      coverageChangedAt: null,
      feedStatus: 'off',
      journalLastSeenAt: null,
      lastSyncAt: null,
      lastErrorCode: null,
      aliases: [],
      feedStartedAt: null,
      subscribed: false,
      subscriptionExpiresAt: null,
      lastChangeAt: null,
      lastGapAt: null,
      consecutiveFailures: 0,
      feedCursor: null,
      subscriptionId: null,
      clientStateHash: null,
      syncRequestedAt: null,
      nextSyncAt: null,
      grantActive: connection.grant?.status === 'active',
      ...patch,
    };
    this.mailboxes.push(row);
    return row;
  }

  addCopy(mailbox: StoredMailbox, patch: Partial<StoredCopy> = {}): StoredCopy {
    const row: StoredCopy = {
      id: this.id(),
      publicId: crypto.randomUUID(),
      organizationId: mailbox.organizationId,
      apiConnectionId: mailbox.apiConnectionId,
      mailboxId: mailbox.id,
      receivedAt: new Date(Date.now() - 60_000),
      mailboxPublicId: mailbox.publicId,
      mailboxAddress: mailbox.primaryAddress,
      connectionPublicId: mailbox.connectionPublicId,
      messageId: this.id(),
      source: 'journal',
      seenJournal: true,
      seenApi: false,
      direction: 'inbound',
      status: 'scanned',
      verdict: 'clean',
      riskScore: 10,
      verdictAuthority: 'copy',
      providerDeliveredAt: null,
      deliveredBasis: 'ingest',
      verdictAt: new Date(),
      lagMs: 1000,
      subject: 'Quarterly invoice',
      headerFrom: 'billing@fabrikam.example',
      ...patch,
    };
    this.copies.push(row);
    return row;
  }

  private facts(c: StoredConnection): ConnectionFacts {
    const { organizationId: _o, ...facts } = c;
    return copy(facts);
  }

  private mine<T extends { organizationId: bigint }>(rows: T[], scope: TenantScope): T[] {
    return rows.filter((r) => r.organizationId === scope.organizationId);
  }

  private orgMode(organizationId: bigint): ProtectionModeValue {
    return this.organizations.find((o) => o.id === organizationId)?.protectionMode ?? 'inline';
  }

  /** The `ApiModeRepository` double. */
  double(): Partial<Record<keyof ApiModeRepository, unknown>> {
    const w = this;
    const conn = (scope: TenantScope, publicId: string) =>
      w.connections.find(
        (c) => c.organizationId === scope.organizationId && c.publicId === publicId,
      );
    const mailboxView = (m: StoredMailbox): MailboxDetailRow => {
      const {
        organizationId: _o,
        apiConnectionId: _a,
        providerUserId: _p,
        feedCursor: _f,
        subscriptionId: _s,
        clientStateHash: _c,
        syncRequestedAt: _r,
        nextSyncAt: _n,
        grantActive: _g,
        ...view
      } = m;
      return copy({ ...view, subscribed: m.subscriptionId !== null });
    };
    const copyView = (c: StoredCopy): CopyRow => {
      const { organizationId: _o, apiConnectionId: _a, mailboxId: _m, ...view } = c;
      return copy(view);
    };
    return {
      findOrganization: (access: OrganizationAccess, publicId: string) => {
        const org = w.organizations.find(
          (o) =>
            o.publicId === publicId &&
            (access.kind === 'platform' || o.id === access.scope.organizationId),
        );
        return Promise.resolve(org ? copy(org) : null);
      },
      lockOrganization: (_tx: unknown, id: bigint) => {
        const org = w.organizations.find((o) => o.id === id);
        return Promise.resolve(org ? copy(org) : null);
      },
      domainModes: (_tx: unknown, organizationId: bigint) =>
        Promise.resolve(
          copy(w.domains.filter((d) => d.organizationId === organizationId)).map(
            ({ organizationId: _o, connectionId: _c, ...d }) => d,
          ),
        ),
      lockDomain: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const d = w.mine(w.domains, scope).find((x) => x.publicId === publicId);
        if (!d) return Promise.resolve(null);
        const { organizationId: _o, connectionId: _c, ...row } = copy(d);
        return Promise.resolve(row);
      },
      setOrganizationMode: (_tx: unknown, id: bigint, mode: ProtectionModeValue, now: Date) => {
        const org = w.organizations.find((o) => o.id === id)!;
        org.protectionMode = mode;
        org.protectionModeChangedAt = now;
        return Promise.resolve();
      },
      setDomainMode: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        mode: ProtectionModeValue | null,
        now: Date,
      ) => {
        const d = w.mine(w.domains, scope).find((x) => x.id === id);
        if (!d) return Promise.resolve(false);
        d.configured = mode;
        d.changedAt = now;
        return Promise.resolve(true);
      },
      connections: (scope: TenantScope) =>
        Promise.resolve(w.mine(w.connections, scope).map((c) => w.facts(c))),
      connection: (scope: TenantScope, publicId: string) => {
        const c = conn(scope, publicId);
        return Promise.resolve(c ? w.facts(c) : null);
      },
      lockConnection: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const c = conn(scope, publicId);
        if (!c) return Promise.resolve(null);
        if (c.api === null) c.api = w.apiRow();
        return Promise.resolve(w.facts(c));
      },
      updateApiConnection: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        rowVersion: number,
        data: ApiConnectionUpdate,
      ) => {
        const c = w.mine(w.connections, scope).find((x) => x.api?.id === id);
        if (!c?.api || c.api.rowVersion !== rowVersion) return Promise.resolve(false);
        Object.assign(c.api, data, { rowVersion: c.api.rowVersion + 1 });
        return Promise.resolve(true);
      },
      requestInventory: (_tx: unknown, scope: TenantScope, id: bigint, now: Date) => {
        const c = w.mine(w.connections, scope).find((x) => x.api?.id === id);
        if (c?.api) Object.assign(c.api, { inventoryRequestedAt: now, nextInventoryAt: now });
        return Promise.resolve();
      },
      markFeedsPending: (
        _tx: unknown,
        scope: TenantScope,
        apiConnectionId: bigint,
        domainIds: readonly bigint[],
        now: Date,
      ) => {
        const ids = new Set(domainIds);
        const names = new Set(w.domains.filter((d) => ids.has(d.id)).map((d) => d.publicId));
        let n = 0;
        for (const m of w.mine(w.mailboxes, scope)) {
          if (
            m.apiConnectionId === apiConnectionId &&
            m.status === 'active' &&
            m.providerUserId !== null &&
            m.domain !== null &&
            names.has(m.domain.publicId)
          ) {
            m.feedStatus = 'pending';
            m.nextSyncAt = now;
            n += 1;
          }
        }
        return Promise.resolve(n);
      },
      apiModeDomains: (scope: TenantScope) =>
        Promise.resolve(
          w
            .mine(w.domains, scope)
            .filter((d) => (d.configured ?? w.orgMode(scope.organizationId)) !== 'inline')
            .map((d) => ({
              id: d.id,
              publicId: d.publicId,
              name: d.name,
              connectionId: d.connectionId,
            })),
        ),
      linkedDomainNames: (scope: TenantScope, connectionId: bigint) =>
        Promise.resolve(
          w
            .mine(w.domains, scope)
            .filter((d) => d.connectionId === connectionId)
            .map((d) => d.name)
            .sort(),
        ),
      coverage: (scope: TenantScope, ids: readonly bigint[]) => {
        const out = new Map<bigint, { covered: number; gap: number }>();
        for (const m of w.mine(w.mailboxes, scope)) {
          if (!ids.includes(m.apiConnectionId) || m.status !== 'active') continue;
          const e = out.get(m.apiConnectionId) ?? { covered: 0, gap: 0 };
          if (m.coverageState === 'covered') e.covered += 1;
          if (m.coverageState === 'gap') e.gap += 1;
          out.set(m.apiConnectionId, e);
        }
        return Promise.resolve(out);
      },
      feedCounts: (scope: TenantScope, apiConnectionId: bigint) => {
        const rows = w
          .mine(w.mailboxes, scope)
          .filter(
            (m) =>
              m.apiConnectionId === apiConnectionId &&
              m.status === 'active' &&
              m.providerUserId !== null,
          );
        return Promise.resolve({
          inScope: rows.length,
          active: rows.filter((m) => m.feedStatus === 'active').length,
        });
      },
      counters: (scope: TenantScope, ids: readonly bigint[], from: Date) =>
        Promise.resolve(
          copy(
            w
              .mine(w.counters, scope)
              .filter((c) => ids.includes(c.apiConnectionId) && c.hour >= from)
              .map(({ organizationId: _o, ...c }) => c),
          ),
        ),
      mailboxes: (
        scope: TenantScope,
        filter: MailboxFilter,
        page: { take: number; beforeId?: bigint },
      ) =>
        Promise.resolve(
          w
            .mine(w.mailboxes, scope)
            .filter(
              (m) =>
                (filter.connectionPublicId === undefined ||
                  m.connectionPublicId === filter.connectionPublicId) &&
                (!filter.coverage || filter.coverage.includes(m.coverageState)) &&
                (!filter.feedStatus || filter.feedStatus.includes(m.feedStatus)) &&
                (!filter.status || filter.status.includes(m.status)) &&
                (filter.domainPublicId === undefined ||
                  m.domain?.publicId === filter.domainPublicId) &&
                (filter.q === undefined ||
                  m.primaryAddress.startsWith(filter.q) ||
                  m.aliases.some((a) => a.startsWith(filter.q!))) &&
                (page.beforeId === undefined || m.id < page.beforeId),
            )
            .sort((a, b) => (a.id < b.id ? 1 : -1))
            .slice(0, page.take)
            .map((m) => mailboxView(m)),
        ),
      mailbox: (scope: TenantScope, publicId: string) => {
        const m = w.mine(w.mailboxes, scope).find((x) => x.publicId === publicId);
        return Promise.resolve(m ? { ...mailboxView(m), id: m.id } : null);
      },
      lockMailbox: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const m = w.mine(w.mailboxes, scope).find((x) => x.publicId === publicId);
        return Promise.resolve(
          m
            ? {
                id: m.id,
                publicId: m.publicId,
                feedStatus: m.feedStatus,
                status: m.status,
                connectionPublicId: m.connectionPublicId,
                grantActive: m.grantActive,
              }
            : null,
        );
      },
      requestResync: (_tx: unknown, scope: TenantScope, id: bigint, now: Date) => {
        const m = w.mine(w.mailboxes, scope).find((x) => x.id === id);
        if (m) Object.assign(m, { feedCursor: null, feedStartedAt: null, syncRequestedAt: now });
        return Promise.resolve();
      },
      detections: (
        scope: TenantScope,
        filter: CopyFilter,
        range: { from: Date; to: Date },
        page: { take: number; before?: { at: Date; id: bigint } },
      ) =>
        Promise.resolve(
          w
            .mine(w.copies, scope)
            .filter(
              (c) =>
                c.receivedAt >= range.from &&
                c.receivedAt < range.to &&
                (!filter.verdict || (c.verdict !== null && filter.verdict.includes(c.verdict))) &&
                (!filter.status || filter.status.includes(c.status)) &&
                (!filter.source || filter.source.includes(c.source)) &&
                (filter.mailboxPublicId === undefined ||
                  c.mailboxPublicId === filter.mailboxPublicId) &&
                (filter.connectionPublicId === undefined ||
                  c.connectionPublicId === filter.connectionPublicId) &&
                (filter.minRiskScore === undefined || (c.riskScore ?? -1) >= filter.minRiskScore) &&
                (page.before === undefined ||
                  c.receivedAt < page.before.at ||
                  (c.receivedAt.getTime() === page.before.at.getTime() && c.id < page.before.id)),
            )
            .sort(
              (a, b) => b.receivedAt.getTime() - a.receivedAt.getTime() || (a.id < b.id ? 1 : -1),
            )
            .slice(0, page.take)
            .map((c) => copyView(c)),
        ),
      detection: (scope: TenantScope, publicId: string) => {
        const c = w.mine(w.copies, scope).find((x) => x.publicId === publicId);
        return Promise.resolve(c ? copyView(c) : null);
      },
      recentCopies: (scope: TenantScope, mailboxId: bigint, take: number) =>
        Promise.resolve(
          w
            .mine(w.copies, scope)
            .filter((c) => c.mailboxId === mailboxId)
            .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())
            .slice(0, take)
            .map((c) => copyView(c)),
        ),
      reasonCodes: (_scope: TenantScope, messageId: bigint) =>
        Promise.resolve([...(w.reasonCodes.get(messageId.toString()) ?? [])]),
      mailboxBySubscription: (subscriptionId: string) => {
        const m = w.mailboxes.find((x) => x.subscriptionId === subscriptionId);
        if (!m) return Promise.resolve(null);
        const c = w.connections.find((x) => x.api?.id === m.apiConnectionId);
        return Promise.resolve({
          id: m.id,
          feedStatus: m.feedStatus,
          clientStateHash: m.clientStateHash,
          boundTenantId: c?.externalTenantId ?? null,
        });
      },
      applyNotification: (mailboxId: bigint, effect: Record<string, boolean>) => {
        w.notifications.push({ mailboxId, effect: { ...effect } });
        const m = w.mailboxes.find((x) => x.id === mailboxId)!;
        if (effect.requestSync) m.syncRequestedAt ??= new Date();
        if (effect.expireSubscription) m.subscriptionExpiresAt = new Date();
        if (effect.clearSubscription) m.subscriptionId = null;
        return Promise.resolve();
      },
    };
  }

  /** The `ApiModeStatusService` double (entitlement and effective modes from the world). */
  statusDouble(): Partial<ApiModeStatusService> {
    const w = this;
    const status = (organizationId: bigint) => {
      const mode = w.orgMode(organizationId);
      const counts = effectiveModeCounts(
        mode,
        w.domains
          .filter((d) => d.organizationId === organizationId)
          .map((d) => ({ mode: d.configured, count: 1 })),
      );
      const entitled = w.entitled.has(organizationId);
      return {
        entitled,
        active: entitled && counts.api + counts.hybrid > 0,
        organizationMode: mode,
        domainsByEffectiveMode: counts,
      };
    };
    return {
      status: (organizationId: bigint) => Promise.resolve(status(organizationId)),
      isActive: (organizationId: bigint) => Promise.resolve(status(organizationId).active),
    };
  }

  /** `OrganizationFeaturesService`: `api_mode_protection` per `entitled`. */
  featuresDouble(): Partial<OrganizationFeaturesService> {
    const w = this;
    const on = (organizationId: bigint, key: string) =>
      key === 'api_mode_protection' && w.entitled.has(organizationId);
    return {
      isEnabled: (organizationId: bigint, key: string) => Promise.resolve(on(organizationId, key)),
      isEffectivelyEnabled: (organizationId: bigint, key: string) =>
        Promise.resolve(on(organizationId, key)),
      effective: (organizationId: bigint, keys: readonly string[]) =>
        Promise.resolve(Object.fromEntries(keys.map((k) => [k, on(organizationId, k)]))),
    };
  }
}

/** Overrides the API-mode repository, the API-mode status and the feature lookup. */
export function overrideApiMode(
  builder: TestingModuleBuilder,
  world: ApiModeWorld,
): TestingModuleBuilder {
  return builder
    .overrideProvider(ApiModeRepository)
    .useValue(world.double())
    .overrideProvider(ApiModeStatusService)
    .useValue(world.statusDouble())
    .overrideProvider(OrganizationFeaturesService)
    .useValue(world.featuresDouble());
}
