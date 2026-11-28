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
import type { DlpAction } from '@email-gateway/database';
import { remediationActionKey, type RemediationActionKind } from '@email-gateway/mailbox-api';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import {
  ApiRemediationRepository,
  type CopyFacts,
  type DomainPolicyRow,
  type LockedRemediation,
  type PolicyRow,
  type PolicyWrite,
  type RemediationDetailRow,
  type RemediationFilter,
} from '../../src/modules/api-mode/repositories/api-remediation.repository';
import {
  type QueuedAction,
  type QueueRemediationAction,
  RemediationActionWriter,
} from '../../src/modules/api-mode/repositories/remediation-action-writer';
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
  type RemediationCounterRow,
} from '../../src/modules/api-mode/repositories/api-mode.repository';
import type { OrganizationAccess } from '../../src/modules/organizations/domain/organization-access';
import {
  ApiModeStatusService,
  effectiveModeCounts,
  type ProtectionModeValue,
} from '../../src/tenancy/api-mode-status.service';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';
import { ApiClawbackRepository } from '../../src/modules/api-mode/repositories/api-clawback.repository';
import { ClawbackStore, clawbackRepositoryDouble } from './api-mode-clawback-fixtures';

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
  /** Step API-4 (B6). */
  scopeState?: 'in_scope' | 'excluded';
  scopeSelected?: boolean;
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
  /** Step API-2: the copy's remediation generation and last action. */
  remediationGeneration: number;
  lastActionId: bigint | null;
}

/** Step API-2: one stored remediation policy row. */
export interface StoredPolicy extends PolicyRow {
  organizationId: bigint;
}

/** Step API-2: one stored remediation action row (provider refs as stored, ids included). */
export interface StoredAction {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
  copyId: bigint;
  copyReceivedAt: Date;
  action: RemediationActionKind;
  generation: number;
  actionKey: string;
  trigger: 'policy' | 'admin' | 'release' | 'end_user' | 'system' | 'clawback' | 'purge';
  /** Step API-3: the clawback of a `clawback` / `purge` row (public id). */
  clawbackPublicId?: string | null;
  status:
    'pending' | 'in_progress' | 'succeeded' | 'failed' | 'skipped' | 'simulated' | 'cancelled';
  reasonCode: string | null;
  decision: unknown;
  reversesActionId: bigint | null;
  reversedByActionId: bigint | null;
  quarantineEntryId: bigint | null;
  quarantineEntryPublicId: string | null;
  releaseLogId: bigint | null;
  requestedByType: 'system' | 'user' | 'api_key';
  requestedByUserId: bigint | null;
  requestReason: string | null;
  attempts: number;
  locateAttempts: number;
  nextAttemptAt: Date | null;
  lastErrorCode: string | null;
  lastHttpStatus: number | null;
  providerRefs: unknown;
  verdictAt: Date | null;
  startedAt: Date | null;
  completedAt: Date | null;
  rowVersion: number;
  createdAt: Date;
  updatedAt: Date;
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
  /** Step API-2: remediation policies, actions, counters and the copies' quarantine entries. */
  policies: StoredPolicy[] = [];
  /** Step API-4: detect rows and DLP results keyed `<organizationId>:<messageId>`. */
  detectRows = new Map<string, unknown>();
  dlpResults = new Map<string, { action: DlpAction; verdict: string; categories: string[] }>();
  actions: StoredAction[] = [];
  remediationCounters: Array<RemediationCounterRow & { organizationId: bigint }> = [];
  /** copy id → its latest mailbox-located quarantine entry (public id, state). */
  copyEntries = new Map<bigint, { publicId: string; state: string }>();
  /** `markCopyPending` calls (copy id, action, last action id). */
  copyUpdates: Array<{ copyId: bigint; remediationAction: string | null; lastActionId: bigint }> =
    [];
  /** Step API-3: clawbacks, targets, reports, settings, outbox and alert windows. */
  claw = new ClawbackStore();
  /** User id → public id (the joined public ids of the clawback and report views). */
  userPublicIds = new Map<bigint, string>();
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
    this.policies = [];
    this.actions = [];
    this.remediationCounters = [];
    this.copyEntries.clear();
    this.copyUpdates = [];
    this.claw.reset();
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
      remediationPaused: false,
      remediationPausedAt: null,
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
      remediationState: 'none',
      remediationAction: null,
      remediationId: null,
      quarantineEntryId: null,
      remediationGeneration: 0,
      lastActionId: null,
      verdictRevision: 0,
      policyState: 'none',
      policyDisposition: null,
      policyTagged: false,
      dlpAction: null,
      ...patch,
    };
    this.copies.push(row);
    return row;
  }

  /** Step API-2: a remediation action of a copy (defaults: a succeeded policy quarantine move). */
  addAction(c: StoredCopy, patch: Partial<StoredAction> = {}): StoredAction {
    const action = patch.action ?? 'move_quarantine';
    const generation = patch.generation ?? c.remediationGeneration;
    const now = new Date();
    const row: StoredAction = {
      id: this.id(),
      publicId: crypto.randomUUID(),
      organizationId: c.organizationId,
      apiConnectionId: c.apiConnectionId,
      mailboxId: c.mailboxId,
      copyId: c.id,
      copyReceivedAt: c.receivedAt,
      action,
      generation,
      actionKey: remediationActionKey(c.publicId, action, generation),
      trigger: 'policy',
      status: 'succeeded',
      reasonCode: null,
      decision: null,
      reversesActionId: null,
      reversedByActionId: null,
      quarantineEntryId: null,
      quarantineEntryPublicId: null,
      releaseLogId: null,
      requestedByType: 'system',
      requestedByUserId: null,
      requestReason: null,
      attempts: 1,
      locateAttempts: 0,
      nextAttemptAt: null,
      lastErrorCode: null,
      lastHttpStatus: null,
      providerRefs: {
        before: ['AAMkAGI2-provider-id'],
        after: ['AAMkAGI3-provider-id'],
        container: 'quarantine_folder',
      },
      verdictAt: new Date(now.getTime() - 5_000),
      startedAt: new Date(now.getTime() - 2_000),
      completedAt: now,
      rowVersion: 1,
      createdAt: new Date(now.getTime() - 4_000),
      updatedAt: now,
      ...patch,
    };
    this.actions.push(row);
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
      const {
        organizationId: _o,
        apiConnectionId: _a,
        mailboxId: _m,
        remediationGeneration: _g,
        lastActionId: _l,
        ...view
      } = c;
      return copy({
        ...view,
        remediationId: w.actions.find((a) => a.id === c.lastActionId)?.publicId ?? c.remediationId,
        quarantineEntryId: w.copyEntries.get(c.id)?.publicId ?? c.quarantineEntryId,
      });
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
                (!filter.remediationState ||
                  filter.remediationState.includes(c.remediationState)) &&
                (!filter.direction || filter.direction.includes(c.direction)) &&
                (!filter.policyDisposition ||
                  (c.policyDisposition !== null &&
                    filter.policyDisposition.includes(c.policyDisposition))) &&
                (!filter.dlpAction ||
                  (c.dlpAction !== null && filter.dlpAction.includes(c.dlpAction))) &&
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
      remediationCounters: (scope: TenantScope, ids: readonly bigint[], from: Date) =>
        Promise.resolve(
          w
            .mine(w.remediationCounters, scope)
            .filter((c) => ids.includes(c.apiConnectionId) && c.hour >= from)
            .map(({ organizationId: _o, ...c }) => ({ ...c })),
        ),
      remediationBacklog: (scope: TenantScope, ids: readonly bigint[], cap: number) => {
        const out = new Map<
          bigint,
          { pending: number; capped: boolean; oldestCreatedAt: Date | null }
        >();
        for (const id of ids) {
          const pending = w
            .mine(w.actions, scope)
            .filter((a) => a.apiConnectionId === id && a.status === 'pending')
            .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
          out.set(id, {
            pending: Math.min(pending.length, cap),
            capped: pending.length > cap,
            oldestCreatedAt: pending[0]?.createdAt ?? null,
          });
        }
        return Promise.resolve(out);
      },
      organizationRemediationMode: (scope: TenantScope) => {
        const row = w.mine(w.policies, scope).find((p) => p.domainId === null);
        return Promise.resolve(row ? { mode: row.mode } : null);
      },
      reasonCodes: (_scope: TenantScope, messageId: bigint) =>
        Promise.resolve([...(w.reasonCodes.get(messageId.toString()) ?? [])]),
      // Step API-4 (A12, B6).
      excludedMailboxes: (scope: TenantScope) =>
        Promise.resolve(
          w
            .mine(w.mailboxes, scope)
            .filter((m) => m.scopeState === 'excluded' && m.status !== 'deleted').length,
        ),
      detectEvaluation: (scope: TenantScope, messageId: bigint) =>
        Promise.resolve(
          w.organizations.some((o) => o.id === scope.organizationId)
            ? (w.detectRows.get(`${scope.organizationId}:${messageId}`) ?? null)
            : null,
        ),
      dlpResult: (scope: TenantScope, messageId: bigint) =>
        Promise.resolve(w.dlpResults.get(`${scope.organizationId}:${messageId}`) ?? null),
      copyPolicyDecision: (scope: TenantScope, c: { id: bigint }) =>
        Promise.resolve(
          w
            .mine(w.actions, scope)
            .filter((a) => a.copyId === c.id && a.trigger === 'policy')
            .sort((a, b) => (a.id < b.id ? 1 : -1))[0]?.decision ?? null,
        ),
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

  /** Step API-2: the `ApiRemediationRepository` double. */
  remediationDouble(): Partial<Record<keyof ApiRemediationRepository, unknown>> {
    const w = this;
    const policyView = (p: StoredPolicy): PolicyRow => {
      const { organizationId: _o, ...row } = p;
      return copy(row);
    };
    const actionRow = (a: StoredAction): RemediationDetailRow => {
      const mailbox = w.mailboxes.find((m) => m.id === a.mailboxId)!;
      const c = w.copies.find((x) => x.id === a.copyId);
      const refs = a.providerRefs as {
        before?: unknown[];
        after?: unknown[];
        container?: string;
      } | null;
      return {
        id: a.id,
        publicId: a.publicId,
        action: a.action,
        trigger: a.trigger,
        status: a.status,
        reasonCode: a.reasonCode,
        attempts: a.attempts,
        locateAttempts: a.locateAttempts,
        lastErrorCode: a.lastErrorCode,
        lastHttpStatus: a.lastHttpStatus,
        generation: a.generation,
        mailboxPublicId: mailbox.publicId,
        mailboxAddress: mailbox.primaryAddress,
        connectionPublicId: mailbox.connectionPublicId,
        detectionPublicId: c?.publicId ?? null,
        quarantineEntryPublicId: a.quarantineEntryPublicId,
        clawbackPublicId: a.clawbackPublicId ?? null,
        createdAt: a.createdAt,
        nextAttemptAt: a.nextAttemptAt,
        verdictAt: a.verdictAt,
        startedAt: a.startedAt,
        completedAt: a.completedAt,
        updatedAt: a.updatedAt,
        decision: copy(a.decision) as RemediationDetailRow['decision'],
        requestedByType: a.requestedByType,
        requestedByUserPublicId: null,
        requestReason: a.requestReason,
        providerRefs:
          refs === null || refs === undefined
            ? null
            : {
                container: refs.container ?? null,
                before: refs.before?.length ?? 0,
                after: refs.after?.length ?? 0,
              },
        reversesPublicId: w.actions.find((x) => x.id === a.reversesActionId)?.publicId ?? null,
        reversedByPublicId: w.actions.find((x) => x.id === a.reversedByActionId)?.publicId ?? null,
        releasePublicId: null,
      };
    };
    const detectOnlyColumns = (write: PolicyWrite) => ({
      detectOnlyUntil: write.detectOnly?.until ?? null,
      detectOnlyThen: write.detectOnly?.then ?? null,
      detectOnlyStartedAt: write.detectOnly?.startedAt ?? null,
      detectOnlyNotifiedAt: null,
    });
    return {
      simulatedSince: (scope: TenantScope, domainId: bigint | null, since: Date, cap: number) => {
        const mailboxIds = new Set(
          w
            .mine(w.mailboxes, scope)
            .filter(
              (m) =>
                domainId === null ||
                w.domains.find((d) => d.id === domainId)?.publicId === m.domain?.publicId,
            )
            .map((m) => m.id),
        );
        const n = w
          .mine(w.actions, scope)
          .filter(
            (a) => a.status === 'simulated' && a.createdAt >= since && mailboxIds.has(a.mailboxId),
          ).length;
        return Promise.resolve(Math.min(cap, n));
      },
      policies: (scope: TenantScope) => {
        const rows = w.mine(w.policies, scope);
        const org = rows.find((p) => p.domainId === null);
        const domains: DomainPolicyRow[] = rows
          .filter((p) => p.domainId !== null)
          .flatMap((p) => {
            const d = w.domains.find((x) => x.id === p.domainId);
            return d ? [{ ...policyView(p), domain: { publicId: d.publicId, name: d.name } }] : [];
          });
        return Promise.resolve({ organization: org ? policyView(org) : null, domains });
      },
      lockOrganization: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(w.organizations.some((o) => o.id === scope.organizationId)),
      lockDomain: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const d = w.mine(w.domains, scope).find((x) => x.publicId === publicId);
        return Promise.resolve(d ? { id: d.id, publicId: d.publicId, name: d.name } : null);
      },
      lockPolicy: (_tx: unknown, scope: TenantScope, domainId: bigint | null) => {
        const p = w.mine(w.policies, scope).find((x) => x.domainId === domainId);
        return Promise.resolve(p ? policyView(p) : null);
      },
      createPolicy: (
        _tx: unknown,
        scope: TenantScope,
        domainId: bigint | null,
        write: PolicyWrite,
      ) => {
        const row: StoredPolicy = {
          id: w.id(),
          publicId: crypto.randomUUID(),
          organizationId: scope.organizationId,
          domainId,
          mode: write.mode,
          document: copy(write.document) as PolicyRow['document'],
          documentSha256: write.documentSha256,
          rowVersion: 1,
          updatedAt: new Date(),
          ...detectOnlyColumns(write),
        };
        w.policies.push(row);
        return Promise.resolve(policyView(row));
      },
      updatePolicy: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        rowVersion: number,
        write: PolicyWrite,
      ) => {
        const p = w.mine(w.policies, scope).find((x) => x.id === id && x.rowVersion === rowVersion);
        if (!p) return Promise.resolve(false);
        Object.assign(p, {
          mode: write.mode,
          document: copy(write.document),
          documentSha256: write.documentSha256,
          rowVersion: p.rowVersion + 1,
          updatedAt: new Date(),
          ...(write.keepDetectOnly === true ? {} : detectOnlyColumns(write)),
        });
        return Promise.resolve(true);
      },
      policyById: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const p = w.mine(w.policies, scope).find((x) => x.id === id);
        return Promise.resolve(p ? policyView(p) : null);
      },
      deletePolicy: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const before = w.policies.length;
        w.policies = w.policies.filter(
          (p) => !(p.id === id && p.organizationId === scope.organizationId),
        );
        return Promise.resolve(w.policies.length < before);
      },
      remediations: (
        scope: TenantScope,
        filter: RemediationFilter,
        range: { from: Date; to: Date },
        page: { take: number; before?: { at: Date; id: bigint } },
      ) =>
        Promise.resolve(
          w
            .mine(w.actions, scope)
            .map((a) => actionRow(a))
            .filter(
              (a) =>
                a.createdAt >= range.from &&
                a.createdAt < range.to &&
                (!filter.status || filter.status.includes(a.status)) &&
                (!filter.action || filter.action.includes(a.action)) &&
                (!filter.trigger || filter.trigger.includes(a.trigger)) &&
                (filter.mailboxPublicId === undefined ||
                  a.mailboxPublicId === filter.mailboxPublicId) &&
                (filter.connectionPublicId === undefined ||
                  a.connectionPublicId === filter.connectionPublicId) &&
                (filter.detectionPublicId === undefined ||
                  a.detectionPublicId === filter.detectionPublicId) &&
                (page.before === undefined ||
                  a.createdAt < page.before.at ||
                  (a.createdAt.getTime() === page.before.at.getTime() && a.id < page.before.id)),
            )
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || (a.id < b.id ? 1 : -1))
            .slice(0, page.take),
        ),
      remediation: (scope: TenantScope, publicId: string) => {
        const a = w.mine(w.actions, scope).find((x) => x.publicId === publicId);
        return Promise.resolve(a ? actionRow(a) : null);
      },
      lockCopy: (_tx: unknown, scope: TenantScope, publicId: string): Promise<CopyFacts | null> => {
        const c = w.mine(w.copies, scope).find((x) => x.publicId === publicId);
        if (!c) return Promise.resolve(null);
        const mailbox = w.mailboxes.find((m) => m.id === c.mailboxId)!;
        return Promise.resolve({
          id: c.id,
          receivedAt: c.receivedAt,
          publicId: c.publicId,
          organizationId: c.organizationId,
          messageId: c.messageId,
          apiConnectionId: c.apiConnectionId,
          mailboxId: c.mailboxId,
          status: c.status,
          verdictAuthority: c.verdictAuthority,
          remediationState: c.remediationState,
          remediationAction: c.remediationAction,
          remediationGeneration: c.remediationGeneration,
          lastActionId: c.lastActionId,
          grantActive: mailbox.grantActive,
        });
      },
      hasActiveAction: (
        _tx: unknown,
        scope: TenantScope,
        c: { id: bigint },
        exceptId: bigint | null = null,
      ) =>
        Promise.resolve(
          w
            .mine(w.actions, scope)
            .some(
              (a) =>
                a.copyId === c.id &&
                a.id !== exceptId &&
                (a.status === 'pending' || a.status === 'in_progress'),
            ),
        ),
      lastSucceeded: (_tx: unknown, scope: TenantScope, c: { id: bigint }, action: string) => {
        const rows = w
          .mine(w.actions, scope)
          .filter(
            (a) =>
              a.copyId === c.id &&
              a.action === action &&
              a.status === 'succeeded' &&
              a.reversedByActionId === null,
          );
        const last = rows[rows.length - 1];
        return Promise.resolve(last ? { id: last.id } : null);
      },
      entryOfCopy: (_tx: unknown, _scope: TenantScope, c: { id: bigint }) =>
        Promise.resolve(w.copyEntries.get(c.id) ?? null),
      lockRemediation: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const a = w.mine(w.actions, scope).find((x) => x.publicId === publicId);
        const c = a ? w.mine(w.copies, scope).find((x) => x.id === a.copyId) : undefined;
        return Promise.resolve<{ row: LockedRemediation; copyGeneration: number } | null>(
          a && c
            ? {
                row: {
                  id: a.id,
                  publicId: a.publicId,
                  action: a.action,
                  status: a.status,
                  quarantineEntryId: a.quarantineEntryId,
                  copyId: a.copyId,
                  copyReceivedAt: a.copyReceivedAt,
                  generation: a.generation,
                  rowVersion: a.rowVersion,
                },
                copyGeneration: c.remediationGeneration,
              }
            : null,
        );
      },
      retry: (_tx: unknown, scope: TenantScope, row: LockedRemediation, now: Date) => {
        const a = w
          .mine(w.actions, scope)
          .find((x) => x.id === row.id && x.rowVersion === row.rowVersion && x.status === 'failed');
        if (!a) return Promise.resolve(false);
        Object.assign(a, {
          status: 'pending',
          attempts: 0,
          locateAttempts: 0,
          nextAttemptAt: now,
          reasonCode: null,
          lastErrorCode: null,
          lastHttpStatus: null,
          startedAt: null,
          completedAt: null,
          rowVersion: a.rowVersion + 1,
        });
        return Promise.resolve(true);
      },
    };
  }

  /** Step API-2: the `RemediationActionWriter` double (the unique key collapses like MySQL's). */
  actionWriterDouble(): Partial<RemediationActionWriter> {
    const w = this;
    return {
      queue: (_tx: unknown, row: QueueRemediationAction): Promise<QueuedAction> => {
        const actionKey = remediationActionKey(row.copyPublicId, row.action, row.generation);
        const existing = w.actions.find((a) => a.actionKey === actionKey);
        if (existing) {
          if (existing.status === 'in_progress' || existing.status === 'succeeded') {
            return Promise.resolve({
              id: existing.id,
              publicId: existing.publicId,
              outcome: existing.status === 'in_progress' ? 'busy' : 'succeeded',
            });
          }
          Object.assign(existing, {
            status: 'pending',
            trigger: row.trigger,
            decision: copy(row.decision),
            attempts: 0,
            nextAttemptAt: row.now,
            requestReason: row.requestReason,
          });
          return Promise.resolve({
            id: existing.id,
            publicId: existing.publicId,
            outcome: 'rearmed',
          });
        }
        const c = w.copies.find((x) => x.id === row.copyId)!;
        const created = w.addAction(c, {
          action: row.action,
          generation: row.generation,
          actionKey,
          trigger: row.trigger as StoredAction['trigger'],
          status: 'pending',
          decision: copy(row.decision),
          reversesActionId: row.reversesActionId,
          quarantineEntryId: row.quarantineEntryId,
          releaseLogId: row.releaseLogId,
          requestedByType: row.requestedByType,
          requestedByUserId: row.requestedByUserId,
          requestReason: row.requestReason,
          attempts: 0,
          nextAttemptAt: row.now,
          providerRefs: null,
          verdictAt: null,
          startedAt: null,
          completedAt: null,
          createdAt: row.now,
          updatedAt: row.now,
        });
        return Promise.resolve({ id: created.id, publicId: created.publicId, outcome: 'inserted' });
      },
      markCopyPending: (
        _tx: unknown,
        target: { copyId: bigint },
        update: { remediationAction: string | null; lastActionId: bigint },
      ) => {
        w.copyUpdates.push({ copyId: target.copyId, ...update });
        const c = w.copies.find((x) => x.id === target.copyId);
        if (c) {
          c.remediationState = 'pending';
          if (update.remediationAction !== null) {
            c.remediationAction = update.remediationAction as StoredCopy['remediationAction'];
          }
          c.lastActionId = update.lastActionId;
        }
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

/**
 * Overrides the API-mode repository, the API-mode status and the feature lookup; step API-2: the
 * remediation repository and the action-row writer.
 */
export function overrideApiMode(
  builder: TestingModuleBuilder,
  world: ApiModeWorld,
): TestingModuleBuilder {
  return builder
    .overrideProvider(ApiModeRepository)
    .useValue(world.double())
    .overrideProvider(ApiRemediationRepository)
    .useValue(world.remediationDouble())
    .overrideProvider(RemediationActionWriter)
    .useValue(world.actionWriterDouble())
    .overrideProvider(ApiClawbackRepository)
    .useValue(clawbackRepositoryDouble(world))
    .overrideProvider(ApiModeStatusService)
    .useValue(world.statusDouble())
    .overrideProvider(OrganizationFeaturesService)
    .useValue(world.featuresDouble());
}
